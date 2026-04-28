use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

const RESETPROP_FALLBACKS: &[ResetpropSpec] = &[
    ResetpropSpec::direct("/system_ext/bin/resetprop"),
    ResetpropSpec::direct("/system/bin/resetprop"),
    ResetpropSpec::direct("/data/adb/ksu/bin/resetprop"),
    ResetpropSpec::subcommand("/data/adb/ksud", "resetprop"),
];

#[derive(Clone, Copy)]
struct ResetpropSpec {
    program: &'static str,
    prepend_arg: Option<&'static str>,
}

impl ResetpropSpec {
    const fn direct(program: &'static str) -> Self {
        Self {
            program,
            prepend_arg: None,
        }
    }

    const fn subcommand(program: &'static str, prepend_arg: &'static str) -> Self {
        Self {
            program,
            prepend_arg: Some(prepend_arg),
        }
    }
}

#[derive(Clone)]
pub struct ResetpropCommand {
    program: String,
    prepend_arg: Option<String>,
}

static HELPER: OnceLock<Mutex<ResetpropHelperClient>> = OnceLock::new();

pub fn bootstrap_privileged_helper() -> Result<()> {
    if HELPER.get().is_some() {
        return Ok(());
    }

    let command = match find_resetprop_command() {
        Ok(command) => command,
        Err(error) => {
            log::warn!("resetprop helper unavailable at startup: {error:#}");
            return Ok(());
        }
    };

    #[cfg(unix)]
    {
        let (parent, child) =
            UnixStream::pair().context("failed to create resetprop socketpair")?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to fork resetprop helper");
        }
        if pid == 0 {
            drop(parent);
            let exit_code = match helper_loop(child, command) {
                Ok(()) => 0,
                Err(error) => {
                    eprintln!("resetprop helper exiting after fatal error: {error:#}");
                    1
                }
            };
            unsafe { libc::_exit(exit_code) };
        }

        drop(child);
        let client = ResetpropHelperClient { stream: parent };
        if HELPER.set(Mutex::new(client)).is_err() {
            log::debug!("resetprop helper was already installed");
        } else {
            log::info!("Started privileged resetprop helper process pid={pid}");
        }
    }

    #[cfg(not(unix))]
    {
        log::warn!("resetprop helper is not available on this platform");
    }

    Ok(())
}

pub fn runtime_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    let helper = HELPER
        .get()
        .ok_or_else(|| anyhow!("privileged resetprop helper is unavailable"))?;
    let mut helper = helper
        .lock()
        .map_err(|_| anyhow!("privileged resetprop helper lock poisoned"))?;
    helper.write_and_verify_property(property, value)
}

pub fn direct_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    let command = find_resetprop_command()?;
    execute_write_and_verify(&command, property, value)
}

pub fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn find_resetprop_command() -> Result<ResetpropCommand> {
    if let Some(program) = find_program_in_path("resetprop") {
        return Ok(ResetpropCommand {
            program,
            prepend_arg: None,
        });
    }

    for fallback in RESETPROP_FALLBACKS {
        if Path::new(fallback.program).exists() {
            return Ok(ResetpropCommand {
                program: fallback.program.to_string(),
                prepend_arg: fallback.prepend_arg.map(str::to_string),
            });
        }
    }

    Err(anyhow!("no usable resetprop binary found"))
}

fn execute_write_and_verify(command: &ResetpropCommand, property: &str, value: &str) -> Result<()> {
    let mut process = Command::new(&command.program);
    if let Some(prepend_arg) = &command.prepend_arg {
        process.arg(prepend_arg);
    }
    let status = process
        .arg(property)
        .arg(value)
        .status()
        .with_context(|| format!("failed to execute resetprop for {property}"))?;
    if !status.success() {
        bail!("resetprop failed for {property} with status {status}");
    }

    let actual = read_string_property(property)
        .ok_or_else(|| anyhow!("property {property} missing after resetprop write"))?;
    if actual.eq_ignore_ascii_case(value) {
        Ok(())
    } else {
        bail!(
            "property verification failed for {property}: expected {value}, got {}",
            actual.trim()
        )
    }
}

fn find_program_in_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

struct ResetpropHelperClient {
    #[cfg(unix)]
    stream: UnixStream,
}

impl ResetpropHelperClient {
    fn write_and_verify_property(&mut self, property: &str, value: &str) -> Result<()> {
        #[cfg(unix)]
        {
            let request = format!("SET\t{property}\t{value}\n");
            self.stream
                .write_all(request.as_bytes())
                .with_context(|| format!("failed to send resetprop request for {property}"))?;
            self.stream
                .flush()
                .with_context(|| format!("failed to flush resetprop request for {property}"))?;

            let mut response = String::new();
            let mut reader = BufReader::new(
                self.stream
                    .try_clone()
                    .context("failed to clone resetprop helper stream")?,
            );
            let read = reader
                .read_line(&mut response)
                .with_context(|| format!("failed to read resetprop response for {property}"))?;
            if read == 0 {
                bail!("resetprop helper closed unexpectedly");
            }
            let response = response.trim_end_matches(['\r', '\n']);
            if response == "OK" {
                return Ok(());
            }
            if let Some(error) = response.strip_prefix("ERR\t") {
                bail!("{error}");
            }
            bail!("unexpected resetprop helper response: {response}");
        }

        #[cfg(not(unix))]
        {
            let _ = (property, value);
            Err(anyhow!("resetprop helper is unsupported on this platform"))
        }
    }
}

#[cfg(unix)]
fn helper_loop(stream: UnixStream, command: ResetpropCommand) -> Result<()> {
    let reader_stream = stream
        .try_clone()
        .context("failed to clone resetprop helper socket")?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("failed to read resetprop helper request")?;
        if read == 0 {
            return Ok(());
        }

        let response = match parse_request(&line) {
            Ok(ResetpropRequest::Set { property, value }) => {
                match execute_write_and_verify(&command, &property, &value) {
                    Ok(()) => "OK\n".to_string(),
                    Err(error) => format!("ERR\t{error:#}\n"),
                }
            }
            Err(error) => format!("ERR\t{error:#}\n"),
        };
        writer
            .write_all(response.as_bytes())
            .context("failed to write resetprop helper response")?;
        writer
            .flush()
            .context("failed to flush resetprop helper response")?;
    }
}

#[cfg(unix)]
enum ResetpropRequest {
    Set { property: String, value: String },
}

#[cfg(unix)]
fn parse_request(line: &str) -> Result<ResetpropRequest> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, '\t');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("SET"), Some(property), Some(value))
            if !property.trim().is_empty() && !value.trim().is_empty() =>
        {
            Ok(ResetpropRequest::Set {
                property: property.to_string(),
                value: value.to_string(),
            })
        }
        _ => Err(anyhow!("invalid resetprop helper request: {trimmed:?}")),
    }
}
