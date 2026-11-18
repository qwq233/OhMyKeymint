// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, Context as _};
use jiff::ZonedDateTime;
use log::{Level, LevelFilter, Record};
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::writer::{console::ConsoleWriter, simple::SimpleWriter};
use log4rs::encode::{Color, Encode, Style, Write as LogWriter};

pub const DEFAULT_MAX_LOG_SIZE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct LockedRotatingFileAppender {
    path: PathBuf,
    file: Mutex<Option<File>>,
    encoder: Box<dyn Encode>,
    max_size_bytes: u64,
}

impl LockedRotatingFileAppender {
    pub fn new<P: AsRef<Path>>(path: P, encoder: Box<dyn Encode>) -> io::Result<Self> {
        Self::with_max_size(path, encoder, DEFAULT_MAX_LOG_SIZE_BYTES)
    }

    pub fn with_max_size<P: AsRef<Path>>(
        path: P,
        encoder: Box<dyn Encode>,
        max_size_bytes: u64,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let _ = fs::remove_file(suffixed_path(&path, ".lock"));
        Ok(Self { path, file: Mutex::new(None), encoder, max_size_bytes })
    }

    fn open_log_file(path: &Path) -> io::Result<File> {
        fs::create_dir_all(Self::parent_dir(path))?;
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let fd = file.as_raw_fd();
        if let Ok(parent_metadata) = fs::metadata(Self::parent_dir(path)) {
            let _ = unsafe { libc::fchown(fd, parent_metadata.uid(), parent_metadata.gid()) };
        }
        let _ = unsafe { libc::fchmod(fd, 0o660) };
        Ok(file)
    }

    fn parent_dir(path: &Path) -> &Path {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn rotate_if_needed(&self, next_write_len: usize) -> io::Result<Option<Metadata>> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };

        if metadata.len() == 0
            || metadata.len().saturating_add(next_write_len as u64) <= self.max_size_bytes
        {
            return Ok(Some(metadata));
        }

        rotate_existing_log_file(&self.path)?;
        Ok(None)
    }
}

fn rotate_existing_log_file(path: &Path) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }

    let rotated_path = suffixed_path(path, ".1");
    let ignore_not_found = |result: io::Result<()>| match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    };

    ignore_not_found(fs::remove_file(&rotated_path))?;
    ignore_not_found(fs::rename(path, &rotated_path))
}

impl Append for LockedRotatingFileAppender {
    fn append(&self, record: &Record) -> anyhow::Result<()> {
        let mut encoded = SimpleWriter(Vec::new());
        self.encoder
            .encode(&mut encoded, record)
            .with_context(|| format!("failed to encode {}", self.path.display()))?;
        let data = encoded.0;

        let mut file =
            self.file.lock().map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        let _file_guard = FileLockGuard::lock_path(&self.path)
            .with_context(|| format!("failed to lock {}", self.path.display()))?;
        let metadata = self
            .rotate_if_needed(data.len())
            .with_context(|| format!("failed to rotate {}", self.path.display()))?;

        let cached_file_matches = match (file.as_ref(), metadata.as_ref()) {
            (Some(file), Some(metadata)) => file.metadata().is_ok_and(|cached| {
                cached.dev() == metadata.dev() && cached.ino() == metadata.ino()
            }),
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !cached_file_matches {
            *file = None;
        }
        if file.is_none() {
            *file = Some(
                Self::open_log_file(&self.path)
                    .with_context(|| format!("failed to open {}", self.path.display()))?,
            );
        }

        if let Err(error) = file.as_mut().unwrap().write_all(&data) {
            *file = None;
            return Err(error).with_context(|| format!("failed to write {}", self.path.display()));
        }
        if let Err(error) = file.as_mut().unwrap().flush() {
            *file = None;
            return Err(error).with_context(|| format!("failed to flush {}", self.path.display()));
        }
        Ok(())
    }

    fn flush(&self) {}
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

struct FileLockGuard {
    #[cfg(unix)]
    file: File,
}

impl FileLockGuard {
    #[cfg(unix)]
    fn lock_path(path: &Path) -> io::Result<Self> {
        let parent = LockedRotatingFileAppender::parent_dir(path);
        let file = match File::open(parent) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(parent)?;
                File::open(parent)?
            }
            Err(error) => return Err(error),
        };
        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if result == 0 {
            Ok(Self { file })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(unix))]
    fn lock_path(_path: &Path) -> io::Result<Self> {
        Ok(Self {})
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug)]
struct LocalLogEncoder;

impl Encode for LocalLogEncoder {
    fn encode(&self, writer: &mut dyn LogWriter, record: &Record<'_>) -> anyhow::Result<()> {
        write!(writer, "{} [", ZonedDateTime::now().strftime("%Y-%m-%d %H:%M:%S UTC%:z"))?;
        let mut style = Style::new();
        let highlight = match record.level() {
            Level::Error => Some(style.text(Color::Red).intense(true)),
            Level::Warn => Some(style.text(Color::Yellow)),
            Level::Info => Some(style.text(Color::Green)),
            Level::Trace => Some(style.text(Color::Cyan)),
            Level::Debug => None,
        };
        if let Some(style) = &highlight {
            writer.set_style(style)?;
        }
        let level = write!(writer, "{}", record.level());
        if highlight.is_some() {
            writer.set_style(&Style::new())?;
        }
        level?;
        writeln!(writer, "] {} - {}", record.module_path().unwrap_or("???"), record.args())?;
        Ok(())
    }
}

// The log4rs console appender enables the chrono-backed pattern encoder.
struct StdoutAppender(Option<ConsoleWriter>);

impl fmt::Debug for StdoutAppender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StdoutAppender").finish_non_exhaustive()
    }
}

impl Append for StdoutAppender {
    fn append(&self, record: &Record<'_>) -> anyhow::Result<()> {
        let mut terminal;
        let mut plain;
        let writer: &mut dyn LogWriter = if let Some(console) = &self.0 {
            terminal = console.lock();
            &mut terminal
        } else {
            plain = SimpleWriter(io::stdout().lock());
            &mut plain
        };
        LocalLogEncoder.encode(writer, record)?;
        writer.flush()?;
        Ok(())
    }

    fn flush(&self) {}
}

pub fn init_console_file_logger(
    file_path: &str,
    configured_level: LevelFilter,
    error_prefix: &str,
) -> anyhow::Result<()> {
    let (config, file_logging_ready) =
        build_console_file_config(file_path, LevelFilter::Trace, error_prefix)?;
    let android_logger = android_logger::AndroidLogger::new(
        android_logger::Config::default()
            .with_max_level(LevelFilter::Trace)
            .with_tag("OhMyKeymint"),
    );
    let log4rs = log4rs::Logger::new(config);
    multi_log::MultiLogger::init(
        vec![Box::new(android_logger), Box::new(log4rs)],
        log::Level::Trace,
    )?;
    log::set_max_level(configured_level);
    if file_logging_ready {
        log::info!("file logging enabled at {} with level {:?}", file_path, configured_level);
    }
    Ok(())
}

fn build_console_file_config<P: AsRef<Path>>(
    file_path: P,
    level: LevelFilter,
    error_prefix: &str,
) -> anyhow::Result<(Config, bool)> {
    let mut builder = Config::builder();
    let mut root = Root::builder();
    if fs::read_link("/proc/self/fd/1")
        .map(|target| target != Path::new("/dev/null"))
        .unwrap_or(true)
    {
        let stdout = StdoutAppender(ConsoleWriter::stdout());
        builder = builder.appender(Appender::builder().build("stdout", Box::new(stdout)));
        root = root.appender("stdout");
    }
    let path = file_path.as_ref();

    match FileLockGuard::lock_path(path).and_then(|_guard| rotate_existing_log_file(path)) {
        Ok(()) => {}
        Err(error) => eprintln!(
            "{} startup log refresh skipped for {}: {}",
            error_prefix,
            path.display(),
            error
        ),
    }

    let file_logging_ready = match LockedRotatingFileAppender::new(path, Box::new(LocalLogEncoder))
    {
        Ok(file) => {
            builder = builder.appender(Appender::builder().build("file", Box::new(file)));
            root = root.appender("file");
            true
        }
        Err(error) => {
            eprintln!("{} file logging disabled for {}: {}", error_prefix, path.display(), error);
            false
        }
    };

    Ok((builder.build(root.build(level))?, file_logging_ready))
}
