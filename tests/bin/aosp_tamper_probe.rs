use std::{env, ffi::CString, process::Command};

use anyhow::{anyhow, bail, Context, Result};

#[path = "../aosp_tamper/mod.rs"]
mod aosp_tamper;
#[path = "../../src/plat/attestation.rs"]
mod attestation;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use aosp_tamper::model::{ProbeOutput, ProbeRow, SignalLevel};

const CLAIMED_PACKAGE: &str = "io.github.vvb2060.keyattestation";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LaunchOptions {
    json: bool,
    quick: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aosp_tamper_probe failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let options = parse_args(env::args().skip(1))?;
    let claimed_uid = adopt_claimed_package_identity()?;
    set_claimed_process_name(CLAIMED_PACKAGE)?;

    let mut output = aosp_tamper::run_probe(options.quick)?;
    output.advisory_rows.insert(
        0,
        ProbeRow::new(
            "Claimed package",
            format!("{CLAIMED_PACKAGE}; uid={claimed_uid}; processName=keyattestation"),
            SignalLevel::Info,
            None,
        ),
    );
    if options.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_text_report(&output);
    }
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<LaunchOptions> {
    let mut options = LaunchOptions::default();

    let args = args.into_iter();
    for arg in args {
        match arg.as_str() {
            "--json" => options.json = true,
            "--quick" => options.quick = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(anyhow!(
                    "unknown argument {other}; expected --json, --quick, or --help"
                ));
            }
        }
    }

    Ok(options)
}

fn adopt_claimed_package_identity() -> Result<u32> {
    let uid = resolve_claimed_package_uid()?;
    let current_uid = unsafe { libc::getuid() as u32 };
    if current_uid == uid {
        return Ok(uid);
    }
    if current_uid != 0 {
        bail!("claiming {CLAIMED_PACKAGE} requires starting as root or the target app uid; current uid={current_uid}, target uid={uid}");
    }

    let gid = uid as libc::gid_t;
    let uid_t = uid as libc::uid_t;
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(std::io::Error::last_os_error()).context("setgroups failed");
        }
        if libc::setresgid(gid, gid, gid) != 0 {
            return Err(std::io::Error::last_os_error()).context("setresgid failed");
        }
        if libc::setresuid(uid_t, uid_t, uid_t) != 0 {
            return Err(std::io::Error::last_os_error()).context("setresuid failed");
        }
    }
    Ok(uid)
}

fn resolve_claimed_package_uid() -> Result<u32> {
    let output = Command::new("/system/bin/cmd")
        .args(["package", "list", "packages", "-U", CLAIMED_PACKAGE])
        .output()
        .context("failed to execute package UID query")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "package UID query exited with status {}: {}",
            output.status,
            stderr.trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("package UID query was not UTF-8")?;
    parse_claimed_package_uid(&stdout)
}

fn parse_claimed_package_uid(contents: &str) -> Result<u32> {
    for line in contents.lines() {
        let Some(rest) = line.strip_prefix("package:") else {
            continue;
        };
        let Some((name, uid)) = rest.split_once(" uid:") else {
            continue;
        };
        if name != CLAIMED_PACKAGE {
            continue;
        }
        return uid
            .trim()
            .parse::<u32>()
            .with_context(|| format!("package UID was invalid: {uid}"));
    }
    bail!("package {CLAIMED_PACKAGE} was not present in package UID query output")
}

fn set_claimed_process_name(package: &str) -> Result<()> {
    let visible = package
        .rsplit('.')
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or(package);
    let trimmed = if visible.len() > 15 {
        &visible[..15]
    } else {
        visible
    };
    let c_name = CString::new(trimmed)?;
    let result = unsafe { libc::prctl(libc::PR_SET_NAME, c_name.as_ptr() as usize, 0, 0, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn print_help() {
    println!("Usage: aosp_tamper_probe [--json] [--quick]");
    println!("  --json   emit machine-readable JSON");
    println!("  --quick  skip higher-cost timing probes");
    println!("  claimed package identity: {CLAIMED_PACKAGE}");
    println!("  note: executable staging must stay outside the claimed app private directory");
}

fn print_text_report(output: &ProbeOutput) {
    println!("{}", output.headline);
    println!("{}", output.summary);
    println!(
        "verdict={} tamper_score={} hard={} soft={} supplementary={}",
        output.verdict.as_text(),
        output.tamper_score,
        output.policy_hard_count,
        output.policy_soft_count,
        output.supplementary_count
    );

    for row in &output.rows {
        let category = row
            .scored_category
            .map(|category| category.as_text())
            .unwrap_or("-");
        println!(
            "- {}: {} [{}; {}{}]",
            row.label,
            row.value,
            row.level.as_text(),
            category,
            row_risk_suffix(row)
        );
    }

    if !output.advisory_rows.is_empty() {
        println!("Advisory");
        for row in &output.advisory_rows {
            println!(
                "- {}: {} [{}{}]",
                row.label,
                row.value,
                row.level.as_text(),
                row_risk_suffix(row)
            );
        }
    }
}

fn row_risk_suffix(row: &ProbeRow) -> String {
    match (row.suspicion_score, row.fatal_on_fail) {
        (Some(score), Some(true)) => format!("; suspicion={score}; fatal_on_fail=true"),
        (Some(score), Some(false)) => format!("; suspicion={score}; fatal_on_fail=false"),
        (Some(score), None) => format!("; suspicion={score}"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_json_and_quick_without_identity_changes() {
        let options = parse_args(["--json", "--quick"].into_iter().map(str::to_string)).unwrap();

        assert_eq!(
            options,
            LaunchOptions {
                json: true,
                quick: true,
            }
        );
    }

    #[test]
    fn parse_args_rejects_arbitrary_spoof_package() {
        let error = parse_args(
            ["--spoof-package", "com.example.app"]
                .into_iter()
                .map(str::to_string),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown argument --spoof-package"));
    }

    #[test]
    fn claimed_package_uid_parser_extracts_exact_package_only() {
        let uid = parse_claimed_package_uid(
            "package:io.github.vvb2060.keyattestation.extra uid:12345\npackage:io.github.vvb2060.keyattestation uid:23456\n",
        )
        .unwrap();
        assert_eq!(uid, 23456);
    }

    #[test]
    fn claimed_package_uid_parser_rejects_missing_package() {
        let error = parse_claimed_package_uid("package:com.example.app uid:12345\n").unwrap_err();
        assert!(error
            .to_string()
            .contains("io.github.vvb2060.keyattestation"));
    }

    #[test]
    fn claimed_package_uid_parser_rejects_invalid_uid() {
        let error = parse_claimed_package_uid("package:io.github.vvb2060.keyattestation uid:abc\n")
            .unwrap_err();
        assert!(error.to_string().contains("package UID was invalid"));
    }

    #[test]
    fn claimed_package_tail_fits_android_process_name_limit() {
        let visible = CLAIMED_PACKAGE.rsplit('.').next().unwrap();
        assert_eq!(visible, "keyattestation");
        assert!(visible.len() <= 15);
    }
}
