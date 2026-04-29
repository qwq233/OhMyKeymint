use std::env;

use anyhow::{anyhow, Result};

#[path = "../aosp_tamper/mod.rs"]
mod aosp_tamper;
#[path = "../../src/plat/attestation.rs"]
mod attestation;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use aosp_tamper::model::ProbeOutput;

fn main() {
    if let Err(error) = run() {
        eprintln!("aosp_tamper_probe failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut json = false;
    let mut quick = false;

    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "--quick" => quick = true,
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => {
                return Err(anyhow!(
                    "unknown argument {other}; expected --json, --quick, or --help"
                ));
            }
        }
    }

    let output = aosp_tamper::run_probe(quick)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_text_report(&output);
    }
    Ok(())
}

fn print_help() {
    println!("Usage: aosp_tamper_probe [--json] [--quick]");
    println!("  --json   emit machine-readable JSON");
    println!("  --quick  skip higher-cost timing probes");
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
            "- {}: {} [{}; {}]",
            row.label,
            row.value,
            row.level.as_text(),
            category
        );
    }

    if !output.advisory_rows.is_empty() {
        println!("Advisory");
        for row in &output.advisory_rows {
            println!("- {}: {} [{}]", row.label, row.value, row.level.as_text());
        }
    }
}
