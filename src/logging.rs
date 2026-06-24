use std::sync::OnceLock;

use anyhow::Result;
use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/omk/keymint.log";
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

pub fn init_logger() {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Err(error) = init_logger_inner() {
            eprintln!("keymint logging failed to initialize: {error:#}");
        }
    });
}

fn init_logger_inner() -> Result<()> {
    let level = LevelFilter::Debug;
    let config = android_logger::Config::default()
        .with_max_level(level)
        .with_tag("OhMyKeymint");

    let android_logger = android_logger::AndroidLogger::new(config);

    let (config, file_logging_ready) = kmr_common::runtime::logging::build_console_file_config(
        DEFAULT_LOG_PATH,
        PATTERN,
        level,
        "keymint logging",
    )?;
    let log4rs = log4rs::Logger::new(config);

    multi_log::MultiLogger::init(
        vec![Box::new(android_logger), Box::new(log4rs)],
        log::Level::Debug,
    )?;

    if file_logging_ready {
        log::info!(
            "file logging enabled at {} with level {:?}",
            DEFAULT_LOG_PATH,
            level
        );
    }

    Ok(())
}
