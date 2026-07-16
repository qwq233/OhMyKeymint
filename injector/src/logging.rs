use std::sync::OnceLock;

use anyhow::Result;
use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/omk/logs/injector.log";
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

pub fn init_logger_fallback(level: LevelFilter) {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Err(error) = init_logger_inner(level) {
            eprintln!("injector logging failed to initialize: {error:#}");
        }
    });
}

fn init_logger_inner(configured_level: LevelFilter) -> Result<()> {
    let (config, file_logging_ready) = kmr_common::runtime::logging::build_console_file_config(
        DEFAULT_LOG_PATH,
        PATTERN,
        LevelFilter::Trace,
        "injector logging",
    )?;

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
    update_runtime_level(configured_level);

    if file_logging_ready {
        log::info!(
            "file logging enabled at {} with level {:?}",
            DEFAULT_LOG_PATH,
            configured_level
        );
    }

    log::info!(
        "initialized fallback logging with fixed level {:?}",
        configured_level
    );

    Ok(())
}

pub fn update_runtime_level(level: LevelFilter) {
    log::set_max_level(level);
}
