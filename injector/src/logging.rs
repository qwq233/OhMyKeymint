use std::sync::OnceLock;

use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/omk/logs/injector.log";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

pub fn init_logger_fallback(level: LevelFilter) {
    let _ =
        LOGGER_INIT.get_or_init(|| {
            match kmr_common::runtime::logging::init_console_file_logger(
                DEFAULT_LOG_PATH,
                level,
                "injector logging",
            ) {
                Ok(()) => log::info!("initialized fallback logging with fixed level {:?}", level),
                Err(error) => eprintln!("injector logging failed to initialize: {error:#}"),
            }
        });
}

pub fn init_logger() {
    init_logger_fallback(LevelFilter::Debug);
    let config = crate::config::get();
    if crate::config::parse_level_filter(&config.main.log_level).is_none() {
        log::warn!(
            "injector logging unknown log level '{}', keeping debug fallback",
            config.main.log_level
        );
    }
    log::set_max_level(config.main.log_level_filter());
    std::panic::set_hook(Box::new(|panic_info| {
        log::error!("{}", panic_info);
    }));
}
