use std::sync::OnceLock;

use log::LevelFilter;

const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/omk/logs/keymint.log";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

pub fn init_logger() {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Err(error) = kmr_common::runtime::logging::init_console_file_logger(
            DEFAULT_LOG_PATH,
            LevelFilter::Debug,
            "keymint logging",
        ) {
            eprintln!("keymint logging failed to initialize: {error:#}");
        }
    });
}
