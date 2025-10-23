use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

#[cfg(not(target_os = "android"))]
pub fn init_logger() {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(PATTERN)))
        .build();
    let root = Root::builder().appender("stdout").build(LevelFilter::Debug);
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(root)
        .unwrap();
    log4rs::init_config(config).unwrap();
}

#[cfg(target_os = "android")]
pub fn init_logger() {
    let config = android_logger::Config::default()
        .with_max_level(LevelFilter::Debug)
        .with_tag("OhMyKeymint");

    let android_logger = android_logger::AndroidLogger::new(config);

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(PATTERN)))
        .build();
    let root = Root::builder().appender("stdout").build(LevelFilter::Debug);
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(root)
        .unwrap();

    let log4rs = log4rs::Logger::new(config);

    multi_log::MultiLogger::init(
        vec![Box::new(android_logger), Box::new(log4rs)],
        log::Level::Debug,
    )
    .unwrap();
}
