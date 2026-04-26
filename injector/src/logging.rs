use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, Context as _};
use log::{LevelFilter, Record};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::{writer::simple::SimpleWriter, Encode};

const DEFAULT_LOG_PATH: &str = "/data/misc/keystore/omk/injector.log";
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

#[derive(Debug)]
struct LockedFileAppender {
    path: PathBuf,
    file: Mutex<SimpleWriter<File>>,
    encoder: Box<dyn Encode>,
}

impl LockedFileAppender {
    fn new<P: AsRef<Path>>(path: P, encoder: Box<dyn Encode>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&path)?;

        Ok(Self {
            path,
            file: Mutex::new(SimpleWriter(file)),
            encoder,
        })
    }
}

impl Append for LockedFileAppender {
    fn append(&self, record: &Record) -> anyhow::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        let _guard = FileLockGuard::lock(&file.0)
            .with_context(|| format!("failed to lock {}", self.path.display()))?;
        self.encoder
            .encode(&mut *file, record)
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush {}", self.path.display()))?;
        Ok(())
    }

    fn flush(&self) {}
}

struct FileLockGuard {
    fd: i32,
}

impl FileLockGuard {
    fn lock(file: &File) -> io::Result<Self> {
        let fd = file.as_raw_fd();
        let result = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if result == 0 {
            Ok(Self { fd })
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.fd, libc::LOCK_UN) };
    }
}

pub fn init_logger() {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Err(error) = init_logger_inner() {
            eprintln!("[Injector][Logger] failed to initialize logger: {error:#}");
        }
    });
}

fn init_logger_inner() -> anyhow::Result<()> {
    let injector_config = crate::config::get();
    let configured_level = injector_config.main.log_level_filter();
    if crate::config::parse_level_filter(&injector_config.main.log_level).is_none() {
        eprintln!(
            "[Injector][Logger] unknown log level '{}', falling back to debug",
            injector_config.main.log_level
        );
    }

    let (config, file_logging_ready) = build_log4rs_config(LevelFilter::Trace)?;

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
            "[Injector][Logger] file logging enabled at {} with level {:?}",
            DEFAULT_LOG_PATH,
            configured_level
        );
    }

    Ok(())
}

pub fn update_runtime_level(level: LevelFilter) {
    log::set_max_level(level);
}

fn build_log4rs_config(level: LevelFilter) -> anyhow::Result<(Config, bool)> {
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(PATTERN)))
        .build();

    let mut builder =
        Config::builder().appender(Appender::builder().build("stdout", Box::new(stdout)));
    let mut root = Root::builder().appender("stdout");

    let file_logging_ready =
        match LockedFileAppender::new(DEFAULT_LOG_PATH, Box::new(PatternEncoder::new(PATTERN))) {
            Ok(file) => {
                builder = builder.appender(Appender::builder().build("file", Box::new(file)));
                root = root.appender("file");
                true
            }
            Err(error) => {
                eprintln!(
                    "[Injector][Logger] file logging disabled for {}: {}",
                    DEFAULT_LOG_PATH, error
                );
                false
            }
        };

    let config = builder.build(root.build(level))?;
    Ok((config, file_logging_ready))
}
