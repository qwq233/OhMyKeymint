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
const MAX_LOG_SIZE_BYTES: u64 = 4 * 1024 * 1024;
const PATTERN: &str = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} [{h({l})}] {M} - {m}{n}";

static LOGGER_INIT: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
enum LoggerInitMode {
    Configured,
    Fixed(LevelFilter),
}

#[derive(Debug)]
struct LockedFileAppender {
    path: PathBuf,
    lock_file: Mutex<File>,
    encoder: Box<dyn Encode>,
}

impl LockedFileAppender {
    fn new<P: AsRef<Path>>(path: P, encoder: Box<dyn Encode>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let _file = Self::open_log_file(&path)?;
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(suffixed_path(&path, ".lock"))?;

        Ok(Self {
            path,
            lock_file: Mutex::new(lock_file),
            encoder,
        })
    }

    fn open_log_file(path: &Path) -> io::Result<File> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new().create(true).append(true).open(path)
    }

    fn rotate_if_needed(&self, next_write_len: usize) -> io::Result<()> {
        let current_len = match fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };

        if current_len == 0
            || current_len.saturating_add(next_write_len as u64) <= MAX_LOG_SIZE_BYTES
        {
            return Ok(());
        }

        let rotated_path = suffixed_path(&self.path, ".1");
        match fs::remove_file(&rotated_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        match fs::rename(&self.path, &rotated_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        Ok(())
    }
}

impl Append for LockedFileAppender {
    fn append(&self, record: &Record) -> anyhow::Result<()> {
        let mut encoded = SimpleWriter(Vec::new());
        self.encoder
            .encode(&mut encoded, record)
            .with_context(|| format!("failed to encode {}", self.path.display()))?;
        let data = encoded.0;

        let lock_file = self
            .lock_file
            .lock()
            .map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        let _guard = FileLockGuard::lock(&*lock_file)
            .with_context(|| format!("failed to lock {}", self.path.display()))?;
        self.rotate_if_needed(data.len())
            .with_context(|| format!("failed to rotate {}", self.path.display()))?;

        let mut file = Self::open_log_file(&self.path)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        file.write_all(&data)
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        file.flush()
            .with_context(|| format!("failed to flush {}", self.path.display()))?;
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
        if let Err(error) = init_logger_inner(LoggerInitMode::Configured) {
            eprintln!("[Injector][Logger] failed to initialize logger: {error:#}");
        }
    });
}

pub fn init_logger_fallback(level: LevelFilter) {
    let _ = LOGGER_INIT.get_or_init(|| {
        if let Err(error) = init_logger_inner(LoggerInitMode::Fixed(level)) {
            eprintln!("[Injector][Logger] failed to initialize logger: {error:#}");
        }
    });
}

fn init_logger_inner(mode: LoggerInitMode) -> anyhow::Result<()> {
    let configured_level = match mode {
        LoggerInitMode::Configured => {
            let injector_config = crate::config::get();
            let configured_level = injector_config.main.log_level_filter();
            if crate::config::parse_level_filter(&injector_config.main.log_level).is_none() {
                eprintln!(
                    "[Injector][Logger] unknown log level '{}', falling back to debug",
                    injector_config.main.log_level
                );
            }
            configured_level
        }
        LoggerInitMode::Fixed(level) => level,
    };

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

    if let LoggerInitMode::Fixed(level) = mode {
        log::info!(
            "[Injector][Logger] initialized fallback logger with fixed level {:?}",
            level
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
