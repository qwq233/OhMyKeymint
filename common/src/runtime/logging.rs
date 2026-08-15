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

use std::boxed::Box;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::{eprintln, format, vec::Vec};

use anyhow::{anyhow, Context as _};
use log::{Level, LevelFilter, Record};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::{writer::simple::SimpleWriter, Encode};

pub const DEFAULT_MAX_LOG_SIZE_BYTES: u64 = 4 * 1024 * 1024;

pub fn parse_level_filter(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}
const FLUSH_THRESHOLD_BYTES: usize = 16 * 1024;

#[derive(Debug)]
struct FileState {
    file: Option<File>,
    pending: Vec<u8>,
}

#[derive(Debug)]
pub struct LockedRotatingFileAppender {
    path: PathBuf,
    state: Mutex<FileState>,
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
        Ok(Self {
            path,
            state: Mutex::new(FileState {
                file: None,
                pending: Vec::new(),
            }),
            encoder,
            max_size_bytes,
        })
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

    fn cached_file_matches(file: &File, metadata: Option<&Metadata>) -> bool {
        match metadata {
            Some(metadata) => file.metadata().is_ok_and(|cached| {
                cached.dev() == metadata.dev() && cached.ino() == metadata.ino()
            }),
            None => false,
        }
    }

    fn flush_pending(state: &mut FileState, path: &Path) -> io::Result<()> {
        if state.pending.is_empty() {
            return Ok(());
        }

        let metadata = match fs::metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(file) = state.file.as_ref() {
            if !Self::cached_file_matches(file, metadata.as_ref()) {
                state.file = None;
            }
        }
        if state.file.is_none() {
            state.file = Some(Self::open_log_file(path)?);
        }

        let file = state.file.as_mut().unwrap();
        if let Err(error) = file.write_all(&state.pending) {
            state.file = None;
            return Err(error);
        }
        if let Err(error) = file.flush() {
            state.file = None;
            return Err(error);
        }
        state.pending.clear();
        Ok(())
    }

    fn flush_locked(&self) -> anyhow::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        Self::flush_pending(&mut state, &self.path)
            .with_context(|| format!("failed to flush {}", self.path.display()))
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
        let flush_now = matches!(record.level(), Level::Error | Level::Warn)
            || data.len() >= FLUSH_THRESHOLD_BYTES;

        let mut state = self
            .state
            .lock()
            .map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        let projected = state.pending.len().saturating_add(data.len());
        if projected > 0 {
            let disk_len = match fs::metadata(&self.path) {
                Ok(metadata) => metadata.len(),
                Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("failed to stat {}", self.path.display()))
                }
            };
            if disk_len.saturating_add(projected as u64) > self.max_size_bytes {
                Self::flush_pending(&mut state, &self.path)
                    .with_context(|| format!("failed to flush {}", self.path.display()))?;
                let metadata = self
                    .rotate_if_needed(data.len())
                    .with_context(|| format!("failed to rotate {}", self.path.display()))?;
                if metadata.is_none() {
                    state.file = None;
                }
            }
        }

        state.pending.extend_from_slice(&data);
        if flush_now || state.pending.len() >= FLUSH_THRESHOLD_BYTES {
            Self::flush_pending(&mut state, &self.path)
                .with_context(|| format!("failed to write {}", self.path.display()))?;
        }
        Ok(())
    }

    fn flush(&self) {
        let _ = self.flush_locked();
    }
}

impl Drop for LockedRotatingFileAppender {
    fn drop(&mut self) {
        let _ = self.flush_locked();
    }
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

pub fn build_console_file_config<P: AsRef<Path>>(
    file_path: P,
    pattern: &str,
    level: LevelFilter,
    error_prefix: &str,
) -> anyhow::Result<(Config, bool)> {
    let mut builder = Config::builder();
    let mut root = Root::builder();
    if fs::read_link("/proc/self/fd/1")
        .map(|target| target != Path::new("/dev/null"))
        .unwrap_or(true)
    {
        let stdout = ConsoleAppender::builder()
            .encoder(Box::new(PatternEncoder::new(pattern)))
            .build();
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

    let file_logging_ready =
        match LockedRotatingFileAppender::new(path, Box::new(PatternEncoder::new(pattern))) {
            Ok(file) => {
                builder = builder.appender(Appender::builder().build("file", Box::new(file)));
                root = root.appender("file");
                true
            }
            Err(error) => {
                eprintln!(
                    "{} file logging disabled for {}: {}",
                    error_prefix,
                    path.display(),
                    error
                );
                false
            }
        };

    Ok((builder.build(root.build(level))?, file_logging_ready))
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_log_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("omk-log-test-{}-{nanos}", std::process::id()))
            .join(name)
    }

    fn append_message(appender: &LockedRotatingFileAppender, message: &'static str) {
        let args = format_args!("{message}");
        let record = Record::builder()
            .args(args)
            .level(Level::Info)
            .target("logging-test")
            .build();
        log4rs::append::Append::append(appender, &record).unwrap();
        log4rs::append::Append::flush(appender);
    }

    fn log_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn appender_does_not_create_sidecar_lock_file() {
        let path = temp_log_path("runtime.log");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let lock_path = suffixed_path(&path, ".lock");
        fs::write(&lock_path, b"legacy").unwrap();

        let appender =
            LockedRotatingFileAppender::new(&path, Box::new(PatternEncoder::new("{m}{n}")))
                .unwrap();
        append_message(&appender, "hello");

        assert_eq!(log_lines(&path), ["hello"]);
        assert!(!lock_path.exists());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn appender_rotates_without_sidecar_lock_file() {
        let path = temp_log_path("runtime.log");
        let parent = path.parent().unwrap();
        let appender = LockedRotatingFileAppender::with_max_size(
            &path,
            Box::new(PatternEncoder::new("{m}{n}")),
            8,
        )
        .unwrap();

        append_message(&appender, "abc");
        append_message(&appender, "defghijkl");

        assert_eq!(log_lines(&suffixed_path(&path, ".1")), ["abc"]);
        assert_eq!(log_lines(&path), ["defghijkl"]);
        assert!(!suffixed_path(&path, ".lock").exists());
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn appender_reopens_after_another_appender_rotates() {
        let path = temp_log_path("runtime.log");
        let parent = path.parent().unwrap();
        let first = LockedRotatingFileAppender::with_max_size(
            &path,
            Box::new(PatternEncoder::new("{m}{n}")),
            8,
        )
        .unwrap();
        let second = LockedRotatingFileAppender::with_max_size(
            &path,
            Box::new(PatternEncoder::new("{m}{n}")),
            8,
        )
        .unwrap();

        append_message(&first, "abc");
        append_message(&second, "defgh");
        append_message(&first, "i");

        assert_eq!(log_lines(&suffixed_path(&path, ".1")), ["abc"]);
        assert_eq!(log_lines(&path), ["defgh", "i"]);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn parse_level_filter_accepts_warning_alias() {
        assert_eq!(parse_level_filter(" warning "), Some(LevelFilter::Warn));
        assert_eq!(parse_level_filter("INFO"), Some(LevelFilter::Info));
        assert_eq!(parse_level_filter("verbose"), None);
    }

    #[test]
    fn info_lines_are_buffered_until_flush() {
        let path = temp_log_path("buffer.log");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let appender =
            LockedRotatingFileAppender::new(&path, Box::new(PatternEncoder::new("{m}{n}")))
                .unwrap();

        let args = format_args!("buffered");
        let record = Record::builder()
            .args(args)
            .level(Level::Info)
            .target("logging-test")
            .build();
        log4rs::append::Append::append(&appender, &record).unwrap();
        assert!(!path.exists() || fs::read_to_string(&path).unwrap().is_empty());

        log4rs::append::Append::flush(&appender);
        assert_eq!(log_lines(&path), ["buffered"]);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn warn_lines_flush_immediately() {
        let path = temp_log_path("warn.log");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let appender =
            LockedRotatingFileAppender::new(&path, Box::new(PatternEncoder::new("{m}{n}")))
                .unwrap();

        let args = format_args!("urgent");
        let record = Record::builder()
            .args(args)
            .level(Level::Warn)
            .target("logging-test")
            .build();
        log4rs::append::Append::append(&appender, &record).unwrap();
        assert_eq!(log_lines(&path), ["urgent"]);
        let _ = fs::remove_dir_all(parent);
    }
}
