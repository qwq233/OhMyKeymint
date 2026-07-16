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
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::{eprintln, format, vec::Vec};

use anyhow::{anyhow, Context as _};
use log::{LevelFilter, Record};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::{writer::simple::SimpleWriter, Encode};

pub const DEFAULT_MAX_LOG_SIZE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct LockedRotatingFileAppender {
    path: PathBuf,
    lock: Mutex<()>,
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
            lock: Mutex::new(()),
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

    fn rotate_if_needed(&self, next_write_len: usize) -> io::Result<()> {
        let current_len = match fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };

        if current_len == 0
            || current_len.saturating_add(next_write_len as u64) <= self.max_size_bytes
        {
            return Ok(());
        }

        rotate_existing_log_file(&self.path)
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

        let _process_guard = self
            .lock
            .lock()
            .map_err(|error| anyhow!("failed to lock log writer: {}", error))?;
        let _file_guard = FileLockGuard::lock_path(&self.path)
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
    #[cfg(unix)]
    file: File,
}

impl FileLockGuard {
    #[cfg(unix)]
    fn lock_path(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::open(LockedRotatingFileAppender::parent_dir(path))?;
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
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let mut builder =
        Config::builder().appender(Appender::builder().build("stdout", Box::new(stdout)));
    let mut root = Root::builder().appender("stdout");
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
}
