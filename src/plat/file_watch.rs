use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

const WATCH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WatchTrigger {
    CloseWrite,
    ReplaceSave,
    Polling,
    Overflow,
}

impl WatchTrigger {
    pub fn label(self) -> &'static str {
        match self {
            Self::CloseWrite => "close-write",
            Self::ReplaceSave => "replace-save",
            Self::Polling => "polling",
            Self::Overflow => "overflow",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct PathStamp {
    len: u64,
    modified: Option<SystemTime>,
}

pub fn spawn_path_watcher<F>(thread_name: &str, path: PathBuf, on_change: F) -> Result<()>
where
    F: Fn(WatchTrigger) + Send + Sync + 'static,
{
    let callback = Arc::new(on_change);
    thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || watch_loop(path, callback))
        .with_context(|| format!("failed to spawn watcher thread {thread_name}"))?;
    Ok(())
}

fn inspect_path(path: &Path) -> Option<PathStamp> {
    let metadata = fs::metadata(path).ok()?;
    Some(PathStamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn watch_loop<F>(path: PathBuf, callback: Arc<F>)
where
    F: Fn(WatchTrigger) + Send + Sync + 'static,
{
    #[cfg(target_os = "android")]
    {
        if let Err(error) = watch_loop_inotify(&path, callback.as_ref()) {
            log::error!(
                "inotify watcher failed for {}: {}; falling back to polling",
                path.display(),
                error
            );
            watch_loop_polling(&path, callback.as_ref());
        }
        return;
    }

    #[cfg(not(target_os = "android"))]
    watch_loop_polling(&path, callback.as_ref());
}

fn watch_loop_polling<F>(path: &Path, callback: &F)
where
    F: Fn(WatchTrigger) + Send + Sync + 'static,
{
    let mut last_seen = inspect_path(path);
    loop {
        thread::sleep(WATCH_INTERVAL);

        let current = inspect_path(path);
        if current == last_seen {
            continue;
        }
        last_seen = current;
        callback(WatchTrigger::Polling);
    }
}

#[cfg(target_os = "android")]
fn watch_loop_inotify<F>(path: &Path, callback: &F) -> io::Result<()>
where
    F: Fn(WatchTrigger) + Send + Sync + 'static,
{
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watch path has no parent: {}", path.display()),
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watch path has no filename: {}", path.display()),
        )
    })?;
    let parent_cstr = CString::new(parent.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("watch path contains NUL byte: {}", parent.display()),
        )
    })?;
    let watch_mask =
        libc::IN_CLOSE_WRITE | libc::IN_CREATE | libc::IN_MOVED_TO | libc::IN_Q_OVERFLOW;

    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let watch = unsafe { libc::inotify_add_watch(fd, parent_cstr.as_ptr(), watch_mask) };
    if watch < 0 {
        let error = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }

    let watched_name = file_name.as_bytes().to_vec();
    let mut buffer = vec![0u8; 4096];
    loop {
        let read =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            unsafe {
                libc::close(fd);
            }
            return Err(error);
        }

        let mut reload_trigger: Option<WatchTrigger> = None;
        let mut offset = 0usize;
        while offset < read as usize {
            let event = unsafe { &*(buffer[offset..].as_ptr() as *const libc::inotify_event) };
            let name_start = offset + std::mem::size_of::<libc::inotify_event>();
            let name_end = name_start + event.len as usize;
            let name_bytes = &buffer[name_start..name_end.min(read as usize)];
            let name = name_bytes
                .split(|byte| *byte == 0)
                .next()
                .unwrap_or_default();

            if (event.mask & libc::IN_Q_OVERFLOW) != 0 || name == watched_name.as_slice() {
                let candidate = if (event.mask & libc::IN_Q_OVERFLOW) != 0 {
                    Some(WatchTrigger::Overflow)
                } else if (event.mask & (libc::IN_CREATE | libc::IN_MOVED_TO)) != 0 {
                    Some(WatchTrigger::ReplaceSave)
                } else if (event.mask & libc::IN_CLOSE_WRITE) != 0 {
                    Some(WatchTrigger::CloseWrite)
                } else {
                    None
                };

                if let Some(candidate) = candidate {
                    reload_trigger = match reload_trigger {
                        Some(current)
                            if watch_trigger_priority(current)
                                <= watch_trigger_priority(candidate) =>
                        {
                            Some(current)
                        }
                        _ => Some(candidate),
                    };
                }
            }

            offset += std::mem::size_of::<libc::inotify_event>() + event.len as usize;
        }

        if let Some(trigger) = reload_trigger {
            callback(trigger);
        }
    }
}

fn watch_trigger_priority(trigger: WatchTrigger) -> u8 {
    match trigger {
        WatchTrigger::CloseWrite => 0,
        WatchTrigger::Overflow => 1,
        WatchTrigger::ReplaceSave => 2,
        WatchTrigger::Polling => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_priority_trigger_is_retained() {
        let selected = match Some(WatchTrigger::CloseWrite) {
            Some(current)
                if watch_trigger_priority(current)
                    <= watch_trigger_priority(WatchTrigger::ReplaceSave) =>
            {
                Some(current)
            }
            _ => Some(WatchTrigger::ReplaceSave),
        };

        assert_eq!(selected, Some(WatchTrigger::CloseWrite));
    }
}
