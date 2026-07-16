use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::Ordering;

use anyhow::{anyhow, bail, Result};
use log::{debug, info, warn};

use super::{new_ioctl, HOOK_INIT, OLD_IOCTL};
use crate::{config, ipc};

pub(super) fn init_hook() -> Result<()> {
    let result = HOOK_INIT.get_or_init(|| install_hooks().map_err(|error| format!("{error:#}")));
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

fn install_hooks() -> Result<()> {
    let _ = config::get();
    info!("initializing binder ioctl hook");
    ipc::ensure_process_state();

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for map in lsplt_rs::MapInfo::scan("self") {
        if let Some(path) = &map.pathname {
            let name = path.rsplit('/').next().unwrap_or(path);
            if (name.starts_with("libbinder") || name == "libhwbinder.so")
                && seen.insert((map.dev, map.inode))
            {
                debug!(
                    "Found binder library for ioctl hook: {} (dev={}, inode={})",
                    path, map.dev, map.inode
                );
                for symbol in ["ioctl", "__ioctl"] {
                    candidates.push((path.clone(), map.dev, map.inode, symbol));
                }
            }
        }
    }

    if candidates.is_empty() {
        bail!("Could not find binder libraries in process maps");
    }

    let mut backups = vec![std::ptr::null_mut(); candidates.len()];
    let mut registered = 0usize;

    for (idx, (path, dev, inode, symbol)) in candidates.iter().enumerate() {
        match lsplt_rs::register_hook(
            *dev,
            *inode,
            symbol,
            new_ioctl as *mut c_void,
            Some(&mut backups[idx]),
        ) {
            Ok(_) => {
                registered += 1;
                info!(
                    "registered binder ioctl hook path={} symbol={}",
                    path, symbol
                );
            }
            Err(e) => {
                warn!(
                    "failed to register binder ioctl hook path={} symbol={}: {:?}",
                    path, symbol, e
                );
            }
        }
    }

    if registered == 0 {
        bail!("Failed to register any binder ioctl hooks");
    }

    lsplt_rs::commit_hook().map_err(|e| anyhow!("Failed to commit lsplt hook: {:?}", e))?;
    let committed = backups.iter().filter(|ptr| !ptr.is_null()).count();
    for ptr in backups {
        if !ptr.is_null() && OLD_IOCTL.load(Ordering::Relaxed).is_null() {
            OLD_IOCTL.store(ptr, Ordering::SeqCst);
        }
    }
    if committed == 0 {
        bail!("Failed to commit any binder ioctl hooks");
    }
    info!(
        "committed {} binder ioctl hook(s) from {} registration(s)",
        committed, registered
    );
    Ok(())
}
