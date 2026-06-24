use std::ffi::c_void;
use std::sync::atomic::Ordering;

use anyhow::{anyhow, bail, Result};
use log::{info, warn};

use super::{new_ioctl, HOOK_INIT, OLD_IOCTL};
use crate::{config, ipc, logging};

pub(super) fn init_hook() -> Result<()> {
    let result = HOOK_INIT.get_or_init(|| install_hooks().map_err(|error| format!("{error:#}")));
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

fn install_hooks() -> Result<()> {
    logging::init_logger();
    let _ = config::get();
    info!("initializing binder ioctl hook");
    ipc::ensure_process_state();

    let maps = lsplt_rs::MapInfo::scan("self");
    let mut targets = Vec::new();

    for map in maps {
        if let Some(path) = &map.pathname {
            if path.ends_with("/libbinder.so")
                || path.ends_with("libbinder.so")
                || path.ends_with("/libhwbinder.so")
                || path.ends_with("libhwbinder.so")
            {
                info!(
                    "Found binder-related library for hook: {} (dev={}, inode={})",
                    path, map.dev, map.inode
                );
                targets.push((path.clone(), map.dev, map.inode));
            }
        }
    }

    if targets.is_empty() {
        bail!("Could not find libbinder.so/libhwbinder.so in process maps");
    }

    let mut registered = 0usize;

    for (path, dev, inode) in targets {
        for symbol in ["ioctl", "__ioctl"] {
            let mut old_ptr: *mut c_void = std::ptr::null_mut();
            match lsplt_rs::register_hook(
                dev,
                inode,
                symbol,
                new_ioctl as *mut c_void,
                Some(&mut old_ptr),
            ) {
                Ok(_) => {
                    if !old_ptr.is_null() && OLD_IOCTL.load(Ordering::Relaxed).is_null() {
                        OLD_IOCTL.store(old_ptr, Ordering::SeqCst);
                    }
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
    }

    if registered == 0 {
        bail!("Failed to register any binder ioctl hooks");
    }

    lsplt_rs::commit_hook().map_err(|e| anyhow!("Failed to commit lsplt hook: {:?}", e))?;
    info!("committed {} binder ioctl hook(s)", registered);
    Ok(())
}
