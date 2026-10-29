use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};

use anyhow::{anyhow, bail, Result};
use log::{debug, info};

use super::{
    intercept, new_close, new_dup, new_dup2, new_dup3, new_fcntl, new_fdsan_close, new_ioctl,
    rewrite, HOOK_INIT, OLD_CLOSE, OLD_DUP, OLD_DUP2, OLD_DUP3, OLD_FCNTL, OLD_FDSAN_CLOSE,
    OLD_IOCTL,
};
use crate::{config, ipc};

pub(super) fn init_hook() -> Result<()> {
    let result = HOOK_INIT.get_or_init(|| install_hooks().map_err(|error| format!("{error:#}")));
    match result {
        Ok(()) => Ok(()),
        Err(error) => Err(anyhow!(error.clone())),
    }
}

fn install_hooks() -> Result<()> {
    fn register_hooks(
        libraries: &[(String, lsplt_rs::DeviceId, lsplt_rs::Inode)],
        symbols: &'static [&'static str],
        replacement: *mut c_void,
        label: &str,
    ) -> Result<Vec<*mut c_void>> {
        let mut backups = vec![std::ptr::null_mut(); libraries.len() * symbols.len()];
        for ((path, dev, inode), backups) in libraries.iter().zip(backups.chunks_mut(symbols.len()))
        {
            for (symbol, backup) in symbols.iter().zip(backups) {
                lsplt_rs::register_hook(*dev, *inode, symbol, replacement, Some(backup)).map_err(
                    |error| {
                        anyhow!(
                            "failed to register binder {label} hook path={path} symbol={symbol}: {error}"
                        )
                    },
                )?;
                debug!("registered binder {label} hook path={path} symbol={symbol}");
            }
        }
        Ok(backups)
    }

    fn store_original(backups: &[*mut c_void], original: &AtomicPtr<c_void>) {
        if let Some(&ptr) = backups.iter().find(|ptr| !ptr.is_null()) {
            let _ = original.compare_exchange(
                std::ptr::null_mut(),
                ptr,
                Ordering::SeqCst,
                Ordering::Relaxed,
            );
        }
    }

    let _ = config::get();
    info!("initializing binder ioctl hook");
    ipc::ensure_process_state();

    let mut libraries = Vec::new();
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
                libraries.push((path.clone(), map.dev, map.inode));
            }
        }
    }

    if libraries.is_empty() {
        bail!("Could not find binder libraries in process maps");
    }

    let ioctl_backups =
        register_hooks(&libraries, &["ioctl", "__ioctl"], new_ioctl as *mut c_void, "ioctl")?;
    let close_backups =
        register_hooks(&libraries, &["close", "__close"], new_close as *mut c_void, "close")?;
    let dup_backups =
        register_hooks(&libraries, &["dup"], new_dup as *mut c_void, "fd duplication")?;
    let fdsan_backups = register_hooks(
        &libraries,
        &["android_fdsan_close_with_tag"],
        new_fdsan_close as *mut c_void,
        "close",
    )?;
    let dup2_backups =
        register_hooks(&libraries, &["dup2"], new_dup2 as *mut c_void, "fd replacement")?;
    let dup3_backups =
        register_hooks(&libraries, &["dup3"], new_dup3 as *mut c_void, "fd replacement")?;
    let fcntl_backups =
        register_hooks(&libraries, &["fcntl"], new_fcntl as *mut c_void, "fd duplication")?;

    lsplt_rs::commit_hook().map_err(|e| anyhow!("Failed to commit lsplt hook: {:?}", e))?;
    let ioctl_committed = ioctl_backups.iter().filter(|ptr| !ptr.is_null()).count();
    let close_committed =
        close_backups.iter().chain(fdsan_backups.iter()).filter(|ptr| !ptr.is_null()).count();
    store_original(&ioctl_backups, &OLD_IOCTL);
    store_original(&close_backups, &OLD_CLOSE);
    store_original(&fdsan_backups, &OLD_FDSAN_CLOSE);
    store_original(&dup_backups, &OLD_DUP);
    store_original(&dup2_backups, &OLD_DUP2);
    store_original(&dup3_backups, &OLD_DUP3);
    store_original(&fcntl_backups, &OLD_FCNTL);
    if ioctl_committed == 0 {
        bail!("Failed to commit any binder ioctl hooks");
    }
    if close_committed == 0 {
        bail!("Failed to commit any binder close hooks");
    }

    intercept::start_operation_publication_worker().map_err(|error| anyhow!(error))?;
    info!(
        "committed {} binder ioctl hook(s) and {} close hook(s)",
        ioctl_committed, close_committed
    );
    Ok(())
}
