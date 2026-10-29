use std::collections::HashSet;
use std::ffi::{c_void, CStr};
use std::path::Path;
use std::sync::atomic::{AtomicPtr, Ordering};

use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};
use omhook::{read_self_maps, ElfImageSelector, MapInfo, PltHookRequest, PltHookRequestGroup};

use super::intercept::{
    new_close, new_dup, new_dup2, new_dup3, new_fcntl, new_fdsan_close, new_ioctl,
};
use super::{
    intercept, HOOK_INIT, OLD_CLOSE, OLD_DUP, OLD_DUP2, OLD_DUP3, OLD_FCNTL, OLD_FDSAN_CLOSE,
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
    fn hook<'a>(
        library: &'a ElfImageSelector,
        symbol: &'static CStr,
        replacement: *const (),
        original: &'static AtomicPtr<c_void>,
    ) -> Result<(PltHookRequest<'a>, &'static AtomicPtr<c_void>)> {
        debug!("registered binder hook symbol={symbol:?}");
        Ok((PltHookRequest::new(library, symbol, replacement)?, original))
    }

    fn store_original(original: *const (), target: &AtomicPtr<c_void>) {
        if original.is_null() {
            return;
        }
        let _ = target.compare_exchange(
            std::ptr::null_mut(),
            original as *mut c_void,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
    }

    let _ = config::get();
    info!("initializing binder ioctl hook");
    ipc::ensure_process_state();

    let maps = read_self_maps().context("failed to read self maps for binder hook discovery")?;
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for map in &maps {
        if let Some(path) = binder_library_path(map) {
            if !seen.insert((map.device, map.inode)) {
                continue;
            }
            debug!(
                "Found binder library for ioctl hook: {} (dev={}:{}, inode={})",
                path.display(),
                map.device.major,
                map.device.minor,
                map.inode
            );
            targets.push(
                ElfImageSelector::new(map.device, map.inode)
                    .with_context(|| format!("failed to create target for {}", path.display()))?,
            );
        }
    }
    drop(maps);

    if targets.is_empty() {
        bail!("Could not find binder libraries in process maps");
    }

    let mut required = Vec::new();
    let mut optional = Vec::new();
    for library in &targets {
        for symbol in [c"ioctl", c"__ioctl"] {
            required.push(hook(library, symbol, new_ioctl as *const (), &OLD_IOCTL)?);
        }
        for symbol in [c"close", c"__close"] {
            required.push(hook(library, symbol, new_close as *const (), &OLD_CLOSE)?);
        }
        required.push(hook(
            library,
            c"android_fdsan_close_with_tag",
            new_fdsan_close as *const (),
            &OLD_FDSAN_CLOSE,
        )?);
        optional.push(hook(library, c"dup", new_dup as *const (), &OLD_DUP)?);
        optional.push(hook(library, c"dup2", new_dup2 as *const (), &OLD_DUP2)?);
        optional.push(hook(library, c"dup3", new_dup3 as *const (), &OLD_DUP3)?);
        optional.push(hook(library, c"fcntl", new_fcntl as *const (), &OLD_FCNTL)?);
    }

    let (required_hooks, required_originals): (Vec<_>, Vec<_>) = required.into_iter().unzip();
    let (optional_hooks, optional_originals): (Vec<_>, Vec<_>) = optional.into_iter().unzip();
    let groups = [
        PltHookRequestGroup::required(&required_hooks),
        PltHookRequestGroup::optional(&optional_hooks),
    ];

    // SAFETY: every replacement is a fully callable extern "C" symbol with the
    // exact libc/binder ABI and process-lifetime validity. Binder libraries
    // are loaded eagerly at process start and never unmapped, and their jump
    // slots are resolved before this point because keystore2 has been issuing
    // binder traffic since startup. Other keystore2 threads may call a hooked
    // symbol between the slot write and publication of the original pointer
    // below; the intercept layer handles that window by falling back to the
    // libc symbol. No concurrent loader transition or competing slot writer
    // affects the selected binder images.
    let report = unsafe { omhook::install_hook_groups(&groups) }
        .map_err(|error| anyhow!("Failed to commit binder hooks: {error}"))?;

    let mut ioctl_committed = 0;
    let mut close_committed = 0;
    for (applied, original) in report[0].iter().zip(required_originals) {
        match applied {
            Ok(applied) => {
                store_original(applied.previous(), original);
                if std::ptr::eq(original, &OLD_IOCTL) {
                    ioctl_committed += 1;
                } else {
                    close_committed += 1;
                }
            }
            Err(error) => debug!("binder hook absent or rejected: {error}"),
        }
    }
    for (applied, original) in report[1].iter().zip(optional_originals) {
        if let Ok(applied) = applied {
            store_original(applied.previous(), original);
        } else if let Err(error) = applied {
            debug!("optional binder hook absent or rejected: {error}");
        }
    }

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

fn binder_library_path(map: &MapInfo) -> Option<&Path> {
    let path = map.path.as_deref()?;
    let name = path.file_name()?.to_str()?;
    (name.starts_with("libbinder") || name == "libhwbinder.so")
        .then_some(path)
        .filter(|path| path.is_absolute())
}
