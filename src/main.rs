#![recursion_limit = "256"]
#![feature(once_cell_try)]

use anyhow::{Context, Result};
use std::panic;
use std::{ffi::CString, os::unix::fs::PermissionsExt, path::Path};

use log::{debug, error, info, warn};
use rsbinder::{hub, BinderFeatures};

use crate::{
    android::system::keystore2::IKeystoreService::BnKeystoreService,
    config::{config, Backend},
    keymaster::service::KeystoreService,
    top::qwq2333::ohmykeymint::IOhMyKsService::BnOhMyKsService,
};

pub mod att_mgr;
pub mod config;
pub mod consts;
pub mod global;
pub mod keybox;
pub mod keymaster;
pub mod keymint;
pub mod logging;
pub mod macros;
pub mod plat;
pub mod proto;
pub mod utils;
pub mod watchdog;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));
// include!( "./aidl.rs"); // for development only

fn sid_features() -> BinderFeatures {
    BinderFeatures {
        set_requesting_sid: true,
    }
}

const KEYSTORE_UID: libc::uid_t = 1017;
const KEYSTORE_GID: libc::gid_t = 1017;
const OMK_ROOT_DIR: &str = "/data/misc/keystore/omk";
const OMK_DATA_DIR: &str = "/data/misc/keystore/omk/data";
const OMK_CONFIG_PATH: &str = "/data/misc/keystore/omk/config.toml";
const OMK_KEYBOX_PATH: &str = "/data/misc/keystore/omk/keybox.xml";

fn chown_path(path: &str, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = CString::new(path).expect("path must not contain interior NUL bytes");
    let result = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn prepare_android_storage() {
    for dir in [OMK_ROOT_DIR, OMK_DATA_DIR] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            warn!("Failed to create OMK directory {}: {:?}", dir, e);
            continue;
        }

        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770)) {
            warn!("Failed to chmod OMK directory {}: {:?}", dir, e);
        }

        if let Err(e) = chown_path(dir, KEYSTORE_UID, KEYSTORE_GID) {
            warn!("Failed to chown OMK directory {}: {:?}", dir, e);
        }
    }

    if let Err(e) = crate::keybox::ensure_keybox_file(OMK_KEYBOX_PATH) {
        warn!("Failed to seed OMK keybox {}: {:?}", OMK_KEYBOX_PATH, e);
    }

    for file in [
        OMK_CONFIG_PATH,
        "/data/misc/keystore/omk/config.toml.bak",
        OMK_KEYBOX_PATH,
    ] {
        if !Path::new(file).exists() {
            continue;
        }

        let mode = if file.ends_with(".xml") { 0o600 } else { 0o660 };

        if let Err(e) = std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)) {
            warn!("Failed to chmod OMK file {}: {:?}", file, e);
        }

        if let Err(e) = chown_path(file, KEYSTORE_UID, KEYSTORE_GID) {
            warn!("Failed to chown OMK file {}: {:?}", file, e);
        }
    }
}

fn main() {
    match plat::device_ids::maybe_run_telephony_probe_command() {
        Ok(true) => return,
        Ok(false) => {}
        Err(error) => {
            eprintln!("Telephony probe helper failed: {error:#}");
            std::process::exit(1);
        }
    }

    logging::init_logger();
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    if let Err(error) = run() {
        error!("Fatal startup error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    info!("Hello, OhMyKeymint!");

    info!("Initial process state");
    rsbinder::ProcessState::init_default();

    prepare_android_storage();
    plat::resetprop::bootstrap_privileged_helper()
        .context("failed to bootstrap resetprop helper")?;

    info!("Bootstrapping config");
    let mut config_file = config::bootstrap_config_file().context("failed to bootstrap config")?;
    plat::device_ids::bootstrap_device_ids(&mut config_file);
    let resolved_trust =
        plat::vbmeta::bootstrap_vbmeta(&mut config_file).context("failed to bootstrap vbmeta")?;
    config::persist_config_file(&config_file).context("failed to persist config")?;
    prepare_android_storage();
    config::install_runtime_config(config_file, resolved_trust)
        .context("failed to install runtime config")?;

    let backend = {
        config()
            .read()
            .map_err(|_| anyhow::anyhow!("config lock poisoned while reading backend"))?
            .main
            .backend
            .clone()
    };

    // We can no longer resolve module info after dropping privileges.
    debug!("Resolving APEX module info with root privileges");
    match crate::keymaster::apex::resolve_module_info_bundle() {
        Ok(bundle) => {
            let source = bundle.source.as_str();
            let module_count = bundle.modules.len();
            let sha256 = hex::encode(&bundle.sha256);
            global::install_module_info_bundle(bundle)
                .context("failed to install APEX module info bundle")?;
            info!(
                "Initialized moduleHash input from {source} with {module_count} active modules (sha256={sha256})"
            );
        }
        Err(e) => {
            warn!("Failed to resolve APEX module info before dropping privileges: {e:#}");
        }
    }

    keybox::initialize().context("failed to initialize keybox runtime")?;

    unsafe {
        info!("Setting UID to KEYSTORE_UID (1017)");
        libc::setuid(KEYSTORE_UID); // KEYSTORE_UID
    }

    info!("Starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    match backend {
        Backend::OMK => {
            info!("Using OhMyKeymint backend");
            info!("Creating keystore service");
            let dev = KeystoreService::new_native_binder()
                .context("failed to create keystore3 service")?;

            let service = BnKeystoreService::new_binder_with_features(dev, sid_features());
            info!("Adding keystore service to hub");
            hub::add_service("keystore3", service.as_binder())
                .context("failed to add keystore3 service")?;
        }
        Backend::Injector => {
            info!("Using Injector backend");
            info!("Creating keystore service");
            let dev =
                KeystoreService::new_native_binder().context("failed to create omk service")?;

            info!("Adding OMK service to hub");
            let service = BnOhMyKsService::new_binder_with_features(dev, sid_features());
            hub::add_service("omk", service.as_binder()).context("failed to add omk service")?;
        }
    }

    info!("Joining thread pool");
    rsbinder::ProcessState::join_thread_pool().context("thread pool join failed")?;
    Ok(())
}
