#![recursion_limit = "256"]
#![feature(once_cell_get_mut)]
#![feature(once_cell_try)]

use std::panic;
use std::{ffi::CString, os::unix::fs::PermissionsExt, path::Path};

use log::{debug, error, info, warn};
use rsbinder::hub;

use crate::{
    android::system::keystore2::IKeystoreService::BnKeystoreService,
    config::{Backend, CONFIG},
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

const TAG: &str = "OhMyKeymint";

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
    logging::init_logger();
    info!("Hello, OhMyKeymint!");
    info!("Reading config");
    let backend = { CONFIG.read().unwrap().main.backend.clone() };

    info!("Initial process state");
    rsbinder::ProcessState::init_default();

    // We can no longer retrieve APEX module info after dropping privileges.
    debug!("Retrieving APEX module hash with root privileges");
    if let Err(e) = global::APEX_MODULE_HASH.as_ref() {
        error!("Failed to retrieve APEX module info: {:?}", e);
    }

    prepare_android_storage();
    if let Err(e) = keybox::initialize() {
        error!("Failed to initialize keybox runtime: {:#}", e);
    }

    unsafe {
        info!("Setting UID to KEYSTORE_UID (1017)");
        libc::setuid(KEYSTORE_UID); // KEYSTORE_UID
    }

    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    info!("Starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    match backend {
        Backend::OMK => {
            info!("Using OhMyKeymint backend");
            info!("Creating keystore service");
            let dev = KeystoreService::new_native_binder().unwrap();

            let service = BnKeystoreService::new_binder(dev);
            info!("Adding keystore service to hub");
            hub::add_service("keystore3", service.as_binder()).unwrap();
        }
        Backend::TrickyStore => {
            info!("Using TrickyStore backend");
            info!("Creating keystore service");
            let dev = KeystoreService::new_native_binder().unwrap();

            info!("Adding OMK service to hub");
            let service = BnOhMyKsService::new_binder(dev);
            hub::add_service("omk", service.as_binder()).unwrap();
        }
    }

    info!("Joining thread pool");
    rsbinder::ProcessState::join_thread_pool().unwrap();
}
