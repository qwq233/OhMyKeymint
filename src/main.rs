#![recursion_limit = "256"]
#![feature(once_cell_try)]

use anyhow::{Context, Result};
use std::panic;
use std::sync::Arc;
use std::{ffi::CString, os::unix::fs::PermissionsExt, path::Path};

use kmr_common::rpc;
use log::{debug, error, info, warn};
use rsbinder::rpc::{PeerIdentity, RpcServer};
use rsbinder::BinderFeatures;

use crate::{
    keymaster::service::KeystoreService,
    keymaster::{
        authorization::AuthorizationManager, maintenance::MaintenanceManager, metrics::Metrics,
    },
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
pub mod selinux;
pub mod utils;
pub mod watchdog;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));
// include!( "./aidl.rs"); // for development only

fn sid_features() -> BinderFeatures {
    let mut features = BinderFeatures::default();
    features.set_requesting_sid = true;

    features
}

const KEYSTORE_UID: libc::uid_t = 1017;
const KEYSTORE_GID: libc::gid_t = 1017;

fn storage_warn(message: String) {
    if log::log_enabled!(log::Level::Warn) {
        warn!("{message}");
    } else {
        eprintln!("Storage warning: {message}");
    }
}

fn chown_path(path: &str, uid: libc::uid_t, gid: libc::gid_t) -> std::io::Result<()> {
    let c_path = CString::new(path).expect("path must not contain interior NUL bytes");
    let result = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn repair_omk_data_files() {
    let entries = match std::fs::read_dir(root_path!("data")) {
        Ok(entries) => entries,
        Err(e) => {
            storage_warn(format!("Failed to list OMK data directory: {e:?}"));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                storage_warn(format!("Failed to read OMK data directory entry: {e:?}"));
                continue;
            }
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                storage_warn(format!("Failed to stat OMK data file {path:?}: {e:?}"));
                continue;
            }
        };
        if !file_type.is_file() {
            continue;
        }

        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            storage_warn(format!("Failed to chmod OMK data file {path:?}: {e:?}"));
        }
        let Some(path) = path.to_str() else {
            storage_warn(format!("Skipping non-UTF8 OMK data file path {path:?}"));
            continue;
        };
        if let Err(e) = chown_path(path, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown OMK data file {path}: {e:?}"));
        }
    }
}

fn prepare_android_storage() {
    for dir in [root_path!(), root_path!("data")] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            storage_warn(format!("Failed to create OMK directory {dir}: {e:?}"));
            continue;
        }

        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o770)) {
            storage_warn(format!("Failed to chmod OMK directory {dir}: {e:?}"));
        }

        if let Err(e) = chown_path(dir, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown OMK directory {dir}: {e:?}"));
        }
    }

    if let Err(e) = crate::keybox::ensure_keybox_file(root_path!("keybox.xml")) {
        storage_warn(format!(
            "Failed to seed OMK keybox {}: {e:?}",
            root_path!("keybox.xml")
        ));
    }

    for file in [
        root_path!("keymint.log.lock"),
        root_path!("injector.log.lock"),
    ] {
        match std::fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => storage_warn(format!(
                "Failed to remove legacy OMK lock file {file}: {e:?}"
            )),
        }
    }

    for file in [
        root_path!("config.toml"),
        root_path!("config.toml.bak"),
        root_path!("keybox.xml"),
        root_path!("crash_count"),
        root_path!("keymint.log"),
        root_path!("keymint.log.1"),
        root_path!("injector.log"),
        root_path!("injector.log.1"),
    ] {
        if !Path::new(file).exists() {
            continue;
        }

        let mode = if file.ends_with(".xml") { 0o600 } else { 0o660 };

        if let Err(e) = std::fs::set_permissions(file, std::fs::Permissions::from_mode(mode)) {
            storage_warn(format!("Failed to chmod OMK file {file}: {e:?}"));
        }

        if let Err(e) = chown_path(file, KEYSTORE_UID, KEYSTORE_GID) {
            storage_warn(format!("Failed to chown OMK file {file}: {e:?}"));
        }
    }
}

fn create_rpc_server() -> Result<Arc<RpcServer>> {
    let server =
        RpcServer::setup_unix_server(rpc::SOCKET).context("failed to bind OMK RPC socket")?;
    server.set_android13plus(rpc::WIRE_MAX_VERSION);

    server.set_authorizer(|peer| {
        let allowed = matches!(
            peer,
            PeerIdentity::Local { uid, .. } if *uid == 0 || *uid == KEYSTORE_UID
        );
        if !allowed {
            warn!("Rejected OMK RPC peer {peer}");
        }
        allowed
    });

    Ok(server)
}

fn should_resolve_module_info_bundle(android_major_version: Option<i32>) -> bool {
    !matches!(android_major_version, Some(version) if version < 16)
}

fn install_module_info_bundle_if_available() -> Result<()> {
    if !should_resolve_module_info_bundle(kmr_common::android_version::android_major_version()) {
        info!("Skipping moduleHash input on pre-Android 16 system");
        return Ok(());
    }

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
        Err(error) => {
            warn!("APEX module info unavailable; moduleHash attestation disabled: {error:#}");
        }
    }

    Ok(())
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

    prepare_android_storage();
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
    crate::keymaster::permission::initialize_runtime_service_context();

    info!("Initial process state");
    let _ = rsbinder::ProcessState::init_default();

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

    install_module_info_bundle_if_available().context("failed to initialize moduleHash input")?;

    std::thread::spawn(global::await_boot_completed);
    crate::keymaster::entropy::register_feeder();
    global::DB
        .with(|db| {
            crate::keymaster::super_key::SuperKeyManager::set_up_boot_level_cache(
                &global::SUPER_KEY,
                &mut db.borrow_mut(),
            )
        })
        .context("failed to initialize boot-level key cache")?;
    repair_omk_data_files();

    keybox::initialize().context("failed to initialize keybox runtime")?;

    let injector_rpc_server = create_rpc_server()?;

    unsafe {
        info!("Setting UID to KEYSTORE_UID (1017)");
        libc::setuid(KEYSTORE_UID); // KEYSTORE_UID
    }

    crate::keymaster::metrics_store::update_keystore_crash_count();

    info!("Starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    info!("Using Injector backend");
    let server = injector_rpc_server;

    info!("Creating keystore service");
    let dev = KeystoreService::new_native_binder().context("failed to create omk service")?;

    info!("Adding OMK service to RPC server");
    let service = BnOhMyKsService::new_binder_with_features(dev, sid_features());
    server
        .add_service(rpc::SERVICE, service.as_binder())
        .context("failed to add OMK RPC service")?;

    info!("Creating OMK authorization service");
    let auth = AuthorizationManager::new_omk_binder()
        .context("failed to create OMK authorization service")?;
    info!("Adding OMK authorization service to RPC server");
    server
        .add_service(rpc::AUTHORIZATION_SERVICE, auth.as_binder())
        .context("failed to add OMK authorization RPC service")?;

    info!("Creating OMK maintenance service");
    let maintenance =
        MaintenanceManager::new_omk_binder().context("failed to create OMK maintenance service")?;
    info!("Adding OMK maintenance service to RPC server");
    server
        .add_service(rpc::MAINTENANCE_SERVICE, maintenance.as_binder())
        .context("failed to add OMK maintenance RPC service")?;

    info!("Creating OMK metrics service");
    let metrics = Metrics::new_native_binder().context("failed to create OMK metrics service")?;
    info!("Adding OMK metrics service to RPC server");
    server
        .add_service(rpc::METRICS_SERVICE, metrics.as_binder())
        .context("failed to add OMK metrics RPC service")?;

    info!("Serving OMK RPC on {}", rpc::SOCKET);
    server.run().context("OMK RPC server stopped")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::should_resolve_module_info_bundle;

    #[test]
    fn module_info_bundle_is_only_resolved_on_android_16_plus() {
        for version in [Some(12), Some(13), Some(14), Some(15)] {
            assert!(!should_resolve_module_info_bundle(version));
        }

        for version in [None, Some(16), Some(17)] {
            assert!(should_resolve_module_info_bundle(version));
        }
    }
}
