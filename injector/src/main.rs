use std::ffi::c_void;

use log::{error, info};
use nix::unistd::Pid;

pub mod config;
pub mod filter;
pub mod forward;
pub mod hook;
pub mod identify;
pub mod inject;
pub mod ipc;
pub mod logging;
pub mod parcel;
pub mod route;
pub mod sys;
pub mod utils;

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

fn main() {
    logging::init_logger();
    let _ = config::get();
    match utils::current_exe_identity() {
        Ok(identity) => {
            info!(
                "[Injector][Startup] build_id={} build_target={} git_sha={} runtime_arch={} exe={} sha256={} elf={}",
                utils::build_id(),
                utils::build_target(),
                utils::build_git_sha(),
                std::env::consts::ARCH,
                identity.path.display(),
                identity.sha256,
                identity.elf,
            );
        }
        Err(error) => {
            error!(
                "[Injector][Startup] failed to describe current injector binary: {:#}",
                error
            );
        }
    }

    let (pid, target_path) = utils::find_process_by_name("keystore2").unwrap();
    match utils::executable_identity(&target_path) {
        Ok(identity) => info!(
            "[Injector][Startup] target=keystore2 pid={} exe={} sha256={} elf={}",
            pid,
            identity.path.display(),
            identity.sha256,
            identity.elf,
        ),
        Err(error) => error!(
            "[Injector][Startup] failed to describe keystore2 executable {}: {:#}",
            target_path.display(),
            error
        ),
    }
    let pid = Pid::from_raw(pid);
    match inject::inject_library(pid) {
        Ok(()) => info!("Injection successful"),
        Err(e) => {
            error!("Injection failed: {:#}", e);
            std::process::exit(1);
        }
    }
}

#[no_mangle]
#[allow(unused)]
pub extern "C" fn entry(handle: *const c_void) -> bool {
    // This runs inside the target process, so we must initialize logging again
    // for that process. On Android this enables both logcat and stdout logging.
    logging::init_logger();
    let _ = config::get();
    println!(
        "[inject::entry] injected library entry called, handle={:?}",
        handle
    );
    log::info!(
        "Injected library entry called! Handle: {:?}, build_id={}, build_target={}, runtime_arch={}, current_exe={}",
        handle,
        utils::build_id(),
        utils::build_target(),
        std::env::consts::ARCH,
        utils::current_exe_path()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string()),
    );
    hook::init_hook();
    true
}
