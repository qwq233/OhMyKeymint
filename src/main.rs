#![recursion_limit = "256"]
#![feature(once_cell_get_mut)]
#![feature(once_cell_try)]

use std::panic;

use log::{debug, error, info};
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

#[cfg(target_os = "android")]
const TAG: &str = "OhMyKeymint";

fn main() {
    logging::init_logger();
    info!("Hello, OhMyKeymint!");
    info!("Reading config");

    unsafe {
        info!("Setting UID to KEYSTORE_UID (1017)");
        libc::setuid(1017); // KEYSTORE_UID
    }

    let config = CONFIG.read().unwrap();

    info!("Initial process state");
    rsbinder::ProcessState::init_default();

    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    info!("Starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    match config.main.backend {
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
