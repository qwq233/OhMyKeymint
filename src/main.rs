#![recursion_limit = "256"]
#![feature(once_cell_get_mut)]
#![feature(once_cell_try)]

use std::panic;

use log::{debug, error};
use rsbinder::hub;

use crate::{
    android::system::keystore2::{
        IKeystoreOperation, IKeystoreService::BnKeystoreService}, keymaster::service::KeystoreService, top::qwq2333::ohmykeymint::IOhMyKsService::BnOhMyKsService}
    
;

pub mod consts;
pub mod global;
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
    debug!("Hello, OhMyKeymint!");
    debug!("Initial process state");
    rsbinder::ProcessState::init_default();

    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    debug!("Starting thread pool");
    rsbinder::ProcessState::start_thread_pool();

    debug!("Creating keystore service");
    let dev = KeystoreService::new_native_binder().unwrap();

    let service = BnKeystoreService::new_binder(dev.clone());

    debug!("Adding keystore service to hub");
    hub::add_service("keystore3", service.as_binder()).unwrap();

    debug!("Adding OMK service to hub");
    let service = BnOhMyKsService::new_binder(dev);
    hub::add_service("omk", service.as_binder()).unwrap();

    debug!("Joining thread pool");
    rsbinder::ProcessState::join_thread_pool().unwrap();
}
