#![recursion_limit = "256"]
#![feature(once_cell_get_mut)]
#![feature(once_cell_try)]

use std::panic;

use log::{debug, error};
use rsbinder::hub;

use crate::{
    android::system::keystore2::
        IKeystoreOperation, keymaster::service::KeystoreService}
    
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
    let service = KeystoreService::new_native_binder().unwrap();

    debug!("Adding service to hub");
    hub::add_service("omk", service.as_binder()).unwrap();

    debug!("Joining thread pool");
    rsbinder::ProcessState::join_thread_pool().unwrap();
}

#[derive(Clone)]
pub struct KeystoreOperation;

impl rsbinder::Interface for KeystoreOperation {}

impl IKeystoreOperation::IKeystoreOperation for KeystoreOperation {
    fn r#updateAad(&self, _arg_aad_input: &[u8]) -> rsbinder::status::Result<()> {
        Ok(())
    }

    fn r#update(&self, _arg_input: &[u8]) -> rsbinder::status::Result<Option<Vec<u8>>> {
        Ok(Some(vec![]))
    }

    fn r#finish(
        &self,
        _arg_input: Option<&[u8]>,
        _arg_signature: Option<&[u8]>,
    ) -> rsbinder::status::Result<Option<Vec<u8>>> {
        Ok(Some(vec![]))
    }

    fn r#abort(&self) -> rsbinder::status::Result<()> {
        Ok(())
    }
}
