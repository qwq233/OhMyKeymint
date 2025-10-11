#![recursion_limit = "256"]
#![feature(once_cell_get_mut)]

use anyhow::Context;
use lazy_static;
use std::{
    panic,
    sync::{Arc, Mutex},
};

use jni::JavaVM;
use log::{debug, error};

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

lazy_static::lazy_static! {
    static ref JAVA_VM: Arc<Mutex<Option<JavaVM>>> = Arc::new(Mutex::new(None));
}

#[no_mangle]
pub extern "C" fn init(_env: jni::JNIEnv, _class: jni::objects::JClass) {
    debug!("nativeInit called");
    // You can add more initialization code here if needed
}

#[no_mangle]
pub extern "C" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    let jvm = unsafe { jni::JavaVM::from_raw(vm).expect("Failed to get JavaVM from raw pointer") };
    let mut env = jvm.get_env().unwrap();

    logging::init_logger();
    rsbinder::ProcessState::init_default();
    debug!("Hello, OhMyKeymint!");

    // Redirect panic messages to logcat.
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    let class = env
        .find_class("top/qwq2333/ohmykeymint/Native")
        .context("Failed to find class top/qwq2333/ohmykeymint/Native")
        .unwrap();

    let methods = jni_methods![["nativeInit", "()V", init], ["init", "()V", init],];

    debug!("Registering native methods");
    env.register_native_methods(class, methods.as_slice())
        .context("Failed to register native methods")
        .unwrap();

    debug!("Saving JavaVM instance");
    let mut java_vm_lock = JAVA_VM.lock().unwrap();
    *java_vm_lock = Some(jvm);

    return jni::sys::JNI_VERSION_1_6;
}
