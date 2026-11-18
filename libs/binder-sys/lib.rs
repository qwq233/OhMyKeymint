/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Generated Rust bindings to libbinder_ndk

use std::error::Error;
use std::fmt;

#[cfg(not(target_os = "trusty"))]
#[allow(bad_style)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

    pub mod driver {
        include!(concat!(env!("OUT_DIR"), "/driver.rs"));
    }
}

// Trusty puts the full path to the auto-generated file in BINDGEN_INC_FILE
// and builds it with warnings-as-errors, so we need to use #[allow(bad_style)].
// We need to use cfg(target_os) instead of cfg(trusty) here because of
// the difference between the two build systems, which we cannot mock.
#[cfg(target_os = "trusty")]
#[allow(bad_style)]
mod bindings {
    include!(env!("BINDGEN_INC_FILE"));
}

pub use bindings::*;

pub mod compat;

pub use compat::exports::{
    ABinderProcess_joinThreadPool, ABinderProcess_setThreadPoolMaxThreadCount,
    ABinderProcess_startThreadPool, ABinderRpc_Accessor_asBinder,
    ABinderRpc_Accessor_delegateAccessor, ABinderRpc_Accessor_delete,
    ABinderRpc_Accessor_fromBinder, ABinderRpc_Accessor_new, ABinderRpc_ConnectionInfo_new,
    ABinderRpc_registerAccessorProvider, ABinderRpc_unregisterAccessorProvider,
    AIBinder_Class_setHandleShellCommand, AIBinder_Class_setTransactionCodeToFunctionNameMap,
    AIBinder_DeathRecipient_setOnUnlinked, AIBinder_getCallingSid, AIBinder_isSystemStable,
    AIBinder_isVendorStable, AIBinder_markSystemStability, AIBinder_markVintfStability,
    AIBinder_requiresVintfDeclaration, AIBinder_setInheritRt, AIBinder_setRequestingSid,
    AParcel_markSensitive, AParcel_marshal, AParcel_unmarshal, AServiceManager_addService,
    AServiceManager_checkService, AServiceManager_checkServiceAccess,
    AServiceManager_forEachDeclaredInstance, AServiceManager_forceLazyServicesPersist,
    AServiceManager_getService, AServiceManager_isDeclared, AServiceManager_registerLazyService,
    AServiceManager_waitForService,
};
pub use compat::{
    ABinderRpc_Accessor, ABinderRpc_AccessorProvider,
    ABinderRpc_AccessorProviderUserData_deleteCallback,
    ABinderRpc_AccessorProvider_getAccessorCallback, ABinderRpc_ConnectionInfo,
    ABinderRpc_ConnectionInfoProvider, ABinderRpc_ConnectionInfoProviderUserData_delete,
    AServiceManager_PermissionType,
};

impl Error for android_c_interface_StatusCode {}

impl fmt::Display for android_c_interface_StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "StatusCode::{:?}", self)
    }
}
