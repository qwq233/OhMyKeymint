/*
 * Copyright (C) 2024 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
use std::env;
use std::path::{Path, PathBuf};

const PLATFORM_FUNCTIONS: &[&str] = &[
    "android_get_device_api_level",
    "AServiceManager_.*", "ABinderProcess_.*", "ABinderRpc_.*",
    "AIBinder_(setRequestingSid|getCallingSid|setInheritRt|markSystemStability|markVendorStability|markVintfStability|requiresVintfDeclaration|isVendorStable|isSystemStable)",
    "AIBinder_Class_(setHandleShellCommand|setTransactionCodeToFunctionNameMap|getFunctionName)",
    "AIBinder_DeathRecipient_setOnUnlinked", "AParcel_(markSensitive|marshal|unmarshal)",
];

fn builder(manifest: &Path, target: &str, cpp: bool) -> bindgen::Builder {
    bindgen::Builder::default()
        .clang_arg(format!("--target={target}33"))
        .clang_arg(if cpp { "-std=c++20" } else { "-std=c17" })
        .clang_arg("-x")
        .clang_arg(if cpp { "c++" } else { "c" })
        .clang_arg("-DANDROID_PLATFORM")
        .clang_arg("-D__ANDROID_UNAVAILABLE_SYMBOLS_ARE_WEAK__")
        .clang_arg(format!("-I{}", manifest.join("include").display()))
        .formatter(bindgen::Formatter::Rustfmt)
        .rustfmt_configuration_file(Some(manifest.join("../../rustfmt.toml")))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .layout_tests(false)
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: true })
}

fn main() {
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies CARGO_MANIFEST_DIR"),
    );
    let target = env::var("TARGET").expect("Cargo supplies TARGET");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let mut public = builder(&manifest, &target, true)
        .header(manifest.join("BinderBindings.hpp").to_str().expect("Binder header path is UTF-8"))
        .constified_enum("android::c_interface::consts::.*")
        .allowlist_type("android::c_interface::.*")
        .allowlist_type("A(Status|IBinder.*|Parcel)")
        .blocklist_type("AServiceManager_PermissionType|ABinderRpc_.*")
        .allowlist_type("binder_status_t")
        .allowlist_function("A.*");
    let platform = builder(&manifest, &target, true)
        .header(manifest.join("PlatformBindings.hpp").to_str().expect("platform header path is UTF-8"))
        .blocklist_type("AIBinder|AIBinder_Class|AIBinder_DeathRecipient|AParcel|binder_status_t|binder_exception_t|sockaddr")
        .allowlist_type("ABinderRpc_.*|AServiceManager_PermissionType");
    for function in PLATFORM_FUNCTIONS {
        public = public.blocklist_function(function);
    }
    public
        .generate()
        .expect("generate public NDK Binder bindings")
        .write_to_file(output.join("bindings.rs"))
        .expect("write public Binder bindings");
    platform
        .generate()
        .expect("generate platform Binder declarations")
        .write_to_file(output.join("platform.rs"))
        .expect("write platform Binder bindings");
    builder(&manifest, &target, false)
        .header_contents("DriverBindings.h", "#include <linux/android/binder.h>")
        .allowlist_type("binder_(write_read|transaction_data.*|object_header|ptr_cookie|node_debug_info|version|driver_.*)")
        .allowlist_type("flat_binder_object")
        .allowlist_type("flat_binder_object_flags|transaction_flags")
        .allowlist_var("BINDER_.*|BC_.*|BR_.*|TF_.*|FLAT_BINDER_FLAG_.*|_IOC_.*")
        .constified_enum("binder_driver_.*")
        .prepend_enum_name(false)
        .default_enum_style(bindgen::EnumVariation::Consts)
        .derive_default(true)
        .generate()
        .expect("generate Binder driver UAPI")
        .write_to_file(output.join("driver.rs"))
        .expect("write Binder driver UAPI");
    println!("cargo::rustc-link-lib=binder_ndk");
}
