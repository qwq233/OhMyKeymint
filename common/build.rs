use std::env;
use std::path::PathBuf;

fn main() {
    let input = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies CARGO_MANIFEST_DIR"),
    )
    .join("../aidl");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    let mut aidl = aidl_generator::Builder::new(&input, output, "37.0.0")
        .min_sdk_version(33)
        .framework_keymint_union_guard("crate::android_version::framework_keymint_v5_union()");
    for (directory, version, hash) in [
        ("android/hardware/security/keymint", 5, "177877c3782ff5543c231b8616f1ee6a300f810d"),
        ("android/system/keystore2", 6, "b115fcb5d111eb616a65f0f32e0c2cef131575ec"),
        ("android/hardware/security/secureclock", 1, "cd55ca9963c6a57fa5f2f120a45c6e0c4fafb423"),
        ("android/hardware/security/sharedsecret", 1, "aea3745b559d2977f0676952e510fb0547a52140"),
    ] {
        aidl = aidl.vintf_source_dir(directory, version, hash);
    }
    for directory in [
        "android/security/authorization",
        "android/security/compat",
        "android/security/maintenance",
        "android/security/metrics",
        "android/security/keystore",
        "android/apex",
        "android/content/pm",
        "android/os",
        "top/qwq2333/ohmykeymint",
    ] {
        aidl = aidl.source_dir(directory);
    }
    for (public, private) in [
        ("android.system.keystore2.IKeystoreService", "top.qwq2333.ohmykeymint.IOhMyKsService"),
        (
            "android.system.keystore2.IKeystoreSecurityLevel",
            "top.qwq2333.ohmykeymint.IOhMySecurityLevel",
        ),
        (
            "android.security.authorization.IKeystoreAuthorization",
            "top.qwq2333.ohmykeymint.IOhMyAuthorizationService",
        ),
        (
            "android.security.maintenance.IKeystoreMaintenance",
            "top.qwq2333.ohmykeymint.IOhMyMaintenanceService",
        ),
        (
            "android.system.keystore2.IKeystoreOperation",
            "android.system.keystore2.IKeystoreOperation",
        ),
    ] {
        aidl = aidl.rpc_interface(public, private);
    }
    for (interface, request) in [
        ("android.system.keystore2.IKeystoreService", "ParsedServiceRequest"),
        ("android.system.keystore2.IKeystoreSecurityLevel", "ParsedLevelRequest"),
    ] {
        aidl = aidl.transport_interface(
            interface,
            format!("crate::aidl::{}::{request}", interface.replace('.', "::")),
        );
    }
    aidl.generate().expect("generate shared Rust AIDL");
    println!("cargo:rerun-if-changed=build.rs");
}
