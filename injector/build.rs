use std::{fs, path::PathBuf, process::Command};

fn add_all_aidl_sources(builder: rsbinder_aidl::Builder, dir: &str) -> rsbinder_aidl::Builder {
    let mut builder = builder;
    let entries = fs::read_dir(dir).unwrap();
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
            builder = builder.source(path);
        }
    }
    builder
}

fn main() {
    println!("cargo:rerun-if-changed=../aidl");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo:rerun-if-env-changed=TARGET");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-arg-bin=inject=-Wl,--export-dynamic");
    }

    let build_target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    let package_version =
        std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown-version".to_string());
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-git".to_string());
    let build_id = format!("{package_version}-{git_sha}-{build_target}");

    println!("cargo:rustc-env=INJECTOR_BUILD_TARGET={build_target}");
    println!("cargo:rustc-env=INJECTOR_BUILD_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=INJECTOR_BUILD_ID={build_id}");

    let aidl = rsbinder_aidl::Builder::new()
        .include_dir(PathBuf::from("../aidl/android/system/keystore2"))
        .include_dir(PathBuf::from("../aidl/android/hardware/security/keymint"))
        .include_dir(PathBuf::from(
            "../aidl/android/hardware/security/secureclock",
        ))
        .include_dir(PathBuf::from("../aidl/android/security/keystore"))
        .include_dir(PathBuf::from("../aidl/top/qwq2333/ohmykeymint"))
        .output(PathBuf::from("aidl.rs"));

    let aidl = add_all_aidl_sources(aidl, "../aidl/android/system/keystore2");
    let aidl = add_all_aidl_sources(aidl, "../aidl/android/hardware/security/keymint");
    let aidl = add_all_aidl_sources(aidl, "../aidl/android/hardware/security/secureclock");
    let aidl = add_all_aidl_sources(aidl, "../aidl/android/security/keystore");
    let aidl = add_all_aidl_sources(aidl, "../aidl/top/qwq2333/ohmykeymint");

    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();
    let patched_content = content
        .replace("SecurityLevel.", "super::super::super::hardware::security::keymint::SecurityLevel::SecurityLevel::")
        .replace("HardwareAuthenticatorType.", "super::super::super::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType::")
        .replace("r#authenticatorType: super::Digest::Digest::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#authenticatorType: super::KeyPermission::KeyPermission::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#authenticatorType: super::PaddingMode::PaddingMode::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#operation: rsbinder::Strong<dyn super::IKeyMintOperation::IKeyMintOperation>,", "r#operation: Option<rsbinder::Strong<dyn super::IKeyMintOperation::IKeyMintOperation>>,");

    fs::write(&generated_path, &patched_content).unwrap();

    // Verify patches were applied. If any assertion fails, rsbinder-aidl codegen has changed
    // and the string replacements above need to be updated.
    let verify = fs::read_to_string(&generated_path).unwrap();
    assert!(
        verify.contains("super::super::super::hardware::security::keymint::SecurityLevel::SecurityLevel"),
        "BUG: SecurityLevel enum path patch was NOT applied. rsbinder-aidl codegen may have changed."
    );
    assert!(
        verify.contains("super::super::super::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType"),
        "BUG: HardwareAuthenticatorType enum path patch was NOT applied."
    );
    assert!(
        !verify.contains("r#authenticatorType: super::Digest::Digest::NONE,"),
        "BUG: Digest::NONE still present -- authenticatorType patch was not applied."
    );
    assert!(
        !verify.contains("r#authenticatorType: super::KeyPermission::KeyPermission::NONE,"),
        "BUG: KeyPermission::NONE still present -- patch not applied."
    );
    assert!(
        !verify.contains("r#authenticatorType: super::PaddingMode::PaddingMode::NONE,"),
        "BUG: PaddingMode::NONE still present -- patch not applied."
    );
}
