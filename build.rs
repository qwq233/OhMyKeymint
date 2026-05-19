use std::{fs, path::PathBuf, process::Command, vec};

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=static=c++_static");
    }

    println!("cargo:rerun-if-changed=aidl");
    println!("cargo:rerun-if-changed=src/proto");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = "src/proto";

    fs::create_dir_all(out_dir).unwrap();

    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_protos(&["proto/storage.proto"], &["proto/"])
        .expect("Failed to compile .proto files");

    let mod_file = format!("{}/mod.rs", out_dir);
    let mod_content = ["storage.rs"]
        .iter()
        .map(|file| format!("pub mod {};", file.trim_end_matches(".rs")))
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&mod_file, mod_content).unwrap();
    let _ = Command::new("rustfmt")
        .args([&mod_file, &format!("{}/storage.rs", out_dir)])
        .status();

    let mut aidl = rsbinder_aidl::Builder::new()
        .include_dir(PathBuf::from("aidl/android/system/keystore2"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/keymint"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/secureclock"))
        .include_dir(PathBuf::from("aidl/android/security/authorization"))
        .include_dir(PathBuf::from("aidl/android/security/maintenance"))
        .output(PathBuf::from("aidl.rs"));

    let dirs = vec![
        "aidl/android/content/pm",
        "aidl/android/system/keystore2",
        "aidl/android/hardware/security/keymint",
        "aidl/android/hardware/security/secureclock",
        "aidl/android/security/authorization",
        "aidl/android/security/maintenance",
        "aidl/android/security/metrics",
        "aidl/android/security/keystore",
        "aidl/android/apex",
        "aidl/top/qwq2333/ohmykeymint",
    ];
    for dir in dirs {
        println!("Processing AIDL files in directory: {}", dir);
        let dir = fs::read_dir(dir).unwrap();

        for entry in dir {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
                aidl = aidl.source(path);
            }
        }
    }
    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();

    // dirty fixes for name conflicts and incorrect types
    let patched_content = content
        .replace("SecurityLevel.", "super::super::super::hardware::security::keymint::SecurityLevel::SecurityLevel::")
        .replace("HardwareAuthenticatorType.", "super::super::super::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType::")
        .replace("r#authenticatorType: super::Digest::Digest::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#authenticatorType: super::KeyPermission::KeyPermission::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#authenticatorType: super::PaddingMode::PaddingMode::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#operation: rsbinder::Strong<dyn super::IKeyMintOperation::IKeyMintOperation>,", "r#operation: Option<rsbinder::Strong<dyn super::IKeyMintOperation::IKeyMintOperation>>,")
        .replace("\npub mod top {", "\n#[allow(clippy::all)]\n#[allow(unused_imports)]\npub mod top {");

    println!("Patched AIDL content:\n{}", generated_path.display());

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
