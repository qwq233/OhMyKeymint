use std::{fs, path::PathBuf, vec};
 
fn main() {
    let out_dir = "src/proto";
 
    fs::create_dir_all(out_dir).unwrap();
 
    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_protos(
            &["proto/storage.proto"],
            &["proto/"],
        )
        .expect("Failed to compile .proto files");
 
    let mod_file = format!("{}/mod.rs", out_dir);
    let mod_content = ["storage.rs"]
        .iter()
        .map(|file| format!("pub mod {};", file.trim_end_matches(".rs")))
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&mod_file, mod_content).unwrap();

    let mut aidl = rsbinder_aidl::Builder::new()
        .include_dir(PathBuf::from("aidl/android/system/keystore2"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/keymint"))
        .output(PathBuf::from("aidl.rs"));

    let dirs = vec![
        "aidl/android/system/keystore2",
        "aidl/android/hardware/security/keymint",
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

    let patched_content = content
        .replace("SecurityLevel.", "super::super::super::hardware::security::keymint::SecurityLevel::SecurityLevel::")
        .replace("HardwareAuthenticatorType.", "super::super::super::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType::")
        .replace("r#authenticatorType: super::Digest::Digest::NONE,", "r#authenticatorType: super::HardwareAuthenticatorType::HardwareAuthenticatorType::NONE,")
        .replace("r#operation: rsbinder::Strong<dyn super::IKeyMintOperation::IKeyMintOperation>,", "r#operation: Option<rsbinder::Strong<dyn super::IKeyMintOperation::IKeyMintOperation>>,");

    println!("Patched AIDL content:\n{}", generated_path.display());
    
    fs::write(generated_path, patched_content).unwrap(); 
}