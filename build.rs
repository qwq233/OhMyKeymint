use std::fs;
use std::process::Command;

fn main() {
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
    let _ = Command::new("rustfmt").args([&mod_file, &format!("{}/storage.rs", out_dir)]).status();
}
