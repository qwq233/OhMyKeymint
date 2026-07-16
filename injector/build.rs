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
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rustc-link-arg-bin=inject=-Wl,--export-dynamic-symbol=entry");

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

    let aidl_dirs = [
        "../aidl/android/system/keystore2",
        "../aidl/android/hardware/security/keymint",
        "../aidl/android/hardware/security/secureclock",
        "../aidl/android/security/authorization",
        "../aidl/android/security/maintenance",
        "../aidl/android/security/keystore",
        "../aidl/top/qwq2333/ohmykeymint",
    ];
    let mut aidl = rsbinder_aidl::Builder::new();
    for dir in aidl_dirs {
        aidl = aidl.include_dir(PathBuf::from(dir));
    }
    let mut aidl = aidl.output(PathBuf::from("aidl.rs"));
    for dir in aidl_dirs {
        aidl = add_all_aidl_sources(aidl, dir);
    }

    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();
    let patched_content = content
        .replace(
            "\npub mod top {",
            "\n#[allow(clippy::all)]\n#[allow(unused_imports)]\npub mod top {",
        )
        .replace(
            "fn build_parcel_getNumberOfEntries(&self, _arg_domain: super::Domain::Domain, _arg_nspace: i64) -> rsbinder::Result<rsbinder::Parcel>",
            "pub(crate) fn build_parcel_getNumberOfEntries(&self, _arg_domain: super::Domain::Domain, _arg_nspace: i64) -> rsbinder::Result<rsbinder::Parcel>",
        );

    fs::write(&generated_path, &patched_content).unwrap();
}
