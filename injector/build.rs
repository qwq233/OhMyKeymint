use std::process::Command;

fn main() {
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
}
