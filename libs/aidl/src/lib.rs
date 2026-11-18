// Copyright 2026 The OhMyKeymint Authors
// SPDX-License-Identifier: Apache-2.0

//! Generate Rust AIDL with the SDK compiler and assemble its module tree.
//!
//! Module assembly follows AOSP system/tools/aidl's aidl_rust_glue.py.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::{env, fs, io};

mod rust;
mod transport;

struct SourceGroup {
    directory: PathBuf,
    version: Option<(u32, String)>,
}

/// Module-specific inputs to the official Rust AIDL backend.
pub struct Builder {
    input: PathBuf,
    output: PathBuf,
    groups: Vec<SourceGroup>,
    min_sdk: u32,
    build_tools_version: String,
    transport_interfaces: BTreeMap<String, String>,
    rpc_interfaces: BTreeMap<String, String>,
    keymint_union_guard: Option<String>,
}

impl Builder {
    /// Use the calling module's import root, OUT_DIR, and Build Tools version.
    pub fn new(
        input: impl Into<PathBuf>,
        output: impl Into<PathBuf>,
        build_tools_version: impl Into<String>,
    ) -> Self {
        Self {
            input: input.into(),
            output: output.into(),
            groups: Vec::new(),
            min_sdk: 33,
            build_tools_version: build_tools_version.into(),
            transport_interfaces: BTreeMap::new(),
            rpc_interfaces: BTreeMap::new(),
            keymint_union_guard: None,
        }
    }

    /// Add unversioned interfaces relative to the import root.
    pub fn source_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        self.groups.push(SourceGroup { directory: directory.into(), version: None });
        self
    }

    /// Add a frozen VINTF interface and its exact AOSP version/hash.
    pub fn vintf_source_dir(
        mut self,
        directory: impl Into<PathBuf>,
        version: u32,
        hash: impl Into<String>,
    ) -> Self {
        self.groups.push(SourceGroup {
            directory: directory.into(),
            version: Some((version, hash.into())),
        });
        self
    }

    /// Set the minimum supported Android API level.
    pub fn min_sdk_version(mut self, version: u32) -> Self {
        self.min_sdk = version;
        self
    }

    /// Derive a request codec from this interface's official Rust dispatcher.
    pub fn transport_interface(
        mut self,
        interface: impl Into<String>,
        request_type: impl Into<String>,
    ) -> Self {
        self.transport_interfaces.insert(interface.into(), request_type.into());
        self
    }

    /// Derive transaction and caller-prefix mappings from two SDK interfaces.
    pub fn rpc_interface(mut self, public: impl Into<String>, private: impl Into<String>) -> Self {
        self.rpc_interfaces.insert(public.into(), private.into());
        self
    }

    /// Select the running framework's KeyParameterValue union contract in this module.
    pub fn framework_keymint_union_guard(mut self, guard: impl Into<String>) -> Self {
        self.keymint_union_guard = Some(guard.into());
        self
    }

    /// Compile the declared sources and write aidl.rs in OUT_DIR.
    pub fn generate(self) -> io::Result<()> {
        for name in ["AIDL", "ANDROID_HOME", "ANDROID_SDK_ROOT"] {
            println!("cargo:rerun-if-env-changed={name}");
        }
        println!("cargo:rustc-check-cfg=cfg(android_ndk)");
        println!("cargo:rustc-check-cfg=cfg(android_vndk)");
        let compiler = compiler_from_env(&self.build_tools_version)?;
        println!("cargo:rerun-if-changed={}", compiler.display());
        println!("cargo:rerun-if-changed={}", self.input.display());
        fs::create_dir_all(&self.output)?;

        let mut tree = Module::default();
        let mut transport_interfaces = self.transport_interfaces;
        let mut keymint_union_guard = self.keymint_union_guard;
        for group in self.groups {
            if group.directory.components().any(|part| !matches!(part, Component::Normal(_))) {
                return Err(invalid("AIDL source directories must be relative to the import root"));
            }
            if let Some((version, hash)) = &group.version {
                if *version == 0 || hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err(invalid(
                        "a frozen AIDL interface requires a version and SHA-1 hash",
                    ));
                }
            }
            let mut sources = fs::read_dir(self.input.join(&group.directory))?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<io::Result<Vec<_>>>()?;
            sources.retain(|path| path.extension() == Some(OsStr::new("aidl")));
            sources.sort();
            for source in sources {
                let mut command = Command::new(&compiler);
                let mut output_argument = OsString::from("--out=");
                output_argument.push(&self.output);
                command
                    .args(["--lang=rust", "--structured", "--omit_invocation"])
                    .arg(format!("--min_sdk_version={}", self.min_sdk))
                    .arg(output_argument)
                    .arg("-I")
                    .arg(&self.input);
                if let Some((version, hash)) = &group.version {
                    command
                        .arg("--stability=vintf")
                        .arg(format!("--version={version}"))
                        .arg(format!("--hash={hash}"));
                }
                let result = command.arg(&source).output()?;
                if !result.status.success() {
                    return Err(io::Error::other(format!(
                        "Rust AIDL compilation failed for {}: {}",
                        source.display(),
                        String::from_utf8_lossy(&result.stderr)
                    )));
                }
                let relative = source.strip_prefix(&self.input).map_err(io::Error::other)?;
                let generated = self.output.join(relative).with_extension("rs");
                let interface = relative
                    .with_extension("")
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(".");
                let request_type = transport_interfaces.remove(&interface);
                let union_guard =
                    if interface == "android.hardware.security.keymint.KeyParameterValue" {
                        keymint_union_guard.take()
                    } else {
                        None
                    };
                let contents = rust::prepare(
                    &fs::read_to_string(generated)?,
                    request_type.as_deref(),
                    union_guard.as_deref(),
                    matches!(
                        interface.as_str(),
                        "android.system.keystore2.IKeystoreSecurityLevel"
                            | "android.system.keystore2.IKeystoreOperation"
                    ),
                )?;
                tree.insert(&relative.with_extension("rs"), contents)?;
            }
        }
        if !transport_interfaces.is_empty() {
            return Err(invalid("a requested transport interface was not generated"));
        }
        for (public, private) in self.rpc_interfaces {
            let public_path = PathBuf::from(public.replace('.', "/")).with_extension("rs");
            let private_path = PathBuf::from(private.replace('.', "/")).with_extension("rs");
            let peer =
                syn::parse_file(tree.source_mut(&private_path)?).map_err(io::Error::other)?;
            let source = tree.source_mut(&public_path)?;
            let mut file = syn::parse_file(source).map_err(io::Error::other)?;
            transport::rpc_mapping(
                &mut file,
                &peer,
                &format!("crate::aidl::{}", private.replace('.', "::")),
            )?;
            transport::validate(&mut file)?;
            *source = quote::ToTokens::to_token_stream(&file).to_string();
            if public != private {
                let source = tree.source_mut(&private_path)?;
                let mut file = syn::parse_file(source).map_err(io::Error::other)?;
                transport::validate(&mut file)?;
                *source = quote::ToTokens::to_token_stream(&file).to_string();
            }
        }
        if keymint_union_guard.is_some() {
            return Err(invalid(
                "the requested framework KeyParameterValue union was not generated",
            ));
        }
        let mut output = String::from("#[allow(non_snake_case)]\npub mod aidl {\n");
        tree.emit(&mut output);
        output.push_str("}\npub mod mangled {\n");
        tree.emit_mangled(&mut output, "super::aidl");
        output.push_str("}\n");
        let path = self.output.join("aidl.rs");
        fs::write(&path, output)?;
        let formatted = Command::new("rustfmt")
            .args(["--edition", "2021", "--config", "skip_children=true"])
            .arg(&path)
            .output()?;
        if !formatted.status.success() {
            return Err(io::Error::other(String::from_utf8_lossy(&formatted.stderr).into_owned()));
        }
        fs::write(self.output.join("aidl-compiler.txt"), compiler.to_string_lossy().as_bytes())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn compiler_from_env(build_tools_version: &str) -> io::Result<PathBuf> {
    if let Some(path) = env::var_os("AIDL") {
        let compiler = PathBuf::from(path);
        if !compiler.is_file() {
            return Err(invalid("AIDL must point to the SDK aidl executable"));
        }
        return Ok(compiler);
    }
    let sdk = env::var_os("ANDROID_HOME")
        .or_else(|| env::var_os("ANDROID_SDK_ROOT"))
        .ok_or_else(|| invalid("set ANDROID_HOME or ANDROID_SDK_ROOT to the Android SDK"))?;
    let build_tools = PathBuf::from(sdk).join("build-tools").join(build_tools_version);
    println!("cargo:rerun-if-changed={}", build_tools.display());
    let executable = if cfg!(windows) { "aidl.exe" } else { "aidl" };
    let compiler = build_tools.join(executable);
    if compiler.is_file() {
        Ok(compiler)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Android Build Tools {build_tools_version} aidl executable not found"),
        ))
    }
}

#[derive(Default)]
struct Module {
    modules: BTreeMap<String, Module>,
    files: BTreeMap<String, String>,
}

impl Module {
    fn insert(&mut self, path: &Path, source: String) -> io::Result<()> {
        let mut module = self;
        if let Some(parent) = path.parent() {
            for part in parent.components() {
                let name =
                    part.as_os_str().to_str().ok_or_else(|| invalid("AIDL module is not UTF-8"))?;
                module = module.modules.entry(name.to_owned()).or_default();
            }
        }
        let name = path
            .file_stem()
            .and_then(OsStr::to_str)
            .ok_or_else(|| invalid("AIDL type is not UTF-8"))?;
        if module.files.insert(name.to_owned(), source).is_some() {
            return Err(invalid("duplicate AIDL type"));
        }
        Ok(())
    }

    fn source_mut(&mut self, path: &Path) -> io::Result<&mut String> {
        let mut module = self;
        if let Some(parent) = path.parent() {
            for part in parent.components() {
                let name =
                    part.as_os_str().to_str().ok_or_else(|| invalid("AIDL module is not UTF-8"))?;
                module = module
                    .modules
                    .get_mut(name)
                    .ok_or_else(|| invalid("RPC interface module missing"))?;
            }
        }
        module
            .files
            .get_mut(
                path.file_stem()
                    .and_then(OsStr::to_str)
                    .ok_or_else(|| invalid("AIDL type is not UTF-8"))?,
            )
            .ok_or_else(|| invalid("RPC interface missing"))
    }

    fn emit(&self, output: &mut String) {
        use std::fmt::Write as _;
        for (name, source) in &self.files {
            writeln!(output, "pub mod {name} {{\n{source}\n}}")
                .expect("writing to String cannot fail");
        }
        for (name, module) in &self.modules {
            writeln!(output, "pub mod {name} {{").expect("writing to String cannot fail");
            module.emit(output);
            output.push_str("}\n");
        }
    }

    fn emit_mangled(&self, output: &mut String, prefix: &str) {
        use std::fmt::Write as _;
        for name in self.files.keys() {
            writeln!(output, "pub use {prefix}::{name}::mangled::*;")
                .expect("writing to String cannot fail");
        }
        for (name, module) in &self.modules {
            module.emit_mangled(output, &format!("{prefix}::{name}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_tree_preserves_cross_package_mangled_paths() {
        let mut tree = Module::default();
        tree.insert(Path::new("android/one/A.rs"), "pub use crate::mangled::B;".into()).unwrap();
        tree.insert(Path::new("android/two/B.rs"), "pub mod mangled {}".into()).unwrap();
        let mut output = String::new();
        tree.emit(&mut output);
        tree.emit_mangled(&mut output, "super::aidl");
        assert!(output.contains("pub mod android {"));
        assert!(output.contains("pub use crate::mangled::B;"));
        assert!(output.contains("pub use super::aidl::android::two::B::mangled::*;"));
    }
}
