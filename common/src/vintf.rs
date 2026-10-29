// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

const VINTF_MANIFEST_DIRS: &[&str] = &[
    "/system/etc/vintf/manifest",
    "/system_ext/etc/vintf/manifest",
    "/product/etc/vintf/manifest",
    "/vendor/etc/vintf/manifest",
    "/odm/etc/vintf/manifest",
];
const VINTF_MANIFEST_FILES: &[&str] = &[
    "/system/etc/vintf/manifest.xml",
    "/system_ext/etc/vintf/manifest.xml",
    "/product/etc/vintf/manifest.xml",
    "/vendor/etc/vintf/manifest.xml",
    "/odm/etc/vintf/manifest.xml",
];
const DEFAULT_AIDL_VERSION: i32 = 1;
const META_VERSION_NO_HAL_INTERFACE_INSTANCE: MetaVersion = MetaVersion { major: 6, minor: 0 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestKind {
    Device,
    Framework,
}

impl ManifestKind {
    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "device" => Some(Self::Device),
            "framework" => Some(Self::Framework),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Framework => "framework",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MetaVersion {
    major: u32,
    minor: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct InstanceKey {
    interface: String,
    instance: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "manifest")]
struct ManifestXml {
    #[serde(rename = "@version")]
    version: String,
    #[serde(rename = "@type")]
    manifest_type: String,
    #[serde(rename = "hal", default)]
    hals: Vec<HalXml>,
}

#[derive(Debug, Deserialize)]
struct HalXml {
    #[serde(rename = "@format")]
    format: Option<String>,
    #[serde(rename = "@override", default)]
    is_override: bool,
    name: Option<String>,
    #[serde(rename = "version", default)]
    versions: Vec<String>,
    #[serde(rename = "fqname", default)]
    fqnames: Vec<String>,
    #[serde(rename = "interface", default)]
    interfaces: Vec<InterfaceXml>,
}

#[derive(Debug, Deserialize)]
struct InterfaceXml {
    name: Option<String>,
    #[serde(rename = "instance", default)]
    instances: Vec<String>,
}

#[derive(Debug)]
struct ParsedAidlHal {
    is_override: bool,
    versions: BTreeSet<i32>,
    instances: BTreeSet<InstanceKey>,
}

#[derive(Debug)]
struct LoadedManifest {
    path: PathBuf,
    xml: String,
}

struct ManifestMerger<'a> {
    expected_kind: ManifestKind,
    target_hal: &'a str,
    source_meta_version: Option<MetaVersion>,
    instances: BTreeMap<InstanceKey, BTreeSet<i32>>,
}

#[derive(Clone, Copy)]
enum ApexPartitionGroup {
    Vendor,
    Odm,
    Framework,
}

pub fn resolve_aidl_hal_version(
    kind: ManifestKind,
    hal_name: &str,
    interface: &str,
    instance: &str,
) -> Result<Option<i32>> {
    resolve_aidl_hal_version_with(
        Path::new("/"),
        kind,
        hal_name,
        interface,
        instance,
        &read_string_property,
    )
}

fn resolve_aidl_hal_version_with(
    root: &Path,
    kind: ManifestKind,
    hal_name: &str,
    interface: &str,
    instance: &str,
    read_property: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<i32>> {
    let mut merger = ManifestMerger::new(kind, hal_name);
    match kind {
        ManifestKind::Device => resolve_device_manifest(root, read_property, &mut merger)?,
        ManifestKind::Framework => resolve_framework_manifest(root, read_property, &mut merger)?,
    }
    Ok(merger.version_for(interface, instance))
}

impl<'a> ManifestMerger<'a> {
    fn new(expected_kind: ManifestKind, target_hal: &'a str) -> Self {
        Self { expected_kind, target_hal, source_meta_version: None, instances: BTreeMap::new() }
    }

    fn version_for(&self, interface: &str, instance: &str) -> Option<i32> {
        self.instances
            .get(&InstanceKey { interface: interface.to_string(), instance: instance.to_string() })
            .and_then(|versions| versions.last().copied())
    }

    fn merge_loaded(&mut self, loaded: LoadedManifest) -> Result<()> {
        self.merge_xml(&loaded.xml, &loaded.path)
    }

    fn merge_xml(&mut self, xml: &str, source: &Path) -> Result<()> {
        let manifest: ManifestXml = quick_xml::de::from_str(xml).with_context(|| {
            format!("failed to deserialize VINTF manifest {}", source.display())
        })?;
        let kind = ManifestKind::parse(&manifest.manifest_type).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid VINTF manifest type {:?} in {}",
                manifest.manifest_type,
                source.display()
            )
        })?;
        if kind != self.expected_kind {
            bail!(
                "cannot merge {} VINTF manifest {} into {} manifest",
                kind.as_str(),
                source.display(),
                self.expected_kind.as_str()
            );
        }

        let meta_version = parse_meta_version(&manifest.version)
            .with_context(|| format!("invalid meta-version in {}", source.display()))?;
        let source_meta_version = *self.source_meta_version.get_or_insert(meta_version);

        for hal in manifest.hals {
            if hal.format.as_deref().map(str::trim) != Some("aidl")
                || hal.name.as_deref().map(str::trim) != Some(self.target_hal)
            {
                continue;
            }

            let hal = parse_aidl_hal(hal, meta_version, source)?;
            if hal.is_override {
                // libvintf represents every AIDL version with the same fake major version, so an
                // override removes every prior declaration for this package before adding itself.
                self.instances.clear();
            } else if source_meta_version >= META_VERSION_NO_HAL_INTERFACE_INSTANCE {
                if let Some(conflict) =
                    hal.instances.iter().find(|candidate| self.instances.contains_key(*candidate))
                {
                    bail!(
                        "conflicting AIDL FqInstance {}/{} for HAL {} while merging {}",
                        conflict.interface,
                        conflict.instance,
                        self.target_hal,
                        source.display()
                    );
                }
            }

            for instance in hal.instances {
                self.instances.entry(instance).or_default().extend(hal.versions.iter().copied());
            }
        }

        Ok(())
    }
}

fn parse_aidl_hal(hal: HalXml, meta_version: MetaVersion, source: &Path) -> Result<ParsedAidlHal> {
    let versions = if hal.versions.is_empty() {
        BTreeSet::from([DEFAULT_AIDL_VERSION])
    } else {
        if hal.versions.len() != 1 {
            bail!("duplicated AIDL major version in {}", source.display());
        }
        let value = &hal.versions[0];
        let version = value
            .trim()
            .parse::<i32>()
            .with_context(|| format!("invalid AIDL version {value:?} in {}", source.display()))?;
        if version < 0 {
            bail!("invalid negative AIDL version {version} in {}", source.display());
        }
        BTreeSet::from([version])
    };

    let mut instances = BTreeSet::new();
    for fqname in hal.fqnames {
        let key = parse_aidl_fqname(&fqname, source)?;
        if !instances.insert(key.clone()) {
            bail!(
                "duplicated AIDL fqname {}/{} in {}",
                key.interface,
                key.instance,
                source.display()
            );
        }
    }

    let mut interface_names = BTreeSet::new();
    for interface in hal.interfaces {
        let name =
            interface.name.as_deref().map(str::trim).filter(|name| !name.is_empty()).ok_or_else(
                || anyhow::anyhow!("AIDL interface is missing its name in {}", source.display()),
            )?;
        if !interface_names.insert(name.to_string()) {
            bail!("duplicated AIDL interface entry {name:?} in {}", source.display());
        }
        if meta_version >= META_VERSION_NO_HAL_INTERFACE_INSTANCE && interface.instances.is_empty()
        {
            bail!("AIDL interface {name:?} has no instance in {}", source.display());
        }

        let mut interface_instances = BTreeSet::new();
        for instance in interface.instances {
            let instance = instance.trim();
            if instance.is_empty() {
                bail!("AIDL interface {name:?} has an empty instance in {}", source.display());
            }
            if !interface_instances.insert(instance.to_string()) {
                bail!(
                    "duplicated AIDL instance {instance:?} in interface {name:?} in {}",
                    source.display()
                );
            }
            let key = InstanceKey { interface: name.to_string(), instance: instance.to_string() };
            let inserted = instances.insert(key.clone());
            if meta_version >= META_VERSION_NO_HAL_INTERFACE_INSTANCE && !inserted {
                bail!(
                    "duplicated AIDL FqInstance {}/{} in {}",
                    key.interface,
                    key.instance,
                    source.display()
                );
            }
        }
    }

    if meta_version >= META_VERSION_NO_HAL_INTERFACE_INSTANCE
        && instances.is_empty()
        && !hal.is_override
    {
        bail!("AIDL HAL has no instance and is not disabled in {}", source.display());
    }

    Ok(ParsedAidlHal { is_override: hal.is_override, versions, instances })
}

fn parse_aidl_fqname(value: &str, source: &Path) -> Result<InstanceKey> {
    let value = value.trim();
    if value.contains('@') || value.contains("::") {
        bail!(
            "AIDL fqname must not contain a package or version: {value:?} in {}",
            source.display()
        );
    }
    let mut parts = value.split('/');
    let interface = parts.next().unwrap_or_default().trim();
    let instance = parts.next().unwrap_or_default().trim();
    if interface.is_empty() || instance.is_empty() || parts.next().is_some() {
        bail!("invalid AIDL fqname {value:?} in {}", source.display());
    }
    Ok(InstanceKey { interface: interface.to_string(), instance: instance.to_string() })
}

fn parse_meta_version(value: &str) -> Result<MetaVersion> {
    let (major, minor) = value
        .trim()
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid VINTF meta-version {value:?}"))?;
    if minor.contains('.') {
        bail!("invalid VINTF meta-version {value:?}");
    }
    Ok(MetaVersion {
        major: major
            .parse::<u32>()
            .with_context(|| format!("invalid VINTF meta-version {value:?}"))?,
        minor: minor
            .parse::<u32>()
            .with_context(|| format!("invalid VINTF meta-version {value:?}"))?,
    })
}

fn resolve_device_manifest(
    root: &Path,
    read_property: &dyn Fn(&str) -> Option<String>,
    merger: &mut ManifestMerger<'_>,
) -> Result<()> {
    let mut vendor_candidates = Vec::new();
    if let Some(sku) = property_value(read_property, "ro.boot.product.vendor.sku") {
        vendor_candidates.push(format!("{}_{sku}.xml", VINTF_MANIFEST_DIRS[3]));
    }
    vendor_candidates.push(VINTF_MANIFEST_FILES[3].to_string());
    let vendor = read_first_manifest(root, &vendor_candidates)?;

    let mut odm_candidates = Vec::new();
    let odm_sku = property_value(read_property, "ro.boot.product.hardware.sku");
    if let Some(sku) = odm_sku.as_deref() {
        odm_candidates.push(format!("{}_{sku}.xml", VINTF_MANIFEST_DIRS[4]));
    }
    odm_candidates.push(VINTF_MANIFEST_FILES[4].to_string());
    if let Some(sku) = odm_sku.as_deref() {
        odm_candidates.push(format!("/odm/etc/manifest_{sku}.xml"));
    }
    odm_candidates.push("/odm/etc/manifest.xml".to_string());
    let odm = read_first_manifest(root, &odm_candidates)?;

    if let Some(vendor) = vendor {
        merger.merge_loaded(vendor)?;
        merge_partition_fragments(
            root,
            read_property,
            VINTF_MANIFEST_DIRS[3],
            ApexPartitionGroup::Vendor,
            merger,
        )?;
        if let Some(odm) = odm {
            merger.merge_loaded(odm)?;
        }
        // AOSP loads ODM fragments whenever a vendor or ODM base manifest exists, even when the
        // ODM base itself is absent.
        merge_partition_fragments(
            root,
            read_property,
            VINTF_MANIFEST_DIRS[4],
            ApexPartitionGroup::Odm,
            merger,
        )?;
        return Ok(());
    }

    if let Some(odm) = odm {
        merger.merge_loaded(odm)?;
        merge_partition_fragments(
            root,
            read_property,
            VINTF_MANIFEST_DIRS[4],
            ApexPartitionGroup::Odm,
            merger,
        )?;
        return Ok(());
    }

    if let Some(legacy) = read_first_manifest(root, &["/vendor/manifest.xml".to_string()])? {
        merger.merge_loaded(legacy)?;
    }
    Ok(())
}

fn resolve_framework_manifest(
    root: &Path,
    read_property: &dyn Fn(&str) -> Option<String>,
    merger: &mut ManifestMerger<'_>,
) -> Result<()> {
    let system =
        read_first_manifest(root, &[VINTF_MANIFEST_FILES[0].to_string()]).and_then(|loaded| {
            let Some(loaded) = loaded else {
                return Ok(None);
            };
            let mut parsed = ManifestMerger::new(merger.expected_kind, merger.target_hal);
            parsed.merge_loaded(loaded)?;
            Ok(Some(parsed))
        });

    match system {
        Ok(Some(parsed)) => {
            *merger = parsed;
            merge_manifest_directory(root, VINTF_MANIFEST_DIRS[0], merger)?;
            for (manifest, directory) in [
                (VINTF_MANIFEST_FILES[2], VINTF_MANIFEST_DIRS[2]),
                (VINTF_MANIFEST_FILES[1], VINTF_MANIFEST_DIRS[1]),
            ] {
                if let Some(extension) = read_first_manifest(root, &[manifest.to_string()])? {
                    merger.merge_loaded(extension)?;
                }
                merge_manifest_directory(root, directory, merger)?;
            }
        }
        Ok(None) => {
            let Some(legacy) = read_first_manifest(root, &["/system/manifest.xml".to_string()])?
            else {
                return Ok(());
            };
            merger.merge_loaded(legacy)?;
        }
        Err(system_error) => {
            let Some(legacy) = read_first_manifest(root, &["/system/manifest.xml".to_string()])?
            else {
                return Err(system_error);
            };
            merger.merge_loaded(legacy)?;
        }
    }

    for directory in apex_vintf_directories(root, read_property, ApexPartitionGroup::Framework)? {
        merge_manifest_directory_path(&directory, merger)?;
    }
    Ok(())
}

fn merge_partition_fragments(
    root: &Path,
    read_property: &dyn Fn(&str) -> Option<String>,
    local_directory: &str,
    partition: ApexPartitionGroup,
    merger: &mut ManifestMerger<'_>,
) -> Result<()> {
    merge_manifest_directory(root, local_directory, merger)?;
    for directory in apex_vintf_directories(root, read_property, partition)? {
        merge_manifest_directory_path(&directory, merger)?;
    }
    Ok(())
}

fn apex_vintf_directories(
    root: &Path,
    read_property: &dyn Fn(&str) -> Option<String>,
    group: ApexPartitionGroup,
) -> Result<Vec<PathBuf>> {
    let ready =
        property_value(read_property, "apex.all.ready").as_deref().is_some_and(parse_bool_property);
    let (info_path, apex_root) = if ready {
        (crate::apex::APEX_INFO_LIST_PATH, "/apex")
    } else {
        (crate::apex::BOOTSTRAP_APEX_INFO_LIST_PATH, "/bootstrap-apex")
    };
    let Some(info_xml) = read_optional_path(&rooted_path(root, info_path))? else {
        return Ok(Vec::new());
    };
    let infos = crate::apex::parse_apex_info_list_xml(&info_xml)
        .with_context(|| format!("failed to parse VINTF APEX info {info_path}"))?;

    let mut directories = Vec::new();
    for info in infos {
        if !info.is_active || !apex_partition_matches(group, info.partition.trim()) {
            continue;
        }
        let module_name = info.module_name.trim();
        if module_name.is_empty() {
            bail!("active APEX entry in {info_path} is missing moduleName");
        }
        directories.push(rooted_path(root, apex_root).join(module_name).join("etc/vintf"));
    }
    Ok(directories)
}

fn apex_partition_matches(group: ApexPartitionGroup, partition: &str) -> bool {
    match group {
        ApexPartitionGroup::Vendor => partition == "VENDOR",
        ApexPartitionGroup::Odm => partition == "ODM",
        ApexPartitionGroup::Framework => {
            matches!(partition, "SYSTEM" | "SYSTEM_EXT" | "PRODUCT")
        }
    }
}

fn merge_manifest_directory(
    root: &Path,
    directory: &str,
    merger: &mut ManifestMerger<'_>,
) -> Result<()> {
    merge_manifest_directory_path(&rooted_path(root, directory), merger)
}

fn merge_manifest_directory_path(directory: &Path, merger: &mut ManifestMerger<'_>) -> Result<()> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to list VINTF directory {}", directory.display()))
        }
    };

    for entry in entries {
        let entry = entry
            .with_context(|| format!("failed to read VINTF directory {}", directory.display()))?;
        if entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry.path().display()))?
            .is_dir()
        {
            continue;
        }
        let path = entry.path();
        let xml = fs::read_to_string(&path)
            .with_context(|| format!("failed to read VINTF manifest {}", path.display()))?;
        merger.merge_xml(&xml, &path)?;
    }
    Ok(())
}

fn read_first_manifest(root: &Path, candidates: &[String]) -> Result<Option<LoadedManifest>> {
    for candidate in candidates {
        let path = rooted_path(root, candidate);
        if let Some(xml) = read_optional_path(&path)? {
            return Ok(Some(LoadedManifest { path, xml }));
        }
    }
    Ok(None)
}

fn read_optional_path(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(xml) => Ok(Some(xml)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn rooted_path(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn property_value(read_property: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    read_property(name).map(|value| value.trim().to_string()).filter(|value| !value.is_empty())
}

fn parse_bool_property(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "y" | "yes" | "on")
}

fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name).ok().map(|value| value.trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const KEYMINT_HAL_NAME: &str = "android.hardware.security.keymint";
    const KEYMINT_DEVICE_INTERFACE: &str = "IKeyMintDevice";

    fn resolve_xmls(
        kind: ManifestKind,
        interface: &str,
        instance: &str,
        xmls: &[&str],
    ) -> Result<Option<i32>> {
        let mut merger = ManifestMerger::new(kind, KEYMINT_HAL_NAME);
        for (index, xml) in xmls.iter().enumerate() {
            merger.merge_xml(xml, &PathBuf::from(format!("fixture-{index}.xml")))?;
        }
        Ok(merger.version_for(interface, instance))
    }

    #[test]
    fn versionless_qti_manifest_defaults_to_v1() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <fqname>IRemotelyProvisionedComponent/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            resolve_xmls(ManifestKind::Device, KEYMINT_DEVICE_INTERFACE, "default", &[xml])
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            resolve_xmls(ManifestKind::Device, "IRemotelyProvisionedComponent", "default", &[xml])
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn multiple_fragments_and_instance_forms_use_highest_version() {
        let version_2 = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>2</version>
        <fqname>IKeyMintDevice/default</fqname>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
</manifest>
"#;
        let version_4 = version_2.replace("<version>2</version>", "<version>4</version>");

        for instance in ["default", "strongbox"] {
            assert_eq!(
                resolve_xmls(
                    ManifestKind::Device,
                    KEYMINT_DEVICE_INTERFACE,
                    instance,
                    &[version_2, &version_4]
                )
                .unwrap(),
                Some(4)
            );
        }
    }

    #[test]
    fn multiple_versions_in_one_aidl_hal_are_rejected() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>2</version>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;

        assert!(resolve_xmls(ManifestKind::Device, KEYMINT_DEVICE_INTERFACE, "default", &[xml])
            .is_err());
    }

    #[test]
    fn duplicates_within_one_aidl_declaration_are_always_rejected() {
        let duplicate_fqname = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <fqname>IKeyMintDevice/default</fqname>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        let duplicate_instance = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>default</instance>
            <instance>default</instance>
        </interface>
    </hal>
</manifest>
"#;

        for xml in [duplicate_fqname, duplicate_instance] {
            assert!(resolve_xmls(
                ManifestKind::Device,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                &[xml]
            )
            .is_err());
        }
    }

    #[test]
    fn explicit_aidl_version_zero_is_parsed_but_left_to_the_caller() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>0</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            resolve_xmls(ManifestKind::Device, KEYMINT_DEVICE_INTERFACE, "default", &[xml])
                .unwrap(),
            Some(0)
        );
    }

    #[test]
    fn aidl_override_is_package_wide_and_can_disable_hal() {
        let base = r#"
<manifest version="6.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>1</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        let rkp_override = r#"
<manifest version="6.0" type="device">
    <hal format="aidl" override="true">
        <name>android.hardware.security.keymint</name>
        <version>3</version>
        <fqname>IRemotelyProvisionedComponent/default</fqname>
    </hal>
</manifest>
"#;
        let disabled = r#"
<manifest version="6.0" type="device">
    <hal format="aidl" override="true">
        <name>android.hardware.security.keymint</name>
    </hal>
</manifest>
"#;

        assert_eq!(
            resolve_xmls(
                ManifestKind::Device,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                &[base, rkp_override]
            )
            .unwrap(),
            None
        );
        assert_eq!(
            resolve_xmls(
                ManifestKind::Device,
                "IRemotelyProvisionedComponent",
                "default",
                &[base, rkp_override, disabled]
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn duplicate_instance_conflict_depends_on_manifest_meta_version() {
        let old_a = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>1</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        let old_b = old_a.replace("<version>1</version>", "<version>4</version>");
        assert_eq!(
            resolve_xmls(
                ManifestKind::Device,
                KEYMINT_DEVICE_INTERFACE,
                "default",
                &[old_a, &old_b]
            )
            .unwrap(),
            Some(4)
        );

        let new_a = old_a.replace("version=\"1.0\"", "version=\"6.0\"");
        let new_b = old_b.replace("version=\"1.0\"", "version=\"6.0\"");
        assert!(resolve_xmls(
            ManifestKind::Device,
            KEYMINT_DEVICE_INTERFACE,
            "default",
            &[&new_a, &new_b]
        )
        .is_err());
    }

    #[test]
    fn target_errors_are_not_replaced_by_partial_results() {
        let wrong_type = r#"
<manifest version="1.0" type="framework">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        assert!(resolve_xmls(
            ManifestKind::Device,
            KEYMINT_DEVICE_INTERFACE,
            "default",
            &[wrong_type]
        )
        .is_err());

        let invalid_version = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>1-4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;
        assert!(resolve_xmls(
            ManifestKind::Device,
            KEYMINT_DEVICE_INTERFACE,
            "default",
            &[invalid_version]
        )
        .is_err());
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "omk-vintf-{label}-{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, absolute: &str, contents: &str) {
            let path = rooted_path(&self.0, absolute);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn resolve_at(
        root: &TestRoot,
        kind: ManifestKind,
        properties: &HashMap<&str, &str>,
    ) -> Result<Option<i32>> {
        resolve_aidl_hal_version_with(
            &root.0,
            kind,
            KEYMINT_HAL_NAME,
            KEYMINT_DEVICE_INTERFACE,
            "default",
            &|name| properties.get(name).map(|value| value.to_string()),
        )
    }

    #[test]
    fn device_assembly_uses_sku_fragments_and_partitioned_active_apexes() {
        let root = TestRoot::new("device");
        root.write(
            "/vendor/etc/vintf/manifest_sku.xml",
            r#"<manifest version="1.0" type="device"><hal format="aidl"><name>android.hardware.security.keymint</name><version>1</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            VINTF_MANIFEST_FILES[3],
            r#"<manifest version="1.0" type="device"><hal format="aidl"><name>android.hardware.security.keymint</name><version>5</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            "/apex/com.vendor.keymint/etc/vintf/keymint.xml",
            r#"<manifest version="1.0" type="device"><hal format="aidl"><name>android.hardware.security.keymint</name><version>3</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            "/odm/etc/vintf/manifest/override.xml",
            r#"<manifest version="1.0" type="device"><hal format="aidl" override="true"><name>android.hardware.security.keymint</name><version>2</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            "/apex/com.odm.keymint/etc/vintf/keymint.xml",
            r#"<manifest version="1.0" type="device"><hal format="aidl" override="true"><name>android.hardware.security.keymint</name><version>4</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            crate::apex::APEX_INFO_LIST_PATH,
            r#"<apex-info-list>
    <apex-info moduleName="com.vendor.keymint" versionCode="1" isActive="true" partition="VENDOR" />
    <apex-info moduleName="com.odm.keymint" versionCode="1" isActive="true" partition="ODM" />
    <apex-info moduleName="com.inactive.keymint" versionCode="1" isActive="false" partition="ODM" />
</apex-info-list>"#,
        );

        let properties =
            HashMap::from([("ro.boot.product.vendor.sku", "sku"), ("apex.all.ready", "true")]);
        assert_eq!(resolve_at(&root, ManifestKind::Device, &properties).unwrap(), Some(4));
    }

    #[test]
    fn device_legacy_fallback_ignores_modern_fragments() {
        let root = TestRoot::new("legacy");
        root.write(
            "/vendor/manifest.xml",
            r#"<manifest version="1.0" type="device"><hal format="aidl"><name>android.hardware.security.keymint</name><version>2</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            "/vendor/etc/vintf/manifest/ignored.xml",
            r#"<manifest version="1.0" type="device"><hal format="aidl" override="true"><name>android.hardware.security.keymint</name><version>5</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );

        assert_eq!(resolve_at(&root, ManifestKind::Device, &HashMap::new()).unwrap(), Some(2));
    }

    #[test]
    fn framework_assembly_uses_bootstrap_apex_until_apex_is_ready() {
        let root = TestRoot::new("framework");
        root.write(
            VINTF_MANIFEST_FILES[0],
            r#"<manifest version="1.0" type="framework"><hal format="aidl"><name>android.hardware.security.keymint</name><version>1</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            VINTF_MANIFEST_FILES[2],
            r#"<manifest version="1.0" type="framework"><hal format="aidl"><name>android.hardware.security.keymint</name><version>2</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            "/system_ext/etc/vintf/manifest/keymint.xml",
            r#"<manifest version="1.0" type="framework"><hal format="aidl"><name>android.hardware.security.keymint</name><version>3</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            crate::apex::BOOTSTRAP_APEX_INFO_LIST_PATH,
            r#"<apex-info-list>
    <apex-info moduleName="com.android.keymint" versionCode="1" isActive="true" partition="SYSTEM" />
    <apex-info moduleName="com.vendor.ignored" versionCode="1" isActive="true" partition="VENDOR" />
</apex-info-list>"#,
        );
        root.write(
            "/bootstrap-apex/com.android.keymint/etc/vintf/keymint.xml",
            r#"<manifest version="1.0" type="framework"><hal format="aidl" override="true"><name>android.hardware.security.keymint</name><version>4</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            "/apex/com.android.keymint/etc/vintf/keymint.xml",
            r#"<manifest version="1.0" type="framework"><hal format="aidl" override="true"><name>android.hardware.security.keymint</name><version>5</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );

        assert_eq!(resolve_at(&root, ManifestKind::Framework, &HashMap::new()).unwrap(), Some(4));
    }

    #[test]
    fn framework_invalid_modern_base_falls_back_to_legacy_then_apex() {
        let root = TestRoot::new("framework-legacy");
        root.write(VINTF_MANIFEST_FILES[0], "<manifest");
        root.write(
            "/system/manifest.xml",
            r#"<manifest version="1.0" type="framework"><hal format="aidl"><name>android.hardware.security.keymint</name><version>2</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );
        root.write(
            crate::apex::BOOTSTRAP_APEX_INFO_LIST_PATH,
            r#"<apex-info-list><apex-info moduleName="com.android.keymint" versionCode="1" isActive="true" partition="SYSTEM" /></apex-info-list>"#,
        );
        root.write(
            "/bootstrap-apex/com.android.keymint/etc/vintf/keymint.xml",
            r#"<manifest version="1.0" type="framework"><hal format="aidl" override="true"><name>android.hardware.security.keymint</name><version>4</version><fqname>IKeyMintDevice/default</fqname></hal></manifest>"#,
        );

        assert_eq!(resolve_at(&root, ManifestKind::Framework, &HashMap::new()).unwrap(), Some(4));
    }
}
