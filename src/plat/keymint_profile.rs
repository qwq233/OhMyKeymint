use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use rsbinder::{hub, Strong};
use serde::Deserialize;

use crate::android::hardware::security::keymint::{
    IKeyMintDevice::IKeyMintDevice, KeyMintHardwareInfo::KeyMintHardwareInfo,
    SecurityLevel::SecurityLevel,
};

use super::resetprop;

const KEYMINT_V1: i32 = 100;
const KEYMINT_V2: i32 = 200;
const KEYMINT_V3: i32 = 300;
const KEYMINT_V4: i32 = 400;
const KEYMINT_V5: i32 = 500;
const KEYMINT_HAL_NAME: &str = "android.hardware.security.keymint";
const KEYMINT_DEVICE_INTERFACE: &str = "IKeyMintDevice";
const AOSP_AUTHOR_NAME: &str = "The Android Open Source Project";

const VINTF_MANIFEST_DIRS: &[&str] = &["/vendor/etc/vintf/manifest", "/odm/etc/vintf/manifest"];
const VINTF_MANIFEST_FILES: &[&str] = &[
    "/vendor/etc/vintf/manifest.xml",
    "/odm/etc/vintf/manifest.xml",
    "/system/etc/vintf/manifest.xml",
    "/system_ext/etc/vintf/manifest.xml",
    "/product/etc/vintf/manifest.xml",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyMintHardwareProfile {
    pub version_number: i32,
    pub impl_name: String,
    pub author_name: String,
    pub unique_id: String,
}

pub(crate) fn strongbox_keymint_present() -> bool {
    static STRONGBOX_PRESENT: OnceLock<bool> = OnceLock::new();
    *STRONGBOX_PRESENT.get_or_init(detect_strongbox_keymint_present)
}

#[derive(Debug, Deserialize)]
struct ManifestXml {
    #[serde(rename = "hal", default)]
    hals: Vec<HalXml>,
}

#[derive(Debug, Deserialize)]
struct HalXml {
    #[serde(rename = "@format")]
    format: Option<String>,
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

pub(crate) fn resolve_hardware_profile(security_level: SecurityLevel) -> KeyMintHardwareProfile {
    let version_number = probe_keymint_version_from_vintf(security_level)
        .unwrap_or_else(fallback_keymint_version_from_android);

    if let Some(profile) = resolve_property_profile_with(
        security_level,
        version_number,
        resetprop::read_string_property,
    ) {
        return profile;
    }

    match probe_system_keymint_profile(security_level, version_number) {
        Ok(profile) => profile,
        Err(error) => {
            log::warn!("Failed to resolve dynamic KeyMint hardware profile: {error:#}");
            fallback_profile(security_level, version_number)
        }
    }
}

fn detect_strongbox_keymint_present() -> bool {
    let security_level = SecurityLevel::STRONGBOX;
    if system_keymint_declared(security_level) {
        return true;
    }

    match probe_system_keymint_presence(security_level) {
        Ok(_) => true,
        Err(error) => {
            log::info!("StrongBox KeyMint HAL is not present: {error:#}");
            false
        }
    }
}

fn system_keymint_declared(security_level: SecurityLevel) -> bool {
    let Some(service) = system_keymint_service_name(security_level) else {
        return false;
    };
    hub::is_declared(service) || keymint_instance_declared_in_vintf(security_level)
}

fn resolve_property_profile_with(
    security_level: SecurityLevel,
    version_number: i32,
    read_property: impl Fn(&str) -> Option<String>,
) -> Option<KeyMintHardwareProfile> {
    resolve_property_profile_from_namespace(
        "ro.product.vendor.",
        security_level,
        version_number,
        &read_property,
    )
    .or_else(|| {
        resolve_property_profile_from_namespace(
            "ro.product.",
            security_level,
            version_number,
            &read_property,
        )
    })
}

fn resolve_property_profile_from_namespace(
    prefix: &str,
    security_level: SecurityLevel,
    version_number: i32,
    read_property: &impl Fn(&str) -> Option<String>,
) -> Option<KeyMintHardwareProfile> {
    let manufacturer = product_property(prefix, "manufacturer", read_property);
    let brand = product_property(prefix, "brand", read_property);
    let model = product_property(prefix, "model", read_property);
    let device = product_property(prefix, "device", read_property);
    let name = product_property(prefix, "name", read_property);

    let author_name = first_value([manufacturer.as_ref(), brand.as_ref()])?.to_string();
    let identity = first_value([
        device.as_ref(),
        name.as_ref(),
        model.as_ref(),
        brand.as_ref(),
    ]);
    let impl_name = build_impl_name(&author_name, identity, security_level);
    let unique_id = derive_unique_id(&author_name, &impl_name, security_level, version_number)?;

    Some(KeyMintHardwareProfile {
        version_number,
        impl_name,
        author_name,
        unique_id,
    })
}

fn product_property(
    prefix: &str,
    name: &str,
    read_property: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    read_property(&format!("{prefix}{name}")).and_then(clean_dynamic_value)
}

fn clean_dynamic_value(value: String) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "unknown" | "unavailable" | "null" | "n/a") {
        return None;
    }

    Some(value.to_string())
}

fn first_value<const N: usize>(values: [Option<&String>; N]) -> Option<&str> {
    values.into_iter().flatten().map(String::as_str).next()
}

fn build_impl_name(
    author_name: &str,
    identity: Option<&str>,
    security_level: SecurityLevel,
) -> String {
    let mut parts = vec![author_name.to_string()];
    if let Some(identity) = identity {
        if !starts_with_ignore_ascii_case(identity, author_name) {
            parts.push(identity.to_string());
        }
    }
    parts.push(security_level_label(security_level).to_string());
    parts.push("KeyMint".to_string());
    parts.join(" ")
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn probe_system_keymint_profile(
    security_level: SecurityLevel,
    version_number: i32,
) -> Result<KeyMintHardwareProfile> {
    let info = probe_system_keymint_hardware_info(security_level)?;
    profile_from_system_hardware_info(&info, security_level, version_number)
}

fn probe_system_keymint_presence(security_level: SecurityLevel) -> Result<()> {
    let info = probe_system_keymint_hardware_info(security_level)?;
    ensure_system_hardware_security_level(&info, security_level)
}

fn probe_system_keymint_hardware_info(
    security_level: SecurityLevel,
) -> Result<KeyMintHardwareInfo> {
    let service = system_keymint_service_name(security_level)
        .ok_or_else(|| anyhow!("unsupported security level for system KeyMint probe"))?;
    let keymint: Strong<dyn IKeyMintDevice> =
        hub::get_interface(service).with_context(|| format!("connect {service}"))?;
    if keymint.as_binder().as_proxy().is_none() {
        bail!("system KeyMint service {service} resolved to a local binder");
    }

    let info = keymint
        .getHardwareInfo()
        .map_err(|status| anyhow!("getHardwareInfo from {service} failed: {status}"))?;
    Ok(info)
}

fn profile_from_system_hardware_info(
    info: &KeyMintHardwareInfo,
    security_level: SecurityLevel,
    version_number: i32,
) -> Result<KeyMintHardwareProfile> {
    ensure_system_hardware_security_level(info, security_level)?;

    let impl_name = clean_dynamic_value(info.keyMintName.clone())
        .ok_or_else(|| anyhow!("system KeyMint returned an empty implementation name"))?;
    let author_name = clean_dynamic_value(info.keyMintAuthorName.clone())
        .ok_or_else(|| anyhow!("system KeyMint returned an empty author name"))?;
    let unique_id = derive_unique_id(&author_name, &impl_name, security_level, version_number)
        .ok_or_else(|| anyhow!("failed to derive KeyMint unique id"))?;

    Ok(KeyMintHardwareProfile {
        version_number,
        impl_name,
        author_name,
        unique_id,
    })
}

fn ensure_system_hardware_security_level(
    info: &KeyMintHardwareInfo,
    security_level: SecurityLevel,
) -> Result<()> {
    if info.securityLevel != security_level {
        bail!(
            "system KeyMint security level mismatch: expected {:?}, got {:?}",
            security_level,
            info.securityLevel
        );
    }

    Ok(())
}

fn system_keymint_service_name(security_level: SecurityLevel) -> Option<&'static str> {
    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            Some("android.hardware.security.keymint.IKeyMintDevice/default")
        }
        SecurityLevel::STRONGBOX => {
            Some("android.hardware.security.keymint.IKeyMintDevice/strongbox")
        }
        _ => None,
    }
}

fn probe_keymint_version_from_vintf(security_level: SecurityLevel) -> Option<i32> {
    let instance = security_level_instance(security_level)?;

    for path in vintf_manifest_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        match parse_keymint_version_xml(&contents, instance) {
            Ok(Some(version)) => return Some(version),
            Ok(None) => {}
            Err(error) => {
                log::warn!(
                    "Ignoring invalid VINTF manifest {}: {error:#}",
                    path.display()
                );
            }
        }
    }

    None
}

fn keymint_instance_declared_in_vintf(security_level: SecurityLevel) -> bool {
    let Some(instance) = security_level_instance(security_level) else {
        return false;
    };

    for path in vintf_manifest_paths() {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        match parse_keymint_instance_xml(&contents, instance) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(error) => {
                log::warn!(
                    "Ignoring invalid VINTF manifest {}: {error:#}",
                    path.display()
                );
            }
        }
    }

    false
}

fn vintf_manifest_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for directory in VINTF_MANIFEST_DIRS {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("xml") {
                paths.push(path);
            }
        }
    }
    for file in VINTF_MANIFEST_FILES {
        paths.push(PathBuf::from(file));
    }
    paths
}

fn parse_keymint_version_xml(xml: &str, instance: &str) -> Result<Option<i32>> {
    let manifest: ManifestXml =
        quick_xml::de::from_str(xml).context("failed to deserialize VINTF XML")?;
    for hal in manifest.hals {
        if !hal.references_keymint_device_instance(instance) {
            continue;
        }

        for version in hal.versions {
            let version = version
                .trim()
                .parse::<i32>()
                .with_context(|| format!("invalid KeyMint VINTF version {version:?}"))?;
            if let Some(version) = normalize_keymint_version(version) {
                return Ok(Some(version));
            }
        }
    }

    Ok(None)
}

fn parse_keymint_instance_xml(xml: &str, instance: &str) -> Result<bool> {
    let manifest: ManifestXml =
        quick_xml::de::from_str(xml).context("failed to deserialize VINTF XML")?;
    Ok(manifest
        .hals
        .iter()
        .any(|hal| hal.references_keymint_device_instance(instance)))
}

impl HalXml {
    fn references_keymint_device_instance(&self, instance: &str) -> bool {
        self.format
            .as_deref()
            .is_some_and(|format| format.trim() == "aidl")
            && self.name.as_deref().map(str::trim) == Some(KEYMINT_HAL_NAME)
            && self.references_instance(KEYMINT_DEVICE_INTERFACE, instance)
    }

    fn references_instance(&self, interface: &str, instance: &str) -> bool {
        let fqname = format!("{interface}/{instance}");
        self.fqnames
            .iter()
            .any(|candidate| candidate.trim() == fqname)
            || self.interfaces.iter().any(|candidate| {
                candidate.name.as_deref().map(str::trim) == Some(interface)
                    && candidate
                        .instances
                        .iter()
                        .any(|candidate| candidate.trim() == instance)
            })
    }
}

fn fallback_keymint_version_from_android() -> i32 {
    match detect_android_major_version() {
        Some(version) if version >= 16 => KEYMINT_V4, // TODO: still use V4 until V5 is implemented upstream.
        Some(14 | 15) => KEYMINT_V3,
        Some(13) => KEYMINT_V2,
        Some(12) => KEYMINT_V1,
        _ => KEYMINT_V4,
    }
}

fn detect_android_major_version() -> Option<i32> {
    kmr_common::android_version::android_major_version()
}

#[cfg(test)]
fn detect_android_major_version_with(
    read_property: impl Fn(&str) -> Option<String>,
) -> Option<i32> {
    kmr_common::android_version::android_major_version_with(read_property)
}

fn normalize_keymint_version(version: i32) -> Option<i32> {
    match version {
        1..=5 => Some(version * 100),
        KEYMINT_V1 | KEYMINT_V2 | KEYMINT_V3 | KEYMINT_V4 | KEYMINT_V5 => Some(version),
        _ => None,
    }
}

fn fallback_profile(security_level: SecurityLevel, version_number: i32) -> KeyMintHardwareProfile {
    let line = version_number / 100;
    let sec_label = security_level_label(security_level);
    KeyMintHardwareProfile {
        version_number,
        impl_name: format!("Android {sec_label} KeyMint {line}"),
        author_name: AOSP_AUTHOR_NAME.to_string(),
        unique_id: format!("android-{sec_label}-keymint-{line}"),
    }
}

fn derive_unique_id(
    author_name: &str,
    impl_name: &str,
    security_level: SecurityLevel,
    version_number: i32,
) -> Option<String> {
    let input = format!("{author_name}\n{impl_name}\n{security_level:?}\n{version_number}");
    let digest = BoringSha256 {}.hash(input.as_bytes()).ok()?;
    let digest = hex::encode(&digest[..6]);
    Some(format!(
        "keymint-{}-{}-{digest}",
        security_level_slug(security_level),
        version_number / 100
    ))
}

fn security_level_instance(security_level: SecurityLevel) -> Option<&'static str> {
    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => Some("default"),
        SecurityLevel::STRONGBOX => Some("strongbox"),
        _ => None,
    }
}

fn security_level_label(security_level: SecurityLevel) -> &'static str {
    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => "TEE",
        SecurityLevel::STRONGBOX => "StrongBox",
        SecurityLevel::SOFTWARE => "Software",
        _ => "Unknown",
    }
}

fn security_level_slug(security_level: SecurityLevel) -> &'static str {
    match security_level {
        SecurityLevel::TRUSTED_ENVIRONMENT => "tee",
        SecurityLevel::STRONGBOX => "strongbox",
        SecurityLevel::SOFTWARE => "software",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn property_reader<'a>(
        values: &'a HashMap<&'a str, &'a str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| values.get(name).map(|value| value.to_string())
    }

    #[test]
    fn property_profile_prefers_vendor_properties() {
        let values = HashMap::from([
            ("ro.product.manufacturer", "ProductCorp"),
            ("ro.product.brand", "ProductBrand"),
            ("ro.product.vendor.brand", "VendorCorp"),
            ("ro.product.model", "ProductModel"),
            ("ro.product.vendor.device", "VendorDevice"),
        ]);

        let profile = resolve_property_profile_with(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            KEYMINT_V4,
            property_reader(&values),
        )
        .unwrap();

        assert_eq!(profile.author_name, "VendorCorp");
        assert_eq!(profile.impl_name, "VendorCorp VendorDevice TEE KeyMint");
        assert_eq!(profile.version_number, KEYMINT_V4);
    }

    #[test]
    fn property_profile_prefers_device_over_model_and_name() {
        let values = HashMap::from([
            ("ro.product.vendor.brand", "Pixel"),
            ("ro.product.vendor.name", "pixel-9-pro"),
            ("ro.product.vendor.model", "Pixel 9 Pro XL"),
            ("ro.product.vendor.device", "akita"),
        ]);

        let profile = resolve_property_profile_with(
            SecurityLevel::STRONGBOX,
            KEYMINT_V4,
            property_reader(&values),
        )
        .unwrap();

        assert_eq!(profile.author_name, "Pixel");
        assert_eq!(profile.impl_name, "Pixel akita StrongBox KeyMint");
    }

    #[test]
    fn fallback_profile_preserves_legacy_strings() {
        let tee = fallback_profile(SecurityLevel::TRUSTED_ENVIRONMENT, KEYMINT_V4);
        let strongbox = fallback_profile(SecurityLevel::STRONGBOX, KEYMINT_V4);

        assert_eq!(tee.impl_name, "Android TEE KeyMint 4");
        assert_eq!(tee.author_name, AOSP_AUTHOR_NAME);
        assert_eq!(tee.unique_id, "android-TEE-keymint-4");
        assert_eq!(strongbox.impl_name, "Android StrongBox KeyMint 4");
        assert_eq!(strongbox.author_name, AOSP_AUTHOR_NAME);
        assert_eq!(strongbox.unique_id, "android-StrongBox-keymint-4");
    }

    #[test]
    fn unique_id_is_stable_ascii_bounded_and_security_level_specific() {
        let values = HashMap::from([
            ("ro.product.vendor.manufacturer", "Google"),
            ("ro.product.vendor.model", "Pixel 9"),
        ]);
        let tee = resolve_property_profile_with(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            KEYMINT_V4,
            property_reader(&values),
        )
        .unwrap();
        let tee_again = resolve_property_profile_with(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            KEYMINT_V4,
            property_reader(&values),
        )
        .unwrap();
        let strongbox = resolve_property_profile_with(
            SecurityLevel::STRONGBOX,
            KEYMINT_V4,
            property_reader(&values),
        )
        .unwrap();

        assert_eq!(tee.unique_id, tee_again.unique_id);
        assert_ne!(tee.unique_id, strongbox.unique_id);
        assert!(tee.unique_id.len() <= 32);
        assert!(strongbox.unique_id.len() <= 32);
        assert!(tee.unique_id.is_ascii());
        assert!(strongbox.unique_id.is_ascii());
    }

    #[test]
    fn vintf_parser_matches_default_and_strongbox_instances() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <version>3</version>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert_eq!(
            parse_keymint_version_xml(xml, "default").unwrap(),
            Some(400)
        );
        assert_eq!(
            parse_keymint_version_xml(xml, "strongbox").unwrap(),
            Some(300)
        );
        assert!(parse_keymint_instance_xml(xml, "default").unwrap());
        assert!(parse_keymint_instance_xml(xml, "strongbox").unwrap());
        assert!(!parse_keymint_instance_xml(xml, "foo").unwrap());
    }

    #[test]
    fn vintf_instance_parser_does_not_require_version() {
        let xml = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.security.keymint</name>
        <interface>
            <name>IKeyMintDevice</name>
            <instance>strongbox</instance>
        </interface>
    </hal>
</manifest>
"#;

        assert!(parse_keymint_instance_xml(xml, "strongbox").unwrap());
    }

    #[test]
    fn vintf_parser_ignores_unrelated_hals_and_rejects_malformed_xml() {
        let unrelated = r#"
<manifest version="1.0" type="device">
    <hal format="aidl">
        <name>android.hardware.foo</name>
        <version>4</version>
        <fqname>IKeyMintDevice/default</fqname>
    </hal>
</manifest>
"#;

        assert_eq!(
            parse_keymint_version_xml(unrelated, "default").unwrap(),
            None
        );
        assert!(parse_keymint_version_xml("<manifest>", "default").is_err());
    }

    #[test]
    fn keymint_version_normalization_allows_known_versions_only() {
        assert_eq!(normalize_keymint_version(1), Some(100));
        assert_eq!(normalize_keymint_version(4), Some(400));
        assert_eq!(normalize_keymint_version(100), Some(100));
        assert_eq!(normalize_keymint_version(400), Some(400));
        assert_eq!(normalize_keymint_version(999), None);
    }

    #[test]
    fn android_major_version_uses_sdk_when_release_is_codename() {
        let values = HashMap::from([
            ("ro.build.version.release_or_codename", "Baklava"),
            ("ro.build.version.sdk", "36"),
        ]);

        assert_eq!(
            detect_android_major_version_with(property_reader(&values)),
            Some(16)
        );
    }

    #[test]
    fn system_hardware_info_keeps_canonical_version() {
        let info = KeyMintHardwareInfo {
            versionNumber: 999,
            securityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            keyMintName: "VendorKeyMint".to_string(),
            keyMintAuthorName: "Vendor".to_string(),
            timestampTokenRequired: false,
        };

        let profile = profile_from_system_hardware_info(
            &info,
            SecurityLevel::TRUSTED_ENVIRONMENT,
            KEYMINT_V4,
        )
        .unwrap();

        assert_eq!(profile.version_number, KEYMINT_V4);
        assert_eq!(profile.impl_name, "VendorKeyMint");
        assert_eq!(profile.author_name, "Vendor");
    }

    #[test]
    fn system_hardware_info_rejects_empty_names_and_mismatched_security_level() {
        let empty = KeyMintHardwareInfo {
            versionNumber: 4,
            securityLevel: SecurityLevel::TRUSTED_ENVIRONMENT,
            keyMintName: " ".to_string(),
            keyMintAuthorName: "Vendor".to_string(),
            timestampTokenRequired: false,
        };
        assert!(profile_from_system_hardware_info(
            &empty,
            SecurityLevel::TRUSTED_ENVIRONMENT,
            KEYMINT_V4
        )
        .is_err());

        let mismatched = KeyMintHardwareInfo {
            keyMintName: "VendorKeyMint".to_string(),
            keyMintAuthorName: "Vendor".to_string(),
            securityLevel: SecurityLevel::STRONGBOX,
            ..empty
        };
        assert!(profile_from_system_hardware_info(
            &mismatched,
            SecurityLevel::TRUSTED_ENVIRONMENT,
            KEYMINT_V4
        )
        .is_err());
    }

    #[test]
    fn system_hardware_presence_only_checks_security_level() {
        let info = KeyMintHardwareInfo {
            versionNumber: 999,
            securityLevel: SecurityLevel::STRONGBOX,
            keyMintName: String::new(),
            keyMintAuthorName: String::new(),
            timestampTokenRequired: false,
        };

        assert!(ensure_system_hardware_security_level(&info, SecurityLevel::STRONGBOX).is_ok());
        assert!(
            profile_from_system_hardware_info(&info, SecurityLevel::STRONGBOX, KEYMINT_V4).is_err()
        );
    }
}
