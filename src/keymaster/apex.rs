use std::{cmp::Ordering, collections::BTreeSet, fs, path::Path};

use anyhow::{bail, Context, Result};
use der::{
    asn1::{OctetString, SetOfVec},
    DerOrd, Encode, Sequence,
};
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use serde::Deserialize;

pub const APEX_INFO_LIST_PATH: &str = "/apex/apex-info-list.xml";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleInfoSource {
    ApexInfoList,
    ApexService,
}

impl ModuleInfoSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApexInfoList => "apex-info-list.xml",
            Self::ApexService => "apexservice",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleInfoBundle {
    pub modules: Vec<ApexModuleInfo>,
    pub encoded_der: Vec<u8>,
    pub sha256: Vec<u8>,
    pub source: ModuleInfoSource,
}

#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct ApexModuleInfo {
    pub package_name: OctetString,
    pub version_code: u64,
}

impl DerOrd for ApexModuleInfo {
    // DER mandates "encodings of the component values of a set-of value shall appear in ascending
    // order". `der_cmp` serves as a proxy for determining that ordering (though why the `der` crate
    // requires this is unclear). Essentially, we just need to compare the `name` lengths, and then
    // if those are equal, the `name`s themselves. (No need to consider `version`s since there can't
    // be more than one `ModuleInfo` with the same `name` in the set-of `ModuleInfo`s.) We rely on
    // `OctetString`'s `der_cmp` to do the aforementioned comparison.
    fn der_cmp(&self, other: &Self) -> std::result::Result<Ordering, der::Error> {
        self.package_name.der_cmp(&other.package_name)
    }
}

impl ModuleInfoBundle {
    pub fn from_modules(modules: Vec<ApexModuleInfo>, source: ModuleInfoSource) -> Result<Self> {
        if modules.is_empty() {
            bail!("no active APEX modules available");
        }

        let encoded_der =
            encode_module_info(&modules).context("failed to DER-encode active APEX modules")?;
        let sha256 = BoringSha256 {}
            .hash(&encoded_der)
            .map_err(|e| anyhow::anyhow!("failed to hash DER-encoded APEX modules: {e:?}"))?
            .to_vec();

        Ok(Self {
            modules,
            encoded_der,
            sha256,
            source,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ApexInfoListXml {
    #[serde(rename = "apex-info", default)]
    apex_infos: Vec<ApexInfoXml>,
}

#[derive(Debug, Deserialize)]
struct ApexInfoXml {
    #[serde(rename = "@moduleName")]
    module_name: String,
    #[serde(rename = "@versionCode")]
    version_code: String,
    #[serde(rename = "@isActive")]
    is_active: bool,
}

pub fn resolve_module_info_bundle() -> Result<ModuleInfoBundle> {
    match load_apex_info_list(APEX_INFO_LIST_PATH) {
        Ok(modules) => ModuleInfoBundle::from_modules(modules, ModuleInfoSource::ApexInfoList),
        Err(file_error) => {
            log::warn!(
                "Failed to read active APEX modules from {}: {file_error:#}; falling back to apexservice",
                APEX_INFO_LIST_PATH
            );
            let modules = crate::plat::utils::get_apex_module_info()
                .context("failed to resolve active APEX modules from apexservice")?;
            ModuleInfoBundle::from_modules(modules, ModuleInfoSource::ApexService)
        }
    }
}

pub fn load_apex_info_list<P: AsRef<Path>>(path: P) -> Result<Vec<ApexModuleInfo>> {
    let path = path.as_ref();
    let xml =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    parse_active_modules_xml(&xml).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn parse_active_modules_xml(xml: &str) -> Result<Vec<ApexModuleInfo>> {
    let parsed: ApexInfoListXml =
        quick_xml::de::from_str(xml).context("failed to deserialize apex-info-list XML")?;

    let mut seen_names = BTreeSet::new();
    let mut modules = Vec::new();
    for apex_info in parsed.apex_infos {
        if !apex_info.is_active {
            continue;
        }

        let module_name = apex_info.module_name.trim();
        if module_name.is_empty() {
            bail!("active APEX entry is missing moduleName");
        }
        if !seen_names.insert(module_name.to_owned()) {
            bail!("duplicate active APEX module name: {module_name}");
        }

        let version_code = apex_info
            .version_code
            .trim()
            .parse::<u64>()
            .with_context(|| format!("invalid versionCode for active module {module_name}"))?;

        modules.push(ApexModuleInfo {
            package_name: OctetString::new(module_name.as_bytes())
                .context("invalid APEX module name bytes")?,
            version_code,
        });
    }

    if modules.is_empty() {
        bail!("apex-info-list did not contain any active modules");
    }

    Ok(modules)
}

pub fn encode_module_info(module_info: &[ApexModuleInfo]) -> Result<Vec<u8>, der::Error> {
    SetOfVec::<ApexModuleInfo>::from_iter(module_info.iter().cloned())?.to_der()
}

#[cfg(test)]
mod tests {
    use super::{parse_active_modules_xml, ApexModuleInfo, ModuleInfoBundle, ModuleInfoSource};
    use kmr_common::crypto::Sha256;
    use kmr_crypto_boring::sha256::BoringSha256;

    fn test_module(name: &str, version: u64) -> ApexModuleInfo {
        ApexModuleInfo {
            package_name: der::asn1::OctetString::new(name.as_bytes()).unwrap(),
            version_code: version,
        }
    }

    #[test]
    fn parses_active_modules_only() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<apex-info-list>
    <apex-info moduleName="com.android.alpha" versionCode="1" isActive="true" />
    <apex-info moduleName="com.android.beta" versionCode="2" isActive="false" />
    <apex-info moduleName="com.android.gamma" versionCode="3" isActive="true" />
</apex-info-list>"#;

        let modules = parse_active_modules_xml(xml).unwrap();

        assert_eq!(
            modules,
            vec![
                test_module("com.android.alpha", 1),
                test_module("com.android.gamma", 3)
            ]
        );
    }

    #[test]
    fn rejects_duplicate_active_module_names() {
        let xml = r#"<apex-info-list>
    <apex-info moduleName="com.android.alpha" versionCode="1" isActive="true" />
    <apex-info moduleName="com.android.alpha" versionCode="2" isActive="true" />
</apex-info-list>"#;

        let error = parse_active_modules_xml(xml).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate active APEX module name"));
    }

    #[test]
    fn rejects_invalid_version_code() {
        let xml = r#"<apex-info-list>
    <apex-info moduleName="com.android.alpha" versionCode="NaN" isActive="true" />
</apex-info-list>"#;

        let error = parse_active_modules_xml(xml).unwrap_err();
        assert!(format!("{error:#}").contains("invalid versionCode"));
    }

    #[test]
    fn rejects_empty_active_module_set() {
        let xml = r#"<apex-info-list>
    <apex-info moduleName="com.android.alpha" versionCode="1" isActive="false" />
</apex-info-list>"#;

        let error = parse_active_modules_xml(xml).unwrap_err();
        assert!(format!("{error:#}").contains("did not contain any active modules"));
    }

    #[test]
    fn bundle_der_and_hash_match() {
        let bundle = ModuleInfoBundle::from_modules(
            vec![
                test_module("com.android.beta", 2),
                test_module("com.android.alpha", 1),
            ],
            ModuleInfoSource::ApexInfoList,
        )
        .unwrap();

        let expected_hash = BoringSha256 {}.hash(&bundle.encoded_der).unwrap();
        assert_eq!(bundle.sha256, expected_hash.to_vec());
        assert_eq!(bundle.source, ModuleInfoSource::ApexInfoList);
    }
}
