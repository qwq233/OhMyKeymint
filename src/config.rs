use std::{
    fs,
    io::Write,
    path::Path,
    sync::{OnceLock, RwLock},
};

use anyhow::{anyhow, Context, Result};
use hotwatch::Hotwatch;
use kmr_common::crypto::Rng;
use kmr_crypto_boring::rng::BoringRng;
use serde::{ser::SerializeStruct, Deserialize, Serialize};

pub static CONFIG: OnceLock<RwLock<Config>> = OnceLock::new();
static CONFIG_WATCHER_STARTED: OnceLock<()> = OnceLock::new();

#[cfg(target_os = "android")]
const CONFIG_PATH: &str = "/data/misc/keystore/omk/config.toml";

#[cfg(not(target_os = "android"))]
const CONFIG_PATH: &str = "./omk/config.toml";

pub fn config() -> &'static RwLock<Config> {
    CONFIG
        .get()
        .expect("CONFIG must be bootstrapped before use")
}

pub fn config_path() -> &'static str {
    CONFIG_PATH
}

pub fn bootstrap_config_file() -> Result<ConfigFile> {
    match fs::read_to_string(CONFIG_PATH) {
        Ok(contents) => match parse_config_file(&contents) {
            Ok(config_file) => Ok(config_file),
            Err(error) => {
                log::error!("Failed to parse config file, repairing: {error:#}");
                let config_file = ConfigFile::default();
                rewrite_invalid_config(&config_file, &format!("{error:#}"))?;
                Ok(config_file)
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let config_file = ConfigFile::default();
            persist_config_file(&config_file)?;
            Ok(config_file)
        }
        Err(error) => {
            log::error!("Failed to read config file, repairing: {error:#}");
            let config_file = ConfigFile::default();
            rewrite_invalid_config(&config_file, &format!("{error:#}"))?;
            Ok(config_file)
        }
    }
}

pub fn persist_config_file(config_file: &ConfigFile) -> Result<()> {
    let path = Path::new(CONFIG_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("config path has no parent: {}", CONFIG_PATH))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    let serialized =
        toml::to_string_pretty(config_file).context("failed to serialize config.toml")?;
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == serialized {
            log::debug!("Config file unchanged, skipping rewrite");
            return Ok(());
        }
    }
    fs::write(path, serialized)
        .with_context(|| format!("failed to write config file {}", path.display()))?;
    Ok(())
}

pub fn install_runtime_config(
    config_file: ConfigFile,
    resolved_trust: ResolvedTrust,
) -> Result<()> {
    let runtime = Config::from_file(&config_file, resolved_trust);
    if CONFIG.set(RwLock::new(runtime.clone())).is_err() {
        let mut guard = config()
            .write()
            .map_err(|_| anyhow!("config lock poisoned while installing runtime config"))?;
        *guard = runtime;
    }
    start_config_watcher()?;
    Ok(())
}

fn parse_config_file(contents: &str) -> Result<ConfigFile> {
    let config_file: ConfigFile =
        toml::from_str(contents).context("failed to deserialize config.toml")?;
    validate_security_patch(&config_file.trust.security_patch)
        .context("invalid trust.security_patch")?;
    Ok(config_file)
}

fn rewrite_invalid_config(replacement: &ConfigFile, reason: &str) -> Result<()> {
    backup_existing_config(reason)?;
    persist_config_file(replacement)?;
    Ok(())
}

fn backup_existing_config(reason: &str) -> Result<()> {
    let path = Path::new(CONFIG_PATH);
    if !path.exists() {
        return Ok(());
    }

    let backup_path = format!("{CONFIG_PATH}.bak");
    let backup = Path::new(&backup_path);
    if backup.exists() {
        fs::remove_file(backup)
            .with_context(|| format!("failed to remove stale backup {}", backup.display()))?;
    }

    fs::rename(path, backup)
        .or_else(|rename_error| {
            fs::copy(path, backup)
                .with_context(|| {
                    format!(
                        "failed to copy invalid config to backup {} after rename error {rename_error}",
                        backup.display()
                    )
                })
                .and_then(|_| {
                    fs::remove_file(path).with_context(|| {
                        format!("failed to remove original config {}", path.display())
                    })
                })
        })
        .with_context(|| format!("failed to move invalid config to {}", backup.display()))?;

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(backup)
        .with_context(|| format!("failed to open backup {}", backup.display()))?;
    writeln!(file)?;
    writeln!(file, "# OMK config recovery reason:")?;
    for line in reason.lines() {
        writeln!(file, "# {line}")?;
    }
    Ok(())
}

fn start_config_watcher() -> Result<()> {
    if CONFIG_WATCHER_STARTED.set(()).is_err() {
        return Ok(());
    }

    std::thread::spawn(|| {
        let mut watcher = match Hotwatch::new() {
            Ok(watcher) => watcher,
            Err(error) => {
                log::error!("Failed to start config watcher: {error:?}");
                return;
            }
        };

        if let Err(error) = watcher.watch(CONFIG_PATH, |event| {
            log::info!("Config file changed: {:?}", event);
            let contents = match fs::read_to_string(CONFIG_PATH) {
                Ok(contents) => contents,
                Err(error) => {
                    log::error!("Failed to read config file after change, ignoring: {error:?}");
                    return;
                }
            };

            let new_config_file = match parse_config_file(&contents) {
                Ok(config_file) => config_file,
                Err(error) => {
                    log::error!("Failed to parse changed config file, ignoring: {error:#}");
                    return;
                }
            };

            let mut runtime = match config().write() {
                Ok(runtime) => runtime,
                Err(_) => {
                    log::error!("Config lock poisoned while handling config change");
                    return;
                }
            };

            if runtime.trust_intent != new_config_file.trust {
                log::warn!(
                    "Trust config changed on disk; restart keymint to apply vbmeta changes."
                );
            }

            if runtime.crypto != new_config_file.crypto {
                log::warn!("Crypto config changed on disk; restart keymint to apply seed changes.");
            }

            let resolved_trust = runtime.trust.clone();
            *runtime = Config::from_file(&new_config_file, resolved_trust);
            log::info!("Config updated");
        }) {
            log::error!("Failed to watch config file: {error:?}");
            return;
        }

        loop {
            std::thread::park();
        }
    });

    Ok(())
}

fn validate_security_patch(value: &str) -> Result<()> {
    let is_valid = regex::Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$")
        .expect("security patch regex must compile")
        .is_match(value);
    if is_valid {
        Ok(())
    } else {
        Err(anyhow!("security_patch must be in YYYY-MM-DD format"))
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub main: MainConfig,
    pub crypto: CryptoConfig,
    pub trust: ResolvedTrust,
    pub trust_record: TrustRecord,
    pub device: DeviceProperty,
    trust_intent: RawTrustConfig,
}

impl Config {
    fn from_file(config_file: &ConfigFile, resolved_trust: ResolvedTrust) -> Self {
        Self {
            main: config_file.main.clone(),
            crypto: config_file.crypto.clone(),
            trust: resolved_trust,
            trust_record: config_file.trust_record.clone(),
            device: config_file.device.clone(),
            trust_intent: config_file.trust.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    pub main: MainConfig,
    pub crypto: CryptoConfig,
    pub trust: RawTrustConfig,
    #[serde(default, skip_serializing_if = "TrustRecord::is_empty")]
    pub trust_record: TrustRecord,
    pub device: DeviceProperty,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Backend {
    Injector,
    OMK,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Injector => write!(f, "injector"),
            Backend::OMK => write!(f, "omk"),
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ts" => Ok(Backend::Injector),
            "omk" => Ok(Backend::OMK),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MainConfig {
    /// default to tricky store for compatibility, we will
    /// switch to omk later when we are sure everything works
    pub backend: Backend,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Injector,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoConfig {
    pub root_kek_seed: [u8; 32],
    pub kak_seed: [u8; 32],
}

impl Serialize for CryptoConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("CryptoConfig", 2)?;
        state.serialize_field("root_kek_seed", &hex::encode(self.root_kek_seed))?;
        state.serialize_field("kak_seed", &hex::encode(self.kak_seed))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CryptoConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct CryptoConfigHelper {
            root_kek_seed: String,
            kak_seed: String,
        }

        let helper = CryptoConfigHelper::deserialize(deserializer)?;
        let root_kek_seed = hex::decode(&helper.root_kek_seed).map_err(serde::de::Error::custom)?;
        let kak_seed = hex::decode(&helper.kak_seed).map_err(serde::de::Error::custom)?;

        if root_kek_seed.len() != 32 {
            return Err(serde::de::Error::custom("root_kek_seed must be 32 bytes"));
        }
        if kak_seed.len() != 32 {
            return Err(serde::de::Error::custom("kak_seed must be 32 bytes"));
        }

        let mut root_kek_array = [0u8; 32];
        root_kek_array.copy_from_slice(&root_kek_seed);

        let mut kak_array = [0u8; 32];
        kak_array.copy_from_slice(&kak_seed);

        Ok(CryptoConfig {
            root_kek_seed: root_kek_array,
            kak_seed: kak_array,
        })
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        let mut rng = BoringRng {};
        Self {
            root_kek_seed: {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                key
            },
            kak_seed: {
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                key
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTrust {
    pub os_version: i32,
    pub security_patch: String,
    pub vb_key: [u8; 32],
    pub vb_hash: [u8; 32],
    pub vb_key_source: TrustValueSource,
    pub vb_hash_source: TrustValueSource,
    pub verified_boot_state: bool,
    pub device_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawTrustConfig {
    pub os_version: i32,
    pub security_patch: String,
    #[serde(default)]
    pub vb_key: TrustValueSpec,
    #[serde(default)]
    pub vb_hash: TrustValueSpec,
    pub verified_boot_state: bool,
    pub device_locked: bool,
}

impl Default for RawTrustConfig {
    fn default() -> Self {
        Self {
            os_version: rsproperties::get_or("ro.build.version.release", 35 /* Android 15 */),
            security_patch: rsproperties::get_or(
                "ro.build.version.security_patch",
                "2024-01-05".to_string(),
            ),
            vb_key: TrustValueSpec::Auto,
            vb_hash: TrustValueSpec::Auto,
            verified_boot_state: true,
            device_locked: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustValueSpec {
    Auto,
    Random,
    Hex([u8; 32]),
}

impl Default for TrustValueSpec {
    fn default() -> Self {
        Self::Auto
    }
}

impl Serialize for TrustValueSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            TrustValueSpec::Auto => serializer.serialize_str("auto"),
            TrustValueSpec::Random => serializer.serialize_str("random"),
            TrustValueSpec::Hex(bytes) => serializer.serialize_str(&hex::encode(bytes)),
        }
    }
}

impl<'de> Deserialize<'de> for TrustValueSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        match raw.trim() {
            "auto" => Ok(TrustValueSpec::Auto),
            "random" => Ok(TrustValueSpec::Random),
            candidate => {
                let decoded = hex::decode(candidate).map_err(serde::de::Error::custom)?;
                if decoded.len() != 32 {
                    return Err(serde::de::Error::custom(
                        "vb_key/vb_hash hex values must be exactly 32 bytes",
                    ));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&decoded);
                Ok(TrustValueSpec::Hex(bytes))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustValueSource {
    ExplicitHex,
    Property,
    Computed,
    Original,
    RandomExplicit,
    RandomFallback,
}

impl std::fmt::Display for TrustValueSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustValueSource::ExplicitHex => write!(f, "explicit_hex"),
            TrustValueSource::Property => write!(f, "property"),
            TrustValueSource::Computed => write!(f, "computed"),
            TrustValueSource::Original => write!(f, "original"),
            TrustValueSource::RandomExplicit => write!(f, "random_explicit"),
            TrustValueSource::RandomFallback => write!(f, "random_fallback"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vb_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vb_key_source: Option<TrustValueSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vb_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vb_hash_source: Option<TrustValueSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_suffix: Option<String>,
}

impl TrustRecord {
    pub fn is_empty(&self) -> bool {
        self.vb_key.is_none()
            && self.vb_key_source.is_none()
            && self.vb_hash.is_none()
            && self.vb_hash_source.is_none()
            && self.build_fingerprint.is_none()
            && self.slot_suffix.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceProperty {
    pub brand: String,
    pub device: String,
    pub product: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    #[serde(rename = "overrideTelephonyProperties", default)]
    pub override_telephony_properties: bool,
    pub meid: String,
    pub imei: String,
    pub imei2: String,
}

impl Default for DeviceProperty {
    fn default() -> Self {
        Self {
            brand: rsproperties::get_or("ro.product.brand", "google".to_string()),
            device: rsproperties::get_or("ro.product.device", "generic".to_string()),
            product: rsproperties::get_or("ro.product.name", "mainline".to_string()),
            manufacturer: rsproperties::get_or("ro.product.manufacturer", "google".to_string()),
            model: rsproperties::get_or("ro.product.model", "mainline".to_string()),
            serial: rsproperties::get_or("ro.serialno", "f7bade12".to_string()),
            override_telephony_properties: false,
            meid: String::new(),
            imei: String::new(),
            imei2: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_value_spec_parses_tokens_and_hex() {
        let parsed: TrustValueSpec = toml::from_str::<TrustValueToml>("value = \"auto\"")
            .unwrap_or_else(|_| panic!("toml helper should parse"))
            .value;
        assert_eq!(parsed, TrustValueSpec::Auto);

        let parsed: TrustValueSpec = toml::from_str::<TrustValueToml>("value = \"random\"")
            .unwrap_or_else(|_| panic!("toml helper should parse"))
            .value;
        assert_eq!(parsed, TrustValueSpec::Random);

        let parsed: TrustValueSpec = toml::from_str::<TrustValueToml>(
            "value = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"",
        )
        .unwrap_or_else(|_| panic!("toml helper should parse"))
        .value;
        assert!(matches!(parsed, TrustValueSpec::Hex(_)));
    }

    #[test]
    fn trust_value_spec_serializes_tokens() {
        #[derive(Serialize)]
        struct Wrapper {
            value: TrustValueSpec,
        }

        let serialized = toml::to_string(&Wrapper {
            value: TrustValueSpec::Random,
        })
        .unwrap();
        assert!(serialized.contains("value = \"random\""));
    }

    #[test]
    fn trust_record_emptiness_tracks_fields() {
        let mut record = TrustRecord::default();
        assert!(record.is_empty());
        record.vb_key = Some("aa".to_string());
        assert!(!record.is_empty());
    }

    #[test]
    fn raw_trust_default_uses_auto_modes() {
        let trust = RawTrustConfig::default();
        assert_eq!(trust.vb_key, TrustValueSpec::Auto);
        assert_eq!(trust.vb_hash, TrustValueSpec::Auto);
    }

    #[test]
    fn config_file_parses_legacy_hex_values() {
        let config = parse_config_file(
            r#"
[main]
backend = "injector"

[crypto]
root_kek_seed = "0000000000000000000000000000000000000000000000000000000000000000"
kak_seed = "1111111111111111111111111111111111111111111111111111111111111111"

[trust]
os_version = 16
security_patch = "2026-04-05"
vb_key = "2222222222222222222222222222222222222222222222222222222222222222"
vb_hash = "3333333333333333333333333333333333333333333333333333333333333333"
verified_boot_state = true
device_locked = true

[device]
brand = "Google"
device = "caiman"
product = "caiman"
manufacturer = "Google"
model = "Pixel 9"
serial = "serial"
overrideTelephonyProperties = false
meid = ""
imei = ""
imei2 = ""
"#,
        )
        .unwrap();

        assert!(matches!(config.trust.vb_key, TrustValueSpec::Hex(_)));
        assert!(matches!(config.trust.vb_hash, TrustValueSpec::Hex(_)));
    }

    #[test]
    fn device_property_default_leaves_telephony_ids_empty() {
        let device = DeviceProperty::default();
        assert!(!device.override_telephony_properties);
        assert!(device.imei.is_empty());
        assert!(device.imei2.is_empty());
        assert!(device.meid.is_empty());
    }

    #[derive(Deserialize)]
    struct TrustValueToml {
        value: TrustValueSpec,
    }
}
