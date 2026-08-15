use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, RwLock},
};

use anyhow::{anyhow, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    crypto::Rng,
    runtime::{
        file_watch::{self, WatchTrigger},
        fs::atomic_replace_preserving_metadata,
        retry::{retry_read_race, ReadRaceErrorKind},
    },
};
use kmr_crypto_boring::rng::BoringRng;
use serde::{ser::SerializeStruct, Deserialize, Serialize};

pub static CONFIG: OnceLock<RwLock<Config>> = OnceLock::new();
static CONFIG_WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static CONFIG_FILE_WRITE_LOCK: Mutex<()> = Mutex::new(());

const CONFIG_PATH: &str = "/data/misc/keystore/omk/config.toml";
const CONFIG_VERSION_V1: u32 = 1;
const CURRENT_CONFIG_VERSION: u32 = 2;

const REPLACE_SAVE_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
const REPLACE_SAVE_RETRY_LIMIT: usize = 10;

fn decode_hex32_field<E>(field: &str, value: &str) -> Result<[u8; 32], E>
where
    E: serde::de::Error,
{
    let decoded = hex::decode(value).map_err(E::custom)?;
    if decoded.len() != 32 {
        return Err(E::custom(format!("{field} must be 32 bytes")));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn random_32(rng: &mut impl Rng) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn config() -> &'static RwLock<Config> {
    CONFIG
        .get()
        .expect("CONFIG must be bootstrapped before use")
}

pub fn config_path() -> &'static str {
    CONFIG_PATH
}

#[derive(Debug)]
enum ConfigLoadError {
    Missing(io::Error),
    Read(io::Error),
    Parse(String),
}

impl std::fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(error) | Self::Read(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug)]
struct LoadedConfigFile {
    config_file: ConfigFile,
    retries: usize,
}

struct ParsedConfigFile {
    config_file: ConfigFile,
    table: toml::Table,
    migrated: bool,
}

pub fn bootstrap_config_file() -> Result<ConfigFile> {
    bootstrap_config_file_to_path(Path::new(CONFIG_PATH))
}

pub fn load_config_file() -> Result<ConfigFile> {
    load_config_file_once()
        .map(|loaded| loaded.config_file)
        .map_err(|error| anyhow!("{error}"))
}

pub fn persist_config_file(config_file: &ConfigFile) -> Result<()> {
    persist_config_file_to_path(Path::new(CONFIG_PATH), config_file)
}

fn bootstrap_config_file_to_path(path: &Path) -> Result<ConfigFile> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| anyhow!("config file write lock poisoned"))?;
    let (contents, parsed) = match fs::read_to_string(path) {
        Ok(contents) => {
            let parsed = parse_config_file(&contents, true)?;
            (Some(contents), parsed)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            log::warn!("config file missing during startup: {error}; seeding defaults");
            let config_file = ConfigFile::default();
            let table = toml::from_str(&toml::to_string_pretty(&config_file)?)?;
            (
                None,
                ParsedConfigFile {
                    config_file,
                    table,
                    migrated: false,
                },
            )
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read config file {}", path.display()))
        }
    };

    let typed =
        toml::to_string_pretty(&parsed.config_file).context("failed to serialize config.toml")?;
    let updated: toml::Table =
        toml::from_str(&typed).context("failed to deserialize serialized config.toml")?;
    let migrated = parsed.migrated;
    let original_table = parsed.table.clone();
    let mut merged = parsed.table;
    merged.remove("trust_record");
    merge_config_table(&mut merged, updated);
    let needs_write = contents.is_none() || migrated || merged != original_table;
    let serialized =
        toml::to_string_pretty(&merged).context("failed to serialize merged config.toml")?;
    let config_file = parse_config_file(&serialized, false)
        .context("failed to validate merged config.toml")?
        .config_file;
    if needs_write {
        persist_config_contents_unlocked(path, &serialized)?;
    }
    if migrated {
        log::info!("migrated config.toml to version {CURRENT_CONFIG_VERSION}");
    }
    Ok(config_file)
}

fn persist_config_file_to_path(path: &Path, config_file: &ConfigFile) -> Result<()> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| anyhow!("config file write lock poisoned"))?;
    let typed = toml::to_string_pretty(config_file).context("failed to serialize config.toml")?;
    let mut updated: toml::Table =
        toml::from_str(&typed).context("failed to deserialize serialized config.toml")?;
    updated.insert(
        "version".to_string(),
        toml::Value::Integer(i64::from(CURRENT_CONFIG_VERSION)),
    );
    let mut merged = match fs::read_to_string(path) {
        Ok(existing) => {
            parse_config_file(&existing, false)
                .context("refusing to overwrite invalid existing config.toml")?
                .table
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => toml::Table::new(),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read config file {}", path.display()))
        }
    };
    merged.remove("trust_record");
    if config_file.crypto.auth_token_hmac_key.is_none() {
        if let Some(crypto) = merged.get_mut("crypto").and_then(toml::Value::as_table_mut) {
            crypto.remove("auth_token_hmac_key");
        }
    }
    merge_config_table(&mut merged, updated);
    let serialized =
        toml::to_string_pretty(&merged).context("failed to serialize merged config.toml")?;
    parse_config_file(&serialized, false).context("failed to validate merged config.toml")?;
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == serialized {
            log::debug!("config file unchanged; skipping rewrite");
            return Ok(());
        }
    }
    persist_config_contents_unlocked(path, &serialized)
}

fn merge_config_table(target: &mut toml::Table, updated: toml::Table) {
    for (key, value) in updated {
        match (target.get_mut(&key), value) {
            (Some(toml::Value::Table(target)), toml::Value::Table(updated)) => {
                merge_config_table(target, updated);
            }
            (_, value) => {
                target.insert(key, value);
            }
        }
    }
}

fn persist_config_contents_unlocked(path: &Path, contents: &str) -> Result<()> {
    let (default_uid, default_gid) = if path == Path::new(CONFIG_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    };
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o660, default_uid, default_gid)
        .with_context(|| format!("failed to atomically replace config {}", path.display()))
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

fn load_config_file_once() -> Result<LoadedConfigFile, ConfigLoadError> {
    match fs::read_to_string(CONFIG_PATH) {
        Ok(contents) => {
            let parsed = parse_config_file(&contents, false)
                .map_err(|error| ConfigLoadError::Parse(format!("{error:#}")))?;
            Ok(LoadedConfigFile {
                config_file: parsed.config_file,
                retries: 0,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(ConfigLoadError::Missing(error))
        }
        Err(error) => Err(ConfigLoadError::Read(error)),
    }
}

fn config_load_error_kind(error: &ConfigLoadError) -> ReadRaceErrorKind {
    match error {
        ConfigLoadError::Missing(_) | ConfigLoadError::Read(_) => ReadRaceErrorKind::Retryable,
        ConfigLoadError::Parse(_) => ReadRaceErrorKind::Fatal,
    }
}

fn load_config_file_with_retry(trigger: WatchTrigger) -> Result<LoadedConfigFile, ConfigLoadError> {
    if !trigger.should_retry_reads() {
        return load_config_file_once();
    }

    retry_read_race(
        load_config_file_once,
        config_load_error_kind,
        REPLACE_SAVE_RETRY_LIMIT,
        REPLACE_SAVE_RETRY_INTERVAL,
        std::thread::sleep,
        |retries, error, interval| {
            log::warn!(
                "Config reload via {} hit read-side race on retry {}/{}: {}; waiting {} ms",
                trigger.label(),
                retries,
                REPLACE_SAVE_RETRY_LIMIT,
                error,
                interval.as_millis()
            );
        },
    )
    .map(|outcome| {
        let mut loaded = outcome.value;
        loaded.retries = outcome.retries;
        loaded
    })
}

fn parse_config_file(contents: &str, allow_migration: bool) -> Result<ParsedConfigFile> {
    let mut table: toml::Table =
        toml::from_str(contents).context("failed to deserialize config.toml")?;
    let version = config_version(&table)?;
    let migrated = match version {
        0 if allow_migration => {
            upgrade_v0_to_v1(&mut table)?;
            upgrade_v1_to_v2(&mut table)?;
            true
        }
        CONFIG_VERSION_V1 if allow_migration => {
            upgrade_v1_to_v2(&mut table)?;
            true
        }
        0 | CONFIG_VERSION_V1 => {
            return Err(anyhow!(
                "config version {version} requires a keymint restart to migrate"
            ))
        }
        CURRENT_CONFIG_VERSION => false,
        version => {
            return Err(anyhow!(
                "config version {version} is newer than supported version {CURRENT_CONFIG_VERSION}"
            ))
        }
    };
    let serialized =
        toml::to_string_pretty(&table).context("failed to serialize migrated config.toml")?;
    let config_file: ConfigFile =
        toml::from_str(&serialized).context("failed to validate migrated config.toml")?;
    validate_trust_config(&config_file.trust)?;
    Ok(ParsedConfigFile {
        config_file,
        table,
        migrated,
    })
}

fn config_version(table: &toml::Table) -> Result<u32> {
    match table.get("version") {
        None => Ok(0),
        Some(toml::Value::Integer(version)) if *version >= 0 => u32::try_from(*version)
            .map_err(|_| anyhow!("config version is out of range: {version}")),
        Some(toml::Value::Integer(version)) => {
            Err(anyhow!("config version must not be negative: {version}"))
        }
        Some(_) => Err(anyhow!("config version must be an integer")),
    }
}

fn upgrade_v0_to_v1(table: &mut toml::Table) -> Result<()> {
    table.remove("trust_record");
    table.insert(
        "version".to_string(),
        toml::Value::Integer(i64::from(CONFIG_VERSION_V1)),
    );
    let trust = table
        .get_mut("trust")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("config is missing a valid [trust] table"))?;
    let inherited_patchlevel = trust
        .get("security_patch")
        .cloned()
        .unwrap_or_else(|| toml::Value::String("auto".to_string()));
    for field in ["os_patchlevel", "vendor_patchlevel", "boot_patchlevel"] {
        trust
            .entry(field.to_string())
            .or_insert_with(|| inherited_patchlevel.clone());
    }
    Ok(())
}

fn upgrade_v1_to_v2(table: &mut toml::Table) -> Result<()> {
    let trust = table
        .get_mut("trust")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| anyhow!("config is missing a valid [trust] table"))?;
    trust.insert(
        "os_version".to_string(),
        toml::Value::String("auto".to_string()),
    );
    table.insert(
        "version".to_string(),
        toml::Value::Integer(i64::from(CURRENT_CONFIG_VERSION)),
    );
    Ok(())
}

fn start_config_watcher() -> Result<()> {
    if CONFIG_WATCHER_STARTED.set(()).is_err() {
        return Ok(());
    }

    file_watch::spawn_path_watcher(
        "omk-config-watch",
        PathBuf::from(CONFIG_PATH),
        reload_runtime_config,
    )
}

fn reload_runtime_config(trigger: WatchTrigger) {
    let new_config_file = match load_config_file_with_retry(trigger) {
        Ok(loaded) => {
            if loaded.retries > 0 {
                log::info!(
                    "Config reload via {} succeeded after {} retr{}",
                    trigger.label(),
                    loaded.retries,
                    if loaded.retries == 1 { "y" } else { "ies" }
                );
            }
            loaded.config_file
        }
        Err(ConfigLoadError::Missing(error)) => {
            log::error!("failed to read changed config file: {error}; keeping current config");
            return;
        }
        Err(ConfigLoadError::Read(error)) => {
            log::error!("failed to read changed config file: {error}; keeping current config");
            return;
        }
        Err(ConfigLoadError::Parse(error)) => {
            log::error!("failed to parse changed config file: {error}; keeping current config");
            return;
        }
    };

    let runtime_snapshot = match config().read() {
        Ok(runtime) => runtime.clone(),
        Err(_) => {
            log::error!("config lock poisoned while snapshotting config change");
            return;
        }
    };

    let previous_trust = runtime_snapshot.trust.clone();
    let previous_trust_intent = runtime_snapshot.trust_intent.clone();
    let mut applied_trust = previous_trust.clone();
    let mut applied_trust_intent = previous_trust_intent.clone();
    let mut update_patchlevels = false;
    let mut security_patch_update = None;

    if trust_changed_beyond_patchlevels(&runtime_snapshot.trust_intent, &new_config_file.trust) {
        log::warn!(
            "Trust config changed on disk beyond patch levels; restart keymint to apply it."
        );
    } else {
        let mut trust_to_resolve = new_config_file.trust.clone();
        if trust_to_resolve.boot_patchlevel.trim() == "auto" {
            if previous_trust_intent.boot_patchlevel.trim() != "auto" {
                log::warn!(
                    "boot_patchlevel changed to auto; keeping the current runtime value until keymint restarts"
                );
            }
            trust_to_resolve.boot_patchlevel = previous_trust.boot_patchlevel.clone();
        }
        match crate::plat::vbmeta::resolve_patch_levels(&trust_to_resolve) {
            Ok(patches) => {
                update_patchlevels = previous_trust.os_patchlevel != patches.os_patchlevel
                    || previous_trust.vendor_patchlevel != patches.vendor_patchlevel
                    || boot_patchlevel_changed(
                        &previous_trust.boot_patchlevel,
                        &patches.boot_patchlevel,
                    );
                if patches.write_security_patch {
                    security_patch_update = Some((
                        patches.security_patch.clone(),
                        patches.observed_security_patch,
                    ));
                }
                applied_trust.security_patch = patches.security_patch;
                applied_trust.os_patchlevel = patches.os_patchlevel;
                applied_trust.vendor_patchlevel = patches.vendor_patchlevel;
                applied_trust.boot_patchlevel = patches.boot_patchlevel;
                applied_trust_intent = new_config_file.trust.clone();
            }
            Err(error) => {
                log::error!(
                    "failed to resolve changed patch levels; keeping previous values: {error:#}"
                );
            }
        }
    }

    let mut applied_crypto = new_config_file.crypto.clone();
    if runtime_snapshot.crypto != new_config_file.crypto {
        log::warn!("crypto config changed on disk; restart keymint to apply seed changes");
        applied_crypto = runtime_snapshot.crypto.clone();
    }

    let mut updated = Config::from_file(&new_config_file, applied_trust);
    updated.trust_intent = applied_trust_intent;
    updated.crypto = applied_crypto;
    match crate::keymaster::keymint_device::apply_runtime_config_update(
        updated,
        update_patchlevels,
        security_patch_update,
    ) {
        Ok(()) => log::info!("config updated via {}", trigger.label()),
        Err(error) => log::error!(
            "failed to apply config update via {}; keeping previous runtime: {error:#}",
            trigger.label()
        ),
    }
}

fn validate_trust_config(trust: &RawTrustConfig) -> Result<()> {
    if let OsVersionSpec::Fixed(value) = trust.os_version {
        if !(0..=99).contains(&value) {
            return Err(anyhow!(
                "trust.os_version must be \"auto\" or a one- or two-digit Android major version"
            ));
        }
    }
    for (field, value) in [
        ("security_patch", trust.security_patch.as_str()),
        ("os_patchlevel", trust.os_patchlevel.as_str()),
        ("vendor_patchlevel", trust.vendor_patchlevel.as_str()),
        ("boot_patchlevel", trust.boot_patchlevel.as_str()),
    ] {
        validate_patchlevel(field, value)?;
    }
    Ok(())
}

fn validate_patchlevel(field: &str, value: &str) -> Result<()> {
    let normalized = value.trim();
    if matches!(normalized, "auto" | "latest")
        || is_security_patch_date(normalized)
        || (field == "boot_patchlevel" && normalized.parse::<u32>().is_ok())
    {
        Ok(())
    } else {
        let formats = if field == "boot_patchlevel" {
            "auto, latest, YYYY-MM-DD, or a decimal u32"
        } else {
            "auto, latest, or YYYY-MM-DD"
        };
        Err(anyhow!("trust.{field} must be {formats}"))
    }
}

pub fn is_security_patch_date(value: &str) -> bool {
    regex::Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$")
        .expect("security patch regex must compile")
        .is_match(value)
}

fn trust_changed_beyond_patchlevels(old: &RawTrustConfig, new: &RawTrustConfig) -> bool {
    old.os_version != new.os_version
        || old.vb_key != new.vb_key
        || old.vb_hash != new.vb_hash
        || old.verified_boot_state != new.verified_boot_state
        || old.device_locked != new.device_locked
}

fn boot_patchlevel_changed(previous: &str, next: &str) -> bool {
    let extract = crate::keymaster::keymint_device::extract_boot_patchlevel;
    match (extract(previous), extract(next)) {
        (Ok(previous), Ok(next)) => previous != next,
        _ => true,
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub main: MainConfig,
    pub crypto: CryptoConfig,
    pub trust: ResolvedTrust,
    pub device: DeviceProperty,
    trust_intent: RawTrustConfig,
}

impl Config {
    fn from_file(config_file: &ConfigFile, resolved_trust: ResolvedTrust) -> Self {
        Self {
            main: config_file.main.clone(),
            crypto: config_file.crypto.clone(),
            trust: resolved_trust,
            device: config_file.device.clone(),
            trust_intent: config_file.trust.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    pub version: u32,
    pub main: MainConfig,
    pub crypto: CryptoConfig,
    pub trust: RawTrustConfig,
    pub device: DeviceProperty,
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            main: MainConfig::default(),
            crypto: CryptoConfig::default(),
            trust: RawTrustConfig::default(),
            device: DeviceProperty::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    Injector,
}

impl Serialize for Backend {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Backend {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value
            .parse()
            .map_err(|()| serde::de::Error::custom(format!("unknown backend {value:?}")))
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Injector => write!(f, "injector"),
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // ponytail: keep old configs booting while the OMK system-service backend is disabled.
            "injector" => Ok(Backend::Injector),
            "omk" => Ok(Backend::Injector),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct MainConfig {
    /// Only the injector backend is currently enabled.
    pub backend: Backend,
    pub log_level: String,
    /// Insecure fallback for devices whose system TEE cannot verify HATs.
    /// When enabled, OMK accepts shape-valid HATs without system KeyMint MAC verification.
    #[serde(default)]
    pub force_skip_system_biometric_hat_verification: bool,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            backend: Backend::Injector,
            log_level: "info".to_string(),
            force_skip_system_biometric_hat_verification: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoConfig {
    pub root_kek_seed: [u8; 32],
    pub kak_seed: [u8; 32],
    pub shared_secret_seed: [u8; 32],
    pub shared_secret_nonce: [u8; 32],
    pub auth_token_hmac_key: Option<[u8; 32]>,
}

impl Serialize for CryptoConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct(
            "CryptoConfig",
            4 + usize::from(self.auth_token_hmac_key.is_some()),
        )?;
        state.serialize_field("root_kek_seed", &hex::encode(self.root_kek_seed))?;
        state.serialize_field("kak_seed", &hex::encode(self.kak_seed))?;
        state.serialize_field("shared_secret_seed", &hex::encode(self.shared_secret_seed))?;
        state.serialize_field(
            "shared_secret_nonce",
            &hex::encode(self.shared_secret_nonce),
        )?;
        if let Some(key) = self.auth_token_hmac_key {
            state.serialize_field("auth_token_hmac_key", &hex::encode(key))?;
        }
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
            #[serde(default)]
            shared_secret_seed: Option<String>,
            #[serde(default)]
            shared_secret_nonce: Option<String>,
            #[serde(default)]
            auth_token_hmac_key: Option<String>,
        }

        let helper = CryptoConfigHelper::deserialize(deserializer)?;
        let root_kek_seed = decode_hex32_field("root_kek_seed", &helper.root_kek_seed)?;
        let kak_seed = decode_hex32_field("kak_seed", &helper.kak_seed)?;
        let defaults = CryptoConfig::default();
        let shared_secret_seed = match helper.shared_secret_seed {
            Some(value) => decode_hex32_field("shared_secret_seed", &value)?,
            None => defaults.shared_secret_seed,
        };
        let shared_secret_nonce = match helper.shared_secret_nonce {
            Some(value) => decode_hex32_field("shared_secret_nonce", &value)?,
            None => defaults.shared_secret_nonce,
        };
        let auth_token_hmac_key = match helper.auth_token_hmac_key {
            Some(value) => Some(decode_hex32_field("auth_token_hmac_key", &value)?),
            None => None,
        };

        Ok(CryptoConfig {
            root_kek_seed,
            kak_seed,
            shared_secret_seed,
            shared_secret_nonce,
            auth_token_hmac_key,
        })
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        let mut rng = BoringRng {};
        Self {
            root_kek_seed: random_32(&mut rng),
            kak_seed: random_32(&mut rng),
            shared_secret_seed: random_32(&mut rng),
            shared_secret_nonce: random_32(&mut rng),
            auth_token_hmac_key: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTrust {
    pub os_version: i32,
    pub security_patch: String,
    pub os_patchlevel: String,
    pub vendor_patchlevel: String,
    pub boot_patchlevel: String,
    pub vb_key: [u8; 32],
    pub vb_hash: [u8; 32],
    pub vb_key_source: TrustValueSource,
    pub vb_hash_source: TrustValueSource,
    pub verified_boot_state: bool,
    pub device_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawTrustConfig {
    pub os_version: OsVersionSpec,
    pub security_patch: String,
    #[serde(default = "default_patchlevel_mode")]
    pub os_patchlevel: String,
    #[serde(default = "default_patchlevel_mode")]
    pub vendor_patchlevel: String,
    #[serde(default = "default_patchlevel_mode")]
    pub boot_patchlevel: String,
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
            os_version: OsVersionSpec::Auto,
            security_patch: "auto".to_string(),
            os_patchlevel: default_patchlevel_mode(),
            vendor_patchlevel: default_patchlevel_mode(),
            boot_patchlevel: default_patchlevel_mode(),
            vb_key: TrustValueSpec::Auto,
            vb_hash: TrustValueSpec::Auto,
            verified_boot_state: true,
            device_locked: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OsVersionSpec {
    #[default]
    Auto,
    Fixed(i32),
}

impl Serialize for OsVersionSpec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Auto => serializer.serialize_str("auto"),
            Self::Fixed(value) => serializer.serialize_i32(*value),
        }
    }
}

impl<'de> Deserialize<'de> for OsVersionSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match toml::Value::deserialize(deserializer)? {
            toml::Value::String(value) if value == "auto" => Ok(Self::Auto),
            toml::Value::Integer(value) => i32::try_from(value)
                .map(Self::Fixed)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "os_version must be \"auto\" or an integer",
            )),
        }
    }
}

fn default_patchlevel_mode() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TrustValueSpec {
    #[default]
    Auto,
    Random,
    Hex([u8; 32]),
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
    fn os_version_spec_accepts_auto_or_fixed_integer() {
        let auto: OsVersionToml = toml::from_str("value = \"auto\"").unwrap();
        assert_eq!(auto.value, OsVersionSpec::Auto);
        assert!(toml::to_string(&auto).unwrap().contains("value = \"auto\""));

        let fixed: OsVersionToml = toml::from_str("value = 17").unwrap();
        assert_eq!(fixed.value, OsVersionSpec::Fixed(17));
        assert!(toml::to_string(&fixed).unwrap().contains("value = 17"));

        for invalid in ["value = \"latest\"", "value = 16.0", "value = 2147483648"] {
            assert!(toml::from_str::<OsVersionToml>(invalid).is_err());
        }

        let mut trust = RawTrustConfig::default();
        for value in [0, 99] {
            trust.os_version = OsVersionSpec::Fixed(value);
            validate_trust_config(&trust).unwrap();
        }
        for value in [-1, 100] {
            trust.os_version = OsVersionSpec::Fixed(value);
            assert!(validate_trust_config(&trust).is_err());
        }

        let mut config_file = ConfigFile::default();
        config_file.trust.os_version = OsVersionSpec::Fixed(17);
        let parsed = parse_config_file(&toml::to_string(&config_file).unwrap(), false).unwrap();
        assert!(!parsed.migrated);
        assert_eq!(
            parsed.config_file.trust.os_version,
            OsVersionSpec::Fixed(17)
        );

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("config.toml");
        persist_config_file_to_path(&path, &config_file).unwrap();
        let persisted: toml::Table = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            persisted
                .get("trust")
                .and_then(toml::Value::as_table)
                .and_then(|trust| trust.get("os_version"))
                .and_then(toml::Value::as_integer),
            Some(17)
        );
    }

    #[test]
    fn raw_trust_default_uses_auto_modes() {
        let trust = RawTrustConfig::default();
        assert_eq!(ConfigFile::default().version, CURRENT_CONFIG_VERSION);
        assert_eq!(trust.os_version, OsVersionSpec::Auto);
        assert!(toml::to_string(&trust)
            .unwrap()
            .contains("os_version = \"auto\""));
        assert_eq!(trust.security_patch, "auto");
        assert_eq!(trust.os_patchlevel, "auto");
        assert_eq!(trust.vendor_patchlevel, "auto");
        assert_eq!(trust.boot_patchlevel, "auto");
        assert_eq!(trust.vb_key, TrustValueSpec::Auto);
        assert_eq!(trust.vb_hash, TrustValueSpec::Auto);
    }

    #[test]
    fn validate_security_patch_accepts_auto_latest_and_dates() {
        validate_patchlevel("security_patch", "auto").expect("auto should validate");
        validate_patchlevel("security_patch", "latest").expect("latest should validate");
        validate_patchlevel("security_patch", "2026-04-05")
            .expect("explicit patch level should validate");
    }

    #[test]
    fn validate_security_patch_rejects_invalid_values() {
        assert!(validate_patchlevel("security_patch", "2026-4-5").is_err());
        assert!(validate_patchlevel("security_patch", "yesterday").is_err());
        assert!(validate_patchlevel("security_patch", "").is_err());
        assert!(validate_patchlevel("security_patch", "20000000").is_err());
    }

    #[test]
    fn validate_boot_patchlevel_accepts_raw_wire_value() {
        validate_patchlevel("boot_patchlevel", "20000000")
            .expect("raw boot patch level should validate");
        assert!(validate_patchlevel("boot_patchlevel", "4294967296").is_err());
    }

    #[test]
    fn boot_patchlevel_change_compares_wire_values() {
        assert!(!boot_patchlevel_changed("2025-06-05", "20250605"));
        assert!(!boot_patchlevel_changed("20250605", "2025-06-05"));
        assert!(boot_patchlevel_changed("2025-06-05", "20250606"));
        assert!(boot_patchlevel_changed("2025-06-05", "unavailable"));
    }

    #[test]
    fn backend_config_accepts_injector_and_legacy_omk_alias() {
        let injector: MainConfig = toml::from_str(r#"backend = "injector""#).unwrap();
        assert_eq!(injector.backend, Backend::Injector);

        let omk: MainConfig = toml::from_str(r#"backend = "omk""#).unwrap();
        assert_eq!(omk.backend, Backend::Injector);

        assert!(toml::from_str::<MainConfig>(r#"backend = "ts""#).is_err());
        assert!(toml::from_str::<MainConfig>(r#"backend = "Injector""#).is_err());
        assert!(toml::from_str::<MainConfig>(r#"backend = "OMK""#).is_err());

        let serialized = toml::to_string(&MainConfig::default()).unwrap();
        assert!(serialized.contains(r#"backend = "injector""#));
        assert!(serialized.contains(r#"log_level = "info""#));
    }

    #[test]
    fn main_config_parses_hat_verification_fallback() {
        let parsed: MainConfig = toml::from_str(
            r#"backend = "injector"
force_skip_system_biometric_hat_verification = true"#,
        )
        .unwrap();
        assert!(parsed.force_skip_system_biometric_hat_verification);
        assert!(!MainConfig::default().force_skip_system_biometric_hat_verification);
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
shared_secret_seed = "2222222222222222222222222222222222222222222222222222222222222222"
shared_secret_nonce = "3333333333333333333333333333333333333333333333333333333333333333"

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
            true,
        )
        .unwrap()
        .config_file;

        assert!(matches!(config.trust.vb_key, TrustValueSpec::Hex(_)));
        assert!(matches!(config.trust.vb_hash, TrustValueSpec::Hex(_)));
        assert_eq!(config.trust.os_version, OsVersionSpec::Auto);
        assert_eq!(config.trust.os_patchlevel, "2026-04-05");
        assert_eq!(config.trust.vendor_patchlevel, "2026-04-05");
        assert_eq!(config.trust.boot_patchlevel, "2026-04-05");
    }

    #[test]
    fn config_v0_migration_removes_trust_record_and_preserves_unknown_keys() {
        let mut table: toml::Table =
            toml::from_str(&toml::to_string_pretty(&ConfigFile::default()).unwrap()).unwrap();
        table.insert("version".to_string(), toml::Value::Integer(0));
        table.insert(
            "trust_record".to_string(),
            toml::Value::Table(toml::Table::new()),
        );
        table.insert(
            "future_key".to_string(),
            toml::Value::String("preserve-me".to_string()),
        );
        let trust = table
            .get_mut("trust")
            .and_then(toml::Value::as_table_mut)
            .unwrap();
        trust.insert(
            "future_trust_key".to_string(),
            toml::Value::String("preserve-me-too".to_string()),
        );
        trust.insert("os_version".to_string(), toml::Value::Integer(17));
        trust.remove("os_patchlevel");
        trust.insert(
            "vendor_patchlevel".to_string(),
            toml::Value::String("2026-03-05".to_string()),
        );
        trust.remove("boot_patchlevel");
        let crypto = table
            .get_mut("crypto")
            .and_then(toml::Value::as_table_mut)
            .unwrap();
        crypto.remove("shared_secret_seed");
        crypto.remove("shared_secret_nonce");
        crypto.insert(
            "auth_token_hmac_key".to_string(),
            toml::Value::String("44".repeat(32)),
        );

        let original = toml::to_string_pretty(&table).unwrap();
        let parsed = parse_config_file(&original, true).unwrap();
        assert_eq!(parsed.config_file.version, CURRENT_CONFIG_VERSION);
        assert!(parsed.migrated);
        assert_eq!(parsed.config_file.trust.os_version, OsVersionSpec::Auto);
        assert_eq!(parsed.config_file.trust.os_patchlevel, "auto");
        assert_eq!(parsed.config_file.trust.vendor_patchlevel, "2026-03-05");
        assert_eq!(parsed.config_file.trust.boot_patchlevel, "auto");
        assert!(!parsed.table.contains_key("trust_record"));
        assert_eq!(
            parsed.table.get("future_key").and_then(toml::Value::as_str),
            Some("preserve-me")
        );

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("config.toml");
        fs::write(&path, original).unwrap();
        let mut config_file = bootstrap_config_file_to_path(&path).unwrap();
        let expected_shared_secret_seed = hex::encode(config_file.crypto.shared_secret_seed);
        let expected_shared_secret_nonce = hex::encode(config_file.crypto.shared_secret_nonce);
        let migrated: toml::Table = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            migrated.get("version").and_then(toml::Value::as_integer),
            Some(i64::from(CURRENT_CONFIG_VERSION))
        );
        assert_eq!(
            migrated
                .get("trust")
                .and_then(toml::Value::as_table)
                .and_then(|trust| trust.get("os_version"))
                .and_then(toml::Value::as_str),
            Some("auto")
        );
        assert!(!migrated.contains_key("trust_record"));
        assert_eq!(
            migrated.get("future_key").and_then(toml::Value::as_str),
            Some("preserve-me")
        );
        let migrated_crypto = migrated
            .get("crypto")
            .and_then(toml::Value::as_table)
            .unwrap();
        assert_eq!(
            migrated_crypto
                .get("shared_secret_seed")
                .and_then(toml::Value::as_str),
            Some(expected_shared_secret_seed.as_str())
        );
        assert_eq!(
            migrated_crypto
                .get("shared_secret_nonce")
                .and_then(toml::Value::as_str),
            Some(expected_shared_secret_nonce.as_str())
        );
        assert_eq!(
            migrated_crypto
                .get("auth_token_hmac_key")
                .and_then(toml::Value::as_str),
            Some("4444444444444444444444444444444444444444444444444444444444444444")
        );

        config_file.crypto.auth_token_hmac_key = None;
        config_file.device.imei = "355231937352445".to_string();
        persist_config_file_to_path(&path, &config_file).unwrap();

        let persisted: toml::Table = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(
            persisted.get("version").and_then(toml::Value::as_integer),
            Some(i64::from(CURRENT_CONFIG_VERSION))
        );
        assert_eq!(
            persisted.get("future_key").and_then(toml::Value::as_str),
            Some("preserve-me")
        );
        assert_eq!(
            persisted
                .get("trust")
                .and_then(toml::Value::as_table)
                .and_then(|trust| trust.get("future_trust_key"))
                .and_then(toml::Value::as_str),
            Some("preserve-me-too")
        );
        assert!(!persisted.contains_key("trust_record"));
        assert_eq!(
            persisted
                .get("trust")
                .and_then(toml::Value::as_table)
                .and_then(|trust| trust.get("os_version"))
                .and_then(toml::Value::as_str),
            Some("auto")
        );
        assert!(persisted
            .get("crypto")
            .and_then(toml::Value::as_table)
            .unwrap()
            .get("auth_token_hmac_key")
            .is_none());
        let persisted_crypto = persisted
            .get("crypto")
            .and_then(toml::Value::as_table)
            .unwrap();
        assert_eq!(
            persisted_crypto
                .get("shared_secret_seed")
                .and_then(toml::Value::as_str),
            Some(expected_shared_secret_seed.as_str())
        );
        assert_eq!(
            persisted_crypto
                .get("shared_secret_nonce")
                .and_then(toml::Value::as_str),
            Some(expected_shared_secret_nonce.as_str())
        );
    }

    #[test]
    fn config_v1_migration_forces_os_version_auto() {
        let mut table: toml::Table =
            toml::from_str(&toml::to_string_pretty(&ConfigFile::default()).unwrap()).unwrap();
        table.insert(
            "version".to_string(),
            toml::Value::Integer(i64::from(CONFIG_VERSION_V1)),
        );
        table
            .get_mut("trust")
            .and_then(toml::Value::as_table_mut)
            .unwrap()
            .insert("os_version".to_string(), toml::Value::Integer(17));
        table
            .get_mut("main")
            .and_then(toml::Value::as_table_mut)
            .unwrap()
            .insert(
                "log_level".to_string(),
                toml::Value::String("trace".to_string()),
            );

        let parsed = parse_config_file(&toml::to_string_pretty(&table).unwrap(), true).unwrap();
        assert!(parsed.migrated);
        assert_eq!(parsed.config_file.version, CURRENT_CONFIG_VERSION);
        assert_eq!(parsed.config_file.trust.os_version, OsVersionSpec::Auto);
        assert_eq!(parsed.config_file.main.log_level, "trace");
    }

    #[test]
    fn bootstrap_uses_latest_v2_instead_of_stale_migration_snapshot() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("config.toml");

        let legacy = ConfigFile {
            version: CONFIG_VERSION_V1,
            trust: RawTrustConfig {
                os_version: OsVersionSpec::Fixed(16),
                ..Default::default()
            },
            ..Default::default()
        };
        let stale = parse_config_file(&toml::to_string_pretty(&legacy).unwrap(), true).unwrap();
        assert!(stale.migrated);
        assert_eq!(stale.config_file.trust.os_version, OsVersionSpec::Auto);

        let current = ConfigFile {
            main: MainConfig {
                log_level: "trace".to_string(),
                ..Default::default()
            },
            trust: RawTrustConfig {
                os_version: OsVersionSpec::Fixed(17),
                ..Default::default()
            },
            ..Default::default()
        };
        let current_contents = toml::to_string_pretty(&current).unwrap();
        fs::write(&path, &current_contents).unwrap();

        let loaded = bootstrap_config_file_to_path(&path).unwrap();
        assert_eq!(loaded.trust.os_version, OsVersionSpec::Fixed(17));
        assert_eq!(loaded.main.log_level, "trace");
        assert_eq!(fs::read_to_string(path).unwrap(), current_contents);
    }

    #[test]
    fn config_version_validation_handles_v0_and_rejects_unsupported_values() {
        assert_eq!(config_version(&toml::Table::new()).unwrap(), 0);

        for value in [
            toml::Value::Integer(-1),
            toml::Value::String("1".to_string()),
        ] {
            let mut table = toml::Table::new();
            table.insert("version".to_string(), value);
            assert!(config_version(&table).is_err());
        }

        for version in [0, CONFIG_VERSION_V1] {
            let mut table: toml::Table =
                toml::from_str(&toml::to_string_pretty(&ConfigFile::default()).unwrap()).unwrap();
            table.insert(
                "version".to_string(),
                toml::Value::Integer(i64::from(version)),
            );
            assert!(parse_config_file(&toml::to_string_pretty(&table).unwrap(), false).is_err());
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("config.toml");
        let mut future: toml::Table =
            toml::from_str(&toml::to_string_pretty(&ConfigFile::default()).unwrap()).unwrap();
        future.insert(
            "version".to_string(),
            toml::Value::Integer(i64::from(CURRENT_CONFIG_VERSION) + 1),
        );
        let original = toml::to_string_pretty(&future).unwrap();
        fs::write(&path, &original).unwrap();
        assert!(bootstrap_config_file_to_path(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert!(persist_config_file_to_path(&path, &ConfigFile::default()).is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), original);
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

    #[derive(Serialize, Deserialize)]
    struct OsVersionToml {
        value: OsVersionSpec,
    }
}
