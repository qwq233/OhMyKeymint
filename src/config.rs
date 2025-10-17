use core::panic;
use std::sync::RwLock;

use hotwatch::Hotwatch;
use kmr_common::crypto::Rng;
use kmr_crypto_boring::rng::BoringRng;
use serde::{ser::SerializeStruct, Deserialize, Serialize};

lazy_static::lazy_static! {
    pub static ref CONFIG: RwLock<Config> = init_config();
}

#[cfg(target_os = "android")]
const CONFIG_PATH: &str = "/data/adb/omk/config.toml";

#[cfg(not(target_os = "android"))]
const CONFIG_PATH: &str = "./omk/config.toml";

fn init_config() -> RwLock<Config> {
    let config = std::fs::read_to_string(CONFIG_PATH);
    let config: Config = match config {
        Ok(s) => match toml::from_str(&s) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to parse config file, using default: {:?}", e);
                Config::default()
            }
        },
        Err(e) => {
            log::error!("Failed to read config file, using default: {:?}", e);
            Config::default()
        }
    };

    // write back the config file to ensure it's always present
    let s = toml::to_string_pretty(&config).unwrap();
    if let Err(e) = std::fs::create_dir_all(std::path::Path::new(CONFIG_PATH).parent().unwrap()) {
        log::error!("Failed to create config directory: {:?}", e);
    } else if let Err(e) = {
        // backup old config
        if std::path::Path::new(CONFIG_PATH).exists() {
            let backup_path = format!("{}.bak", CONFIG_PATH);
            if let Err(e) = std::fs::copy(CONFIG_PATH, &backup_path) {
                log::error!("Failed to backup config file: {:?}", e);
            } else {
                log::info!("Backed up old config file to {}", backup_path);
            }
        }
        std::fs::write(CONFIG_PATH, s)
    } {
        log::error!("Failed to write config file: {:?}", e);
        panic!("Failed to write config file: {:?}", e);
    }

    std::thread::spawn(|| {
        let mut watcher = Hotwatch::new().unwrap();
        watcher
            .watch(CONFIG_PATH, |event| {
                log::info!("Config file changed: {:?}", event);
                let config = std::fs::read_to_string(CONFIG_PATH);
                let config: Config = match config {
                    Ok(s) => match toml::from_str(&s) {
                        Ok(c) => c,
                        Err(e) => {
                            log::error!("Failed to parse config file, ignoring change: {:?}", e);
                            return;
                        }
                    },
                    Err(e) => {
                        log::error!("Failed to read config file, ignoring change: {:?}", e);
                        return;
                    }
                };
                let mut cfg = CONFIG.write().unwrap();
                *cfg = config;
                log::info!("Config updated");
            })
            .unwrap();
        loop {
            std::thread::park();
        }
    });

    RwLock::new(config)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub main: MainConfig,
    pub crypto: CryptoConfig,
    pub trust: TrustConfig,
    pub device: DeviceProperty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Backend {
    TrickyStore,
    OMK,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::TrickyStore => write!(f, "ts"),
            Backend::OMK => write!(f, "omk"),
        }
    }
}

impl std::str::FromStr for Backend {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ts" => Ok(Backend::TrickyStore),
            "omk" => Ok(Backend::OMK),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MainConfig {
    /// default to tricky store for compatibility, we will
    /// switch to omk later when we are sure everything works
    pub backend: Backend,
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            backend: Backend::TrickyStore,
        }
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct TrustConfig {
    pub os_version: i32,
    pub security_patch: String,
    pub vb_key: [u8; 32],  // hex encoded
    pub vb_hash: [u8; 32], // hex encoded

    pub verified_boot_state: bool, // you sure?
    pub device_locked: bool,
}

impl Serialize for TrustConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("TrustConfig", 6)?;
        state.serialize_field("os_version", &self.os_version)?;
        state.serialize_field("security_patch", &self.security_patch)?;
        state.serialize_field("vb_key", &hex::encode(self.vb_key))?;
        state.serialize_field("vb_hash", &hex::encode(self.vb_hash))?;
        state.serialize_field("verified_boot_state", &self.verified_boot_state)?;
        state.serialize_field("device_locked", &self.device_locked)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TrustConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TrustConfigHelper {
            os_version: i32,
            security_patch: String,
            vb_key: String,
            vb_hash: String,
            verified_boot_state: bool,
            device_locked: bool,
        }

        let helper = TrustConfigHelper::deserialize(deserializer)?;
        let vb_key = hex::decode(&helper.vb_key).map_err(serde::de::Error::custom)?;
        let vb_hash = hex::decode(&helper.vb_hash).map_err(serde::de::Error::custom)?;

        if vb_key.len() != 32 {
            return Err(serde::de::Error::custom("vb_key must be 32 bytes"));
        }
        if vb_hash.len() != 32 {
            return Err(serde::de::Error::custom("vb_hash must be 32 bytes"));
        }

        let mut vb_key_array = [0u8; 32];
        vb_key_array.copy_from_slice(&vb_key);

        let mut vb_hash_array = [0u8; 32];
        vb_hash_array.copy_from_slice(&vb_hash);

        // check security patch format
        if !regex::Regex::new(r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$")
            .unwrap()
            .is_match(&helper.security_patch)
        {
            return Err(serde::de::Error::custom(
                "security_patch must be in YYYY-MM-DD format",
            ));
        }

        Ok(TrustConfig {
            os_version: helper.os_version,
            security_patch: helper.security_patch,
            vb_key: vb_key_array,
            vb_hash: vb_hash_array,
            verified_boot_state: helper.verified_boot_state,
            device_locked: helper.device_locked,
        })
    }
}

impl Default for TrustConfig {
    fn default() -> Self {
        let mut rng = BoringRng {};

        let mut vb_key = [0u8; 32];
        rng.fill_bytes(&mut vb_key);
        let mut vb_hash = [0u8; 32];
        rng.fill_bytes(&mut vb_hash);

        Self {
            os_version: rsproperties::get_or("ro.build.version.release", 35 /* Android 15 */),
            security_patch: rsproperties::get_or(
                "ro.build.version.security_patch",
                "2024-01-05".to_string(),
            ),
            vb_key,
            vb_hash,
            verified_boot_state: true, // rsproperties::get_or("ro.boot.verifiedbootstate", "green".to_string()) != "orange",
            device_locked: true, // rsproperties::get_or("ro.boot.verifiedbootstate", "green".to_string()) != "orange",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProperty {
    pub brand: String,
    pub device: String,
    pub product: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,

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
            meid: rsproperties::get_or("ro.ril.oem.meid", "".to_string()),
            imei: rsproperties::get_or("ro.ril.oem.imei", "".to_string()),
            imei2: rsproperties::get_or("ro.ril.oem.imei2", "".to_string()),
        }
    }
}
