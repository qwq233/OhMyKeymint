// Copyright 2020, The Android Open Source Project
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

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyFormat::KeyFormat,
    KeyParameter::KeyParameter as KmKeyParameter, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel,
};
use crate::android::system::keystore2::{Domain::Domain, KeyDescriptor::KeyDescriptor};
use crate::err as ks_err;
use crate::keymaster::{
    boot_key::{get_level_zero_key, BootLevel, BootLevelKeyCache, LegacyBootLevelKeyCache},
    crypto::{
        aes_gcm_decrypt, aes_gcm_encrypt, generate_aes256_key, generate_salt,
        is_decryption_failure, ECDHPrivateKey, Password, ZVec, AES_256_KEY_LENGTH,
    },
    db::{
        BlobMetaData, BlobMetaEntry, EncryptedBy, KeyEntry, KeyEntryLoadBits, KeyIdGuard,
        KeyMetaData, KeyMetaEntry, KeyType, KeystoreDB,
    },
    enforcements::Enforcements,
    error::{Error, ResponseCode},
    key_parameter::{KeyParameter, KeyParameterValue},
    keymint_device::{KeyMintDevice, OneStepKeyOperation},
    utils::{watchdog as wd, AesGcm, AndroidUserId, SecureUserId, AID_KEYSTORE},
};
use crate::plat::property_watcher::PropertyWatcher;
use anyhow::{Context, Result};
use log::{error, info, warn};
use std::{
    collections::HashMap,
    sync::Arc,
    sync::{Mutex, RwLock, Weak},
};
use std::{convert::TryFrom, ops::Deref};

const MAX_MAX_BOOT_LEVEL: BootLevel = BootLevel(1_000_000_000);

/// Allow up to 15 seconds between the user unlocking using a biometric, and the auth
/// token being used to unlock in [`SuperKeyManager::try_unlock_user_with_biometric`].
/// This seems short enough for security purposes, while long enough that even the
/// very slowest device will present the auth token in time.
const BIOMETRIC_AUTH_TIMEOUT_S: i32 = 15; // seconds

/// Specify which keys should be wiped given a particular user's UserSuperKeys
#[derive(PartialEq)]
pub enum WipeKeyOption {
    /// Wipe unlocked_device_required_symmetric/private and biometric_unlock keys
    PlaintextAndBiometric,
    /// Wipe only unlocked_device_required_symmetric/private keys
    PlaintextOnly,
}

/// Encryption algorithm used by a particular type of superencryption key
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperEncryptionAlgorithm {
    /// Symmetric encryption with AES-256-GCM
    Aes256Gcm,
    /// Public-key encryption with ECDH P-521
    EcdhP521,
}

/// A particular user may have several superencryption keys in the database, each for a
/// different purpose, distinguished by alias. Each is associated with a static
/// constant of this type.
pub struct SuperKeyType<'a> {
    /// Alias used to look up the key in the `persistent.keyentry` table.
    pub alias: &'a str,
    /// Encryption algorithm
    pub algorithm: SuperEncryptionAlgorithm,
    /// What to call this key in log messages. Not used for anything else.
    pub name: &'a str,
}

/// The user's CredentialEncrypted super key. This super key is loaded into memory when the user's
/// credential encrypted storage is unlocked. It remains in memory until the user's credential
/// encrypted storage is locked, through a device reboot or user logout. This is used to encrypt
/// keys that require user authentication but not an unlocked device.
pub const CREDENTIAL_ENCRYPTED_SUPER_KEY: SuperKeyType = SuperKeyType {
    alias: "USER_SUPER_KEY",
    algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
    name: "CredentialEncrypted super key",
};

/// The user's UnlockedDeviceRequired symmetric super key. This super key is loaded into memory each
/// time the user unlocks the device, and it is cleared from memory each time the user locks the
/// device. This is used to encrypt keys that use the UnlockedDeviceRequired key parameter.
pub const USER_UNLOCKED_DEVICE_REQUIRED_SYMMETRIC_SUPER_KEY: SuperKeyType = SuperKeyType {
    alias: "USER_SCREEN_LOCK_BOUND_KEY",
    algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
    name: "UnlockedDeviceRequired symmetric super key",
};

/// The user's UnlockedDeviceRequired asymmetric super key. This is used to allow, while the device
/// is locked, the creation of keys that use the UnlockedDeviceRequired key parameter. The private
/// part of this key is loaded and cleared when the symmetric key is loaded and cleared.
pub const USER_UNLOCKED_DEVICE_REQUIRED_P521_SUPER_KEY: SuperKeyType = SuperKeyType {
    alias: "USER_SCREEN_LOCK_BOUND_P521_KEY",
    algorithm: SuperEncryptionAlgorithm::EcdhP521,
    name: "UnlockedDeviceRequired asymmetric super key",
};

/// Superencryption to apply to a new key.
#[derive(Debug, Clone, Copy)]
pub enum SuperEncryptionType {
    /// Do not superencrypt this key.
    None,
    /// Superencrypt with the CredentialEncrypted super key.
    CredentialEncrypted,
    /// Superencrypt with an UnlockedDeviceRequired super key.
    UnlockedDeviceRequired,
    /// Superencrypt with a key based on the desired boot level
    BootLevel(BootLevel),
}

#[derive(Debug, Clone, Copy)]
pub enum SuperKeyIdentifier {
    /// id of the super key in the database.
    DatabaseId(i64),
    /// Boot level of the encrypting boot level key
    BootLevel(BootLevel),
}

impl SuperKeyIdentifier {
    fn from_metadata(metadata: &BlobMetaData) -> Option<Self> {
        if let Some(EncryptedBy::KeyId(key_id)) = metadata.encrypted_by() {
            Some(SuperKeyIdentifier::DatabaseId(*key_id))
        } else {
            metadata
                .max_boot_level()
                .map(|boot_level| SuperKeyIdentifier::BootLevel(BootLevel(*boot_level as usize)))
        }
    }

    fn add_to_metadata(&self, metadata: &mut BlobMetaData) {
        match self {
            SuperKeyIdentifier::DatabaseId(id) => {
                metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(*id)));
            }
            SuperKeyIdentifier::BootLevel(level) => {
                metadata.add(BlobMetaEntry::MaxBootLevel(level.0 as i32));
            }
        }
    }
}

pub struct SuperKey {
    algorithm: SuperEncryptionAlgorithm,
    key: ZVec,
    /// Identifier of the encrypting key, used to write an encrypted blob
    /// back to the database after re-encryption eg on a key update.
    id: SuperKeyIdentifier,
    /// ECDH is more expensive than AES. So on ECDH private keys we set the
    /// reencrypt_with field to point at the corresponding AES key, and the
    /// keys will be re-encrypted with AES on first use.
    reencrypt_with: Option<Arc<SuperKey>>,
}

impl AesGcm for SuperKey {
    fn decrypt(&self, data: &[u8], iv: &[u8], tag: &[u8]) -> Result<ZVec> {
        if self.algorithm == SuperEncryptionAlgorithm::Aes256Gcm {
            aes_gcm_decrypt(data, iv, tag, &self.key).context(ks_err!("Decryption failed."))
        } else {
            Err(Error::sys()).context(ks_err!("Key is not an AES key."))
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        if self.algorithm == SuperEncryptionAlgorithm::Aes256Gcm {
            aes_gcm_encrypt(plaintext, &self.key).context(ks_err!("Encryption failed."))
        } else {
            Err(Error::sys()).context(ks_err!("Key is not an AES key."))
        }
    }
}

/// A SuperKey that has been encrypted with an AES-GCM key. For
/// encryption the key is in memory, and for decryption it is in KM.
struct LockedKey {
    algorithm: SuperEncryptionAlgorithm,
    id: SuperKeyIdentifier,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>, // with tag appended
}

impl LockedKey {
    fn new(key: &[u8], to_encrypt: &Arc<SuperKey>) -> Result<Self> {
        let (mut ciphertext, nonce, mut tag) = aes_gcm_encrypt(&to_encrypt.key, key)?;
        ciphertext.append(&mut tag);
        Ok(LockedKey {
            algorithm: to_encrypt.algorithm,
            id: to_encrypt.id,
            nonce,
            ciphertext,
        })
    }

    fn decrypt(
        &self,
        db: &mut KeystoreDB,
        km_dev: &KeyMintDevice,
        key_id_guard: &KeyIdGuard,
        key_entry: &KeyEntry,
        auth_token: &HardwareAuthToken,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        let key_blob = key_entry
            .key_blob_info()
            .as_ref()
            .map(|(key_blob, _)| KeyBlob::Ref(key_blob))
            .ok_or(Error::Rc(ResponseCode::KEY_NOT_FOUND))
            .context(ks_err!("Missing key blob info."))?;
        let key_params = vec![
            KeyParameterValue::Algorithm(Algorithm::AES),
            KeyParameterValue::KeySize(256),
            KeyParameterValue::BlockMode(BlockMode::GCM),
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
            KeyParameterValue::Nonce(self.nonce.clone()),
            KeyParameterValue::MacLength(128),
        ];
        let key_params: Vec<KmKeyParameter> = key_params.into_iter().map(|x| x.into()).collect();
        let key = ZVec::try_from(km_dev.use_key_in_one_step(
            db,
            key_id_guard,
            OneStepKeyOperation {
                key_blob: &key_blob,
                purpose: KeyPurpose::DECRYPT,
                parameters: &key_params,
                auth_token: Some(auth_token),
                input: &self.ciphertext,
            },
        )?)?;
        Ok(Arc::new(SuperKey {
            algorithm: self.algorithm,
            key,
            id: self.id,
            reencrypt_with,
        }))
    }
}

/// A user's UnlockedDeviceRequired super keys, encrypted with a biometric-bound key, and
/// information about that biometric-bound key.
struct BiometricUnlock {
    /// List of auth token SIDs that are accepted by the encrypting biometric-bound key.
    sids: Vec<SecureUserId>,
    /// Key descriptor of the encrypting biometric-bound key.
    key_desc: KeyDescriptor,
    /// The UnlockedDeviceRequired super keys, encrypted with a biometric-bound key.
    symmetric: LockedKey,
    private: LockedKey,
}

#[derive(Default)]
struct UserSuperKeys {
    /// The CredentialEncrypted super key is used for synthetic password binding of authentication
    /// bound keys. There is one key per android user. The key is stored on flash encrypted with a
    /// key derived from a secret, that is itself derived from the user's synthetic password. (In
    /// most cases, the user's synthetic password can, in turn, only be decrypted using the user's
    /// Lock Screen Knowledge Factor or LSKF.) When the user logs into the device this key is
    /// unlocked, i.e., decrypted, and stays memory resident until the user logs out or the device
    /// reboots.
    credential_encrypted: Option<Arc<SuperKey>>,
    /// The UnlockedDeviceRequired symmetric super key works like the CredentialEncrypted super key
    /// with the distinction that it is cleared from memory when the device is locked.
    unlocked_device_required_symmetric: Option<Arc<SuperKey>>,
    /// When the device is locked, keys that use the UnlockedDeviceRequired key parameter can still
    /// be created, using ECDH public-key encryption. This field holds the decryption private key.
    unlocked_device_required_private: Option<Arc<SuperKey>>,
    /// Versions of the above two keys, locked behind a biometric.
    biometric_unlock: Option<BiometricUnlock>,
}

#[derive(Default)]
struct SkmState {
    user_keys: HashMap<AndroidUserId, UserSuperKeys>,
    key_index: HashMap<i64, Weak<SuperKey>>,
    boot_level_key_cache: Option<Mutex<BootLevelKeyCache>>,
    legacy_boot_level_key_cache: Mutex<Option<LegacyBootLevelKeyCache>>,
}

impl SkmState {
    fn add_key_to_key_index(&mut self, super_key: &Arc<SuperKey>) -> Result<()> {
        if let SuperKeyIdentifier::DatabaseId(id) = super_key.id {
            self.key_index.insert(id, Arc::downgrade(super_key));
            Ok(())
        } else {
            Err(Error::sys()).context(ks_err!("Cannot add key with ID {:?}", super_key.id))
        }
    }
}

#[derive(Default)]
pub struct SuperKeyManager {
    data: SkmState,
}

impl SuperKeyManager {
    pub fn set_up_boot_level_cache(skm: &Arc<RwLock<Self>>, db: &mut KeystoreDB) -> Result<()> {
        let mut skm_guard = skm.write().unwrap();
        if skm_guard.data.boot_level_key_cache.is_some() {
            info!("In set_up_boot_level_cache: called for a second time");
            return Ok(());
        }
        let level_zero_key =
            get_level_zero_key(db).context(ks_err!("get_level_zero_key failed"))?;
        let legacy_level_zero_key = level_zero_key.try_clone();
        skm_guard.data.boot_level_key_cache =
            Some(Mutex::new(BootLevelKeyCache::new(level_zero_key)));
        *skm_guard
            .data
            .legacy_boot_level_key_cache
            .get_mut()
            .unwrap() = match legacy_level_zero_key {
            Ok(key) => Some(LegacyBootLevelKeyCache::new(key)),
            Err(error) => {
                warn!("failed to initialize legacy boot-level cache: {error:?}");
                None
            }
        };
        info!("Starting boot level watcher.");
        let clone = skm.clone();
        std::thread::spawn(move || {
            Self::watch_boot_level(clone)
                .unwrap_or_else(|e| error!("watch_boot_level failed: {e:?}"));
        });
        Ok(())
    }

    /// Watch the `keystore.boot_level` system property, and keep boot level up to date.
    /// Blocks waiting for system property changes, so must be run in its own thread.
    fn watch_boot_level(skm: Arc<RwLock<Self>>) -> Result<()> {
        let w = PropertyWatcher::new("keystore.boot_level")
            .context(ks_err!("PropertyWatcher::new failed"))?;
        loop {
            let level = w
                .read_and_parse(|v| Ok(BootLevel(v.parse::<usize>()?)))
                .context(ks_err!("read of property failed"))?;

            // This scope limits the skm_guard life, so we don't hold the skm_guard while
            // waiting.
            {
                let mut skm_guard = skm.write().unwrap();
                let boot_level_key_cache = skm_guard
                    .data
                    .boot_level_key_cache
                    .as_mut()
                    .ok_or_else(Error::sys)
                    .context(ks_err!("Boot level cache not initialized"))?
                    .get_mut()
                    .unwrap();
                if level < MAX_MAX_BOOT_LEVEL {
                    info!("Read keystore.boot_level value {level:?}");
                    boot_level_key_cache
                        .advance_boot_level(level)
                        .context(ks_err!("advance_boot_level failed"))?;
                    let legacy_cache = skm_guard
                        .data
                        .legacy_boot_level_key_cache
                        .get_mut()
                        .unwrap();
                    let legacy_result = legacy_cache
                        .as_mut()
                        .map(|cache| cache.advance_boot_level(level));
                    if let Some(Err(error)) = legacy_result {
                        error!(
                            "legacy boot-level cache failed to advance and was disabled: {error:?}"
                        );
                        if let Some(mut cache) = legacy_cache.take() {
                            cache.finish();
                        }
                    }
                } else {
                    info!(
                        "keystore.boot_level {level:?} hits maximum {MAX_MAX_BOOT_LEVEL:?}, finishing.",
                    );
                    boot_level_key_cache.finish();
                    if let Some(mut legacy_cache) = skm_guard
                        .data
                        .legacy_boot_level_key_cache
                        .get_mut()
                        .unwrap()
                        .take()
                    {
                        legacy_cache.finish();
                    }
                    break;
                }
            }
            w.wait(None).context(ks_err!("property wait failed"))?;
        }
        Ok(())
    }

    pub fn level_accessible(&self, boot_level: BootLevel) -> bool {
        self.data
            .boot_level_key_cache
            .as_ref()
            .is_some_and(|c| c.lock().unwrap().level_accessible(boot_level))
    }

    pub fn forget_all_keys_for_user(&mut self, user: AndroidUserId) {
        self.data.user_keys.remove(&user);
    }

    fn install_credential_encrypted_key_for_user(
        &mut self,
        user: AndroidUserId,
        super_key: Arc<SuperKey>,
    ) -> Result<()> {
        self.data
            .add_key_to_key_index(&super_key)
            .context(ks_err!("add_key_to_key_index failed"))?;
        self.data
            .user_keys
            .entry(user)
            .or_default()
            .credential_encrypted = Some(super_key);
        Ok(())
    }

    fn lookup_key(&self, key_id: &SuperKeyIdentifier) -> Result<Option<Arc<SuperKey>>> {
        Ok(match key_id {
            SuperKeyIdentifier::DatabaseId(id) => {
                self.data.key_index.get(id).and_then(|k| k.upgrade())
            }
            SuperKeyIdentifier::BootLevel(level) => self
                .data
                .boot_level_key_cache
                .as_ref()
                .map(|b| b.lock().unwrap().aes_key(*level))
                .transpose()
                .context(ks_err!("aes_key failed"))?
                .flatten()
                .map(|key| {
                    Arc::new(SuperKey {
                        algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
                        key,
                        id: *key_id,
                        reencrypt_with: None,
                    })
                }),
        })
    }

    /// Returns the CredentialEncrypted superencryption key for the given user ID, or None if the
    /// user has not yet unlocked the device since boot.
    pub fn get_credential_encrypted_key_by_user_id(
        &self,
        user: AndroidUserId,
    ) -> Option<Arc<dyn AesGcm + Send + Sync>> {
        self.get_credential_encrypted_key_by_user_id_internal(user)
            .map(|sk| -> Arc<dyn AesGcm + Send + Sync> { sk })
    }

    fn get_credential_encrypted_key_by_user_id_internal(
        &self,
        user: AndroidUserId,
    ) -> Option<Arc<SuperKey>> {
        self.data
            .user_keys
            .get(&user)
            .and_then(|e| e.credential_encrypted.as_ref().cloned())
    }

    /// Check if a given key is super-encrypted, from its metadata. If so, unwrap the key using
    /// the relevant super key.
    pub fn unwrap_key_if_required<'a>(
        &self,
        metadata: &BlobMetaData,
        blob: &'a [u8],
    ) -> Result<KeyBlob<'a>> {
        Ok(
            if let Some(key_id) = SuperKeyIdentifier::from_metadata(metadata) {
                let super_key = self
                    .lookup_key(&key_id)
                    .context(ks_err!("lookup_key failed"))?
                    .ok_or(Error::Rc(ResponseCode::LOCKED))
                    .context(ks_err!("Required super decryption key is not in memory."))?;
                KeyBlob::Sensitive {
                    key: Self::unwrap_key_with_key(blob, metadata, &super_key)
                        .context(ks_err!("unwrap_key_with_key failed"))?,
                    reencrypt_with: super_key
                        .reencrypt_with
                        .as_ref()
                        .unwrap_or(&super_key)
                        .clone(),
                    force_reencrypt: super_key.reencrypt_with.is_some(),
                }
            } else {
                KeyBlob::Ref(blob)
            },
        )
    }

    pub fn unwrap_key_if_required_with_omk_compatibility<'a>(
        &self,
        metadata: &BlobMetaData,
        blob: &'a [u8],
    ) -> Result<KeyBlob<'a>> {
        let aosp_error = match self.unwrap_key_if_required(metadata, blob) {
            Ok(key_blob) => return Ok(key_blob),
            Err(error) => error,
        };
        if !is_decryption_failure(&aosp_error) {
            return Err(aosp_error);
        }

        match self.try_unwrap_key_with_omk_legacy(metadata, blob) {
            Ok(Some(key_blob)) => Ok(key_blob),
            Ok(None) | Err(_) => Err(aosp_error),
        }
    }

    fn try_unwrap_key_with_omk_legacy<'a>(
        &self,
        metadata: &BlobMetaData,
        blob: &'a [u8],
    ) -> Result<Option<KeyBlob<'a>>> {
        let Some(key_id) = SuperKeyIdentifier::from_metadata(metadata) else {
            return Ok(None);
        };
        let Some(super_key) = self
            .lookup_key(&key_id)
            .context(ks_err!("lookup_key failed"))?
        else {
            return Ok(None);
        };

        let key = match key_id {
            SuperKeyIdentifier::BootLevel(level) => {
                let legacy_key = {
                    let mut legacy_cache = self.data.legacy_boot_level_key_cache.lock().unwrap();
                    let Some(cache) = legacy_cache.as_mut() else {
                        return Ok(None);
                    };
                    match cache.aes_key(level) {
                        Ok(Some(key)) => key,
                        Ok(None) => return Ok(None),
                        Err(error) => {
                            error!("legacy boot-level cache failed and was disabled: {error:?}");
                            if let Some(mut cache) = legacy_cache.take() {
                                cache.finish();
                            }
                            return Ok(None);
                        }
                    }
                };
                let legacy_super_key = SuperKey {
                    algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
                    key: legacy_key,
                    id: key_id,
                    reencrypt_with: None,
                };
                match Self::unwrap_key_with_key(blob, metadata, &legacy_super_key) {
                    Ok(key) => key,
                    Err(_) => return Ok(None),
                }
            }
            SuperKeyIdentifier::DatabaseId(_)
                if super_key.algorithm == SuperEncryptionAlgorithm::EcdhP521 =>
            {
                let (Some(public_key), Some(salt), Some(iv), Some(aead_tag)) = (
                    metadata.public_key(),
                    metadata.salt(),
                    metadata.iv(),
                    metadata.aead_tag(),
                ) else {
                    return Ok(None);
                };
                match ECDHPrivateKey::from_private_key(&super_key.key).and_then(|key| {
                    key.decrypt_message_omk_legacy(public_key, salt, iv, blob, aead_tag)
                }) {
                    Ok(key) => key,
                    Err(_) => return Ok(None),
                }
            }
            _ => return Ok(None),
        };

        Ok(Some(KeyBlob::Sensitive {
            key,
            reencrypt_with: super_key
                .reencrypt_with
                .as_ref()
                .unwrap_or(&super_key)
                .clone(),
            force_reencrypt: matches!(key_id, SuperKeyIdentifier::BootLevel(_))
                || super_key.reencrypt_with.is_some(),
        }))
    }

    /// Unwraps an encrypted key blob given an encryption key.
    fn unwrap_key_with_key(blob: &[u8], metadata: &BlobMetaData, key: &SuperKey) -> Result<ZVec> {
        match key.algorithm {
            SuperEncryptionAlgorithm::Aes256Gcm => match (metadata.iv(), metadata.aead_tag()) {
                (Some(iv), Some(tag)) => key
                    .decrypt(blob, iv, tag)
                    .context(ks_err!("Failed to decrypt the key blob.")),
                (iv, tag) => Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(ks_err!(
                    "Key has incomplete metadata. Present: iv: {}, aead_tag: {}.",
                    iv.is_some(),
                    tag.is_some(),
                )),
            },
            SuperEncryptionAlgorithm::EcdhP521 => {
                match (
                    metadata.public_key(),
                    metadata.salt(),
                    metadata.iv(),
                    metadata.aead_tag(),
                ) {
                    (Some(public_key), Some(salt), Some(iv), Some(aead_tag)) => {
                        ECDHPrivateKey::from_private_key(&key.key)
                            .and_then(|k| k.decrypt_message(public_key, salt, iv, blob, aead_tag))
                            .context(ks_err!("Failed to decrypt the key blob with ECDH."))
                    }
                    (public_key, salt, iv, aead_tag) => {
                        Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(ks_err!(
                            concat!(
                                "Key has incomplete metadata. ",
                                "Present: public_key: {}, salt: {}, iv: {}, aead_tag: {}."
                            ),
                            public_key.is_some(),
                            salt.is_some(),
                            iv.is_some(),
                            aead_tag.is_some(),
                        ))
                    }
                }
            }
        }
    }

    /// Checks if the user's CredentialEncrypted super key exists in the database (or legacy database).
    /// The reference to self is unused but it is required to prevent calling this function
    /// concurrently with skm state database changes.
    fn super_key_exists_in_db_for_user(
        &self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
    ) -> Result<bool> {
        db.key_exists(
            Domain::APP,
            user.0 as i64,
            CREDENTIAL_ENCRYPTED_SUPER_KEY.alias,
            KeyType::Super,
        )
        .context(ks_err!())
    }

    // Helper function to populate super key cache from the super key blob loaded from the database.
    fn populate_cache_from_super_key_blob(
        &mut self,
        user: AndroidUserId,
        algorithm: SuperEncryptionAlgorithm,
        entry: KeyEntry,
        pw: &Password,
    ) -> Result<Arc<SuperKey>> {
        let super_key = Self::extract_super_key_from_key_entry_with_omk_compatibility(
            algorithm, entry, pw, None,
        )
        .context(ks_err!("Failed to extract super key from key entry"))?;
        self.install_credential_encrypted_key_for_user(user, super_key.clone())
            .context(ks_err!(
                "Failed to install CredentialEncrypted super key for user!"
            ))?;
        Ok(super_key)
    }

    /// Extracts super key from the entry loaded from the database.
    pub fn extract_super_key_from_key_entry(
        algorithm: SuperEncryptionAlgorithm,
        entry: KeyEntry,
        pw: &Password,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        if let Some((blob, metadata)) = entry.key_blob_info() {
            let key = match (
                metadata.encrypted_by(),
                metadata.salt(),
                metadata.iv(),
                metadata.aead_tag(),
            ) {
                (Some(&EncryptedBy::Password), Some(salt), Some(iv), Some(tag)) => {
                    // Note that password encryption is AES no matter the value of algorithm.
                    let key = pw
                        .derive_key_hkdf(salt, AES_256_KEY_LENGTH)
                        .context(ks_err!("Failed to derive key from password."))?;

                    aes_gcm_decrypt(blob, iv, tag, &key).or_else(|_e| {
                        // Handle old key stored before the switch to HKDF.
                        let key = pw
                            .derive_key_pbkdf2(salt, AES_256_KEY_LENGTH)
                            .context(ks_err!("Failed to derive key from password (PBKDF2)."))?;
                        aes_gcm_decrypt(blob, iv, tag, &key)
                            .context(ks_err!("Failed to decrypt key blob."))
                    })?
                }
                (enc_by, salt, iv, tag) => {
                    return Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(ks_err!(
                        concat!(
                            "Super key has incomplete metadata.",
                            "encrypted_by: {:?}; Present: salt: {}, iv: {}, aead_tag: {}."
                        ),
                        enc_by,
                        salt.is_some(),
                        iv.is_some(),
                        tag.is_some()
                    ));
                }
            };
            Ok(Arc::new(SuperKey {
                algorithm,
                key,
                id: SuperKeyIdentifier::DatabaseId(entry.id()),
                reencrypt_with,
            }))
        } else {
            Err(Error::Rc(ResponseCode::VALUE_CORRUPTED)).context(ks_err!("No key blob info."))
        }
    }

    pub(crate) fn extract_super_key_from_key_entry_with_omk_compatibility(
        algorithm: SuperEncryptionAlgorithm,
        entry: KeyEntry,
        pw: &Password,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        let legacy_input = entry.key_blob_info().as_ref().and_then(|(blob, metadata)| {
            match (
                metadata.encrypted_by(),
                metadata.salt(),
                metadata.iv(),
                metadata.aead_tag(),
            ) {
                (Some(&EncryptedBy::Password), Some(salt), Some(iv), Some(tag)) => Some((
                    entry.id(),
                    blob.clone(),
                    salt.to_vec(),
                    iv.to_vec(),
                    tag.to_vec(),
                )),
                _ => None,
            }
        });
        let legacy_reencrypt_with = reencrypt_with.clone();

        let aosp_error =
            match Self::extract_super_key_from_key_entry(algorithm, entry, pw, reencrypt_with) {
                Ok(super_key) => return Ok(super_key),
                Err(error) => error,
            };
        if !is_decryption_failure(&aosp_error) {
            return Err(aosp_error);
        }

        let Some((id, blob, salt, iv, tag)) = legacy_input else {
            return Err(aosp_error);
        };
        let key = match pw
            .derive_key_omk_legacy(&salt, AES_256_KEY_LENGTH)
            .and_then(|key| aes_gcm_decrypt(&blob, &iv, &tag, &key))
        {
            Ok(key) => key,
            Err(_) => return Err(aosp_error),
        };
        Ok(Arc::new(SuperKey {
            algorithm,
            key,
            id: SuperKeyIdentifier::DatabaseId(id),
            reencrypt_with: legacy_reencrypt_with,
        }))
    }

    /// Encrypts the super key from a key derived from the password, before storing in the database.
    /// This does not stretch the password; i.e., it assumes that the password is a high-entropy
    /// synthetic password, not a low-entropy user provided password.
    pub fn encrypt_with_password(
        super_key: &[u8],
        pw: &Password,
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        let salt = generate_salt().context("In encrypt_with_password: Failed to generate salt.")?;
        let derived_key = pw
            .derive_key_hkdf(&salt, AES_256_KEY_LENGTH)
            .context(ks_err!("Failed to derive key from password."))?;
        let mut metadata = BlobMetaData::new();
        metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
        metadata.add(BlobMetaEntry::Salt(salt));
        let (encrypted_key, iv, tag) = aes_gcm_encrypt(super_key, &derived_key)
            .context(ks_err!("Failed to encrypt new super key."))?;
        metadata.add(BlobMetaEntry::Iv(iv));
        metadata.add(BlobMetaEntry::AeadTag(tag));
        Ok((encrypted_key, metadata))
    }

    // Helper function to encrypt a key with the given super key. Callers should select which super
    // key to be used. This is called when a key is super encrypted at its creation as well as at
    // its upgrade.
    fn encrypt_with_aes_super_key(
        key_blob: &[u8],
        super_key: &SuperKey,
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        if super_key.algorithm != SuperEncryptionAlgorithm::Aes256Gcm {
            return Err(Error::sys()).context(ks_err!("unexpected algorithm"));
        }
        let mut metadata = BlobMetaData::new();
        let (encrypted_key, iv, tag) = aes_gcm_encrypt(key_blob, &(super_key.key))
            .context(ks_err!("Failed to encrypt new super key."))?;
        metadata.add(BlobMetaEntry::Iv(iv));
        metadata.add(BlobMetaEntry::AeadTag(tag));
        super_key.id.add_to_metadata(&mut metadata);
        Ok((encrypted_key, metadata))
    }

    // Encrypts a given key_blob using a hybrid approach, which can either use the symmetric super
    // key or the public super key depending on which is available.
    //
    // If the symmetric_key is available, the key_blob is encrypted using symmetric encryption with
    // the provided symmetric super key.  Otherwise, the function loads the public super key from
    // the KeystoreDB and encrypts the key_blob using ECDH encryption and marks the keyblob to be
    // re-encrypted with the symmetric super key on the first use.
    //
    // This hybrid scheme allows keys that use the UnlockedDeviceRequired key parameter to be
    // created while the device is locked.
    fn encrypt_with_hybrid_super_key(
        key_blob: &[u8],
        symmetric_key: Option<&SuperKey>,
        public_key_type: &SuperKeyType,
        db: &mut KeystoreDB,
        user: AndroidUserId,
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        if let Some(super_key) = symmetric_key {
            Self::encrypt_with_aes_super_key(key_blob, super_key).context(ks_err!(
                "Failed to encrypt with UnlockedDeviceRequired symmetric super key."
            ))
        } else {
            // Symmetric key is not available, use public key encryption
            let loaded = db
                .load_super_key(public_key_type, user)
                .context(ks_err!("load_super_key failed."))?;
            let (key_id_guard, key_entry) = loaded
                .ok_or_else(Error::sys)
                .context(ks_err!("User ECDH super key missing."))?;
            let public_key = key_entry
                .metadata()
                .sec1_public_key()
                .ok_or_else(Error::sys)
                .context(ks_err!("sec1_public_key missing."))?;
            let mut metadata = BlobMetaData::new();
            let (ephem_key, salt, iv, encrypted_key, aead_tag) =
                ECDHPrivateKey::encrypt_message(public_key, key_blob)
                    .context(ks_err!("ECDHPrivateKey::encrypt_message failed."))?;
            metadata.add(BlobMetaEntry::PublicKey(ephem_key));
            metadata.add(BlobMetaEntry::Salt(salt));
            metadata.add(BlobMetaEntry::Iv(iv));
            metadata.add(BlobMetaEntry::AeadTag(aead_tag));
            SuperKeyIdentifier::DatabaseId(key_id_guard.id()).add_to_metadata(&mut metadata);
            Ok((encrypted_key, metadata))
        }
    }

    /// Check if super encryption is required and if so, super-encrypt the key to be stored in
    /// the database.
    #[allow(clippy::too_many_arguments)]
    pub fn handle_super_encryption_on_key_init(
        &self,
        db: &mut KeystoreDB,
        domain: &Domain,
        key_parameters: &[KeyParameter],
        flags: Option<i32>,
        user: AndroidUserId,
        key_blob: &[u8],
    ) -> Result<(Vec<u8>, BlobMetaData)> {
        match Enforcements::super_encryption_required(domain, key_parameters, flags) {
            SuperEncryptionType::None => Ok((key_blob.to_vec(), BlobMetaData::new())),
            SuperEncryptionType::CredentialEncrypted => {
                // Encrypt the given key blob with the user's CredentialEncrypted super key. If the
                // user has not logged in or the super keys were never initialized for the user for
                // some reason, an error is returned.
                match self
                    .get_user_state(db, user)
                    .context(ks_err!("Failed to get user state for {user:?}"))?
                {
                    UserState::CeUnlocked(super_key) => {
                        Self::encrypt_with_aes_super_key(key_blob, &super_key).context(ks_err!(
                            "Failed to encrypt with CredentialEncrypted super key for {user:?}"
                        ))
                    }
                    UserState::CeLocked => {
                        Err(Error::Rc(ResponseCode::LOCKED)).context(ks_err!("Device is locked."))
                    }
                    UserState::Uninitialized => Err(Error::Rc(ResponseCode::UNINITIALIZED))
                        .context(ks_err!("User {user:?} does not have super keys")),
                }
            }
            SuperEncryptionType::UnlockedDeviceRequired => {
                let symmetric_key = self
                    .data
                    .user_keys
                    .get(&user)
                    .and_then(|e| e.unlocked_device_required_symmetric.as_ref())
                    .map(|arc| arc.as_ref());
                Self::encrypt_with_hybrid_super_key(
                    key_blob,
                    symmetric_key,
                    &USER_UNLOCKED_DEVICE_REQUIRED_P521_SUPER_KEY,
                    db,
                    user,
                )
                .context(ks_err!(
                    "Failed to encrypt with UnlockedDeviceRequired hybrid scheme."
                ))
            }
            SuperEncryptionType::BootLevel(level) => {
                let key_id = SuperKeyIdentifier::BootLevel(level);
                let super_key = self
                    .lookup_key(&key_id)
                    .context(ks_err!("lookup_key failed"))?
                    .ok_or(Error::Rc(ResponseCode::LOCKED))
                    .context(ks_err!("Boot stage key absent"))?;
                Self::encrypt_with_aes_super_key(key_blob, &super_key)
                    .context(ks_err!("Failed to encrypt with BootLevel key."))
            }
        }
    }

    /// Check if a given key needs re-super-encryption, from its KeyBlob type.
    /// If so, re-super-encrypt the key and return a new set of metadata,
    /// containing the new super encryption information.
    pub fn reencrypt_if_required<'a>(
        key_blob_before_upgrade: &KeyBlob,
        key_after_upgrade: &'a [u8],
    ) -> Result<(KeyBlob<'a>, Option<BlobMetaData>)> {
        match key_blob_before_upgrade {
            KeyBlob::Sensitive {
                reencrypt_with: super_key,
                ..
            } => {
                let (key, metadata) =
                    Self::encrypt_with_aes_super_key(key_after_upgrade, super_key)
                        .context(ks_err!("Failed to re-super-encrypt key."))?;
                Ok((KeyBlob::NonSensitive(key), Some(metadata)))
            }
            _ => Ok((KeyBlob::Ref(key_after_upgrade), None)),
        }
    }

    fn create_super_key(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        key_type: &SuperKeyType,
        password: &Password,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        info!("Creating {} for {user:?}", key_type.name);
        let (super_key, public_key) = match key_type.algorithm {
            SuperEncryptionAlgorithm::Aes256Gcm => (
                generate_aes256_key().context(ks_err!("Failed to generate AES-256 key."))?,
                None,
            ),
            SuperEncryptionAlgorithm::EcdhP521 => {
                let key =
                    ECDHPrivateKey::generate().context(ks_err!("Failed to generate ECDH key"))?;
                (
                    key.private_key().context(ks_err!("private_key failed"))?,
                    Some(key.public_key().context(ks_err!("public_key failed"))?),
                )
            }
        };
        // Derive an AES-256 key from the password and re-encrypt the super key before we insert it
        // in the database.
        let (encrypted_super_key, blob_metadata) =
            Self::encrypt_with_password(&super_key, password).context(ks_err!())?;
        let mut key_metadata = KeyMetaData::new();
        if let Some(pk) = public_key {
            key_metadata.add(KeyMetaEntry::Sec1PublicKey(pk));
        }
        let key_entry = db
            .store_super_key(
                user,
                key_type,
                &encrypted_super_key,
                &blob_metadata,
                &key_metadata,
            )
            .context(ks_err!("Failed to store super key."))?;
        Ok(Arc::new(SuperKey {
            algorithm: key_type.algorithm,
            key: super_key,
            id: SuperKeyIdentifier::DatabaseId(key_entry.id()),
            reencrypt_with,
        }))
    }

    /// Fetch a superencryption key from the database, or create it if it doesn't already exist.
    /// When this is called, the caller must hold the lock on the SuperKeyManager.
    /// So it's OK that the check and creation are different DB transactions.
    fn get_or_create_super_key(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        key_type: &SuperKeyType,
        password: &Password,
        reencrypt_with: Option<Arc<SuperKey>>,
    ) -> Result<Arc<SuperKey>> {
        let loaded_key = db.load_super_key(key_type, user)?;
        if let Some((_, key_entry)) = loaded_key {
            Ok(
                Self::extract_super_key_from_key_entry_with_omk_compatibility(
                    key_type.algorithm,
                    key_entry,
                    password,
                    reencrypt_with,
                )?,
            )
        } else {
            self.create_super_key(db, user, key_type, password, reencrypt_with)
        }
    }

    /// Decrypt the UnlockedDeviceRequired super keys for this user using the password and store
    /// them in memory. If these keys don't exist yet, create them.
    pub fn unlock_unlocked_device_required_keys(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        password: &Password,
    ) -> Result<()> {
        let (symmetric, private) = self
            .data
            .user_keys
            .get(&user)
            .map(|e| {
                (
                    e.unlocked_device_required_symmetric.clone(),
                    e.unlocked_device_required_private.clone(),
                )
            })
            .unwrap_or((None, None));

        if symmetric.is_some() && private.is_some() {
            // Already unlocked.
            return Ok(());
        }

        let aes = if let Some(symmetric) = symmetric {
            // This is weird. If this point is reached only one of the UnlockedDeviceRequired super
            // keys was initialized. This should never happen.
            symmetric
        } else {
            self.get_or_create_super_key(
                db,
                user,
                &USER_UNLOCKED_DEVICE_REQUIRED_SYMMETRIC_SUPER_KEY,
                password,
                None,
            )
            .context(ks_err!("Trying to get or create symmetric key."))?
        };

        let ecdh = if let Some(private) = private {
            // This is weird. If this point is reached only one of the UnlockedDeviceRequired super
            // keys was initialized. This should never happen.
            private
        } else {
            self.get_or_create_super_key(
                db,
                user,
                &USER_UNLOCKED_DEVICE_REQUIRED_P521_SUPER_KEY,
                password,
                Some(aes.clone()),
            )
            .context(ks_err!("Trying to get or create asymmetric key."))?
        };

        self.data.add_key_to_key_index(&aes)?;
        self.data.add_key_to_key_index(&ecdh)?;
        let entry = self.data.user_keys.entry(user).or_default();
        entry.unlocked_device_required_symmetric = Some(aes);
        entry.unlocked_device_required_private = Some(ecdh);
        Ok(())
    }

    /// Protects the user's UnlockedDeviceRequired super keys in a way such that they can only be
    /// unlocked by the enabled unlock methods.
    pub fn lock_unlocked_device_required_keys(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        unlocking_sids: &[SecureUserId],
        weak_unlock_enabled: bool,
    ) {
        let entry = self.data.user_keys.entry(user).or_default();
        if unlocking_sids.is_empty() {
            entry.biometric_unlock = None;
        } else if let (Some(aes), Some(ecdh)) = (
            entry.unlocked_device_required_symmetric.as_ref().cloned(),
            entry.unlocked_device_required_private.as_ref().cloned(),
        ) {
            // If class 3 biometric unlock methods are enabled, create a biometric-encrypted copy of
            // the keys.  Do this even if weak unlock methods are enabled too; in that case we'll
            // also retain a plaintext copy of the keys, but that copy will be wiped later if weak
            // unlock methods expire.  So we need the biometric-encrypted copy too just in case.
            let res = (|| -> Result<()> {
                let key_desc =
                    KeyMintDevice::internal_descriptor(format!("biometric_unlock_key_{}", user.0));
                let encrypting_key = generate_aes256_key()?;
                let km_dev: KeyMintDevice = KeyMintDevice::get(SecurityLevel::TRUSTED_ENVIRONMENT)
                    .context(ks_err!("KeyMintDevice::get failed"))?;
                let mut key_params = vec![
                    KeyParameterValue::Algorithm(Algorithm::AES),
                    KeyParameterValue::KeySize(256),
                    KeyParameterValue::BlockMode(BlockMode::GCM),
                    KeyParameterValue::PaddingMode(PaddingMode::NONE),
                    KeyParameterValue::CallerNonce,
                    KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
                    KeyParameterValue::MinMacLength(128),
                    KeyParameterValue::AuthTimeout(BIOMETRIC_AUTH_TIMEOUT_S),
                    KeyParameterValue::HardwareAuthenticatorType(
                        HardwareAuthenticatorType::FINGERPRINT,
                    ),
                ];
                for sid in unlocking_sids {
                    key_params.push(KeyParameterValue::UserSecureID(sid.0));
                }
                let key_params: Vec<KmKeyParameter> =
                    key_params.into_iter().map(|x| x.into()).collect();
                km_dev.create_and_store_key(
                    db,
                    &key_desc,
                    KeyType::Client, /* TODO Should be Super b/189470584 */
                    |dev| {
                        let _wp =
                            wd::watch("SKM::lock_unlocked_device_required_keys: calling IKeyMintDevice::importKey.");
                        dev.importKey(key_params.as_slice(), KeyFormat::RAW, &encrypting_key, None)
                    },
                )?;
                entry.biometric_unlock = Some(BiometricUnlock {
                    sids: unlocking_sids.into(),
                    key_desc,
                    symmetric: LockedKey::new(&encrypting_key, &aes)?,
                    private: LockedKey::new(&encrypting_key, &ecdh)?,
                });
                Ok(())
            })();
            if let Err(e) = res {
                error!("Error setting up biometric unlock: {e:#?}");
                // The caller can't do anything about the error, and for security reasons we still
                // wipe the keys (unless a weak unlock method is enabled).  So just log the error.
            }
        }
        // Wipe the plaintext copy of the keys, unless a weak unlock method is enabled.
        if weak_unlock_enabled {
            Self::log_status_of_unlocked_device_required_keys(user, entry);
        } else {
            Self::wipe_unlocked_device_required_keys_internal(
                user,
                entry,
                WipeKeyOption::PlaintextOnly,
            )
        }
    }

    pub fn wipe_unlocked_device_required_keys(
        &mut self,
        user: AndroidUserId,
        wipe_key: WipeKeyOption,
    ) {
        let entry = self.data.user_keys.entry(user).or_default();
        Self::wipe_unlocked_device_required_keys_internal(user, entry, wipe_key);
    }

    fn wipe_unlocked_device_required_keys_internal(
        user: AndroidUserId,
        entry: &mut UserSuperKeys,
        wipe_key: WipeKeyOption,
    ) {
        entry.unlocked_device_required_symmetric = None;
        entry.unlocked_device_required_private = None;
        if wipe_key == WipeKeyOption::PlaintextAndBiometric {
            entry.biometric_unlock = None;
        }
        Self::log_status_of_unlocked_device_required_keys(user, entry);
    }

    fn log_status_of_unlocked_device_required_keys(user: AndroidUserId, entry: &UserSuperKeys) {
        let status = match (
            // Note: the status of the symmetric and private keys should always be in sync.
            // So we only check one here.
            entry.unlocked_device_required_symmetric.is_some(),
            entry.biometric_unlock.is_some(),
        ) {
            (false, false) => "fully protected",
            (false, true) => "biometric-encrypted",
            (true, false) => "retained in plaintext",
            (true, true) => "retained in plaintext, with biometric-encrypted copy too",
        };
        info!("UnlockedDeviceRequired super keys for {user:?} are {status}");
    }

    /// User has unlocked, not using a password. See if any of our stored auth tokens can be used
    /// to unlock the keys protecting UNLOCKED_DEVICE_REQUIRED keys.
    pub fn try_unlock_user_with_biometric(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
    ) -> Result<()> {
        let entry = self.data.user_keys.entry(user).or_default();
        if entry.unlocked_device_required_symmetric.is_some()
            && entry.unlocked_device_required_private.is_some()
        {
            // If the keys are already cached in plaintext, then there is no need to decrypt the
            // biometric-encrypted copy.  Both copies can be present here if the user has both
            // class 3 biometric and weak unlock methods enabled, and the device was unlocked before
            // the weak unlock methods expired.
            return Ok(());
        }
        if let Some(biometric) = entry.biometric_unlock.as_ref() {
            let (key_id_guard, key_entry) = db
                .load_key_entry(
                    &biometric.key_desc,
                    KeyType::Client, // This should not be a Client key.
                    KeyEntryLoadBits::KM,
                    AID_KEYSTORE,
                    |_, _| Ok(()),
                )
                .context(ks_err!("load_key_entry failed"))?;
            let km_dev: KeyMintDevice = KeyMintDevice::get(SecurityLevel::TRUSTED_ENVIRONMENT)
                .context(ks_err!("KeyMintDevice::get failed"))?;
            let mut errs = vec![];
            for sid in &biometric.sids {
                let sid = *sid;
                if let Some(auth_token_entry) = db.find_auth_token_entry(|entry| {
                    entry.auth_token().userId == sid.0
                        || entry.auth_token().authenticatorId == sid.0
                }) {
                    let res: Result<(Arc<SuperKey>, Arc<SuperKey>)> = (|| {
                        let symmetric = biometric.symmetric.decrypt(
                            db,
                            &km_dev,
                            &key_id_guard,
                            &key_entry,
                            auth_token_entry.auth_token(),
                            None,
                        )?;
                        let private = biometric.private.decrypt(
                            db,
                            &km_dev,
                            &key_id_guard,
                            &key_entry,
                            auth_token_entry.auth_token(),
                            Some(symmetric.clone()),
                        )?;
                        Ok((symmetric, private))
                    })();
                    match res {
                        Ok((symmetric, private)) => {
                            entry.unlocked_device_required_symmetric = Some(symmetric.clone());
                            entry.unlocked_device_required_private = Some(private.clone());
                            self.data.add_key_to_key_index(&symmetric)?;
                            self.data.add_key_to_key_index(&private)?;
                            info!("Successfully unlocked {user:?} with biometric {sid:?}",);
                            return Ok(());
                        }
                        Err(e) => {
                            // Don't log an error yet, as some other biometric SID might work.
                            errs.push((sid, e));
                        }
                    }
                }
            }
            if !errs.is_empty() {
                warn!("biometric unlock failed for all SIDs, with errors:");
                for (sid, err) in errs {
                    warn!("  biometric {sid:?}: {err}");
                }
            }
        }
        Ok(())
    }

    /// Returns the keystore locked state of the given user. It requires the thread local
    /// keystore database and a reference to the legacy migrator because it may need to
    /// import the super key from the legacy blob database to the keystore database.
    pub fn get_user_state(&self, db: &mut KeystoreDB, user: AndroidUserId) -> Result<UserState> {
        match self.get_credential_encrypted_key_by_user_id_internal(user) {
            Some(super_key) => Ok(UserState::CeUnlocked(super_key)),
            None => {
                // Check if a super key exists in the database or legacy database.
                // If so, return locked user state.
                if self
                    .super_key_exists_in_db_for_user(db, user)
                    .context(ks_err!())?
                {
                    Ok(UserState::CeLocked)
                } else {
                    Ok(UserState::Uninitialized)
                }
            }
        }
    }

    /// Deletes all keys and super keys for the given user.
    /// This is called when a user is deleted.
    pub fn remove_user(&mut self, db: &mut KeystoreDB, user: AndroidUserId) -> Result<()> {
        info!("remove_user({user:?})");
        // Mark keys created on behalf of the user as unreferenced.
        db.unbind_keys_for_user(user)
            .context(ks_err!("Error in unbinding keys for {user:?}"))?;

        // Delete super key in cache, if exists.
        self.forget_all_keys_for_user(user);
        Ok(())
    }

    /// Resets the user's legacy LSKF-bound state without deleting unrelated APP keys.
    pub fn reset_lskf_bound_state(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
    ) -> Result<()> {
        info!("reset_lskf_bound_state({user:?})");
        db.unbind_lskf_bound_keys_for_user(user)
            .context(ks_err!("Error in unbinding LSKF-bound keys for {user:?}"))?;
        self.forget_all_keys_for_user(user);
        Ok(())
    }

    /// Initializes the given user by creating their super keys, both CredentialEncrypted and
    /// UnlockedDeviceRequired. If allow_existing is true, then the user already being initialized
    /// is not considered an error.
    pub fn initialize_user(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        password: &Password,
        allow_existing: bool,
    ) -> Result<()> {
        // Create the CredentialEncrypted super key.
        if self.super_key_exists_in_db_for_user(db, user)? {
            info!("CredentialEncrypted super key already exists");
            if !allow_existing {
                return Err(Error::sys()).context(ks_err!("Tried to re-init an initialized user!"));
            }
        } else {
            let super_key = self
                .create_super_key(db, user, &CREDENTIAL_ENCRYPTED_SUPER_KEY, password, None)
                .context(ks_err!("Failed to create CredentialEncrypted super key"))?;

            self.install_credential_encrypted_key_for_user(user, super_key)
                .context(ks_err!(
                    "Failed to install CredentialEncrypted super key for user"
                ))?;
        }

        // Create the UnlockedDeviceRequired super keys.
        self.unlock_unlocked_device_required_keys(db, user, password)
            .context(ks_err!(
                "Failed to create UnlockedDeviceRequired super keys"
            ))
    }

    /// Unlocks an existing user, or initializes the user's super keys if OMK missed the
    /// original maintenance event before being hot-replaced into the keystore process.
    pub fn unlock_or_initialize_user(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        password: &Password,
    ) -> Result<()> {
        match self.get_user_state(db, user)? {
            UserState::Uninitialized => self.initialize_user(db, user, password, true),
            UserState::CeLocked | UserState::CeUnlocked(_) => self.unlock_user(db, user, password),
        }
    }

    /// Unlocks the given user with the given password.
    ///
    /// If the user state is CeLocked:
    /// - Unlock the user's CredentialEncrypted super key
    /// - Unlock the user's UnlockedDeviceRequired super keys
    ///
    /// If the user state is CeUnlocked:
    /// - Unlock the user's UnlockedDeviceRequired super keys only
    ///
    pub fn unlock_user(
        &mut self,
        db: &mut KeystoreDB,
        user: AndroidUserId,
        password: &Password,
    ) -> Result<()> {
        match self.get_user_state(db, user)? {
            UserState::CeUnlocked(_) => {
                info!("CredentialEncrypted super key for user {user:?} is already unlocked.");
                self.unlock_unlocked_device_required_keys(db, user, password)
            }
            UserState::Uninitialized => {
                Err(Error::sys()).context(ks_err!("Tried to unlock an uninitialized {user:?}!"))
            }
            UserState::CeLocked => {
                info!("Unlocking CredentialEncrypted super key for user {user:?}.");
                let alias = &CREDENTIAL_ENCRYPTED_SUPER_KEY;
                let result = db
                    .load_super_key(alias, user)
                    .context(ks_err!("Failed to load super key for {user:?}"))?;

                match result {
                    Some((_, entry)) => {
                        self.populate_cache_from_super_key_blob(
                            user,
                            alias.algorithm,
                            entry,
                            password,
                        )
                        .context(ks_err!("Failed when unlocking {user:?}"))?;
                        self.unlock_unlocked_device_required_keys(db, user, password)
                    }
                    None => Err(Error::sys())
                        .context(ks_err!("Locked user {user:?} does not have a super key!")),
                }
            }
        }
    }
}

/// This enum represents different states of the user's life cycle in the device.
/// For now, only three states are defined. More states may be added later.
pub enum UserState {
    // The user's super keys exist, and the user is running and their CE storage is unlocked.
    // Hence, the CredentialEncrypted super key is available in the cache.
    CeUnlocked(Arc<SuperKey>),
    // The user's super keys exist, but the user is not running and their CE storage is locked.
    // Hence, the CredentialEncrypted and UnlockedDeviceRequired super keys are not available in
    // the cache. However, they exist in the database in encrypted form.
    CeLocked,
    // The user's super keys don't exist. I.e., there's no user with the given user ID, or the user
    // is in the process of being created or destroyed.
    Uninitialized,
}

/// This enum represents three states a KeyMint Blob can be in, w.r.t super encryption.
/// `Sensitive` holds the non encrypted key and a reference to its super key.
/// `NonSensitive` holds a non encrypted key that is never supposed to be encrypted.
/// `Ref` holds a reference to a key blob when it does not need to be modified if its
/// life time allows it.
pub enum KeyBlob<'a> {
    Sensitive {
        key: ZVec,
        /// If KeyMint reports that the key must be upgraded, we must
        /// re-encrypt the key before writing to the database; we use
        /// this key.
        reencrypt_with: Arc<SuperKey>,
        /// If this key was decrypted with an ECDH key, we want to
        /// re-encrypt it on first use whether it was upgraded or not;
        /// this field indicates that that's necessary.
        force_reencrypt: bool,
    },
    NonSensitive(Vec<u8>),
    Ref(&'a [u8]),
}

impl KeyBlob<'_> {
    pub fn force_reencrypt(&self) -> bool {
        if let KeyBlob::Sensitive {
            force_reencrypt, ..
        } = self
        {
            *force_reencrypt
        } else {
            false
        }
    }
}

/// Deref returns a reference to the key material in any variant.
impl Deref for KeyBlob<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sensitive { key, .. } => key,
            Self::NonSensitive(key) => key,
            Self::Ref(key) => key,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_legacy_boot_level_blob_is_reencrypted() -> Result<()> {
        let root_key: Vec<u8> = (0..32).collect();
        let mut manager = SuperKeyManager::default();
        manager.data.boot_level_key_cache = Some(Mutex::new(BootLevelKeyCache::new(
            ZVec::try_from(root_key.as_slice())?,
        )));
        *manager.data.legacy_boot_level_key_cache.get_mut().unwrap() = Some(
            LegacyBootLevelKeyCache::new(ZVec::try_from(root_key.as_slice())?),
        );

        let ciphertext = [
            236, 196, 68, 130, 60, 179, 173, 62, 180, 0, 32, 20, 124, 251, 61, 176,
        ];
        let mut metadata = BlobMetaData::new();
        metadata.add(BlobMetaEntry::MaxBootLevel(2));
        metadata.add(BlobMetaEntry::Iv(vec![
            182, 80, 3, 102, 134, 164, 167, 2, 202, 32, 175, 101,
        ]));
        metadata.add(BlobMetaEntry::AeadTag(vec![
            138, 140, 225, 83, 27, 227, 54, 239, 244, 143, 209, 157, 38, 113, 43, 158,
        ]));

        let unwrapped =
            manager.unwrap_key_if_required_with_omk_compatibility(&metadata, &ciphertext)?;
        assert_eq!(&unwrapped[..], b"legacy boot blob");
        assert!(unwrapped.force_reencrypt());

        let (reencrypted, metadata) =
            SuperKeyManager::reencrypt_if_required(&unwrapped, &unwrapped)?;
        let KeyBlob::NonSensitive(ciphertext) = reencrypted else {
            panic!("expected a re-encrypted key blob")
        };
        let metadata = metadata.unwrap();
        let unwrapped =
            manager.unwrap_key_if_required_with_omk_compatibility(&metadata, &ciphertext)?;
        assert_eq!(&unwrapped[..], b"legacy boot blob");
        assert!(!unwrapped.force_reencrypt());
        Ok(())
    }
}
