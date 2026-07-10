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

//! This is the Keystore 2.0 database module.
//! The database module provides a connection to the backing SQLite store.
//! We have two databases one for persistent key blob storage and one for
//! items that have a per boot life cycle.
//!
//! ## Persistent database
//! The persistent database has tables for key blobs. They are organized
//! as follows:
//! The `keyentry` table is the primary table for key entries. It is
//! accompanied by two tables for blobs and parameters.
//! Each key entry occupies exactly one row in the `keyentry` table and
//! zero or more rows in the tables `blobentry` and `keyparameter`.
//!
//! ## Per boot database
//! The per boot database stores items with a per boot lifecycle.
//! Currently, there is only the `grant` table in this database.
//! Grants are references to a key that can be used to access a key by
//! clients that don't own that key. Grants can only be created by the
//! owner of a key. And only certain components can create grants.
//! This is governed by SEPolicy.
//!
//! ## Access control
//! Some database functions that load keys or create grants perform
//! access control. This is because in some cases access control
//! can only be performed after some information about the designated
//! key was loaded from the database. To decouple the permission checks
//! from the database module these functions take permission check
//! callbacks.

use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
    SecurityLevel::SecurityLevel,
};
use crate::android::security::metrics::{
    Storage::Storage as MetricsStorage, StorageStats::StorageStats,
};
use crate::android::system::keystore2::{Domain::Domain, KeyDescriptor::KeyDescriptor};
use crate::err as ks_err;
use crate::impl_metadata;
use crate::keymaster::crypto::ZVec;
use crate::keymaster::database::{perboot, utils, versioning};
use crate::keymaster::gc::Gc;
use crate::keymaster::key_parameter::{KeyParameter, KeyParameterValue, Tag};
use crate::keymaster::permission::KeyPermSet;
use crate::keymaster::utils::{
    get_current_time_in_milliseconds, watchdog as wd, AndroidUserId, AppUid, Challenge,
    SecureUserId, AID_USER_OFFSET,
};
use crate::keymaster::{
    error::{Error as KsError, ErrorCode, ResponseCode},
    super_key::SuperKeyType,
};
use crate::plat::attestation::{parse_tlv, ANDROID_ATTESTATION_OID};
use anyhow::{anyhow, Context, Result};
use log::info;
use rand::random;
use rusqlite::{
    params, params_from_iter,
    types::FromSql,
    types::FromSqlResult,
    types::ToSqlOutput,
    types::{FromSqlError, Value, ValueRef},
    Connection, OptionalExtension, ToSql, Transaction,
};
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, SystemTime},
};
use std::{convert::TryFrom, convert::TryInto, ops::Deref, sync::LazyLock, time::SystemTimeError};
use utils as db_utils;
use utils::SqlField;
use x509_cert::{der::Decode, Certificate};

use TransactionBehavior::Immediate;

/// Wrapper for `rusqlite::TransactionBehavior` which includes information about the transaction
/// being performed.
#[derive(Clone, Copy)]
enum TransactionBehavior {
    Deferred,
    Immediate(&'static str),
}

impl From<TransactionBehavior> for rusqlite::TransactionBehavior {
    fn from(val: TransactionBehavior) -> Self {
        match val {
            TransactionBehavior::Deferred => rusqlite::TransactionBehavior::Deferred,
            TransactionBehavior::Immediate(_) => rusqlite::TransactionBehavior::Immediate,
        }
    }
}

impl TransactionBehavior {
    fn name(&self) -> Option<&'static str> {
        match self {
            TransactionBehavior::Deferred => None,
            TransactionBehavior::Immediate(v) => Some(v),
        }
    }
}

/// Access information for a key.
#[derive(Debug)]
struct KeyAccessInfo {
    key_id: i64,
    descriptor: KeyDescriptor,
    vector: Option<KeyPermSet>,
}

/// If the database returns a busy error code, retry after this interval.
const DB_BUSY_RETRY_INTERVAL: Duration = Duration::from_micros(500);

impl_metadata!(
    /// A set of metadata for key entries.
    #[derive(Debug, Default, Eq, PartialEq)]
    pub struct KeyMetaData;
    /// A metadata entry for key entries.
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub enum KeyMetaEntry {
        /// Date of the creation of the key entry.
        CreationDate(DateTime) with accessor creation_date,
        /// Expiration date for attestation keys.
        AttestationExpirationDate(DateTime) with accessor attestation_expiration_date,
        /// CBOR Blob that represents a COSE_Key and associated metadata needed for remote
        /// provisioning
        AttestationMacedPublicKey(Vec<u8>) with accessor attestation_maced_public_key,
        /// Vector representing the raw public key so results from the server can be matched
        /// to the right entry
        AttestationRawPubKey(Vec<u8>) with accessor attestation_raw_pub_key,
        /// SEC1 public key for ECDH encryption
        Sec1PublicKey(Vec<u8>) with accessor sec1_public_key,
        /// Keybox identity prefix used to produce this entry's device attestation chain.
        KeyboxAttestationUuidPrefix(Vec<u8>) with accessor keybox_attestation_uuid_prefix,
        //  --- ADD NEW META DATA FIELDS HERE ---
        // For backwards compatibility add new entries only to
        // end of this list and above this comment.
    };
);

impl KeyMetaData {
    fn load_from_db(key_id: i64, tx: &Transaction) -> Result<Self> {
        let mut stmt = tx
            .prepare(
                "SELECT tag, data from persistent.keymetadata
                    WHERE keyentryid = ?;",
            )
            .context(ks_err!(
                "KeyMetaData::load_from_db: prepare statement failed."
            ))?;

        let mut metadata: HashMap<i64, KeyMetaEntry> = Default::default();

        let mut rows = stmt
            .query(params![key_id])
            .context(ks_err!("KeyMetaData::load_from_db: query failed."))?;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let db_tag: i64 = row.get(0).context("Failed to read tag.")?;
            metadata.insert(
                db_tag,
                KeyMetaEntry::new_from_sql(db_tag, &SqlField::new(1, row))
                    .context("Failed to read KeyMetaEntry.")?,
            );
            Ok(())
        })
        .context(ks_err!("KeyMetaData::load_from_db."))?;

        Ok(Self { data: metadata })
    }

    fn store_in_db(&self, key_id: i64, tx: &Transaction) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT or REPLACE INTO persistent.keymetadata (keyentryid, tag, data)
                    VALUES (?, ?, ?);",
            )
            .context(ks_err!(
                "KeyMetaData::store_in_db: Failed to prepare statement."
            ))?;

        let iter = self.data.iter();
        for (tag, entry) in iter {
            stmt.insert(params![key_id, tag, entry,]).with_context(|| {
                ks_err!("KeyMetaData::store_in_db: Failed to insert {:?}", entry)
            })?;
        }
        Ok(())
    }
}

impl_metadata!(
    /// A set of metadata for key blobs.
    #[derive(Debug, Default, Eq, PartialEq)]
    pub struct BlobMetaData;
    /// A metadata entry for key blobs.
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub enum BlobMetaEntry {
        /// If present, indicates that the blob is encrypted with another key or a key derived
        /// from a password.
        EncryptedBy(EncryptedBy) with accessor encrypted_by,
        /// If the blob is password encrypted this field is set to the
        /// salt used for the key derivation.
        Salt(Vec<u8>) with accessor salt,
        /// If the blob is encrypted, this field is set to the initialization vector.
        Iv(Vec<u8>) with accessor iv,
        /// If the blob is encrypted, this field holds the AEAD TAG.
        AeadTag(Vec<u8>) with accessor aead_tag,
        /// The uuid of the owning KeyMint instance.
        KmUuid(Uuid) with accessor km_uuid,
        /// If the key is ECDH encrypted, this is the ephemeral public key
        PublicKey(Vec<u8>) with accessor public_key,
        /// If the key is encrypted with a MaxBootLevel key, this is the boot level
        /// of that key
        MaxBootLevel(i32) with accessor max_boot_level,
        //  --- ADD NEW META DATA FIELDS HERE ---
        // For backwards compatibility add new entries only to
        // end of this list and above this comment.
    };
);

impl BlobMetaData {
    fn load_from_db(blob_id: i64, tx: &Transaction) -> Result<Self> {
        let mut stmt = tx
            .prepare(
                "SELECT tag, data from persistent.blobmetadata
                    WHERE blobentryid = ?;",
            )
            .context(ks_err!(
                "BlobMetaData::load_from_db: prepare statement failed."
            ))?;

        let mut metadata: HashMap<i64, BlobMetaEntry> = Default::default();

        let mut rows = stmt
            .query(params![blob_id])
            .context(ks_err!("query failed."))?;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let db_tag: i64 = row.get(0).context("Failed to read tag.")?;
            metadata.insert(
                db_tag,
                BlobMetaEntry::new_from_sql(db_tag, &SqlField::new(1, row))
                    .context("Failed to read BlobMetaEntry.")?,
            );
            Ok(())
        })
        .context(ks_err!("BlobMetaData::load_from_db"))?;

        Ok(Self { data: metadata })
    }

    fn store_in_db(&self, blob_id: i64, tx: &Transaction) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT or REPLACE INTO persistent.blobmetadata (blobentryid, tag, data)
                    VALUES (?, ?, ?);",
            )
            .context(ks_err!(
                "BlobMetaData::store_in_db: Failed to prepare statement.",
            ))?;

        let iter = self.data.iter();
        for (tag, entry) in iter {
            stmt.insert(params![blob_id, tag, entry,])
                .with_context(|| {
                    ks_err!("BlobMetaData::store_in_db: Failed to insert {:?}", entry)
                })?;
        }
        Ok(())
    }
}

/// Indicates the type of the keyentry.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyType {
    /// This is a client key type. These keys are created or imported through the Keystore 2.0
    /// AIDL interface android.system.keystore2.
    Client,
    /// This is a super key type. These keys are created by keystore itself and used to encrypt
    /// other key blobs to provide LSKF binding.
    Super,
    // A previous version also had `Attestation` as value 2 (removed in
    // https://r.android.com/2587525).  Avoid re-using that value just in case there are any
    // left-over rows from old devices that have been updated.
}

impl ToSql for KeyType {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(match self {
            KeyType::Client => 0,
            KeyType::Super => 1,
            // Value 2 is reserved; was previously `KeyType::Attestation`
        })))
    }
}

impl FromSql for KeyType {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match i64::column_result(value)? {
            0 => Ok(KeyType::Client),
            1 => Ok(KeyType::Super),
            // Value 2 is reserved; was previously `KeyType::Attestation`
            v => Err(FromSqlError::OutOfRange(v)),
        }
    }
}

/// Uuid representation that can be stored in the database.
/// Right now it can only be initialized from SecurityLevel.
/// Once KeyMint provides a UUID type a corresponding From impl shall be added.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid([u8; 16]);

const KEYBOX_UUID_DIGEST_BYTES: usize = 12;

impl Deref for Uuid {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SecurityLevel> for Uuid {
    fn from(sec_level: SecurityLevel) -> Self {
        Self::from_keybox_digest(sec_level, crate::keybox::current_identity_digest())
    }
}

impl Uuid {
    pub(crate) fn from_keybox_digest(sec_level: SecurityLevel, digest: [u8; 32]) -> Self {
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes[..KEYBOX_UUID_DIGEST_BYTES].copy_from_slice(&digest[..KEYBOX_UUID_DIGEST_BYTES]);
        uuid_bytes[KEYBOX_UUID_DIGEST_BYTES..].copy_from_slice(&(sec_level.0 as u32).to_be_bytes());
        Self(uuid_bytes)
    }

    pub fn to_security_level(&self) -> Option<SecurityLevel> {
        let mut sec_level_bytes = [0u8; 4];
        sec_level_bytes.copy_from_slice(&self.0[KEYBOX_UUID_DIGEST_BYTES..]);
        match u32::from_be_bytes(sec_level_bytes) {
            0 | 1 | 2 | 100 => Some(SecurityLevel(u32::from_be_bytes(sec_level_bytes) as i32)),
            _ => None,
        }
    }

    pub fn get_digest(&self) -> &[u8] {
        &self.0[..KEYBOX_UUID_DIGEST_BYTES]
    }

    pub(crate) fn is_bound_to_keybox_digest(&self, digest: [u8; 32]) -> bool {
        self.get_digest() == &digest[..KEYBOX_UUID_DIGEST_BYTES]
    }

    pub(crate) fn is_keybox_bound(&self) -> bool {
        *self != KEYSTORE_UUID && self.to_security_level().is_some()
    }
}

impl ToSql for Uuid {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for Uuid {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let blob = Vec::<u8>::column_result(value)?;
        if blob.len() != 16 {
            return Err(FromSqlError::OutOfRange(blob.len() as i64));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&blob);
        Ok(Self(arr))
    }
}

/// Key entries that are not associated with any KeyMint instance, such as pure certificate
/// entries are associated with this UUID.
pub static KEYSTORE_UUID: Uuid = Uuid([
    0x41, 0xe3, 0xb9, 0xce, 0x27, 0x58, 0x4e, 0x91, 0xbc, 0xfd, 0xa5, 0x5d, 0x91, 0x85, 0xab, 0x11,
]);

/// Indicates how the sensitive part of this key blob is encrypted.
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EncryptedBy {
    /// The keyblob is encrypted by a user password.
    /// In the database this variant is represented as NULL.
    Password,
    /// The keyblob is encrypted by another key with wrapped key id.
    /// In the database this variant is represented as non NULL value
    /// that is convertible to i64, typically NUMERIC.
    KeyId(i64),
}

impl ToSql for EncryptedBy {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            Self::Password => Ok(ToSqlOutput::Owned(Value::Null)),
            Self::KeyId(id) => id.to_sql(),
        }
    }
}

impl FromSql for EncryptedBy {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match value {
            ValueRef::Null => Ok(Self::Password),
            _ => Ok(Self::KeyId(i64::column_result(value)?)),
        }
    }
}

/// A database representation of wall clock time. DateTime stores unix epoch time as
/// i64 in milliseconds.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct DateTime(i64);

/// Error type returned when creating DateTime or converting it from and to
/// SystemTime.
#[derive(thiserror::Error, Debug)]
pub enum DateTimeError {
    /// This is returned when SystemTime and Duration computations fail.
    #[error(transparent)]
    SystemTimeError(#[from] SystemTimeError),

    /// This is returned when type conversions fail.
    #[error(transparent)]
    TypeConversion(#[from] std::num::TryFromIntError),

    /// This is returned when checked time arithmetic failed.
    #[error("Time arithmetic failed.")]
    TimeArithmetic,
}

impl DateTime {
    /// Constructs a new DateTime object denoting the current time. This may fail during
    /// conversion to unix epoch time and during conversion to the internal i64 representation.
    pub fn now() -> Result<Self, DateTimeError> {
        Ok(Self(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
        ))
    }

    /// Constructs a new DateTime object from milliseconds.
    pub fn from_millis_epoch(millis: i64) -> Self {
        Self(millis)
    }

    /// Returns unix epoch time in milliseconds.
    pub fn to_millis_epoch(self) -> i64 {
        self.0
    }
}

impl ToSql for DateTime {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(self.0)))
    }
}

impl FromSql for DateTime {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(i64::column_result(value)?))
    }
}

impl TryInto<SystemTime> for DateTime {
    type Error = DateTimeError;

    fn try_into(self) -> Result<SystemTime, Self::Error> {
        // We want to construct a SystemTime representation equivalent to self, denoting
        // a point in time THEN, but we cannot set the time directly. We can only construct
        // a SystemTime denoting NOW, and we can get the duration between EPOCH and NOW,
        // and between EPOCH and THEN. With this common reference we can construct the
        // duration between NOW and THEN which we can add to our SystemTime representation
        // of NOW to get a SystemTime representation of THEN.
        // Durations can only be positive, thus the if statement below.
        let now = SystemTime::now();
        let now_epoch = now.duration_since(SystemTime::UNIX_EPOCH)?;
        let then_epoch = Duration::from_millis(self.0.try_into()?);
        Ok(if now_epoch > then_epoch {
            // then = now - (now_epoch - then_epoch)
            now_epoch
                .checked_sub(then_epoch)
                .and_then(|d| now.checked_sub(d))
                .ok_or(DateTimeError::TimeArithmetic)?
        } else {
            // then = now + (then_epoch - now_epoch)
            then_epoch
                .checked_sub(now_epoch)
                .and_then(|d| now.checked_add(d))
                .ok_or(DateTimeError::TimeArithmetic)?
        })
    }
}

impl TryFrom<SystemTime> for DateTime {
    type Error = DateTimeError;

    fn try_from(t: SystemTime) -> Result<Self, Self::Error> {
        Ok(Self(
            t.duration_since(SystemTime::UNIX_EPOCH)?
                .as_millis()
                .try_into()?,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
enum KeyLifeCycle {
    /// Existing keys have a key ID but are not fully populated yet.
    /// This is a transient state. If Keystore finds any such keys when it starts up, it must move
    /// them to Unreferenced for garbage collection.
    Existing,
    /// A live key is fully populated and usable by clients.
    Live,
    /// An unreferenced key is scheduled for garbage collection.
    Unreferenced,
}

impl ToSql for KeyLifeCycle {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            Self::Existing => Ok(ToSqlOutput::Owned(Value::Integer(0))),
            Self::Live => Ok(ToSqlOutput::Owned(Value::Integer(1))),
            Self::Unreferenced => Ok(ToSqlOutput::Owned(Value::Integer(2))),
        }
    }
}

impl FromSql for KeyLifeCycle {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match i64::column_result(value)? {
            0 => Ok(KeyLifeCycle::Existing),
            1 => Ok(KeyLifeCycle::Live),
            2 => Ok(KeyLifeCycle::Unreferenced),
            v => Err(FromSqlError::OutOfRange(v)),
        }
    }
}

/// Current state of a `blobentry` row.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
enum BlobState {
    #[default]
    /// Current blobentry (of its `subcomponent_type`) for the associated key.
    Current,
    /// Blobentry that is no longer the current blob (of its `subcomponent_type`) for the associated
    /// key.
    Superseded,
    /// Blobentry for a key that no longer exists.
    Orphaned,
}

impl ToSql for BlobState {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        match self {
            Self::Current => Ok(ToSqlOutput::Owned(Value::Integer(0))),
            Self::Superseded => Ok(ToSqlOutput::Owned(Value::Integer(1))),
            Self::Orphaned => Ok(ToSqlOutput::Owned(Value::Integer(2))),
        }
    }
}

impl FromSql for BlobState {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match i64::column_result(value)? {
            0 => Ok(Self::Current),
            1 => Ok(Self::Superseded),
            2 => Ok(Self::Orphaned),
            v => Err(FromSqlError::OutOfRange(v)),
        }
    }
}

/// Keys have a KeyMint blob component and optional public certificate and
/// certificate chain components.
/// KeyEntryLoadBits is a bitmap that indicates to `KeystoreDB::load_key_entry`
/// which components shall be loaded from the database if present.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyEntryLoadBits(u32);

impl KeyEntryLoadBits {
    /// Indicate to `KeystoreDB::load_key_entry` that no component shall be loaded.
    pub const NONE: KeyEntryLoadBits = Self(0);
    /// Indicate to `KeystoreDB::load_key_entry` that the KeyMint component shall be loaded.
    pub const KM: KeyEntryLoadBits = Self(1);
    /// Indicate to `KeystoreDB::load_key_entry` that the Public components shall be loaded.
    pub const PUBLIC: KeyEntryLoadBits = Self(2);
    /// Indicate to `KeystoreDB::load_key_entry` that both components shall be loaded.
    pub const BOTH: KeyEntryLoadBits = Self(3);

    /// Returns true if this object indicates that the public components shall be loaded.
    pub const fn load_public(&self) -> bool {
        self.0 & Self::PUBLIC.0 != 0
    }

    /// Returns true if the object indicates that the KeyMint component shall be loaded.
    pub const fn load_km(&self) -> bool {
        self.0 & Self::KM.0 != 0
    }
}

static KEY_ID_LOCK: LazyLock<KeyIdLockDb> = LazyLock::new(KeyIdLockDb::new);

struct KeyIdLockDb {
    locked_keys: Mutex<HashSet<i64>>,
    cond_var: Condvar,
}

/// A locked key. While a guard exists for a given key id, the same key cannot be loaded
/// from the database a second time. Most functions manipulating the key blob database
/// require a KeyIdGuard.
#[derive(Debug)]
pub struct KeyIdGuard(i64);

impl KeyIdLockDb {
    fn new() -> Self {
        Self {
            locked_keys: Mutex::new(HashSet::new()),
            cond_var: Condvar::new(),
        }
    }

    /// This function blocks until an exclusive lock for the given key entry id can
    /// be acquired. It returns a guard object, that represents the lifecycle of the
    /// acquired lock.
    fn get(&self, key_id: i64) -> KeyIdGuard {
        let mut locked_keys = self.locked_keys.lock().unwrap();
        while locked_keys.contains(&key_id) {
            locked_keys = self.cond_var.wait(locked_keys).unwrap();
        }
        locked_keys.insert(key_id);
        KeyIdGuard(key_id)
    }

    /// This function attempts to acquire an exclusive lock on a given key id. If the
    /// given key id is already taken the function returns None immediately. If a lock
    /// can be acquired this function returns a guard object, that represents the
    /// lifecycle of the acquired lock.
    fn try_get(&self, key_id: i64) -> Option<KeyIdGuard> {
        let mut locked_keys = self.locked_keys.lock().unwrap();
        if locked_keys.insert(key_id) {
            Some(KeyIdGuard(key_id))
        } else {
            None
        }
    }
}

impl KeyIdGuard {
    /// Get the numeric key id of the locked key.
    pub fn id(&self) -> i64 {
        self.0
    }
}

impl Drop for KeyIdGuard {
    fn drop(&mut self) {
        let mut locked_keys = KEY_ID_LOCK.locked_keys.lock().unwrap();
        locked_keys.remove(&self.0);
        drop(locked_keys);
        KEY_ID_LOCK.cond_var.notify_all();
    }
}

/// This type represents a certificate and certificate chain entry for a key.
#[derive(Debug, Default)]
pub struct CertificateInfo {
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<u8>>,
}

/// This type represents a Blob with its metadata and an optional superseded blob.
#[derive(Debug)]
pub struct BlobInfo<'a> {
    blob: &'a [u8],
    metadata: &'a BlobMetaData,
    /// Superseded blobs are an artifact of legacy import. In some rare occasions
    /// the key blob needs to be upgraded during import. In that case two
    /// blob are imported, the superseded one will have to be imported first,
    /// so that the garbage collector can reap it.
    superseded_blob: Option<(&'a [u8], &'a BlobMetaData)>,
}

impl<'a> BlobInfo<'a> {
    /// Create a new instance of blob info with blob and corresponding metadata
    /// and no superseded blob info.
    pub fn new(blob: &'a [u8], metadata: &'a BlobMetaData) -> Self {
        Self {
            blob,
            metadata,
            superseded_blob: None,
        }
    }

    /// Create a new instance of blob info with blob and corresponding metadata
    /// as well as superseded blob info.
    pub fn new_with_superseded(
        blob: &'a [u8],
        metadata: &'a BlobMetaData,
        superseded_blob: Option<(&'a [u8], &'a BlobMetaData)>,
    ) -> Self {
        Self {
            blob,
            metadata,
            superseded_blob,
        }
    }
}

impl CertificateInfo {
    /// Constructs a new CertificateInfo object from `cert` and `cert_chain`
    pub fn new(cert: Option<Vec<u8>>, cert_chain: Option<Vec<u8>>) -> Self {
        Self { cert, cert_chain }
    }

    /// Take the cert
    pub fn take_cert(&mut self) -> Option<Vec<u8>> {
        self.cert.take()
    }

    /// Take the cert chain
    pub fn take_cert_chain(&mut self) -> Option<Vec<u8>> {
        self.cert_chain.take()
    }
}

/// This type represents a certificate chain with a private key corresponding to the leaf
/// certificate. TODO(jbires): This will be used in a follow-on CL, for now it's used in the tests.
pub struct CertificateChain {
    /// A KM key blob
    pub private_key: ZVec,
    /// A batch cert for private_key
    pub batch_cert: Vec<u8>,
    /// A full certificate chain from root signing authority to private_key, including batch_cert
    /// for convenience.
    pub cert_chain: Vec<u8>,
}

/// This type represents a Keystore 2.0 key entry.
/// An entry has a unique `id` by which it can be found in the database.
/// It has a security level field, key parameters, and three optional fields
/// for the KeyMint blob, public certificate and a public certificate chain.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct KeyEntry {
    id: i64,
    key_blob_info: Option<(Vec<u8>, BlobMetaData)>,
    cert: Option<Vec<u8>>,
    cert_chain: Option<Vec<u8>>,
    km_uuid: Uuid,
    parameters: Vec<KeyParameter>,
    metadata: KeyMetaData,
    pure_cert: bool,
}

impl KeyEntry {
    /// Returns the unique id of the Key entry.
    pub fn id(&self) -> i64 {
        self.id
    }
    /// Exposes the optional KeyMint blob.
    pub fn key_blob_info(&self) -> &Option<(Vec<u8>, BlobMetaData)> {
        &self.key_blob_info
    }
    /// Extracts the Optional KeyMint blob including its metadata.
    pub fn take_key_blob_info(&mut self) -> Option<(Vec<u8>, BlobMetaData)> {
        self.key_blob_info.take()
    }
    /// Exposes the optional public certificate.
    pub fn cert(&self) -> &Option<Vec<u8>> {
        &self.cert
    }
    /// Extracts the optional public certificate.
    pub fn take_cert(&mut self) -> Option<Vec<u8>> {
        self.cert.take()
    }
    /// Extracts the optional public certificate_chain.
    pub fn take_cert_chain(&mut self) -> Option<Vec<u8>> {
        self.cert_chain.take()
    }
    /// Returns the uuid of the owning KeyMint instance.
    pub fn km_uuid(&self) -> &Uuid {
        &self.km_uuid
    }
    /// Consumes this key entry and extracts the keyparameters from it.
    pub fn into_key_parameters(self) -> Vec<KeyParameter> {
        self.parameters
    }
    /// Exposes the key metadata of this key entry.
    pub fn metadata(&self) -> &KeyMetaData {
        &self.metadata
    }
    /// This returns true if the entry is a pure certificate entry with no
    /// private key component.
    pub fn pure_cert(&self) -> bool {
        self.pure_cert
    }
    /// This returns true if the entry corresponds to an attested key.
    /// A key is considered attested if it has an associated certificate chain.
    pub fn is_attested(&self) -> bool {
        self.cert_chain.is_some()
    }
}

type LoadedBlobComponents = (
    bool,
    Option<(Vec<u8>, BlobMetaData)>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

/// Indicates the sub component of a key entry for persistent storage.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct SubComponentType(u32);
impl SubComponentType {
    /// Persistent identifier for a key blob.
    pub const KEY_BLOB: SubComponentType = Self(0);
    /// Persistent identifier for a certificate blob.
    pub const CERT: SubComponentType = Self(1);
    /// Persistent identifier for a certificate chain blob.
    pub const CERT_CHAIN: SubComponentType = Self(2);
}

impl ToSql for SubComponentType {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for SubComponentType {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(u32::column_result(value)?))
    }
}

/// This trait is private to the database module. It is used to convey whether or not the garbage
/// collector shall be invoked after a database access. All closures passed to
/// `KeystoreDB::with_transaction` return a tuple (bool, T) where the bool indicates if the
/// gc needs to be triggered. This convenience function allows to turn any anyhow::Result<T>
/// into anyhow::Result<(bool, T)> by simply appending one of `.do_gc(bool)`, `.no_gc()`, or
/// `.need_gc()`.
trait DoGc<T> {
    fn do_gc(self, need_gc: bool) -> Result<(bool, T)>;

    fn no_gc(self) -> Result<(bool, T)>;

    fn need_gc(self) -> Result<(bool, T)>;
}

impl<T> DoGc<T> for Result<T> {
    fn do_gc(self, need_gc: bool) -> Result<(bool, T)> {
        self.map(|r| (need_gc, r))
    }

    fn no_gc(self) -> Result<(bool, T)> {
        self.do_gc(false)
    }

    fn need_gc(self) -> Result<(bool, T)> {
        self.do_gc(true)
    }
}

/// KeystoreDB wraps a connection to an SQLite database and tracks its
/// ownership. It also implements all of Keystore 2.0's database functionality.
pub struct KeystoreDB {
    conn: Connection,
    gc: Option<Arc<Gc>>,
    perboot: Arc<perboot::PerbootDB>,
}

pub type KeymasterDb = KeystoreDB;

/// Database representation of the monotonic time retrieved from the system call clock_gettime with
/// CLOCK_BOOTTIME. Stores monotonic time as i64 in milliseconds.
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct BootTime(i64);

impl BootTime {
    /// Constructs a new BootTime
    pub fn now() -> Self {
        Self(get_current_time_in_milliseconds())
    }

    /// Returns the value of BootTime in milliseconds as i64
    pub fn milliseconds(&self) -> i64 {
        self.0
    }

    /// Returns the integer value of BootTime as i64
    pub fn seconds(&self) -> i64 {
        self.0 / 1000
    }

    /// Like i64::checked_sub.
    pub fn checked_sub(&self, other: &Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

impl ToSql for BootTime {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(self.0)))
    }
}

impl FromSql for BootTime {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(i64::column_result(value)?))
    }
}

/// This struct encapsulates the information to be stored in the database about the auth tokens
/// received by keystore.
#[derive(Clone)]
pub struct AuthTokenEntry {
    auth_token: HardwareAuthToken,
    // Time received in milliseconds
    time_received: BootTime,
}

impl AuthTokenEntry {
    fn new(auth_token: HardwareAuthToken, time_received: BootTime) -> Self {
        AuthTokenEntry {
            auth_token,
            time_received,
        }
    }

    /// Checks if this auth token satisfies the given authentication information.
    pub fn satisfies(
        &self,
        user_sids: &[SecureUserId],
        auth_type: HardwareAuthenticatorType,
    ) -> bool {
        user_sids.iter().any(|&sid| {
            (sid.0 == self.auth_token.userId || sid.0 == self.auth_token.authenticatorId)
                && ((auth_type.0 & self.auth_token.authenticatorType.0) != 0)
        })
    }

    /// Returns the auth token wrapped by the AuthTokenEntry
    pub fn auth_token(&self) -> &HardwareAuthToken {
        &self.auth_token
    }

    /// Returns the auth token wrapped by the AuthTokenEntry
    pub fn take_auth_token(self) -> HardwareAuthToken {
        self.auth_token
    }

    /// Returns the time that this auth token was received.
    pub fn time_received(&self) -> BootTime {
        self.time_received
    }

    /// Returns the challenge value of the auth token.
    pub fn challenge(&self) -> Challenge {
        Challenge(self.auth_token.challenge)
    }
}

/// Information about a superseded blob (a blob that is no longer the
/// most recent blob of that type for a given key, due to upgrade or
/// replacement).
pub struct SupersededBlob {
    /// ID
    pub blob_id: i64,
    /// Contents.
    pub blob: Vec<u8>,
    /// Metadata.
    pub metadata: BlobMetaData,
}

impl KeystoreDB {
    const UNASSIGNED_KEY_ID: i64 = -1i64;
    const CURRENT_DB_VERSION: u32 = 3;
    const UPGRADERS: &'static [fn(&Transaction) -> Result<u32>] =
        &[Self::from_0_to_1, Self::from_1_to_2, Self::from_2_to_3];

    /// Name of the file that holds the cross-boot persistent database.
    pub const PERSISTENT_DB_FILENAME: &'static str = "keymaster.db";

    /// This will create a new database connection connecting the cross-boot
    /// persistent database and perboot.sqlite in the given directory.
    /// It also attempts to initialize all of the tables.
    /// KeystoreDB cannot be used by multiple threads.
    /// Each thread should open their own connection using `thread_local!`.
    pub fn new(db_root: &Path, gc: Option<Arc<Gc>>) -> Result<Self> {
        let _wp = wd::watch("KeystoreDB::new");

        let persistent_path = Self::make_persistent_path(db_root)?;
        let conn = Self::make_connection(&persistent_path)?;

        let mut db = Self {
            conn,
            gc,
            perboot: perboot::PERBOOT_DB.clone(),
        };
        db.with_transaction(Immediate("TX_new"), |tx| {
            versioning::upgrade_database(tx, Self::CURRENT_DB_VERSION, Self::UPGRADERS)
                .context(ks_err!("KeystoreDB::new: trying to upgrade database."))?;
            Self::init_tables(tx)
                .context("Trying to initialize tables.")
                .no_gc()
        })?;
        Ok(db)
    }

    // This upgrade function deletes all MAX_BOOT_LEVEL keys, that were generated before
    // cryptographic binding to the boot level keys was implemented.
    fn from_0_to_1(tx: &Transaction) -> Result<u32> {
        tx.execute(
            "UPDATE persistent.keyentry SET state = ?
             WHERE
                 id IN (SELECT keyentryid FROM persistent.keyparameter WHERE tag = ?)
             AND
                 id NOT IN (
                     SELECT keyentryid FROM persistent.blobentry
                     WHERE id IN (
                         SELECT blobentryid FROM persistent.blobmetadata WHERE tag = ?
                     )
                 );",
            params![
                KeyLifeCycle::Unreferenced,
                Tag::MAX_BOOT_LEVEL.0,
                BlobMetaData::MaxBootLevel
            ],
        )
        .context(ks_err!("Failed to delete logical boot level keys."))?;

        // DB version is now 1.
        Ok(1)
    }

    // This upgrade function adds an additional `state INTEGER` column to the blobentry
    // table, and populates it based on whether each blob is the most recent of its type for
    // the corresponding key.
    fn from_1_to_2(tx: &Transaction) -> Result<u32> {
        let has_state_column = tx
            .query_row(
                "SELECT name FROM persistent.pragma_table_info('blobentry') WHERE name = 'state';",
                [],
                |_| Ok(()),
            )
            .optional()
            .context(ks_err!("Failed to inspect blobentry state column"))?
            .is_some();
        if !has_state_column {
            tx.execute(
                "ALTER TABLE persistent.blobentry ADD COLUMN state INTEGER DEFAULT 0;",
                params![],
            )
            .context(ks_err!("Failed to add state column"))?;
        }

        // Mark keyblobs that are not the most recent for their corresponding key.
        // This may take a while if there are excessive numbers of keys in the database.
        let _wp = wd::watch("KeystoreDB::from_1_to_2 mark all non-current keyblobs");
        let sc_key_blob = SubComponentType::KEY_BLOB;
        let mut stmt = tx
            .prepare(
                "UPDATE persistent.blobentry SET state=?
                     WHERE subcomponent_type = ?
                     AND id NOT IN (
                             SELECT MAX(id) FROM persistent.blobentry
                             WHERE subcomponent_type = ?
                             GROUP BY keyentryid, subcomponent_type
                         );",
            )
            .context("Trying to prepare query to mark superseded keyblobs")?;
        stmt.execute(params![BlobState::Superseded, sc_key_blob, sc_key_blob])
            .context(ks_err!("Failed to set state=superseded state for keyblobs"))?;
        info!("marked non-current blobentry rows for keyblobs as superseded");

        // Mark keyblobs that don't have a corresponding key.
        // This may take a while if there are excessive numbers of keys in the database.
        let _wp = wd::watch("KeystoreDB::from_1_to_2 mark all orphaned keyblobs");
        let mut stmt = tx
            .prepare(
                "UPDATE persistent.blobentry SET state=?
                     WHERE subcomponent_type = ?
                     AND NOT EXISTS (SELECT id FROM persistent.keyentry
                                     WHERE id = keyentryid);",
            )
            .context("Trying to prepare query to mark orphaned keyblobs")?;
        stmt.execute(params![BlobState::Orphaned, sc_key_blob])
            .context(ks_err!("Failed to set state=orphaned for keyblobs"))?;
        info!("marked orphaned blobentry rows for keyblobs");

        // Add an index to make it fast to find out of date blobentry rows.
        let _wp = wd::watch("KeystoreDB::from_1_to_2 add blobentry index");
        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobentry_state_index
            ON blobentry(subcomponent_type, state);",
            [],
        )
        .context("Failed to create index blobentry_state_index.")?;

        // Add an index to make it fast to find unreferenced keyentry rows.
        let _wp = wd::watch("KeystoreDB::from_1_to_2 add keyentry state index");
        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_state_index
            ON keyentry(state);",
            [],
        )
        .context("Failed to create index keyentry_state_index.")?;

        // DB version is now 2.
        Ok(2)
    }

    // Record keybox identity prefixes for legacy client keys with a device attestation chain.
    fn from_2_to_3(tx: &Transaction) -> Result<u32> {
        Self::init_tables(tx)?;

        let _wp = wd::watch("KeystoreDB::from_2_to_3 backfill keybox-attestation metadata");
        let keybox_signing_certs = crate::keybox::signing_certificate_ders_from_disk()
            .unwrap_or_else(|error| {
                log::warn!(
                    "failed to load keybox signing certificates for metadata backfill: {error:#}"
                );
                Default::default()
            });

        let mut stmt = tx
            .prepare(
                "SELECT k.id, k.km_uuid,
                        (SELECT b.blob FROM persistent.blobentry AS b WHERE b.keyentryid = k.id AND b.subcomponent_type = ? ORDER BY b.id DESC LIMIT 1),
                        (SELECT b.blob FROM persistent.blobentry AS b WHERE b.keyentryid = k.id AND b.subcomponent_type = ? ORDER BY b.id DESC LIMIT 1)
                 FROM persistent.keyentry AS k
                 WHERE k.key_type = ?
                   AND k.state != ?
                   AND (
                       SELECT b.state FROM persistent.blobentry AS b WHERE b.keyentryid = k.id AND b.subcomponent_type = ? ORDER BY b.id DESC LIMIT 1
                   ) = ?;",
            )
            .context("Trying to prepare keybox attestation metadata backfill query")?;

        let mut rows = stmt
            .query(params![
                SubComponentType::CERT,
                SubComponentType::CERT_CHAIN,
                KeyType::Client,
                KeyLifeCycle::Unreferenced,
                SubComponentType::KEY_BLOB,
                BlobState::Current,
            ])
            .context("Trying to query keybox attestation metadata backfill candidates")?;

        let mut candidates = Vec::new();
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let key_id: i64 = row.get(0).context("Failed to read key id.")?;
            let km_uuid: Uuid = row.get(1).context("Failed to read key UUID.")?;
            if !km_uuid.is_keybox_bound() {
                return Ok(());
            }
            let leaf_cert = row.get(2).context("Failed to read leaf cert.")?;
            let cert_chain = row.get(3).context("Failed to read cert chain.")?;
            let (Some(leaf_cert), Some(cert_chain)): (Option<Vec<u8>>, Option<Vec<u8>>) =
                (leaf_cert, cert_chain)
            else {
                return Ok(());
            };
            let Ok(leaf_cert) = Certificate::from_der(&leaf_cert) else {
                return Ok(());
            };
            if !leaf_cert
                .tbs_certificate
                .extensions
                .as_ref()
                .is_some_and(|extensions| {
                    extensions
                        .iter()
                        .any(|e| e.extn_id == ANDROID_ATTESTATION_OID)
                })
            {
                return Ok(());
            }

            let Ok((_, remaining_chain)) = parse_tlv(&cert_chain) else {
                return Ok(());
            };
            let first_chain_cert = &cert_chain[..cert_chain.len() - remaining_chain.len()];
            if !keybox_signing_certs
                .iter()
                .any(|cert| cert.as_slice() == first_chain_cert)
            {
                return Ok(());
            }
            let Ok(first_chain_cert) = Certificate::from_der(first_chain_cert) else {
                return Ok(());
            };
            if leaf_cert.tbs_certificate.issuer != first_chain_cert.tbs_certificate.subject {
                return Ok(());
            }

            candidates.push((key_id, km_uuid.get_digest().to_vec()));
            Ok(())
        })
        .context("Failed to extract keybox attestation metadata backfill candidates")?;

        for (key_id, prefix) in candidates {
            tx.execute(
                "INSERT OR IGNORE INTO persistent.keymetadata (keyentryid, tag, data) VALUES (?, ?, ?);",
                params![key_id, KeyMetaData::KeyboxAttestationUuidPrefix, prefix],
            )
            .context("Trying to insert keybox attestation metadata")?;
        }

        // DB version is now 3.
        Ok(3)
    }

    fn init_tables(tx: &Transaction) -> Result<()> {
        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyentry (
                     id INTEGER UNIQUE,
                     key_type INTEGER,
                     domain INTEGER,
                     namespace INTEGER,
                     alias BLOB,
                     state INTEGER,
                     km_uuid BLOB);",
            [],
        )
        .context("Failed to initialize \"keyentry\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_id_index
            ON keyentry(id);",
            [],
        )
        .context("Failed to create index keyentry_id_index.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_domain_namespace_index
            ON keyentry(domain, namespace, alias);",
            [],
        )
        .context("Failed to create index keyentry_domain_namespace_index.")?;

        // Index added in v2 of database schema.
        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_state_index
            ON keyentry(state);",
            [],
        )
        .context("Failed to create index keyentry_state_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobentry (
                    id INTEGER PRIMARY KEY,
                    subcomponent_type INTEGER,
                    keyentryid INTEGER,
                    blob BLOB,
                    state INTEGER DEFAULT 0);", // `state` added in v2 of schema
            [],
        )
        .context("Failed to initialize \"blobentry\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobentry_keyentryid_index
            ON blobentry(keyentryid);",
            [],
        )
        .context("Failed to create index blobentry_keyentryid_index.")?;

        // Index added in v2 of database schema.
        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobentry_state_index
            ON blobentry(subcomponent_type, state);",
            [],
        )
        .context("Failed to create index blobentry_state_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobmetadata (
                     id INTEGER PRIMARY KEY,
                     blobentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     UNIQUE (blobentryid, tag));",
            [],
        )
        .context("Failed to initialize \"blobmetadata\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobmetadata_blobentryid_index
            ON blobmetadata(blobentryid);",
            [],
        )
        .context("Failed to create index blobmetadata_blobentryid_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     security_level INTEGER);",
            [],
        )
        .context("Failed to initialize \"keyparameter\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyparameter_keyentryid_index
            ON keyparameter(keyentryid);",
            [],
        )
        .context("Failed to create index keyparameter_keyentryid_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keymetadata (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     UNIQUE (keyentryid, tag));",
            [],
        )
        .context("Failed to initialize \"keymetadata\" table.")?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keymetadata_keyentryid_index
            ON keymetadata(keyentryid);",
            [],
        )
        .context("Failed to create index keymetadata_keyentryid_index.")?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.grant (
                    id INTEGER UNIQUE,
                    grantee INTEGER,
                    keyentryid INTEGER,
                    access_vector INTEGER);",
            [],
        )
        .context("Failed to initialize \"grant\" table.")?;

        Ok(())
    }

    fn make_persistent_path(db_root: &Path) -> Result<String> {
        // Build the path to the sqlite file.
        let mut persistent_path = db_root.to_path_buf();
        persistent_path.push(Self::PERSISTENT_DB_FILENAME);

        // Now convert them to strings prefixed with "file:"
        let mut persistent_path_str = "file:".to_owned();
        persistent_path_str.push_str(&persistent_path.to_string_lossy());

        Ok(persistent_path_str)
    }

    fn make_connection(persistent_file: &str) -> Result<Connection> {
        let conn =
            Connection::open_in_memory().context("Failed to initialize SQLite connection.")?;

        loop {
            if let Err(e) = conn
                .execute("ATTACH DATABASE ? as persistent;", params![persistent_file])
                .context("Failed to attach database persistent.")
            {
                if Self::is_locked_error(&e) {
                    std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                    continue;
                } else {
                    return Err(e);
                }
            }
            break;
        }

        // Drop the cache size from default (2M) to 0.5M
        conn.execute("PRAGMA persistent.cache_size = -500;", params![])
            .context("Failed to decrease cache size for persistent db")?;

        log::info!("Setting synchronous=EXTRA");
        conn.execute("PRAGMA persistent.synchronous = EXTRA;", params![])
            .context("Failed to set synchronous mode to EXTRA")?;

        Ok(conn)
    }

    fn do_table_size_query(
        &mut self,
        storage_type: MetricsStorage,
        query: &str,
        params: &[&str],
    ) -> Result<StorageStats> {
        let (total, unused) = self.with_transaction(TransactionBehavior::Deferred, |tx| {
            tx.query_row(query, params_from_iter(params), |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .with_context(|| {
                ks_err!(
                    "get_storage_stat: Error size of storage type {}",
                    storage_type.0
                )
            })
            .no_gc()
        })?;
        Ok(StorageStats {
            storage_type,
            size: total,
            unused_size: unused,
        })
    }

    fn get_total_size(&mut self) -> Result<StorageStats> {
        self.do_table_size_query(
            MetricsStorage::DATABASE,
            "SELECT page_count * page_size, freelist_count * page_size
             FROM pragma_page_count('persistent'),
                  pragma_page_size('persistent'),
                  persistent.pragma_freelist_count();",
            &[],
        )
    }

    fn get_table_size(
        &mut self,
        storage_type: MetricsStorage,
        schema: &str,
        table: &str,
    ) -> Result<StorageStats> {
        self.do_table_size_query(
            storage_type,
            "SELECT pgsize,unused FROM dbstat(?1)
             WHERE name=?2 AND aggregate=TRUE;",
            &[schema, table],
        )
    }

    /// Fetches a storage statistics atom for a given storage type. For storage
    /// types that map to a table, information about the table's storage is
    /// returned. Requests for storage types that are not DB tables return None.
    pub fn get_storage_stat(&mut self, storage_type: MetricsStorage) -> Result<StorageStats> {
        let _wp = wd::watch_millis_with("KeystoreDB::get_storage_stat", 500, storage_type);

        match storage_type {
            MetricsStorage::DATABASE => self.get_total_size(),
            MetricsStorage::KEY_ENTRY => {
                self.get_table_size(storage_type, "persistent", "keyentry")
            }
            MetricsStorage::KEY_ENTRY_ID_INDEX => {
                self.get_table_size(storage_type, "persistent", "keyentry_id_index")
            }
            MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX => self.get_table_size(
                storage_type,
                "persistent",
                "keyentry_domain_namespace_index",
            ),
            MetricsStorage::BLOB_ENTRY => {
                self.get_table_size(storage_type, "persistent", "blobentry")
            }
            MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX => {
                self.get_table_size(storage_type, "persistent", "blobentry_keyentryid_index")
            }
            MetricsStorage::KEY_PARAMETER => {
                self.get_table_size(storage_type, "persistent", "keyparameter")
            }
            MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX => {
                self.get_table_size(storage_type, "persistent", "keyparameter_keyentryid_index")
            }
            MetricsStorage::KEY_METADATA => {
                self.get_table_size(storage_type, "persistent", "keymetadata")
            }
            MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX => {
                self.get_table_size(storage_type, "persistent", "keymetadata_keyentryid_index")
            }
            MetricsStorage::GRANT => self.get_table_size(storage_type, "persistent", "grant"),
            MetricsStorage::AUTH_TOKEN => {
                // Since the table is actually a BTreeMap now, unused_size is not meaningfully
                // reportable
                // Size provided is only an approximation
                Ok(StorageStats {
                    storage_type,
                    size: (self.perboot.auth_tokens_len() * std::mem::size_of::<AuthTokenEntry>())
                        as i32,
                    unused_size: 0,
                })
            }
            MetricsStorage::BLOB_METADATA => {
                self.get_table_size(storage_type, "persistent", "blobmetadata")
            }
            MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX => {
                self.get_table_size(storage_type, "persistent", "blobmetadata_blobentryid_index")
            }
            _ => Err(anyhow::Error::msg(format!(
                "Unsupported storage type: {}",
                storage_type.0
            ))),
        }
    }

    /// Return the top `max_usize` uids by numbers of keys owned, together with their key
    /// count. Only return uids that own more than `min_key_count` keys.
    pub fn per_uid_counts(
        &mut self,
        max_uids: usize,
        min_key_count: usize,
    ) -> Result<Vec<(i32, usize)>> {
        self.with_transaction(Immediate("TX_per_uid_counts"), |tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT namespace, COUNT(*) FROM persistent.keyentry
                         WHERE domain = ?
                         GROUP BY namespace
                         ORDER BY COUNT(*) DESC
                         LIMIT ?;",
                )
                .context(ks_err!(
                    "KeystoreDB::per_uid_counts: failed to prepare statement"
                ))?;
            let mut rows = stmt
                .query(params![Domain::APP.0, max_uids as i64])
                .context(ks_err!("KeystoreDB::per_uid_counts: query failed"))?;
            let mut results = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                let uid: i32 = row.get(0).context("Failed to read namespace column")?;
                let count: i64 = row.get(1).context("Failed to read count")?;
                let count = usize::try_from(count).context("key count out of range")?;
                if count > min_key_count {
                    results.push((uid, count));
                }
                Ok(())
            })?;
            Ok(results).no_gc()
        })
        .context("KeystoreDB::per_uid_counts")
    }

    /// This function is intended to be used by the garbage collector.
    /// It deletes the blobs given by `blob_ids_to_delete`. It then tries to find up to `max_blobs`
    /// superseded key blobs that might need special handling by the garbage collector.
    /// If no further superseded blobs can be found it deletes all other superseded blobs that don't
    /// need special handling and returns None.
    pub fn handle_next_superseded_blobs(
        &mut self,
        blob_ids_to_delete: &[i64],
        max_blobs: usize,
    ) -> Result<Vec<SupersededBlob>> {
        let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob");
        self.with_transaction(Immediate("TX_handle_next_superseded_blob"), |tx| {
            // Delete the given blobs.
            for blob_id in blob_ids_to_delete {
                tx.execute(
                    "DELETE FROM persistent.blobmetadata WHERE blobentryid = ?;",
                    params![blob_id],
                )
                .context(ks_err!("Trying to delete blob metadata: {:?}", blob_id))?;
                tx.execute(
                    "DELETE FROM persistent.blobentry WHERE id = ?;",
                    params![blob_id],
                )
                .context(ks_err!("Trying to delete blob: {:?}", blob_id))?;
            }

            Self::cleanup_unreferenced(tx).context("Trying to cleanup unreferenced.")?;

            // Find up to `max_blobs` more out-of-date key blobs, load their metadata and return it.
            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next v2");
            let mut stmt = tx
                .prepare(
                    "SELECT id, blob FROM persistent.blobentry
                        WHERE subcomponent_type = ? AND state != ?
                        LIMIT ?;",
                )
                .context("Trying to prepare query for superseded blobs.")?;

            let rows = stmt
                .query_map(
                    params![
                        SubComponentType::KEY_BLOB,
                        BlobState::Current,
                        max_blobs as i64
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .context("Trying to query superseded blob.")?;

            let result: Vec<(i64, Vec<u8>)> = rows
                .collect::<Result<Vec<(i64, Vec<u8>)>, rusqlite::Error>>()
                .context("Trying to extract superseded blobs.")?;

            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob load_metadata");
            let result = result
                .into_iter()
                .map(|(blob_id, blob)| {
                    Ok(SupersededBlob {
                        blob_id,
                        blob,
                        metadata: BlobMetaData::load_from_db(blob_id, tx)?,
                    })
                })
                .collect::<Result<Vec<_>>>()
                .context("Trying to load blob metadata.")?;
            if !result.is_empty() {
                return Ok(result).no_gc();
            }

            // We did not find any out-of-date key blobs, so let's remove other types of superseded
            // blob in one transaction.
            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete v2");
            tx.execute(
                "DELETE FROM persistent.blobentry
                    WHERE subcomponent_type != ? AND state != ?;",
                params![SubComponentType::KEY_BLOB, BlobState::Current],
            )
            .context("Trying to purge out-of-date blobs (other than keyblobs)")?;
            Ok(vec![]).no_gc()
        })
        .context(ks_err!())
    }

    /// This maintenance function should be called only once before the database is used for the
    /// first time. It restores the invariant that `KeyLifeCycle::Existing` is a transient state.
    ///
    /// The function transitions all key entries from Existing to Unreferenced unconditionally and
    /// returns the number of rows affected. If this returns a value greater than 0, it means that
    /// Keystore crashed at some point during key generation. Callers may want to log such
    /// occurrences.
    ///
    /// Unlike with `remove_key_rows`, we don't need to purge grants, because only keys that made
    /// it to `KeyLifeCycle::Live` may have grants.
    ///
    /// The function also marks any `blobentry` rows that don't have an owning `keyentry` row as
    /// orphaned.
    pub fn cleanup_leftovers(&mut self, orphan_limit: usize) -> Result<usize> {
        let _wp = wd::watch("KeystoreDB::cleanup_leftovers");

        self.with_transaction(Immediate("TX_cleanup_leftovers_mark_orphans"), |tx| {
            // Mark as orphaned any blobentry rows that have no associated keyentry row.
            // Apply a per-reboot limit to avoid the possibility of delayed startup.
            let marked = tx
                .execute(
                    "UPDATE persistent.blobentry SET state = ?
                    WHERE id IN (
                      SELECT id FROM persistent.blobentry
                      WHERE keyentryid NOT IN (
                        SELECT id FROM persistent.keyentry
                      )
                      LIMIT ?);",
                    params![BlobState::Orphaned, orphan_limit as i64],
                )
                .context("Trying to mark orphaned blobs")?;
            if marked > 0 {
                info!("marked {marked} blobs without owners as orphaned");
            }
            Ok(()).need_gc()
        })
        .context(ks_err!())?;

        self.with_transaction(Immediate("TX_cleanup_leftovers"), |tx| {
            tx.execute(
                "UPDATE persistent.keyentry SET state = ? WHERE state = ?;",
                params![KeyLifeCycle::Unreferenced, KeyLifeCycle::Existing],
            )
            .context("Failed to execute query.")
            .need_gc()
        })
        .context(ks_err!())
    }

    pub fn terminate_uuid(&mut self, km_uuid: &Uuid) -> Result<()> {
        self.terminate_uuid_with_count(km_uuid).map(|_| ())
    }

    pub fn retire_stale_keybox_bound_entries(
        &mut self,
        current_identity_digest: [u8; 32],
    ) -> Result<usize> {
        let _wp = wd::watch("KeystoreDB::retire_stale_keybox_bound_entries");

        self.with_transaction(Immediate("TX_retire_stale_keybox_bound_entries"), |tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT k.id, k.km_uuid, m.data
                     FROM persistent.keyentry AS k
                     JOIN persistent.keymetadata AS m
                       ON m.keyentryid = k.id
                      AND m.tag = ?
                     WHERE k.key_type = ?
                       AND k.state != ?;",
                )
                .context("Failed to prepare keybox-bound stale key query.")?;

            let mut rows = stmt
                .query(params![
                    KeyMetaData::KeyboxAttestationUuidPrefix,
                    KeyType::Client,
                    KeyLifeCycle::Unreferenced
                ])
                .context("Failed to query keybox-bound stale keys.")?;

            let mut stale_keys = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                let key_id = row.get(0).context("Failed to read stale key id.")?;
                let km_uuid: Uuid = row.get(1).context("Failed to read stale key UUID.")?;
                let prefix: Value = row
                    .get(2)
                    .context("Failed to read stale keybox attestation metadata.")?;
                let retire = match prefix {
                    Value::Blob(prefix)
                        if prefix.len() == KEYBOX_UUID_DIGEST_BYTES
                            && km_uuid.is_keybox_bound()
                            && prefix.as_slice() == km_uuid.get_digest() =>
                    {
                        !km_uuid.is_bound_to_keybox_digest(current_identity_digest)
                    }
                    Value::Blob(prefix) => {
                        log::warn!(
                            "retiring keybox-bound key with invalid attestation metadata: key_id={key_id:#x} uuid={km_uuid:?} prefix_len={}",
                            prefix.len(),
                        );
                        true
                    }
                    _ => {
                        log::warn!(
                            "retiring keybox-bound key with invalid attestation metadata type: key_id={key_id:#x} uuid={km_uuid:?}",
                        );
                        true
                    }
                };
                if retire {
                    stale_keys.push((key_id, km_uuid));
                }
                Ok(())
            })
            .context("Failed to extract stale keybox-bound rows.")?;

            let key_count = stale_keys.len();
            log::info!("found {key_count} stale keybox-bound keys to retire");

            let mut notify_gc = false;
            for (key_id, km_uuid) in stale_keys {
                log::debug!("retiring stale keybox-bound key key_id={key_id:#x} uuid={km_uuid:?}");
                notify_gc = Self::remove_key_rows(tx, key_id)
                    .context("Retiring stale keybox-bound key.")?
                    || notify_gc;
            }

            Ok(key_count).do_gc(notify_gc)
        })
        .context(ks_err!())
    }

    fn terminate_uuid_with_count(&mut self, km_uuid: &Uuid) -> Result<usize> {
        log::info!("terminating all keys created by uuid={km_uuid:0x?}");
        let _wp = wd::watch("KeystoreDB::terminate_uuid");

        self.with_transaction(Immediate("TX_terminate_uuid"), |tx| {
            let mut stmt = tx
                .prepare(
                    "SELECT id FROM persistent.keyentry
                     WHERE km_uuid = ?;",
                )
                .context(
                    "Failed to prepare the query to find the keys created by the given UUID.",
                )?;

            let mut rows = stmt
                .query(params![km_uuid])
                .context("Failed to query the keys created by the given UUID.")?;

            let mut key_ids: Vec<i64> = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                key_ids.push(row.get(0).context("Failed to read key id.")?);
                Ok(())
            })
            .context("Failed to extract rows.")?;

            let key_count = key_ids.len();
            log::info!("found {key_count} keys to terminate");

            let mut notify_gc = false;
            for key_id in key_ids {
                log::debug!("terminating key key_id={key_id:0x?}");
                notify_gc =
                    Self::remove_key_rows(tx, key_id).context("In terminate_uuid.")? || notify_gc;
            }

            Ok(key_count).do_gc(notify_gc)
        })
        .context(ks_err!())
    }

    /// Checks if a key exists with given key type and key descriptor properties.
    pub fn key_exists(
        &mut self,
        domain: Domain,
        nspace: i64,
        alias: &str,
        key_type: KeyType,
    ) -> Result<bool> {
        let _wp = wd::watch("KeystoreDB::key_exists");

        self.with_transaction(Immediate("TX_key_exists"), |tx| {
            let key_descriptor = KeyDescriptor {
                domain,
                nspace,
                alias: Some(alias.to_string()),
                blob: None,
            };
            let result = Self::load_key_entry_id(tx, &key_descriptor, key_type);
            match result {
                Ok(_) => Ok(true),
                Err(error) => match error.root_cause().downcast_ref::<KsError>() {
                    Some(KsError::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(false),
                    _ => Err(error).context(ks_err!("Failed to find if the key exists.")),
                },
            }
            .no_gc()
        })
        .context(ks_err!())
    }

    /// Stores a super key in the database.
    pub fn store_super_key(
        &mut self,
        user: AndroidUserId,
        key_type: &SuperKeyType,
        blob: &[u8],
        blob_metadata: &BlobMetaData,
        key_metadata: &KeyMetaData,
    ) -> Result<KeyEntry> {
        let _wp = wd::watch("KeystoreDB::store_super_key");

        self.with_transaction(Immediate("TX_store_super_key"), |tx| {
            let key_id = Self::insert_with_retry(|id| {
                tx.execute(
                    "INSERT into persistent.keyentry
                            (id, key_type, domain, namespace, alias, state, km_uuid)
                            VALUES(?, ?, ?, ?, ?, ?, ?);",
                    params![
                        id,
                        KeyType::Super,
                        Domain::APP.0,
                        user.0 as i64,
                        key_type.alias,
                        KeyLifeCycle::Live,
                        &KEYSTORE_UUID,
                    ],
                )
            })
            .context("Failed to insert into keyentry table.")?;

            key_metadata
                .store_in_db(key_id, tx)
                .context("KeyMetaData::store_in_db failed")?;

            Self::set_blob_internal(
                tx,
                key_id,
                SubComponentType::KEY_BLOB,
                Some(blob),
                Some(blob_metadata),
            )
            .context("Failed to store key blob.")?;

            Self::load_key_components(tx, KeyEntryLoadBits::KM, key_id)
                .context("Trying to load key components.")
                .no_gc()
        })
        .context(ks_err!())
    }

    /// Loads super key of a given user, if exists
    pub fn load_super_key(
        &mut self,
        key_type: &SuperKeyType,
        user: AndroidUserId,
    ) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        let _wp = wd::watch("KeystoreDB::load_super_key");

        self.with_transaction(Immediate("TX_load_super_key"), |tx| {
            let key_descriptor = KeyDescriptor {
                domain: Domain::APP,
                nspace: user.0 as i64,
                alias: Some(key_type.alias.into()),
                blob: None,
            };
            let id = Self::load_key_entry_id(tx, &key_descriptor, KeyType::Super);
            match id {
                Ok(id) => {
                    let key_entry = Self::load_key_components(tx, KeyEntryLoadBits::KM, id)
                        .context(ks_err!("Failed to load key entry."))?;
                    Ok(Some((KEY_ID_LOCK.get(id), key_entry)))
                }
                Err(error) => match error.root_cause().downcast_ref::<KsError>() {
                    Some(KsError::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                    _ => Err(error).context(ks_err!()),
                },
            }
            .no_gc()
        })
        .context(ks_err!())
    }

    /// Creates a transaction with the given behavior and executes f with the new transaction.
    /// The transaction is committed only if f returns Ok and retried if DatabaseBusy
    /// or DatabaseLocked is encountered.
    fn with_transaction<T, F>(&mut self, behavior: TransactionBehavior, f: F) -> Result<T>
    where
        F: Fn(&Transaction) -> Result<(bool, T)>,
    {
        let name = behavior.name();
        loop {
            let result = self
                .conn
                .transaction_with_behavior(behavior.into())
                .context(ks_err!())
                .and_then(|tx| {
                    let _wp = name.map(wd::watch);
                    f(&tx).map(|result| (result, tx))
                })
                .and_then(|(result, tx)| {
                    tx.commit()
                        .context(ks_err!("Failed to commit transaction."))?;
                    Ok(result)
                });
            match result {
                Ok(result) => break Ok(result),
                Err(e) => {
                    if Self::is_locked_error(&e) {
                        std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                        continue;
                    } else {
                        return Err(e).context(ks_err!());
                    }
                }
            }
        }
        .map(|(need_gc, result)| {
            if need_gc {
                if let Some(ref gc) = self.gc {
                    gc.notify_gc();
                }
            }
            result
        })
    }

    fn is_locked_error(e: &anyhow::Error) -> bool {
        matches!(
            e.root_cause().downcast_ref::<rusqlite::ffi::Error>(),
            Some(rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy,
                ..
            }) | Some(rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseLocked,
                ..
            })
        )
    }

    fn create_key_entry_internal(
        tx: &Transaction,
        domain: &Domain,
        namespace: &i64,
        key_type: KeyType,
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        match *domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys()).context(ks_err!(
                    "Domain {:?} must be either App or SELinux.",
                    domain
                ));
            }
        }
        Ok(KEY_ID_LOCK.get(
            Self::insert_with_retry(|id| {
                tx.execute(
                    "INSERT into persistent.keyentry
                     (id, key_type, domain, namespace, alias, state, km_uuid)
                     VALUES(?, ?, ?, ?, NULL, ?, ?);",
                    params![
                        id,
                        key_type,
                        domain.0 as u32,
                        *namespace,
                        KeyLifeCycle::Existing,
                        km_uuid,
                    ],
                )
            })
            .context(ks_err!())?,
        ))
    }

    /// Set a new blob and associates it with the given key id. Each blob
    /// has a sub component type.
    /// Each key can have one of each sub component type associated. If more
    /// are added only the most recent can be retrieved, and superseded blobs
    /// will get garbage collected.
    /// Components SubComponentType::CERT and SubComponentType::CERT_CHAIN can be
    /// removed by setting blob to None.
    pub fn set_blob(
        &mut self,
        key_id: &KeyIdGuard,
        sc_type: SubComponentType,
        blob: Option<&[u8]>,
        blob_metadata: Option<&BlobMetaData>,
    ) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::set_blob");

        self.with_transaction(Immediate("TX_set_blob"), |tx| {
            Self::set_blob_internal(tx, key_id.0, sc_type, blob, blob_metadata).need_gc()
        })
        .context(ks_err!())
    }

    /// Why would we insert a deleted blob? This weird function is for the purpose of legacy
    /// key migration in the case where we bulk delete all the keys of an app or even a user.
    /// We use this to insert key blobs into the database which can then be garbage collected
    /// lazily by the key garbage collector.
    pub fn set_deleted_blob(&mut self, blob: &[u8], blob_metadata: &BlobMetaData) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::set_deleted_blob");

        self.with_transaction(Immediate("TX_set_deleted_blob"), |tx| {
            Self::set_blob_internal(
                tx,
                Self::UNASSIGNED_KEY_ID,
                SubComponentType::KEY_BLOB,
                Some(blob),
                Some(blob_metadata),
            )
            .need_gc()
        })
        .context(ks_err!())
    }

    fn set_blob_internal(
        tx: &Transaction,
        key_id: i64,
        sc_type: SubComponentType,
        blob: Option<&[u8]>,
        blob_metadata: Option<&BlobMetaData>,
    ) -> Result<()> {
        match (blob, sc_type) {
            (Some(blob), _) => {
                // Mark any previous blobentry(s) of the same type for the same key as superseded.
                tx.execute(
                    "UPDATE persistent.blobentry SET state = ?
                    WHERE keyentryid = ? AND subcomponent_type = ?",
                    params![BlobState::Superseded, key_id, sc_type],
                )
                .context(ks_err!(
                    "Failed to mark prior {sc_type:?} blobentrys for {key_id} as superseded"
                ))?;

                // Now insert the new, un-superseded, blob.  (If this fails, the marking of
                // old blobs as superseded will be rolled back, because we're inside a
                // transaction.)
                tx.execute(
                    "INSERT INTO persistent.blobentry
                     (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
                    params![sc_type, key_id, blob],
                )
                .context(ks_err!("Failed to insert blob."))?;

                if let Some(blob_metadata) = blob_metadata {
                    let blob_id = tx
                        .query_row("SELECT MAX(id) FROM persistent.blobentry;", [], |row| {
                            row.get(0)
                        })
                        .context(ks_err!("Failed to get new blob id."))?;

                    blob_metadata
                        .store_in_db(blob_id, tx)
                        .context(ks_err!("Trying to store blob metadata."))?;
                }
            }
            (None, SubComponentType::CERT) | (None, SubComponentType::CERT_CHAIN) => {
                tx.execute(
                    "DELETE FROM persistent.blobentry
                    WHERE subcomponent_type = ? AND keyentryid = ?;",
                    params![sc_type, key_id],
                )
                .context(ks_err!("Failed to delete blob."))?;
            }
            (None, _) => {
                return Err(KsError::sys())
                    .context(ks_err!("Other blobs cannot be deleted in this way."));
            }
        }
        if sc_type == SubComponentType::CERT || sc_type == SubComponentType::CERT_CHAIN {
            tx.execute(
                "DELETE FROM persistent.keymetadata
                 WHERE keyentryid = ? AND tag = ?;",
                params![key_id, KeyMetaData::KeyboxAttestationUuidPrefix],
            )
            .context("Trying to clear keybox attestation metadata.")?;
        }
        Ok(())
    }

    fn insert_keyparameter_internal(
        tx: &Transaction,
        key_id: &KeyIdGuard,
        params: &[KeyParameter],
    ) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT into persistent.keyparameter (keyentryid, tag, data, security_level)
                VALUES (?, ?, ?, ?);",
            )
            .context(ks_err!("Failed to prepare statement."))?;

        for p in params.iter() {
            stmt.insert(params![
                key_id.0,
                p.get_tag().0,
                p.key_parameter_value(),
                p.security_level().0
            ])
            .with_context(|| ks_err!("Failed to insert {:?}", p))?;
        }
        Ok(())
    }

    /// Updates the alias column of the given key id `newid` with the given alias,
    /// and atomically, removes the alias, domain, and namespace from another row
    /// with the same alias-domain-namespace tuple if such row exits.
    /// Returns Ok(true) if an old key was marked unreferenced as a hint to the garbage
    /// collector.
    fn rebind_alias(
        tx: &Transaction,
        newid: &KeyIdGuard,
        alias: &str,
        domain: &Domain,
        namespace: &i64,
        key_type: KeyType,
    ) -> Result<bool> {
        match *domain {
            Domain::APP | Domain::SELINUX => {}
            _ => {
                return Err(KsError::sys()).context(ks_err!(
                    "Domain {:?} must be either App or SELinux.",
                    domain
                ));
            }
        }
        // Mark any existing key for the alias/domain/namespace/key_type as `Unreferenced` (and wipe
        // its alias/domain/namespace info) so it can be removed in a subsequent GC pass (in
        // `cleanup_unreferenced()`).
        let updated = tx
            .execute(
                "UPDATE persistent.keyentry
                 SET alias = NULL, domain = NULL, namespace = NULL, state = ?
                 WHERE alias = ? AND domain = ? AND namespace = ? AND key_type = ?;",
                params![
                    KeyLifeCycle::Unreferenced,
                    alias,
                    domain.0 as u32,
                    namespace,
                    key_type
                ],
            )
            .context(ks_err!("Failed to rebind existing entry."))?;
        // Bind the new key ID to the alias and make it `Live`.
        let result = tx
            .execute(
                "UPDATE persistent.keyentry
                    SET alias = ?, state = ?
                    WHERE id = ? AND domain = ? AND namespace = ? AND state = ? AND key_type = ?;",
                params![
                    alias,
                    KeyLifeCycle::Live,
                    newid.0,
                    domain.0 as u32,
                    *namespace,
                    KeyLifeCycle::Existing,
                    key_type,
                ],
            )
            .context(ks_err!("Failed to set alias."))?;
        if result != 1 {
            return Err(KsError::sys()).context(ks_err!(
                "Expected to update a single entry but instead updated {}.",
                result
            ));
        }
        Ok(updated != 0)
    }

    /// Moves the key given by KeyIdGuard to the new location at `destination`. If the destination
    /// is already occupied by a key, this function fails with `ResponseCode::INVALID_ARGUMENT`.
    pub fn migrate_key_namespace(
        &mut self,
        key_id_guard: KeyIdGuard,
        destination: &KeyDescriptor,
        caller_uid: AppUid,
        check_permission: impl Fn(&KeyDescriptor) -> Result<()>,
    ) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::migrate_key_namespace");

        let destination = match destination.domain {
            Domain::APP => KeyDescriptor {
                nspace: caller_uid.0,
                ..(*destination).clone()
            },
            Domain::SELINUX => (*destination).clone(),
            domain => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context(format!("Domain {domain:?} must be either APP or SELINUX."));
            }
        };

        // Security critical: Must return immediately on failure. Do not remove the '?';
        check_permission(&destination).context(ks_err!("Trying to check permission."))?;

        let alias = destination
            .alias
            .as_ref()
            .ok_or(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
            .context(ks_err!("Alias must be specified."))?;

        self.with_transaction(Immediate("TX_migrate_key_namespace"), |tx| {
            // Query the destination location. If there is a key, the migration request fails.
            if tx
                .query_row(
                    "SELECT id FROM persistent.keyentry
                     WHERE alias = ? AND domain = ? AND namespace = ?;",
                    params![alias, destination.domain.0, destination.nspace],
                    |_| Ok(()),
                )
                .optional()
                .context("Failed to query destination.")?
                .is_some()
            {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context("Target already exists.");
            }

            let updated = tx
                .execute(
                    "UPDATE persistent.keyentry
                 SET alias = ?, domain = ?, namespace = ?
                 WHERE id = ?;",
                    params![
                        alias,
                        destination.domain.0,
                        destination.nspace,
                        key_id_guard.id()
                    ],
                )
                .context("Failed to update key entry.")?;

            if updated != 1 {
                return Err(KsError::sys()).context(format!(
                    "Update succeeded, but {updated} rows were updated."
                ));
            }
            Ok(()).no_gc()
        })
        .context(ks_err!())
    }

    /// Store a new key in a single transaction.
    /// The function creates a new key entry, populates the blob, key parameter, and metadata
    /// fields, and rebinds the given alias to the new key.
    /// The boolean returned is a hint for the garbage collector. If true, a key was replaced,
    /// is now unreferenced and needs to be collected.
    #[allow(clippy::too_many_arguments)]
    pub fn store_new_key(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        params: &[KeyParameter],
        blob_info: &BlobInfo,
        cert_info: &CertificateInfo,
        metadata: &KeyMetaData,
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        let _wp = wd::watch("KeystoreDB::store_new_key");

        let (alias, domain, namespace) = match key {
            KeyDescriptor {
                alias: Some(alias),
                domain: Domain::APP,
                nspace,
                blob: None,
            }
            | KeyDescriptor {
                alias: Some(alias),
                domain: Domain::SELINUX,
                nspace,
                blob: None,
            } => (alias, key.domain, nspace),
            _ => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context(ks_err!("Need alias and domain must be APP or SELINUX."));
            }
        };
        self.with_transaction(Immediate("TX_store_new_key"), |tx| {
            let key_id = Self::create_key_entry_internal(tx, &domain, namespace, key_type, km_uuid)
                .context("Trying to create new key entry.")?;
            let BlobInfo {
                blob,
                metadata: blob_metadata,
                superseded_blob,
            } = *blob_info;

            // In some occasions the key blob is already upgraded during the import.
            // In order to make sure it gets properly deleted it is inserted into the
            // database here and then immediately replaced by the superseding blob.
            // The garbage collector will then subject the blob to deleteKey of the
            // KM back end to permanently invalidate the key.
            let need_gc = if let Some((blob, blob_metadata)) = superseded_blob {
                Self::set_blob_internal(
                    tx,
                    key_id.id(),
                    SubComponentType::KEY_BLOB,
                    Some(blob),
                    Some(blob_metadata),
                )
                .context("Trying to insert superseded key blob.")?;
                true
            } else {
                false
            };

            Self::set_blob_internal(
                tx,
                key_id.id(),
                SubComponentType::KEY_BLOB,
                Some(blob),
                Some(blob_metadata),
            )
            .context("Trying to insert the key blob.")?;
            if let Some(cert) = &cert_info.cert {
                Self::set_blob_internal(tx, key_id.id(), SubComponentType::CERT, Some(cert), None)
                    .context("Trying to insert the certificate.")?;
            }
            if let Some(cert_chain) = &cert_info.cert_chain {
                Self::set_blob_internal(
                    tx,
                    key_id.id(),
                    SubComponentType::CERT_CHAIN,
                    Some(cert_chain),
                    None,
                )
                .context("Trying to insert the certificate chain.")?;
            }
            Self::insert_keyparameter_internal(tx, &key_id, params)
                .context("Trying to insert key parameters.")?;
            metadata
                .store_in_db(key_id.id(), tx)
                .context("Trying to insert key metadata.")?;
            let need_gc = Self::rebind_alias(tx, &key_id, alias, &domain, namespace, key_type)
                .context("Trying to rebind alias.")?
                || need_gc;
            Ok(key_id).do_gc(need_gc)
        })
        .context(ks_err!())
    }

    /// Store a new certificate
    /// The function creates a new key entry, populates the blob field and metadata, and rebinds
    /// the given alias to the new cert.
    pub fn store_new_certificate(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        cert: &[u8],
        km_uuid: &Uuid,
    ) -> Result<KeyIdGuard> {
        let _wp = wd::watch("KeystoreDB::store_new_certificate");

        let (alias, domain, namespace) = match key {
            KeyDescriptor {
                alias: Some(alias),
                domain: Domain::APP,
                nspace,
                blob: None,
            }
            | KeyDescriptor {
                alias: Some(alias),
                domain: Domain::SELINUX,
                nspace,
                blob: None,
            } => (alias, key.domain, nspace),
            _ => {
                return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT))
                    .context(ks_err!("Need alias and domain must be APP or SELINUX."));
            }
        };
        self.with_transaction(Immediate("TX_store_new_certificate"), |tx| {
            let key_id = Self::create_key_entry_internal(tx, &domain, namespace, key_type, km_uuid)
                .context("Trying to create new key entry.")?;

            Self::set_blob_internal(
                tx,
                key_id.id(),
                SubComponentType::CERT_CHAIN,
                Some(cert),
                None,
            )
            .context("Trying to insert certificate.")?;

            let mut metadata = KeyMetaData::new();
            metadata.add(KeyMetaEntry::CreationDate(
                DateTime::now().context("Trying to make creation time.")?,
            ));

            metadata
                .store_in_db(key_id.id(), tx)
                .context("Trying to insert key metadata.")?;

            let need_gc = Self::rebind_alias(tx, &key_id, alias, &domain, namespace, key_type)
                .context("Trying to rebind alias.")?;
            Ok(key_id).do_gc(need_gc)
        })
        .context(ks_err!())
    }

    // Helper function loading the key_id given the key descriptor
    // tuple comprising domain, namespace, and alias.
    // Requires a valid transaction.
    fn load_key_entry_id(tx: &Transaction, key: &KeyDescriptor, key_type: KeyType) -> Result<i64> {
        let alias = key
            .alias
            .as_ref()
            .map_or_else(|| Err(KsError::sys()), Ok)
            .context("In load_key_entry_id: Alias must be specified.")?;
        let mut stmt = tx
            .prepare(
                "SELECT id FROM persistent.keyentry
                    WHERE
                    key_type = ?
                    AND domain = ?
                    AND namespace = ?
                    AND alias = ?
                    AND state = ?;",
            )
            .context("In load_key_entry_id: Failed to select from keyentry table.")?;
        let mut rows = stmt
            .query(params![
                key_type,
                key.domain.0 as u32,
                key.nspace,
                alias,
                KeyLifeCycle::Live
            ])
            .context("In load_key_entry_id: Failed to read from keyentry table.")?;
        db_utils::with_rows_extract_one(&mut rows, |row| {
            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?
                .get(0)
                .context("Failed to unpack id.")
        })
        .context(ks_err!())
    }

    /// This helper function completes the access tuple of a key, which is required
    /// to perform access control. The strategy depends on the `domain` field in the
    /// key descriptor.
    /// * Domain::SELINUX: The access tuple is complete and this function only loads
    ///   the key_id for further processing.
    /// * Domain::APP: Like Domain::SELINUX, but the tuple is completed by `caller_uid`
    ///   which serves as the namespace.
    /// * Domain::GRANT: The grant table is queried for the `key_id` and the
    ///   `access_vector`.
    /// * Domain::KEY_ID: The keyentry table is queried for the owning `domain` and
    ///   `namespace`.
    ///
    /// In each case the information returned is sufficient to perform the access
    /// check and the key id can be used to load further key artifacts.
    fn load_access_tuple(
        tx: &Transaction,
        key: &KeyDescriptor,
        key_type: KeyType,
        caller_uid: AppUid,
    ) -> Result<KeyAccessInfo> {
        match key.domain {
            // Domain App or SELinux. In this case we load the key_id from
            // the keyentry database for further loading of key components.
            // We already have the full access tuple to perform access control.
            // The only distinction is that we use the caller_uid instead
            // of the caller supplied namespace if the domain field is
            // Domain::APP.
            Domain::APP | Domain::SELINUX => {
                let mut access_key = key.clone();
                if access_key.domain == Domain::APP {
                    access_key.nspace = caller_uid.0;
                }
                let key_id = Self::load_key_entry_id(tx, &access_key, key_type)
                    .with_context(|| format!("With key.domain = {:?}.", access_key.domain))?;

                Ok(KeyAccessInfo {
                    key_id,
                    descriptor: access_key,
                    vector: None,
                })
            }

            // Domain::GRANT. In this case we load the key_id and the access_vector
            // from the grant table.
            Domain::GRANT => {
                let mut stmt = tx
                    .prepare(
                        "SELECT keyentryid, access_vector FROM persistent.grant
                            WHERE grantee = ? AND id = ? AND
                            (SELECT state FROM persistent.keyentry WHERE id = keyentryid) = ?;",
                    )
                    .context("Domain::GRANT prepare statement failed")?;
                let mut rows = stmt
                    .query(params![caller_uid.0, key.nspace, KeyLifeCycle::Live])
                    .context("Domain:Grant: query failed.")?;
                let (key_id, access_vector): (i64, i32) =
                    db_utils::with_rows_extract_one(&mut rows, |row| {
                        let r =
                            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?;
                        Ok((
                            r.get(0).context("Failed to unpack key_id.")?,
                            r.get(1).context("Failed to unpack access_vector.")?,
                        ))
                    })
                    .context("Domain::GRANT.")?;
                Ok(KeyAccessInfo {
                    key_id,
                    descriptor: key.clone(),
                    vector: Some(access_vector.into()),
                })
            }

            // Domain::KEY_ID. In this case we load the domain and namespace from the
            // keyentry database because we need them for access control.
            Domain::KEY_ID => {
                let (domain, namespace): (Domain, i64) = {
                    let mut stmt = tx
                        .prepare(
                            "SELECT domain, namespace FROM persistent.keyentry
                                WHERE
                                id = ?
                                AND state = ?;",
                        )
                        .context("Domain::KEY_ID: prepare statement failed")?;
                    let mut rows = stmt
                        .query(params![key.nspace, KeyLifeCycle::Live])
                        .context("Domain::KEY_ID: query failed.")?;
                    db_utils::with_rows_extract_one(&mut rows, |row| {
                        let r =
                            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?;
                        Ok((
                            Domain(r.get(0).context("Failed to unpack domain.")?),
                            r.get(1).context("Failed to unpack namespace.")?,
                        ))
                    })
                    .context("Domain::KEY_ID.")?
                };

                // We may use a key by id after loading it by grant.
                // In this case we have to check if the caller has a grant for this particular
                // key. We can skip this if we already know that the caller is the owner.
                // But we cannot know this if domain is anything but App. E.g. in the case
                // of Domain::SELINUX we have to speculatively check for grants because we have to
                // consult the SEPolicy before we know if the caller is the owner.
                let access_vector: Option<KeyPermSet> =
                    if domain != Domain::APP || namespace != caller_uid.0 {
                        let access_vector: Option<i32> = tx
                            .query_row(
                                "SELECT access_vector FROM persistent.grant
                                WHERE grantee = ? AND keyentryid = ?;",
                                params![caller_uid.0, key.nspace],
                                |row| row.get(0),
                            )
                            .optional()
                            .context("Domain::KEY_ID: query grant failed.")?;
                        access_vector.map(|p| p.into())
                    } else {
                        None
                    };

                let key_id = key.nspace;
                let mut access_key: KeyDescriptor = key.clone();
                access_key.domain = domain;
                access_key.nspace = namespace;

                Ok(KeyAccessInfo {
                    key_id,
                    descriptor: access_key,
                    vector: access_vector,
                })
            }
            _ => Err(anyhow!(KsError::Rc(ResponseCode::INVALID_ARGUMENT))),
        }
    }

    fn load_blob_components(
        key_id: i64,
        load_bits: KeyEntryLoadBits,
        tx: &Transaction,
    ) -> Result<LoadedBlobComponents> {
        let mut stmt = tx
            .prepare(
                "SELECT MAX(id), subcomponent_type, blob FROM persistent.blobentry
                    WHERE keyentryid = ? GROUP BY subcomponent_type;",
            )
            .context(ks_err!("prepare statement failed."))?;

        let mut rows = stmt
            .query(params![key_id])
            .context(ks_err!("query failed."))?;

        let mut key_blob: Option<(i64, Vec<u8>)> = None;
        let mut cert_blob: Option<Vec<u8>> = None;
        let mut cert_chain_blob: Option<Vec<u8>> = None;
        let mut has_km_blob: bool = false;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let sub_type: SubComponentType =
                row.get(1).context("Failed to extract subcomponent_type.")?;
            has_km_blob = has_km_blob || sub_type == SubComponentType::KEY_BLOB;
            match (sub_type, load_bits.load_public(), load_bits.load_km()) {
                (SubComponentType::KEY_BLOB, _, true) => {
                    key_blob = Some((
                        row.get(0).context("Failed to extract key blob id.")?,
                        row.get(2).context("Failed to extract key blob.")?,
                    ));
                }
                (SubComponentType::CERT, true, _) => {
                    cert_blob = Some(
                        row.get(2)
                            .context("Failed to extract public certificate blob.")?,
                    );
                }
                (SubComponentType::CERT_CHAIN, true, _) => {
                    cert_chain_blob = Some(
                        row.get(2)
                            .context("Failed to extract certificate chain blob.")?,
                    );
                }
                (SubComponentType::CERT, _, _)
                | (SubComponentType::CERT_CHAIN, _, _)
                | (SubComponentType::KEY_BLOB, _, _) => {}
                _ => Err(KsError::sys()).context("Unknown subcomponent type.")?,
            }
            Ok(())
        })
        .context(ks_err!())?;

        let blob_info = key_blob.map_or::<Result<_>, _>(Ok(None), |(blob_id, blob)| {
            Ok(Some((
                blob,
                BlobMetaData::load_from_db(blob_id, tx)
                    .context(ks_err!("Trying to load blob_metadata."))?,
            )))
        })?;

        Ok((has_km_blob, blob_info, cert_blob, cert_chain_blob))
    }

    fn load_key_parameters(key_id: i64, tx: &Transaction) -> Result<Vec<KeyParameter>> {
        let mut stmt = tx
            .prepare(
                "SELECT tag, data, security_level from persistent.keyparameter
                    WHERE keyentryid = ?;",
            )
            .context("In load_key_parameters: prepare statement failed.")?;

        let mut parameters: Vec<KeyParameter> = Vec::new();

        let mut rows = stmt
            .query(params![key_id])
            .context("In load_key_parameters: query failed.")?;
        db_utils::with_rows_extract_all(&mut rows, |row| {
            let tag = Tag(row.get(0).context("Failed to read tag.")?);
            let sec_level = SecurityLevel(row.get(2).context("Failed to read sec_level.")?);
            parameters.push(
                KeyParameter::new_from_sql(tag, &SqlField::new(1, row), sec_level)
                    .context("Failed to read KeyParameter.")?,
            );
            Ok(())
        })
        .context(ks_err!())?;

        Ok(parameters)
    }

    /// Decrements the usage count of a limited use key. This function first checks whether the
    /// usage has been exhausted, if not, decreases the usage count. If the usage count reaches
    /// zero, the key also gets marked unreferenced and scheduled for deletion.
    /// Returns Ok(true) if the key was marked unreferenced as a hint to the garbage collector.
    pub fn check_and_update_key_usage_count(&mut self, key_id: i64) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::check_and_update_key_usage_count");

        self.with_transaction(Immediate("TX_check_and_update_key_usage_count"), |tx| {
            let limit: Option<i32> = tx
                .query_row(
                    "SELECT data FROM persistent.keyparameter WHERE keyentryid = ? AND tag = ?;",
                    params![key_id, Tag::USAGE_COUNT_LIMIT.0],
                    |row| row.get(0),
                )
                .optional()
                .context("Trying to load usage count")?;

            let limit = limit
                .ok_or(KsError::Km(ErrorCode::INVALID_KEY_BLOB))
                .context("The Key no longer exists. Key is exhausted.")?;

            tx.execute(
                "UPDATE persistent.keyparameter
                 SET data = data - 1
                 WHERE keyentryid = ? AND tag = ? AND data > 0;",
                params![key_id, Tag::USAGE_COUNT_LIMIT.0],
            )
            .context("Failed to update key usage count.")?;

            match limit {
                1 => Self::remove_key_rows(tx, key_id)
                    .map(|need_gc| (need_gc, ()))
                    .context("Trying to mark limited use key for deletion."),
                0 => Err(KsError::Km(ErrorCode::INVALID_KEY_BLOB)).context("Key is exhausted."),
                _ => Ok(()).no_gc(),
            }
        })
        .context(ks_err!())
    }

    /// Load a key entry by the given key descriptor.
    /// It uses the `check_permission` callback to verify if the access is allowed
    /// given the key access tuple read from the database using `load_access_tuple`.
    /// With `load_bits` the caller may specify which blobs shall be loaded from
    /// the blob database.
    pub fn load_key_entry(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        load_bits: KeyEntryLoadBits,
        caller_uid: AppUid,
        check_permission: impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        let _wp = wd::watch("KeystoreDB::load_key_entry");

        loop {
            match self.load_key_entry_internal(
                key,
                key_type,
                load_bits,
                caller_uid,
                &check_permission,
            ) {
                Ok(result) => break Ok(result),
                Err(e) => {
                    if Self::is_locked_error(&e) {
                        std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                        continue;
                    } else {
                        return Err(e).context(ks_err!());
                    }
                }
            }
        }
    }

    fn load_key_entry_internal(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        load_bits: KeyEntryLoadBits,
        caller_uid: AppUid,
        check_permission: &impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        // KEY ID LOCK 1/2
        // If we got a key descriptor with a key id we can get the lock right away.
        // Otherwise we have to defer it until we know the key id.
        let key_id_guard = match key.domain {
            Domain::KEY_ID => Some(KEY_ID_LOCK.get(key.nspace)),
            _ => None,
        };

        let tx = self
            .conn
            .unchecked_transaction()
            .context(ks_err!("Failed to initialize transaction."))?;

        // Load the key_id and complete the access control tuple.
        let access = Self::load_access_tuple(&tx, key, key_type, caller_uid).context(ks_err!())?;

        // Perform access control. It is vital that we return here if the permission is denied.
        // So do not touch that '?' at the end.
        check_permission(&access.descriptor, access.vector).context(ks_err!())?;

        // KEY ID LOCK 2/2
        // If we did not get a key id lock by now, it was because we got a key descriptor
        // without a key id. At this point we got the key id, so we can try and get a lock.
        // However, we cannot block here, because we are in the middle of the transaction.
        // So first we try to get the lock non blocking. If that fails, we roll back the
        // transaction and block until we get the lock. After we successfully got the lock,
        // we start a new transaction and load the access tuple again.
        //
        // We don't need to perform access control again, because we already established
        // that the caller had access to the given key. But we need to make sure that the
        // key id still exists. So we have to load the key entry by key id this time.
        let (key_id_guard, tx) = match key_id_guard {
            None => match KEY_ID_LOCK.try_get(access.key_id) {
                None => {
                    // Roll back the transaction.
                    tx.rollback()
                        .context(ks_err!("Failed to roll back transaction."))?;

                    // Block until we have a key id lock.
                    let key_id_guard = KEY_ID_LOCK.get(access.key_id);

                    // Create a new transaction.
                    let tx = self
                        .conn
                        .unchecked_transaction()
                        .context(ks_err!("Failed to initialize transaction."))?;

                    Self::load_access_tuple(
                        &tx,
                        // This time we have to load the key by the retrieved key id, because the
                        // alias may have been rebound after we rolled back the transaction.
                        &KeyDescriptor {
                            domain: Domain::KEY_ID,
                            nspace: access.key_id,
                            ..Default::default()
                        },
                        key_type,
                        caller_uid,
                    )
                    .context(ks_err!("(deferred key lock)"))?;
                    (key_id_guard, tx)
                }
                Some(l) => (l, tx),
            },
            Some(key_id_guard) => (key_id_guard, tx),
        };

        let key_entry =
            Self::load_key_components(&tx, load_bits, key_id_guard.id()).context(ks_err!())?;

        tx.commit()
            .context(ks_err!("Failed to commit transaction."))?;

        Ok((key_id_guard, key_entry))
    }

    /// Remove database table rows associated with the given `key_id`. The one exception
    /// is that `blobentry` rows are not immediately deleted, but are instead marked as
    /// orphaned so they can be removed in a later GC operation (which also involves
    /// notifying the owning KeyMint of keyblob deletion).
    fn remove_key_rows(tx: &Transaction, key_id: i64) -> Result<bool> {
        let updated = tx
            .execute(
                "DELETE FROM persistent.keyentry WHERE id = ?;",
                params![key_id],
            )
            .context("Trying to delete keyentry.")?;
        tx.execute(
            "DELETE FROM persistent.keymetadata WHERE keyentryid = ?;",
            params![key_id],
        )
        .context("Trying to delete keymetadata.")?;
        tx.execute(
            "DELETE FROM persistent.keyparameter WHERE keyentryid = ?;",
            params![key_id],
        )
        .context("Trying to delete keyparameters.")?;
        tx.execute(
            "DELETE FROM persistent.grant WHERE keyentryid = ?;",
            params![key_id],
        )
        .context("Trying to delete grants to other apps.")?;
        // The associated blobentry rows are not immediately deleted when the owning keyentry is
        // removed, because a KeyMint `deleteKey()` invocation is needed (specifically for the
        // `KEY_BLOB`).  That should not be done from within the database transaction.  Also, calls
        // to `deleteKey()` need to be delayed until the boot has completed, to avoid making
        // permanent changes during an OTA before the point of no return.  Mark the affected rows
        // with `state=Orphaned` so a subsequent garbage collection can do the `deleteKey()`.
        tx.execute(
            "UPDATE persistent.blobentry SET state = ? WHERE keyentryid = ?",
            params![BlobState::Orphaned, key_id],
        )
        .context("Trying to mark blobentrys as orphaned")?;
        Ok(updated != 0)
    }

    fn delete_received_grants(tx: &Transaction, user: AndroidUserId) -> Result<bool> {
        let updated = tx
            .execute(
                &format!("DELETE FROM persistent.grant WHERE cast ( (grantee/{AID_USER_OFFSET}) as int) = ?;"),
                params![user.0],
            )
            .context(format!(
                "Trying to delete grants received by {user:?} from other apps.",
            ))?;
        Ok(updated != 0)
    }

    /// Marks the given key as unreferenced and removes all of the grants to this key.
    /// Returns Ok(true) if a key was marked unreferenced as a hint for the garbage collector.
    pub fn unbind_key(
        &mut self,
        key: &KeyDescriptor,
        key_type: KeyType,
        caller_uid: AppUid,
        check_permission: impl Fn(&KeyDescriptor, Option<KeyPermSet>) -> Result<()>,
    ) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_key");

        self.with_transaction(Immediate("TX_unbind_key"), |tx| {
            let access = Self::load_access_tuple(tx, key, key_type, caller_uid)
                .context("Trying to get access tuple.")?;

            // Perform access control. It is vital that we return here if the permission is denied.
            // So do not touch that '?' at the end.
            check_permission(&access.descriptor, access.vector)
                .context("While checking permission.")?;

            Self::remove_key_rows(tx, access.key_id)
                .map(|need_gc| (need_gc, ()))
                .context("Trying to remove key DB rows")
        })
        .context(ks_err!())
    }

    fn get_key_km_uuid(tx: &Transaction, key_id: i64) -> Result<Uuid> {
        tx.query_row(
            "SELECT km_uuid FROM persistent.keyentry WHERE id = ?",
            params![key_id],
            |row| row.get(0),
        )
        .context(ks_err!())
    }

    /// Delete all artifacts belonging to the namespace given by the domain-namespace tuple.
    /// This leaves all of the blob entries orphaned for subsequent garbage collection.
    pub fn unbind_keys_for_namespace(&mut self, domain: Domain, namespace: i64) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_keys_for_namespace");

        if !(domain == Domain::APP || domain == Domain::SELINUX) {
            return Err(KsError::Rc(ResponseCode::INVALID_ARGUMENT)).context(ks_err!());
        }
        self.with_transaction(Immediate("TX_unbind_keys_for_namespace"), |tx| {
            tx.execute(
                "DELETE FROM persistent.keymetadata
                WHERE keyentryid IN (
                    SELECT id FROM persistent.keyentry
                    WHERE domain = ? AND namespace = ? AND key_type = ?
                );",
                params![domain.0, namespace, KeyType::Client],
            )
            .context("Trying to delete keymetadata.")?;
            tx.execute(
                "DELETE FROM persistent.keyparameter
                WHERE keyentryid IN (
                    SELECT id FROM persistent.keyentry
                    WHERE domain = ? AND namespace = ? AND key_type = ?
                );",
                params![domain.0, namespace, KeyType::Client],
            )
            .context("Trying to delete keyparameters.")?;
            tx.execute(
                "DELETE FROM persistent.grant
                WHERE keyentryid IN (
                    SELECT id FROM persistent.keyentry
                    WHERE domain = ? AND namespace = ? AND key_type = ?
                );",
                params![domain.0, namespace, KeyType::Client],
            )
            .context(format!(
                "Trying to delete grants issued for keys in domain {:?} and namespace {:?}.",
                domain.0, namespace
            ))?;
            if domain == Domain::APP {
                // Keystore uses the UID instead of the namespace argument for Domain::APP, so we
                // just need to delete rows where grantee == namespace.
                tx.execute(
                    "DELETE FROM persistent.grant WHERE grantee = ?;",
                    params![namespace],
                )
                .context(format!(
                    "Trying to delete received grants for domain {:?} and namespace {:?}.",
                    domain.0, namespace
                ))?;
            }
            tx.execute(
                "DELETE FROM persistent.keyentry
                 WHERE domain = ? AND namespace = ? AND key_type = ?;",
                params![domain.0, namespace, KeyType::Client],
            )
            .context("Trying to delete keyentry.")?;
            Ok(()).need_gc()
        })
        .context(ks_err!())
    }

    fn cleanup_unreferenced(tx: &Transaction) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::cleanup_unreferenced");
        {
            tx.execute(
                "DELETE FROM persistent.keymetadata
            WHERE keyentryid IN (
                SELECT id FROM persistent.keyentry
                WHERE state = ?
            );",
                params![KeyLifeCycle::Unreferenced],
            )
            .context("Trying to delete keymetadata.")?;
            tx.execute(
                "DELETE FROM persistent.keyparameter
            WHERE keyentryid IN (
                SELECT id FROM persistent.keyentry
                WHERE state = ?
            );",
                params![KeyLifeCycle::Unreferenced],
            )
            .context("Trying to delete keyparameters.")?;
            tx.execute(
                "DELETE FROM persistent.grant
            WHERE keyentryid IN (
                SELECT id FROM persistent.keyentry
                WHERE state = ?
            );",
                params![KeyLifeCycle::Unreferenced],
            )
            .context("Trying to delete grants.")?;

            // Mark as orphaned any blobentry rows that are associated with keyentry rows that
            // are about to be deleted.  The orphaned rows will be removed in a later GC
            // operation (which also involves notifying the owning KeyMint of keyblob deletion).
            tx.execute(
                "UPDATE persistent.blobentry SET state=?
                    WHERE keyentryid IN (
                      SELECT id FROM persistent.keyentry
                      WHERE state = ?
                    );",
                params![BlobState::Orphaned, KeyLifeCycle::Unreferenced],
            )
            .context("Trying to mark to-be-orphaned blobs")?;

            tx.execute(
                "DELETE FROM persistent.keyentry
                WHERE state = ?;",
                params![KeyLifeCycle::Unreferenced],
            )
            .context("Trying to delete keyentry.")?;
            Result::<()>::Ok(())
        }
        .context(ks_err!())
    }

    /// Deletes all keys for the given user, including both client keys and super keys.
    pub fn unbind_keys_for_user(&mut self, user: AndroidUserId) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_keys_for_user");

        self.with_transaction(Immediate("TX_unbind_keys_for_user"), |tx| {
            Self::delete_received_grants(tx, user).context(format!(
                "In unbind_keys_for_user. Failed to delete received grants for {user:?}",
            ))?;

            let mut stmt = tx
                .prepare(&format!(
                    "SELECT id from persistent.keyentry
                     WHERE (
                         key_type = ?
                         AND domain = ?
                         AND cast ( (namespace/{AID_USER_OFFSET}) as int) = ?
                         AND state = ?
                     ) OR (
                         key_type = ?
                         AND namespace = ?
                         AND state = ?
                     );",
                ))
                .context(concat!(
                    "In unbind_keys_for_user. ",
                    "Failed to prepare the query to find the keys created by apps."
                ))?;

            let mut rows = stmt
                .query(params![
                    // WHERE client key:
                    KeyType::Client,
                    Domain::APP.0 as u32,
                    user.0,
                    KeyLifeCycle::Live,
                    // OR super key:
                    KeyType::Super,
                    user.0,
                    KeyLifeCycle::Live
                ])
                .context(ks_err!("Failed to query the keys created by apps."))?;

            let mut key_ids: Vec<i64> = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                key_ids.push(
                    row.get(0)
                        .context("Failed to read key id of a key created by an app.")?,
                );
                Ok(())
            })
            .context(ks_err!())?;

            let mut notify_gc = false;
            for key_id in key_ids {
                notify_gc = Self::remove_key_rows(tx, key_id)
                    .context("In unbind_keys_for_user. Failed to remove key rows.")?
                    || notify_gc;
            }
            Ok(()).do_gc(notify_gc)
        })
        .context(ks_err!())
    }

    /// Deletes all auth-bound keys, i.e. keys that require user authentication, for the given user.
    /// This runs when the user's lock screen is being changed to Swipe or None.
    ///
    /// This intentionally does *not* delete keys that require that the device be unlocked, unless
    /// such keys also require user authentication.  Keystore's concept of user authentication is
    /// fairly strong, and it requires that keys that require authentication be deleted as soon as
    /// authentication is no longer possible.  In contrast, keys that just require that the device
    /// be unlocked should remain usable when the lock screen is set to Swipe or None, as the device
    /// is always considered "unlocked" in that case.
    pub fn unbind_auth_bound_keys_for_user(&mut self, user: AndroidUserId) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_auth_bound_keys_for_user");

        self.with_transaction(Immediate("TX_unbind_auth_bound_keys_for_user"), |tx| {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT id from persistent.keyentry
                     WHERE key_type = ?
                     AND domain = ?
                     AND cast ( (namespace/{AID_USER_OFFSET}) as int) = ?
                     AND state = ?;",
                ))
                .context(concat!(
                    "In unbind_auth_bound_keys_for_user. ",
                    "Failed to prepare the query to find the keys created by apps."
                ))?;

            let mut rows = stmt
                .query(params![
                    KeyType::Client,
                    Domain::APP.0 as u32,
                    user.0,
                    KeyLifeCycle::Live,
                ])
                .context(ks_err!("Failed to query the keys created by apps."))?;

            let mut key_ids: Vec<i64> = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                key_ids.push(
                    row.get(0)
                        .context("Failed to read key id of a key created by an app.")?,
                );
                Ok(())
            })
            .context(ks_err!())?;

            let mut notify_gc = false;
            let mut num_unbound = 0;
            for key_id in key_ids {
                // Load the key parameters and filter out non-auth-bound keys.  To identify
                // auth-bound keys, use the presence of UserSecureID.  The absence of NoAuthRequired
                // could also be used, but UserSecureID is what Keystore treats as authoritative
                // when actually enforcing the key parameters (it might not matter, though).
                let params = Self::load_key_parameters(key_id, tx)
                    .context("Failed to load key parameters.")?;
                let is_auth_bound_key = params.iter().any(|kp| {
                    matches!(kp.key_parameter_value(), KeyParameterValue::UserSecureID(_))
                });
                if is_auth_bound_key {
                    notify_gc = Self::remove_key_rows(tx, key_id)
                        .context("In unbind_auth_bound_keys_for_user.")?
                        || notify_gc;
                    num_unbound += 1;
                }
            }
            info!("Deleting {num_unbound} auth-bound keys for {user:?}");
            Ok(()).do_gc(notify_gc)
        })
        .context(ks_err!())
    }

    /// Deletes auth-bound client keys, super-encrypted client keys, and super keys for the user.
    /// This is the legacy password-removal scope; user removal must still use
    /// `unbind_keys_for_user`.
    pub fn unbind_lskf_bound_keys_for_user(&mut self, user: AndroidUserId) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_lskf_bound_keys_for_user");

        self.with_transaction(Immediate("TX_unbind_lskf_bound_keys_for_user"), |tx| {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT id, key_type from persistent.keyentry
                     WHERE (
                         key_type = ?
                         AND domain = ?
                         AND cast ( (namespace/{AID_USER_OFFSET}) as int) = ?
                         AND state = ?
                     ) OR (
                         key_type = ?
                         AND namespace = ?
                         AND state = ?
                     );",
                ))
                .context(concat!(
                    "In unbind_lskf_bound_keys_for_user. ",
                    "Failed to prepare the query to find the keys created by apps."
                ))?;

            let mut rows = stmt
                .query(params![
                    KeyType::Client,
                    Domain::APP.0 as u32,
                    user.0,
                    KeyLifeCycle::Live,
                    KeyType::Super,
                    user.0,
                    KeyLifeCycle::Live
                ])
                .context(ks_err!("Failed to query the keys created by apps."))?;

            let mut candidates: Vec<(i64, KeyType)> = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                candidates.push((
                    row.get(0)
                        .context("Failed to read key id of a key created by an app.")?,
                    row.get(1)
                        .context("Failed to read key type of a key created by an app.")?,
                ));
                Ok(())
            })
            .context(ks_err!())?;

            let mut notify_gc = false;
            let mut num_unbound = 0;
            for (key_id, key_type) in candidates {
                let should_unbind = if key_type == KeyType::Super {
                    true
                } else {
                    let key_params = Self::load_key_parameters(key_id, tx)
                        .context("Failed to load key parameters.")?;
                    let is_auth_bound_key = key_params.iter().any(|kp| {
                        matches!(kp.key_parameter_value(), KeyParameterValue::UserSecureID(_))
                    });
                    let is_super_encrypted_key =
                        match Self::load_blob_components(key_id, KeyEntryLoadBits::KM, tx)
                            .context(ks_err!("Trying to load blob info."))?
                        {
                            (_, Some((_, blob_metadata)), _, _) => {
                                blob_metadata.encrypted_by().is_some()
                            }
                            _ => false,
                        };

                    is_auth_bound_key || is_super_encrypted_key
                };

                if should_unbind {
                    notify_gc = Self::remove_key_rows(tx, key_id)
                        .context("In unbind_lskf_bound_keys_for_user.")?
                        || notify_gc;
                    num_unbound += 1;
                }
            }
            info!("deleting {num_unbound} LSKF-bound keys for {user:?}");
            Ok(()).do_gc(notify_gc)
        })
        .context(ks_err!())
    }

    /// Removes every known key entry after KeyMint deleteAllKeys succeeds.
    pub fn unbind_all_keys(&mut self) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_all_keys");

        self.with_transaction(Immediate("TX_unbind_all_keys"), |tx| {
            let mut stmt = tx
                .prepare("SELECT id FROM persistent.keyentry;")
                .context(ks_err!("Preparing full key deletion query."))?;
            let mut rows = stmt
                .query([])
                .context(ks_err!("Querying keys for full deletion."))?;

            let mut key_ids = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                key_ids.push(row.get(0).context("Failed to read key id.")?);
                Ok(())
            })
            .context(ks_err!("Extracting keys for full deletion."))?;

            let mut notify_gc = false;
            for key_id in key_ids {
                notify_gc =
                    Self::remove_key_rows(tx, key_id).context("In unbind_all_keys.")? || notify_gc;
            }
            Ok(()).do_gc(notify_gc)
        })
        .context(ks_err!())
    }

    fn load_key_components(
        tx: &Transaction,
        load_bits: KeyEntryLoadBits,
        key_id: i64,
    ) -> Result<KeyEntry> {
        let metadata = KeyMetaData::load_from_db(key_id, tx).context("In load_key_components.")?;

        let (has_km_blob, key_blob_info, cert_blob, cert_chain_blob) =
            Self::load_blob_components(key_id, load_bits, tx).context("In load_key_components.")?;

        let parameters = Self::load_key_parameters(key_id, tx)
            .context("In load_key_components: Trying to load key parameters.")?;

        let km_uuid = Self::get_key_km_uuid(tx, key_id)
            .context("In load_key_components: Trying to get KM uuid.")?;

        Ok(KeyEntry {
            id: key_id,
            key_blob_info,
            cert: cert_blob,
            cert_chain: cert_chain_blob,
            km_uuid,
            parameters,
            metadata,
            pure_cert: !has_km_blob,
        })
    }

    /// Returns a list of KeyDescriptors in the selected domain/namespace whose
    /// aliases are greater than the specified 'start_past_alias'. If no value
    /// is provided, returns all KeyDescriptors.
    /// The key descriptors will have the domain, nspace, and alias field set.
    /// The returned list will be sorted by alias.
    /// Domain must be APP or SELINUX, the caller must make sure of that.
    /// Number of returned values is limited to 10,000 (which is empirically roughly
    /// what will fit in a Binder message).
    pub fn list_past_alias(
        &mut self,
        domain: Domain,
        namespace: i64,
        key_type: KeyType,
        start_past_alias: Option<&str>,
    ) -> Result<Vec<KeyDescriptor>> {
        let _wp = wd::watch("KeystoreDB::list_past_alias");

        let query = format!(
            "SELECT DISTINCT alias FROM persistent.keyentry
                     WHERE domain = ?
                     AND namespace = ?
                     AND alias IS NOT NULL
                     AND state = ?
                     AND key_type = ?
                     {}
                     ORDER BY alias ASC
                     LIMIT 10000;",
            if start_past_alias.is_some() {
                " AND alias > ?"
            } else {
                ""
            }
        );

        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            let mut stmt = tx.prepare(&query).context(ks_err!("Failed to prepare."))?;

            let mut rows = match start_past_alias {
                Some(past_alias) => stmt
                    .query(params![
                        domain.0 as u32,
                        namespace,
                        KeyLifeCycle::Live,
                        key_type,
                        past_alias
                    ])
                    .context(ks_err!("Failed to query."))?,
                None => stmt
                    .query(params![
                        domain.0 as u32,
                        namespace,
                        KeyLifeCycle::Live,
                        key_type,
                    ])
                    .context(ks_err!("Failed to query."))?,
            };

            let mut descriptors: Vec<KeyDescriptor> = Vec::new();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                descriptors.push(KeyDescriptor {
                    domain,
                    nspace: namespace,
                    alias: Some(row.get(0).context("Trying to extract alias.")?),
                    blob: None,
                });
                Ok(())
            })
            .context(ks_err!("Failed to extract rows."))?;
            Ok(descriptors).no_gc()
        })
    }

    /// Returns a number of KeyDescriptors in the selected domain/namespace.
    /// Domain must be APP or SELINUX, the caller must make sure of that.
    pub fn count_keys(
        &mut self,
        domain: Domain,
        namespace: i64,
        key_type: KeyType,
    ) -> Result<usize> {
        let _wp = wd::watch("KeystoreDB::countKeys");

        let num_keys = self.with_transaction(TransactionBehavior::Deferred, |tx| {
            tx.query_row(
                "SELECT COUNT(alias) FROM persistent.keyentry
                     WHERE domain = ?
                     AND namespace = ?
                     AND alias IS NOT NULL
                     AND state = ?
                     AND key_type = ?;",
                params![domain.0 as u32, namespace, KeyLifeCycle::Live, key_type],
                |row| {
                    let count: i64 = row.get(0)?;
                    Ok(count)
                },
            )
            .context(ks_err!("Failed to count number of keys."))
            .no_gc()
        })?;
        usize::try_from(num_keys).context(ks_err!("key count out of range"))
    }

    /// Adds a grant to the grant table.
    /// Like `load_key_entry` this function loads the access tuple before
    /// it uses the callback for a permission check. Upon success,
    /// it inserts the `grantee_uid`, `key_id`, and `access_vector` into the
    /// grant table. The new row will have a randomized id, which is used as
    /// grant id in the namespace field of the resulting KeyDescriptor.
    pub fn grant(
        &mut self,
        key: &KeyDescriptor,
        caller_uid: AppUid,
        grantee_uid: AppUid,
        access_vector: KeyPermSet,
        check_permission: impl Fn(&KeyDescriptor, &KeyPermSet) -> Result<()>,
    ) -> Result<KeyDescriptor> {
        let _wp = wd::watch("KeystoreDB::grant");

        self.with_transaction(Immediate("TX_grant"), |tx| {
            // Load the key_id and complete the access control tuple.
            // We ignore the access vector here because grants cannot be granted.
            // The access vector returned here expresses the permissions the
            // grantee has if key.domain == Domain::GRANT. But this vector
            // cannot include the grant permission by design, so there is no way the
            // subsequent permission check can pass.
            // We could check key.domain == Domain::GRANT and fail early.
            // But even if we load the access tuple by grant here, the permission
            // check denies the attempt to create a grant by grant descriptor.
            let access =
                Self::load_access_tuple(tx, key, KeyType::Client, caller_uid).context(ks_err!())?;

            // Perform access control. It is vital that we return here if the permission
            // was denied. So do not touch that '?' at the end of the line.
            // This permission check checks if the caller has the grant permission
            // for the given key and in addition to all of the permissions
            // expressed in `access_vector`.
            check_permission(&access.descriptor, &access_vector)
                .context(ks_err!("check_permission failed"))?;

            let grant_id = if let Some(grant_id) = tx
                .query_row(
                    "SELECT id FROM persistent.grant
                WHERE keyentryid = ? AND grantee = ?;",
                    params![access.key_id, grantee_uid.0],
                    |row| row.get(0),
                )
                .optional()
                .context(ks_err!("Failed get optional existing grant id."))?
            {
                tx.execute(
                    "UPDATE persistent.grant
                    SET access_vector = ?
                    WHERE id = ?;",
                    params![i32::from(access_vector), grant_id],
                )
                .context(ks_err!("Failed to update existing grant."))?;
                grant_id
            } else {
                Self::insert_with_retry(|id| {
                    tx.execute(
                        "INSERT INTO persistent.grant (id, grantee, keyentryid, access_vector)
                        VALUES (?, ?, ?, ?);",
                        params![id, grantee_uid.0, access.key_id, i32::from(access_vector)],
                    )
                })
                .context(ks_err!())?
            };

            Ok(KeyDescriptor {
                domain: Domain::GRANT,
                nspace: grant_id,
                alias: None,
                blob: None,
            })
            .no_gc()
        })
    }

    /// This function checks permissions like `grant` and `load_key_entry`
    /// before removing a grant from the grant table.
    pub fn ungrant(
        &mut self,
        key: &KeyDescriptor,
        caller_uid: AppUid,
        grantee_uid: AppUid,
        check_permission: impl Fn(&KeyDescriptor) -> Result<()>,
    ) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::ungrant");

        self.with_transaction(Immediate("TX_ungrant"), |tx| {
            // Load the key_id and complete the access control tuple.
            // We ignore the access vector here because grants cannot be granted.
            let access =
                Self::load_access_tuple(tx, key, KeyType::Client, caller_uid).context(ks_err!())?;

            // Perform access control. We must return here if the permission
            // was denied. So do not touch the '?' at the end of this line.
            check_permission(&access.descriptor).context(ks_err!("check_permission failed."))?;

            tx.execute(
                "DELETE FROM persistent.grant
                WHERE keyentryid = ? AND grantee = ?;",
                params![access.key_id, grantee_uid.0],
            )
            .context("Failed to delete grant.")?;

            Ok(()).no_gc()
        })
    }

    // Generates a random id and passes it to the given function, which will
    // try to insert it into a database.  If that insertion fails, retry;
    // otherwise return the id.
    fn insert_with_retry(inserter: impl Fn(i64) -> rusqlite::Result<usize>) -> Result<i64> {
        loop {
            let newid: i64 = match random() {
                Self::UNASSIGNED_KEY_ID => continue, // UNASSIGNED_KEY_ID cannot be assigned.
                i => i,
            };
            match inserter(newid) {
                // If the id already existed, try again.
                Err(rusqlite::Error::SqliteFailure(
                    libsqlite3_sys::Error {
                        code: libsqlite3_sys::ErrorCode::ConstraintViolation,
                        extended_code: libsqlite3_sys::SQLITE_CONSTRAINT_UNIQUE,
                    },
                    _,
                )) => (),
                Err(e) => {
                    return Err(e).context(ks_err!("failed to insert into database."));
                }
                _ => return Ok(newid),
            }
        }
    }

    /// Insert or replace the auth token based on (user_id, auth_id, auth_type)
    pub fn insert_auth_token(&mut self, auth_token: &HardwareAuthToken) {
        self.perboot
            .insert_auth_token_entry(AuthTokenEntry::new(auth_token.clone(), BootTime::now()))
    }

    /// Find the newest auth token matching the given predicate.
    pub fn find_auth_token_entry<F>(&self, p: F) -> Option<AuthTokenEntry>
    where
        F: Fn(&AuthTokenEntry) -> bool,
    {
        self.perboot.find_auth_token_entry(p)
    }

    /// Load descriptor of a key by key id
    pub fn load_key_descriptor(&mut self, key_id: i64) -> Result<Option<KeyDescriptor>> {
        let _wp = wd::watch("KeystoreDB::load_key_descriptor");

        self.with_transaction(TransactionBehavior::Deferred, |tx| {
            tx.query_row(
                "SELECT domain, namespace, alias FROM persistent.keyentry WHERE id = ?;",
                params![key_id],
                |row| {
                    Ok(KeyDescriptor {
                        domain: Domain(row.get(0)?),
                        nspace: row.get(1)?,
                        alias: row.get(2)?,
                        blob: None,
                    })
                },
            )
            .optional()
            .context("Trying to load key descriptor")
            .no_gc()
        })
        .context(ks_err!())
    }

    /// Returns a list of app UIDs that have keys authenticated by the given secure_user_id
    /// (for the given user_id).
    /// This is helpful for finding out which apps will have their keys invalidated when
    /// the user changes biometrics enrollment or removes their LSKF.
    pub fn get_app_uids_affected_by_sid(
        &mut self,
        user: AndroidUserId,
        sid: SecureUserId,
    ) -> Result<Vec<AppUid>> {
        let _wp = wd::watch("KeystoreDB::get_app_uids_affected_by_sid");

        let ids = self.with_transaction(Immediate("TX_get_app_uids_affected_by_sid"), |tx| {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT id, namespace from persistent.keyentry
                     WHERE key_type = ?
                     AND domain = ?
                     AND cast ( (namespace/{AID_USER_OFFSET}) as int) = ?
                     AND state = ?;",
                ))
                .context(concat!(
                    "In get_app_uids_affected_by_sid, ",
                    "failed to prepare the query to find the keys created by apps."
                ))?;

            let mut rows = stmt
                .query(params![
                    KeyType::Client,
                    Domain::APP.0 as u32,
                    user.0,
                    KeyLifeCycle::Live,
                ])
                .context(ks_err!("Failed to query the keys created by apps."))?;

            let mut key_ids_and_app_uids: HashMap<i64, AppUid> = Default::default();
            db_utils::with_rows_extract_all(&mut rows, |row| {
                key_ids_and_app_uids.insert(
                    row.get(0)
                        .context("Failed to read key id of a key created by an app.")?,
                    AppUid(row.get(1).context("Failed to read the app uid")?),
                );
                Ok(())
            })?;
            Ok(key_ids_and_app_uids).no_gc()
        })?;
        let mut app_uids_affected_by_sid: HashSet<AppUid> = Default::default();
        for (key_id, app_uid) in ids {
            // Read the key parameters for each key in its own transaction. It is OK to ignore
            // an error to get the properties of a particular key since it might have been deleted
            // under our feet after the previous transaction concluded. If the key was deleted
            // then it is no longer applicable if it was auth-bound or not.
            if let Ok(is_key_bound_to_sid) =
                self.with_transaction(Immediate("TX_get_app_uids_affects_by_sid 2"), |tx| {
                    let params = Self::load_key_parameters(key_id, tx)
                        .context("Failed to load key parameters.")?;
                    // Check if the key is bound to this secure user ID.
                    let is_key_bound_to_sid = params.iter().any(|kp| {
                        matches!(
                            kp.key_parameter_value(),
                            KeyParameterValue::UserSecureID(s) if *s == sid.0
                        )
                    });
                    Ok(is_key_bound_to_sid).no_gc()
                })
            {
                if is_key_bound_to_sid {
                    app_uids_affected_by_sid.insert(app_uid);
                }
            }
        }

        let app_uids_vec: Vec<AppUid> = app_uids_affected_by_sid.into_iter().collect();
        Ok(app_uids_vec)
    }

    /// Retrieve a database PRAGMA config value.
    pub fn pragma<T: FromSql>(&mut self, name: &str) -> Result<T> {
        self.conn
            .query_row(&format!("PRAGMA persistent.{name}"), (), |row| row.get(0))
            .context(format!("failed to read pragma {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NAMESPACE: i64 = 10001;

    fn make_test_db() -> KeystoreDB {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute("ATTACH DATABASE 'file::memory:' AS persistent;", [])
            .unwrap();

        {
            let tx = conn.transaction().unwrap();
            KeystoreDB::init_tables(&tx).unwrap();
            tx.commit().unwrap();
        }

        KeystoreDB {
            conn,
            gc: None,
            perboot: perboot::PERBOOT_DB.clone(),
        }
    }

    fn insert_live_client_key(tx: &Transaction, id: i64, km_uuid: Uuid, alias: &str) {
        tx.execute(
            "INSERT INTO persistent.keyentry
                (id, key_type, domain, namespace, alias, state, km_uuid)
                VALUES (?, ?, ?, ?, ?, ?, ?);",
            params![
                id,
                KeyType::Client,
                Domain::APP.0 as u32,
                TEST_NAMESPACE,
                alias,
                KeyLifeCycle::Live,
                km_uuid
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO persistent.blobentry
                (id, subcomponent_type, keyentryid, blob, state)
                VALUES (?, ?, ?, ?, ?);",
            params![
                id + 100,
                SubComponentType::KEY_BLOB,
                id,
                vec![id as u8],
                BlobState::Current
            ],
        )
        .unwrap();
    }

    fn insert_live_super_key(tx: &Transaction, id: i64, user: AndroidUserId) {
        tx.execute(
            "INSERT INTO persistent.keyentry
                (id, key_type, domain, namespace, alias, state, km_uuid)
                VALUES (?, ?, ?, ?, ?, ?, ?);",
            params![
                id,
                KeyType::Super,
                Domain::APP.0 as u32,
                user.0,
                "super",
                KeyLifeCycle::Live,
                KEYSTORE_UUID
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO persistent.blobentry
                (id, subcomponent_type, keyentryid, blob, state)
                VALUES (?, ?, ?, ?, ?);",
            params![
                id + 100,
                SubComponentType::KEY_BLOB,
                id,
                vec![id as u8],
                BlobState::Current
            ],
        )
        .unwrap();
    }

    fn add_user_secure_id(tx: &Transaction, key_id: i64) {
        let param = KeyParameter::new(
            KeyParameterValue::UserSecureID(0x1234),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        );
        tx.execute(
            "INSERT INTO persistent.keyparameter
                (keyentryid, tag, data, security_level)
                VALUES (?, ?, ?, ?);",
            params![
                key_id,
                param.get_tag().0,
                param.key_parameter_value(),
                param.security_level().0
            ],
        )
        .unwrap();
    }

    fn add_super_encryption_metadata(tx: &Transaction, key_id: i64) {
        let mut metadata = BlobMetaData::new();
        metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(42)));
        metadata.store_in_db(key_id + 100, tx).unwrap();
    }

    fn add_keybox_attestation_metadata(tx: &Transaction, key_id: i64, km_uuid: Uuid) {
        let mut metadata = KeyMetaData::new();
        metadata.add(KeyMetaEntry::KeyboxAttestationUuidPrefix(
            km_uuid.get_digest().to_vec(),
        ));
        metadata.store_in_db(key_id, tx).unwrap();
    }

    fn key_entry_count(db: &KeystoreDB, id: i64) -> i64 {
        db.conn
            .query_row(
                "SELECT COUNT(*) FROM persistent.keyentry WHERE id = ?;",
                params![id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn blob_state(db: &KeystoreDB, key_id: i64) -> BlobState {
        db.conn
            .query_row(
                "SELECT state FROM persistent.blobentry WHERE keyentryid = ?;",
                params![key_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn try_blob_state(db: &KeystoreDB, key_id: i64) -> Option<BlobState> {
        db.conn
            .query_row(
                "SELECT state FROM persistent.blobentry WHERE keyentryid = ?;",
                params![key_id],
                |row| row.get(0),
            )
            .optional()
            .unwrap()
    }

    fn make_legacy_conn(with_blob_state: bool) -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        let state_column = if with_blob_state {
            ", state INTEGER DEFAULT 0"
        } else {
            ""
        };
        conn.execute_batch(&format!(
            "ATTACH DATABASE 'file::memory:' AS persistent;
             CREATE TABLE persistent.keyentry (
                id INTEGER UNIQUE,
                key_type INTEGER,
                domain INTEGER,
                namespace INTEGER,
                alias BLOB,
                state INTEGER,
                km_uuid BLOB);
             CREATE TABLE persistent.keyparameter (
                keyentryid INTEGER,
                tag INTEGER,
                data INTEGER,
                security_level INTEGER);
             CREATE TABLE persistent.blobmetadata (
                blobentryid INTEGER,
                tag INTEGER,
                data INTEGER);
             CREATE TABLE persistent.blobentry (
                id INTEGER PRIMARY KEY,
                subcomponent_type INTEGER,
                keyentryid INTEGER,
                blob BLOB{state_column});
             INSERT INTO persistent.keyentry
                (id, key_type, domain, namespace, alias, state, km_uuid)
                VALUES (1, 0, 0, 0, X'01', 1, X'00000000000000000000000000000000');
             INSERT INTO persistent.blobentry
                (id, subcomponent_type, keyentryid, blob)
                VALUES (10, 0, 1, X'01'), (11, 0, 1, X'02');"
        ))
        .unwrap();
        conn
    }

    #[test]
    fn uuid_from_keybox_digest_uses_digest_prefix_and_security_level() {
        let mut digest = [0u8; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = index as u8;
        }

        let uuid = Uuid::from_keybox_digest(SecurityLevel::STRONGBOX, digest);

        assert_eq!(
            &uuid.0[..KEYBOX_UUID_DIGEST_BYTES],
            &digest[..KEYBOX_UUID_DIGEST_BYTES]
        );
        assert_eq!(
            &uuid.0[KEYBOX_UUID_DIGEST_BYTES..],
            &(SecurityLevel::STRONGBOX.0 as u32).to_be_bytes()
        );
        assert_eq!(uuid.to_security_level(), Some(SecurityLevel::STRONGBOX));
        assert!(uuid.is_keybox_bound());
        assert!(uuid.is_bound_to_keybox_digest(digest));

        let mut other_digest = digest;
        other_digest[0] ^= 0xff;
        assert!(!uuid.is_bound_to_keybox_digest(other_digest));
    }

    #[test]
    fn retire_stale_keybox_bound_entries_keeps_current_and_keystore_entries() {
        let current_digest = [0x11; 32];
        let stale_digest = [0x22; 32];
        let current_uuid =
            Uuid::from_keybox_digest(SecurityLevel::TRUSTED_ENVIRONMENT, current_digest);
        let stale_tee_uuid =
            Uuid::from_keybox_digest(SecurityLevel::TRUSTED_ENVIRONMENT, stale_digest);
        let stale_strongbox_uuid = Uuid::from_keybox_digest(SecurityLevel::STRONGBOX, stale_digest);
        let mut db = make_test_db();

        {
            let tx = db.conn.transaction().unwrap();
            insert_live_client_key(&tx, 1, stale_tee_uuid, "stale-tee");
            insert_live_client_key(&tx, 2, stale_strongbox_uuid, "stale-strongbox");
            insert_live_client_key(&tx, 3, current_uuid, "current-keybox");
            insert_live_client_key(&tx, 4, KEYSTORE_UUID, "keystore");
            insert_live_client_key(&tx, 5, stale_tee_uuid, "stale-without-metadata");
            add_keybox_attestation_metadata(&tx, 1, stale_tee_uuid);
            add_keybox_attestation_metadata(&tx, 2, stale_strongbox_uuid);
            add_keybox_attestation_metadata(&tx, 3, current_uuid);
            tx.commit().unwrap();
        }

        assert_eq!(
            2,
            db.retire_stale_keybox_bound_entries(current_digest)
                .unwrap()
        );

        assert_eq!(0, key_entry_count(&db, 1));
        assert_eq!(0, key_entry_count(&db, 2));
        assert_eq!(1, key_entry_count(&db, 3));
        assert_eq!(1, key_entry_count(&db, 4));
        assert_eq!(1, key_entry_count(&db, 5));
        assert_eq!(BlobState::Orphaned, blob_state(&db, 1));
        assert_eq!(BlobState::Orphaned, blob_state(&db, 2));
        assert_eq!(BlobState::Current, blob_state(&db, 3));
        assert_eq!(BlobState::Current, blob_state(&db, 4));
        assert_eq!(BlobState::Current, blob_state(&db, 5));
    }

    #[test]
    fn alias_can_be_reused_after_stale_keybox_entry_is_retired() {
        let current_digest = [0x33; 32];
        let stale_digest = [0x44; 32];
        let current_uuid =
            Uuid::from_keybox_digest(SecurityLevel::TRUSTED_ENVIRONMENT, current_digest);
        let stale_uuid = Uuid::from_keybox_digest(SecurityLevel::TRUSTED_ENVIRONMENT, stale_digest);
        let mut db = make_test_db();

        {
            let tx = db.conn.transaction().unwrap();
            insert_live_client_key(&tx, 1, stale_uuid, "shared-alias");
            add_keybox_attestation_metadata(&tx, 1, stale_uuid);
            tx.commit().unwrap();
        }

        assert_eq!(
            1,
            db.retire_stale_keybox_bound_entries(current_digest)
                .unwrap()
        );

        {
            let tx = db.conn.transaction().unwrap();
            insert_live_client_key(&tx, 2, current_uuid, "shared-alias");
            let descriptor = KeyDescriptor {
                domain: Domain::APP,
                nspace: TEST_NAMESPACE,
                alias: Some("shared-alias".to_string()),
                blob: None,
            };

            assert_eq!(
                2,
                KeystoreDB::load_key_entry_id(&tx, &descriptor, KeyType::Client).unwrap()
            );
            tx.commit().unwrap();
        }

        assert_eq!(0, key_entry_count(&db, 1));
        assert_eq!(1, key_entry_count(&db, 2));
        assert_eq!(BlobState::Orphaned, blob_state(&db, 1));
        assert_eq!(BlobState::Current, blob_state(&db, 2));
    }

    #[test]
    fn unbind_lskf_bound_keys_keeps_unbound_client_keys() {
        let mut db = make_test_db();
        let user = AndroidUserId(0);

        {
            let tx = db.conn.transaction().unwrap();
            insert_live_client_key(&tx, 1, KEYSTORE_UUID, "plain");
            insert_live_client_key(&tx, 2, KEYSTORE_UUID, "auth-bound");
            add_user_secure_id(&tx, 2);
            insert_live_client_key(&tx, 3, KEYSTORE_UUID, "super-encrypted");
            add_super_encryption_metadata(&tx, 3);
            insert_live_super_key(&tx, 4, user);
            tx.commit().unwrap();
        }

        db.unbind_lskf_bound_keys_for_user(user).unwrap();

        assert_eq!(1, key_entry_count(&db, 1));
        assert_eq!(0, key_entry_count(&db, 2));
        assert_eq!(0, key_entry_count(&db, 3));
        assert_eq!(0, key_entry_count(&db, 4));
        assert_eq!(BlobState::Current, blob_state(&db, 1));
        assert_eq!(Some(BlobState::Orphaned), try_blob_state(&db, 2));
        assert_eq!(Some(BlobState::Orphaned), try_blob_state(&db, 3));
        assert_eq!(Some(BlobState::Orphaned), try_blob_state(&db, 4));
    }

    #[test]
    fn legacy_upgrade_handles_blobentry_state_column_presence() {
        for with_blob_state in [false, true] {
            let mut conn = make_legacy_conn(with_blob_state);
            {
                let tx = conn.transaction().unwrap();
                versioning::upgrade_database(
                    &tx,
                    KeystoreDB::CURRENT_DB_VERSION,
                    KeystoreDB::UPGRADERS,
                )
                .unwrap();
                tx.commit().unwrap();
            }

            assert_eq!(
                3,
                conn.query_row(
                    "SELECT version FROM persistent.version WHERE id = 0;",
                    [],
                    |row| { row.get::<_, u32>(0) }
                )
                .unwrap()
            );
            assert_eq!(
                BlobState::Superseded,
                conn.query_row(
                    "SELECT state FROM persistent.blobentry WHERE id = 10;",
                    [],
                    |row| row.get::<_, BlobState>(0),
                )
                .unwrap()
            );
            assert_eq!(
                BlobState::Current,
                conn.query_row(
                    "SELECT state FROM persistent.blobentry WHERE id = 11;",
                    [],
                    |row| row.get::<_, BlobState>(0),
                )
                .unwrap()
            );
        }
    }
}
