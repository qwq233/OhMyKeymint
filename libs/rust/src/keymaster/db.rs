use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
    path::Path,
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::{Duration, SystemTime, SystemTimeError},
};

use anyhow::{anyhow, Context, Result};
use rand::random;
use rusqlite::{
    Connection, OptionalExtension, ToSql, Transaction, params, params_from_iter, types::{FromSql, FromSqlError, FromSqlResult, ToSqlOutput, Value, ValueRef}
};

use crate::{
    android::{hardware::security::keymint::ErrorCode::ErrorCode, security::metrics::{Storage::Storage as MetricsStorage, StorageStats::StorageStats}},
    keymaster::{database::perboot::PerbootDB, super_key::SuperKeyType},
    plat::utils::AID_USER_OFFSET,
    watchdog as wd,
};

use TransactionBehavior::Immediate;

#[cfg(not(target_os = "android"))]
const DB_ROOT_PATH: &str = "./omk/data";

#[cfg(target_os = "android")]
const DB_ROOT_PATH: &str = "/data/adb/omk/data";

const PERSISTENT_DB_FILENAME: &'static str = "keymaster.db";

const DB_BUSY_RETRY_INTERVAL: Duration = Duration::from_micros(500);

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

use crate::{
    android::{
        hardware::security::keymint::{
            HardwareAuthToken::HardwareAuthToken,
            HardwareAuthenticatorType::HardwareAuthenticatorType, SecurityLevel::SecurityLevel, Tag::Tag,
        },
        system::keystore2::{
            Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
        },
    },
    err, impl_metadata,
    keymaster::{
        database::utils::{self, SqlField},
        error::KsError,
        key_parameter::KeyParameter,
        permission::KeyPermSet,
    },
    utils::get_current_time_in_milliseconds,
};

pub struct KeymasterDb {
    conn: Connection,
    perboot: Arc<PerbootDB>,
}

impl KeymasterDb {
    const UNASSIGNED_KEY_ID: i64 = -1i64;

    pub fn new() -> Result<Self> {
        let _wp = wd::watch("KeystoreDB::new");

        let path = format!("{}/{}", DB_ROOT_PATH, PERSISTENT_DB_FILENAME);
        if let Some(p) = Path::new(&path).parent() {
            std::fs::create_dir_all(p).context("Failed to create directory for database.")?;
        }

        let mut conn = Self::make_connection(&path)?;
        let init_table = conn.transaction().context(err!(
            "Failed to create transaction for initializing database."
        ))?;
        Self::init_tables(&init_table)?;
        init_table.commit().context(err!(
            "Failed to commit transaction for initializing database."
        ))?;

        Ok(KeymasterDb {
            conn,
            perboot: crate::keymaster::database::perboot::PERBOOT_DB.clone(),
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn close(self) -> Result<()> {
        self.conn
            .close()
            .map_err(|(_, e)| e)
            .context("Failed to close database connection.")
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
        .context(err!("Failed to initialize \"keyentry\" table."))?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_id_index
            ON keyentry(id);",
            [],
        )
        .context(err!("Failed to create index keyentry_id_index."))?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_domain_namespace_index
            ON keyentry(domain, namespace, alias);",
            [],
        )
        .context(err!(
            "Failed to create index keyentry_domain_namespace_index."
        ))?;

        // Index added in v2 of database schema.
        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyentry_state_index
            ON keyentry(state);",
            [],
        )
        .context(err!("Failed to create index keyentry_state_index."))?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobentry (
                    id INTEGER PRIMARY KEY,
                    subcomponent_type INTEGER,
                    keyentryid INTEGER,
                    blob BLOB,
                    state INTEGER DEFAULT 0);", // `state` added in v2 of schema
            [],
        )
        .context(err!("Failed to initialize \"blobentry\" table."))?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobentry_keyentryid_index
            ON blobentry(keyentryid);",
            [],
        )
        .context(err!("Failed to create index blobentry_keyentryid_index."))?;

        // Index added in v2 of database schema.
        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobentry_state_index
            ON blobentry(subcomponent_type, state);",
            [],
        )
        .context(err!("Failed to create index blobentry_state_index."))?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.blobmetadata (
                     id INTEGER PRIMARY KEY,
                     blobentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     UNIQUE (blobentryid, tag));",
            [],
        )
        .context(err!("Failed to initialize \"blobmetadata\" table."))?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.blobmetadata_blobentryid_index
            ON blobmetadata(blobentryid);",
            [],
        )
        .context(err!(
            "Failed to create index blobmetadata_blobentryid_index."
        ))?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keyparameter (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     security_level INTEGER);",
            [],
        )
        .context(err!("Failed to initialize \"keyparameter\" table."))?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keyparameter_keyentryid_index
            ON keyparameter(keyentryid);",
            [],
        )
        .context(err!(
            "Failed to create index keyparameter_keyentryid_index."
        ))?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.keymetadata (
                     keyentryid INTEGER,
                     tag INTEGER,
                     data ANY,
                     UNIQUE (keyentryid, tag));",
            [],
        )
        .context(err!("Failed to initialize \"keymetadata\" table."))?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS persistent.keymetadata_keyentryid_index
            ON keymetadata(keyentryid);",
            [],
        )
        .context(err!("Failed to create index keymetadata_keyentryid_index."))?;

        tx.execute(
            "CREATE TABLE IF NOT EXISTS persistent.grant (
                    id INTEGER UNIQUE,
                    grantee INTEGER,
                    keyentryid INTEGER,
                    access_vector INTEGER);",
            [],
        )
        .context(err!("Failed to initialize \"grant\" table."))?;

        Ok(())
    }

    fn make_connection(persistent_file: &str) -> Result<Connection> {
        let conn =
            Connection::open_in_memory().context("Failed to initialize SQLite connection.")?;

        loop {
            if let Err(e) = conn
                .execute("ATTACH DATABASE ? as persistent;", params![persistent_file])
                .context(err!("Failed to attach database persistent."))
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
            .context(err!("Failed to decrease cache size for persistent db"))?;

        Ok(conn)
    }

    /// Creates a transaction with the given behavior and executes f with the new transaction.
    /// The transaction is committed only if f returns Ok and retried if DatabaseBusy
    /// or DatabaseLocked is encountered.
    fn with_transaction<T, F>(&mut self, behavior: TransactionBehavior, f: F) -> Result<T>
    where
        F: Fn(&Transaction) -> Result<T>,
    {
        let name = behavior.name().unwrap_or("<unnamed>");
        loop {
            let result = self
                .conn
                .transaction_with_behavior(behavior.into())
                .context("Failed to create transaction.")
                .and_then(|tx| {
                    let value = f(&tx)?;
                    tx.commit()
                        .context(err!("Failed to commit transaction: {}", name))?;
                    Ok(value)
                });
            match result {
                Ok(result) => break Ok(result),
                Err(e) => {
                    if Self::is_locked_error(&e) {
                        std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                        continue;
                    } else {
                        return Err(e).context(err!("Failed to process transaction: {}", name));
                    }
                }
            }
        }
    }

    /// This maintenance function should be called only once before the database is used for the
    /// first time. It restores the invariant that `KeyLifeCycle::Existing` is a transient state.
    /// The function transitions all key entries from Existing to Unreferenced unconditionally and
    /// returns the number of rows affected. If this returns a value greater than 0, it means that
    /// Keystore crashed at some point during key generation. Callers may want to log such
    /// occurrences.
    /// Unlike with `mark_unreferenced`, we don't need to purge grants, because only keys that made
    /// it to `KeyLifeCycle::Live` may have grants.
    pub fn cleanup_leftovers(&mut self) -> Result<usize> {
        self.with_transaction(Immediate("TX_cleanup_leftovers"), |tx| {
            tx.execute(
                "UPDATE persistent.keyentry SET state = ? WHERE state = ?;",
                params![KeyLifeCycle::Unreferenced, KeyLifeCycle::Existing],
            )
            .context("Failed to execute query.")
        })
        .context("Failed to cleanup leftovers.")
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

    fn mark_unreferenced(tx: &Transaction, key_id: i64) -> Result<bool> {
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
        .context("Trying to mark blobentrys as superseded")?;
        Ok(updated != 0)
    }

    /// This helper function completes the access tuple of a key, which is required
    /// to perform access control. The strategy depends on the `domain` field in the
    /// key descriptor.
    /// * Domain::SELINUX: The access tuple is complete and this function only loads
    ///       the key_id for further processing.
    /// * Domain::APP: Like Domain::SELINUX, but the tuple is completed by `caller_uid`
    ///       which serves as the namespace.
    /// * Domain::GRANT: The grant table is queried for the `key_id` and the
    ///       `access_vector`.
    /// * Domain::KEY_ID: The keyentry table is queried for the owning `domain` and
    ///       `namespace`.
    ///
    /// In each case the information returned is sufficient to perform the access
    /// check and the key id can be used to load further key artifacts.
    fn load_access_tuple(
        tx: &Transaction,
        key: &KeyDescriptor,
        key_type: KeyType,
        caller_uid: u32,
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
                    access_key.nspace = caller_uid as i64;
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
                    .query(params![caller_uid as i64, key.nspace, KeyLifeCycle::Live])
                    .context("Domain:Grant: query failed.")?;
                let (key_id, access_vector): (i64, i32) =
                    utils::with_rows_extract_one(&mut rows, |row| {
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
                    utils::with_rows_extract_one(&mut rows, |row| {
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
                    if domain != Domain::APP || namespace != caller_uid as i64 {
                        let access_vector: Option<i32> = tx
                            .query_row(
                                "SELECT access_vector FROM persistent.grant
                                WHERE grantee = ? AND keyentryid = ?;",
                                params![caller_uid as i64, key.nspace],
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

    // Helper function loading the key_id given the key descriptor
    // tuple comprising domain, namespace, and alias.
    // Requires a valid transaction.
    fn load_key_entry_id(tx: &Transaction, key: &KeyDescriptor, key_type: KeyType) -> Result<i64> {
        let alias = key
            .alias
            .as_ref()
            .map_or_else(|| Err(KsError::sys()), Ok)
            .context(err!("In load_key_entry_id: Alias must be specified."))?;
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
            .context(err!(
                "In load_key_entry_id: Failed to select from keyentry table."
            ))?;
        let mut rows = stmt
            .query(params![
                key_type,
                key.domain.0 as u32,
                key.nspace,
                alias,
                KeyLifeCycle::Live
            ])
            .context(err!(
                "In load_key_entry_id: Failed to read from keyentry table."
            ))?;
        utils::with_rows_extract_one(&mut rows, |row| {
            row.map_or_else(|| Err(KsError::Rc(ResponseCode::KEY_NOT_FOUND)), Ok)?
                .get(0)
                .context("Failed to unpack id.")
        })
        .context(err!("In load_key_entry_id: Failed to load key entry id."))
    }

    /// Checks if a key exists with given key type and key descriptor properties.
    pub fn key_exists(
        &mut self,
        domain: Domain,
        nspace: i64,
        alias: &str,
        key_type: KeyType,
    ) -> anyhow::Result<bool> {
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
                    _ => Err(error).context(err!("Failed to find if the key exists.")),
                },
            }
        })
        .context(err!("Failed to check if key exists."))
    }

    fn get_key_km_uuid(tx: &Transaction, key_id: i64) -> Result<Uuid> {
        tx.query_row(
            "SELECT km_uuid FROM persistent.keyentry WHERE id = ?",
            params![key_id],
            |row| row.get(0),
        )
        .context(err!())
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

    fn load_blob_components(
        key_id: i64,
        load_bits: KeyEntryLoadBits,
        tx: &Transaction,
    ) -> Result<(
        bool,
        Option<(Vec<u8>, BlobMetaData)>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    )> {
        let mut stmt = tx
            .prepare(
                "SELECT MAX(id), subcomponent_type, blob FROM persistent.blobentry
                    WHERE keyentryid = ? GROUP BY subcomponent_type;",
            )
            .context(err!("prepare statement failed."))?;

        let mut rows = stmt.query(params![key_id]).context(err!("query failed."))?;

        let mut key_blob: Option<(i64, Vec<u8>)> = None;
        let mut cert_blob: Option<Vec<u8>> = None;
        let mut cert_chain_blob: Option<Vec<u8>> = None;
        let mut has_km_blob: bool = false;
        utils::with_rows_extract_all(&mut rows, |row| {
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
        .context(err!())?;

        let blob_info = key_blob.map_or::<Result<_>, _>(Ok(None), |(blob_id, blob)| {
            Ok(Some((
                blob,
                BlobMetaData::load_from_db(blob_id, tx)
                    .context(err!("Trying to load blob_metadata."))?,
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
        utils::with_rows_extract_all(&mut rows, |row| {
            let tag = Tag(row.get(0).context("Failed to read tag.")?);
            let sec_level = SecurityLevel(row.get(2).context("Failed to read sec_level.")?);
            parameters.push(
                KeyParameter::new_from_sql(tag, &SqlField::new(1, row), sec_level)
                    .context("Failed to read KeyParameter.")?,
            );
            Ok(())
        })
        .context(err!())?;

        Ok(parameters)
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
        caller_uid: u32,
    ) -> Result<(KeyIdGuard, KeyEntry)> {
        loop {
            match self.load_key_entry_internal(key, key_type, load_bits, caller_uid) {
                Ok(result) => break Ok(result),
                Err(e) => {
                    if Self::is_locked_error(&e) {
                        std::thread::sleep(DB_BUSY_RETRY_INTERVAL);
                        continue;
                    } else {
                        return Err(e).context(err!());
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
        caller_uid: u32,
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
            .context(err!("Failed to initialize transaction."))?;

        // Load the key_id and complete the access control tuple.
        let access = Self::load_access_tuple(&tx, key, key_type, caller_uid).context(err!())?;

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
                        .context(err!("Failed to roll back transaction."))?;

                    // Block until we have a key id lock.
                    let key_id_guard = KEY_ID_LOCK.get(access.key_id);

                    // Create a new transaction.
                    let tx = self
                        .conn
                        .unchecked_transaction()
                        .context(err!("Failed to initialize transaction."))?;

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
                    .context(err!("(deferred key lock)"))?;
                    (key_id_guard, tx)
                }
                Some(l) => (l, tx),
            },
            Some(key_id_guard) => (key_id_guard, tx),
        };

        let key_entry =
            Self::load_key_components(&tx, load_bits, key_id_guard.id()).context(err!())?;

        tx.commit().context(err!("Failed to commit transaction."))?;

        Ok((key_id_guard, key_entry))
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
                return Err(KsError::sys())
                    .context(err!("Domain {:?} must be either App or SELinux.", domain));
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
            .context(err!())?,
        ))
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
                    return Err(e).context(err!("failed to insert into database."));
                }
                _ => return Ok(newid),
            }
        }
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
            .context(err!("Failed to prepare statement."))?;

        for p in params.iter() {
            stmt.insert(params![
                key_id.0,
                p.get_tag().0,
                p.key_parameter_value(),
                p.security_level().0
            ])
            .with_context(|| err!("Failed to insert {:?}", p))?;
        }
        Ok(())
    }

    /// Store a new key in a single transaction.
    /// The function creates a new key entry, populates the blob, key parameter, and metadata
    /// fields, and rebinds the given alias to the new key.
    /// The boolean returned is a hint for the garbage collector. If true, a key was replaced,
    /// is now unreferenced and needs to be collected.
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
                    .context(err!("Need alias and domain must be APP or SELINUX."));
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

            Ok(key_id)
        })
        .context(err!())
    }

    /// Loads super key of a given user, if exists
    pub fn load_super_key(
        &mut self,
        key_type: &SuperKeyType,
        user_id: u32,
    ) -> Result<Option<(KeyIdGuard, KeyEntry)>> {
        let _wp = wd::watch("KeystoreDB::load_super_key");

        self.with_transaction(Immediate("TX_load_super_key"), |tx| {
            let key_descriptor = KeyDescriptor {
                domain: Domain::APP,
                nspace: user_id as i64,
                alias: Some(key_type.alias.into()),
                blob: None,
            };
            let id = Self::load_key_entry_id(tx, &key_descriptor, KeyType::Super);
            match id {
                Ok(id) => {
                    let key_entry = Self::load_key_components(tx, KeyEntryLoadBits::KM, id)
                        .context(err!("Failed to load key entry."))?;
                    Ok(Some((KEY_ID_LOCK.get(id), key_entry)))
                }
                Err(error) => match error.root_cause().downcast_ref::<KsError>() {
                    Some(KsError::Rc(ResponseCode::KEY_NOT_FOUND)) => Ok(None),
                    _ => Err(error).context(err!()),
                },
            }
        })
        .context(err!())
    }

    /// Stores a super key in the database.
    pub fn store_super_key(
        &mut self,
        user_id: u32,
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
                        user_id as i64,
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
        })
        .context(err!())
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
                .context(err!(
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
                .context(err!("Failed to insert blob."))?;

                if let Some(blob_metadata) = blob_metadata {
                    let blob_id = tx
                        .query_row("SELECT MAX(id) FROM persistent.blobentry;", [], |row| {
                            row.get(0)
                        })
                        .context(err!("Failed to get new blob id."))?;

                    blob_metadata
                        .store_in_db(blob_id, tx)
                        .context(err!("Trying to store blob metadata."))?;
                }
            }
            (None, SubComponentType::CERT) | (None, SubComponentType::CERT_CHAIN) => {
                tx.execute(
                    "DELETE FROM persistent.blobentry
                    WHERE subcomponent_type = ? AND keyentryid = ?;",
                    params![sc_type, key_id],
                )
                .context(err!("Failed to delete blob."))?;
            }
            (None, _) => {
                return Err(KsError::sys())
                    .context(err!("Other blobs cannot be deleted in this way."));
            }
        }
        Ok(())
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
            Self::set_blob_internal(tx, key_id.0, sc_type, blob, blob_metadata)
        })
        .context(err!())
    }

    fn delete_received_grants(tx: &Transaction, user_id: u32) -> Result<bool> {
        let updated = tx
            .execute(
                &format!("DELETE FROM persistent.grant WHERE cast ( (grantee/{AID_USER_OFFSET}) as int) = ?;"),
                params![user_id],
            )
            .context(format!(
                "Trying to delete grants received by user ID {:?} from other apps.",
                user_id
            ))?;
        Ok(updated != 0)
    }

    /// Deletes all keys for the given user, including both client keys and super keys.
    pub fn unbind_keys_for_user(&mut self, user_id: u32) -> Result<()> {
        let _wp = wd::watch("KeystoreDB::unbind_keys_for_user");

        self.with_transaction(Immediate("TX_unbind_keys_for_user"), |tx| {
            Self::delete_received_grants(tx, user_id).context(format!(
                "In unbind_keys_for_user. Failed to delete received grants for user ID {:?}.",
                user_id
            ))?;

            let mut stmt = tx
                .prepare(&format!(
                    "SELECT id from persistent.keyentry
                     WHERE (
                         key_type = ?
                         AND domain = ?
                         AND cast ( (namespace/{aid_user_offset}) as int) = ?
                         AND state = ?
                     ) OR (
                         key_type = ?
                         AND namespace = ?
                         AND state = ?
                     );",
                    aid_user_offset = AID_USER_OFFSET
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
                    user_id,
                    KeyLifeCycle::Live,
                    // OR super key:
                    KeyType::Super,
                    user_id,
                    KeyLifeCycle::Live
                ])
                .context(err!("Failed to query the keys created by apps."))?;

            let mut key_ids: Vec<i64> = Vec::new();
            utils::with_rows_extract_all(&mut rows, |row| {
                key_ids.push(
                    row.get(0)
                        .context("Failed to read key id of a key created by an app.")?,
                );
                Ok(())
            })
            .context(err!())?;

            Ok(())
        })
        .context(err!())
    }

    /// Find the newest auth token matching the given predicate.
    pub fn find_auth_token_entry<F>(&self, p: F) -> Option<AuthTokenEntry>
    where
        F: Fn(&AuthTokenEntry) -> bool,
    {
        self.perboot.find_auth_token_entry(p)
    }

    /// Insert or replace the auth token based on (user_id, auth_id, auth_type)
    pub fn insert_auth_token(&mut self, auth_token: &HardwareAuthToken) {
        self.perboot
            .insert_auth_token_entry(AuthTokenEntry::new(auth_token.clone(), BootTime::now()))
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
        })
        .context(err!())
    }

    fn do_table_size_query(
        &mut self,
        storage_type: MetricsStorage,
        query: &str,
        params: &[&str],
    ) -> Result<StorageStats> {
        let (total, unused) = self.with_transaction(TransactionBehavior::Deferred, |tx| {
            tx.query_row(query, params_from_iter(params), |row| Ok((row.get(0)?, row.get(1)?)))
                .with_context(|| {
                    err!("get_storage_stat: Error size of storage type {}", storage_type.0)
                })
        })?;
        Ok(StorageStats { storage_type, size: total, unused_size: unused })
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
            MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX => {
                self.get_table_size(storage_type, "persistent", "keyentry_domain_namespace_index")
            }
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
            _ => Err(anyhow::Error::msg(format!("Unsupported storage type: {}", storage_type.0))),
        }
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
                1 => {
                    Self::mark_unreferenced(tx, key_id)
                        .context("Trying to mark limited use key for deletion.")?;
                    Ok(())
                }
                0 => Err(KsError::Km(ErrorCode::INVALID_KEY_BLOB)).context("Key is exhausted."),
                _ => Ok(()),
            }
        })
        .context(err!())
    }
}

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
    pub(crate) auth_token: HardwareAuthToken,
    // Time received in milliseconds
    pub(crate) time_received: BootTime,
}

impl AuthTokenEntry {
    fn new(auth_token: HardwareAuthToken, time_received: BootTime) -> Self {
        AuthTokenEntry {
            auth_token,
            time_received,
        }
    }

    /// Checks if this auth token satisfies the given authentication information.
    pub fn satisfies(&self, user_secure_ids: &[i64], auth_type: HardwareAuthenticatorType) -> bool {
        user_secure_ids.iter().any(|&sid| {
            (sid == self.auth_token.userId || sid == self.auth_token.authenticatorId)
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
    pub fn challenge(&self) -> i64 {
        self.auth_token.challenge
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyType {
    /// This is a client key type. These keys are created or imported through the Keystore 2.0
    /// AIDL interface android.system.keystore2.
    Client,
    /// This is a super key type. These keys are created by keystore itself and used to encrypt
    /// other key blobs to provide LSKF binding.
    Super,
}

impl ToSql for KeyType {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Owned(Value::Integer(match self {
            KeyType::Client => 0,
            KeyType::Super => 1,
        })))
    }
}

impl FromSql for KeyType {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        match i64::column_result(value)? {
            0 => Ok(KeyType::Client),
            1 => Ok(KeyType::Super),
            v => Err(FromSqlError::OutOfRange(v)),
        }
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
            .context(err!("KeyMetaData::load_from_db: prepare statement failed."))?;

        let mut metadata: HashMap<i64, KeyMetaEntry> = Default::default();

        let mut rows = stmt
            .query(params![key_id])
            .context(err!("KeyMetaData::load_from_db: query failed."))?;
        utils::with_rows_extract_all(&mut rows, |row| {
            let db_tag: i64 = row.get(0).context("Failed to read tag.")?;
            metadata.insert(
                db_tag,
                KeyMetaEntry::new_from_sql(db_tag, &SqlField::new(1, row))
                    .context("Failed to read KeyMetaEntry.")?,
            );
            Ok(())
        })
        .context(err!("KeyMetaData::load_from_db."))?;

        Ok(Self { data: metadata })
    }

    fn store_in_db(&self, key_id: i64, tx: &Transaction) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT or REPLACE INTO persistent.keymetadata (keyentryid, tag, data)
                    VALUES (?, ?, ?);",
            )
            .context(err!(
                "KeyMetaData::store_in_db: Failed to prepare statement."
            ))?;

        let iter = self.data.iter();
        for (tag, entry) in iter {
            stmt.insert(params![key_id, tag, entry,])
                .with_context(|| err!("KeyMetaData::store_in_db: Failed to insert {:?}", entry))?;
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
            .context(err!(
                "BlobMetaData::load_from_db: prepare statement failed."
            ))?;

        let mut metadata: HashMap<i64, BlobMetaEntry> = Default::default();

        let mut rows = stmt
            .query(params![blob_id])
            .context(err!("query failed."))?;
        utils::with_rows_extract_all(&mut rows, |row| {
            let db_tag: i64 = row.get(0).context("Failed to read tag.")?;
            metadata.insert(
                db_tag,
                BlobMetaEntry::new_from_sql(db_tag, &SqlField::new(1, row))
                    .context("Failed to read BlobMetaEntry.")?,
            );
            Ok(())
        })
        .context(err!("BlobMetaData::load_from_db"))?;

        Ok(Self { data: metadata })
    }

    fn store_in_db(&self, blob_id: i64, tx: &Transaction) -> Result<()> {
        let mut stmt = tx
            .prepare(
                "INSERT or REPLACE INTO persistent.blobmetadata (blobentryid, tag, data)
                    VALUES (?, ?, ?);",
            )
            .context(err!(
                "BlobMetaData::store_in_db: Failed to prepare statement.",
            ))?;

        let iter = self.data.iter();
        for (tag, entry) in iter {
            stmt.insert(params![blob_id, tag, entry,])
                .with_context(|| err!("BlobMetaData::store_in_db: Failed to insert {:?}", entry))?;
        }
        Ok(())
    }
}

/// Uuid representation that can be stored in the database.
/// Right now it can only be initialized from SecurityLevel.
/// Once KeyMint provides a UUID type a corresponding From impl shall be added.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid([u8; 16]);

impl Deref for Uuid {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ToSql for Uuid {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
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
pub struct DateTime(pub(crate) i64);

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
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
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
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
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
    pub private_key: Vec<u8>,
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
}

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
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        self.0.to_sql()
    }
}

impl FromSql for SubComponentType {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        Ok(Self(u32::column_result(value)?))
    }
}

/// Access information for a key.
#[derive(Debug)]
struct KeyAccessInfo {
    key_id: i64,
    descriptor: KeyDescriptor,
    vector: Option<KeyPermSet>,
}
