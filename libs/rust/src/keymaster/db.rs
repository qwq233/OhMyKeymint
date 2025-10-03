use std::{path::Path, time::Duration};

use anyhow::{Context, Result};
use rusqlite::{params, types::{FromSql, FromSqlResult, ToSqlOutput, Value, ValueRef}, Connection, ToSql, Transaction};

use crate::{android::hardware::security::keymint::{HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType}, utils::get_current_time_in_milliseconds};

const DB_ROOT_PATH: &str = "./omk/data";

#[cfg(target_os = "android")]
const DB_ROOT_PATH: &str = "/data/adb/omk/data";

const PERSISTENT_DB_FILENAME: &'static str = "keymaster.db";

const DB_BUSY_RETRY_INTERVAL: Duration = Duration::from_micros(500);

pub struct KeymasterDb {
    conn: Connection,
}

impl KeymasterDb {
    pub fn new() -> Result<Self> {
        let path = format!("{}/{}", DB_ROOT_PATH, PERSISTENT_DB_FILENAME);
        if let Some(p) = Path::new(&path).parent() {
            std::fs::create_dir_all(p).context("Failed to create directory for database.")?;
        }

        let mut conn = Self::make_connection(&path)?;
        let init_table = conn
            .transaction()
            .context("Failed to create transaction for initializing database.")?;
        Self::init_tables(&init_table)?;
        init_table
            .commit()
            .context("Failed to commit transaction for initializing database.")?;

        Ok(KeymasterDb { conn })
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

        Ok(conn)
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
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
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
        AuthTokenEntry { auth_token, time_received }
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
