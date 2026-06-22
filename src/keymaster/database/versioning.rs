// Copyright 2021, The Android Open Source Project
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

use anyhow::{anyhow, Context, Result};
use log::info;
use rusqlite::{params, OptionalExtension, Transaction};

fn create_or_get_version(tx: &Transaction, current_version: u32) -> Result<u32> {
    tx.execute(
        "CREATE TABLE IF NOT EXISTS persistent.version (
                id INTEGER PRIMARY KEY,
                version INTEGER);",
        [],
    )
    .context("In create_or_get_version: Failed to create version table.")?;

    let version = tx
        .query_row(
            "SELECT version FROM persistent.version WHERE id = 0;",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("In create_or_get_version: Failed to read version.")?;

    let version = if let Some(version) = version {
        version
    } else {
        // If no version table existed it could mean one of two things:
        // 1) This database is completely new. In this case the version has to be set
        //    to the current version and the current version which also needs to be
        //    returned.
        // 2) The database predates db versioning. In this case the version needs to be
        //    set to 0, and 0 needs to be returned.
        let version = if tx
            .query_row(
                "SELECT name FROM persistent.sqlite_master
                 WHERE type = 'table' AND name = 'keyentry';",
                [],
                |_| Ok(()),
            )
            .optional()
            .context("In create_or_get_version: Failed to check for keyentry table.")?
            .is_none()
        {
            current_version
        } else {
            0
        };

        tx.execute(
            "INSERT INTO persistent.version (id, version) VALUES(0, ?);",
            params![version],
        )
        .context("In create_or_get_version: Failed to insert initial version.")?;
        version
    };
    Ok(version)
}

pub(crate) fn update_version(tx: &Transaction, new_version: u32) -> Result<()> {
    let updated = tx
        .execute(
            "UPDATE persistent.version SET version = ? WHERE id = 0;",
            params![new_version],
        )
        .context("In update_version: Failed to update row.")?;
    if updated == 1 {
        Ok(())
    } else {
        Err(anyhow!("In update_version: No rows were updated."))
    }
}

pub fn upgrade_database<F>(tx: &Transaction, current_version: u32, upgraders: &[F]) -> Result<()>
where
    F: Fn(&Transaction) -> Result<u32> + 'static,
{
    if upgraders.len() < current_version as usize {
        return Err(anyhow!(
            "In upgrade_database: Insufficient upgraders provided."
        ));
    }
    let mut db_version = create_or_get_version(tx, current_version)
        .context("In upgrade_database: Failed to get database version.")?;
    while db_version < current_version {
        info!("Current DB version={db_version}, perform upgrade");
        db_version = upgraders[db_version as usize](tx).with_context(|| {
            format!("In upgrade_database: Trying to upgrade from db version {db_version}.")
        })?;
        info!("DB upgrade successful, current DB version now={db_version}");
    }
    update_version(tx, db_version).context("In upgrade_database.")
}

#[cfg(test)]
mod test {
    use super::*;
    use rusqlite::{Connection, TransactionBehavior};

    #[test]
    fn upgrade_database_test() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute("ATTACH DATABASE 'file::memory:' as persistent;", [])
            .unwrap();

        let upgraders: Vec<_> = (0..30_u32)
            .map(move |i| {
                move |tx: &Transaction| {
                    tx.execute(
                        "INSERT INTO persistent.test (test_field) VALUES(?);",
                        params![i + 1],
                    )
                    .with_context(|| format!("In upgrade_from_{}_to_{}.", i, i + 1))?;
                    Ok(i + 1)
                }
            })
            .collect();

        for legacy in &[false, true] {
            if *legacy {
                conn.execute(
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
                .unwrap();
            }
            for from in 1..29 {
                for to in from..30 {
                    conn.execute("DROP TABLE IF EXISTS persistent.version;", [])
                        .unwrap();
                    conn.execute("DROP TABLE IF EXISTS persistent.test;", [])
                        .unwrap();
                    conn.execute(
                        "CREATE TABLE IF NOT EXISTS persistent.test (
                            id INTEGER PRIMARY KEY,
                            test_field INTEGER);",
                        [],
                    )
                    .unwrap();

                    {
                        let tx = conn
                            .transaction_with_behavior(TransactionBehavior::Immediate)
                            .unwrap();
                        create_or_get_version(&tx, from).unwrap();
                        tx.commit().unwrap();
                    }
                    {
                        let tx = conn
                            .transaction_with_behavior(TransactionBehavior::Immediate)
                            .unwrap();
                        upgrade_database(&tx, to, &upgraders).unwrap();
                        tx.commit().unwrap();
                    }

                    // In the legacy database case all upgraders starting from 0 have to run. So
                    // after the upgrade step, the expectations need to be adjusted.
                    let from = if *legacy { 0 } else { from };

                    // There must be exactly to - from rows.
                    assert_eq!(
                        to - from,
                        conn.query_row(
                            "SELECT COUNT(test_field) FROM persistent.test;",
                            [],
                            |row| row.get::<_, u32>(0)
                        )
                        .unwrap()
                    );
                    // Each row must have the correct relation between id and test_field. If this
                    // is not the case, the upgraders were not executed in the correct order.
                    assert_eq!(
                        to - from,
                        conn.query_row(
                            "SELECT COUNT(test_field) FROM persistent.test
                             WHERE id = test_field - ?;",
                            params![from],
                            |row| row.get::<_, u32>(0)
                        )
                        .unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn create_or_get_version_new_database() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute("ATTACH DATABASE 'file::memory:' as persistent;", [])
            .unwrap();
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let version = create_or_get_version(&tx, 3).unwrap();
            tx.commit().unwrap();
            assert_eq!(version, 3);
        }

        // Was the version table created as expected?
        assert_eq!(
            Ok("version".to_owned()),
            conn.query_row(
                "SELECT name FROM persistent.sqlite_master
                 WHERE type = 'table' AND name = 'version';",
                [],
                |row| row.get(0),
            )
        );

        // There is exactly one row in the version table.
        assert_eq!(
            Ok(1),
            conn.query_row("SELECT COUNT(id) from persistent.version;", [], |row| row
                .get(0))
        );

        // The version must be set to 3
        assert_eq!(
            Ok(3),
            conn.query_row(
                "SELECT version from persistent.version WHERE id = 0;",
                [],
                |row| row.get(0)
            )
        );

        // Will subsequent calls to create_or_get_version still return the same version even
        // if the current version changes.
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let version = create_or_get_version(&tx, 5).unwrap();
            tx.commit().unwrap();
            assert_eq!(version, 3);
        }

        // There is still exactly one row in the version table.
        assert_eq!(
            Ok(1),
            conn.query_row("SELECT COUNT(id) from persistent.version;", [], |row| row
                .get(0))
        );

        // Bump the version.
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            update_version(&tx, 5).unwrap();
            tx.commit().unwrap();
        }

        // Now the version should have changed.
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let version = create_or_get_version(&tx, 7).unwrap();
            tx.commit().unwrap();
            assert_eq!(version, 5);
        }

        // There is still exactly one row in the version table.
        assert_eq!(
            Ok(1),
            conn.query_row("SELECT COUNT(id) from persistent.version;", [], |row| row
                .get(0))
        );

        // The version must be set to 5
        assert_eq!(
            Ok(5),
            conn.query_row(
                "SELECT version from persistent.version WHERE id = 0;",
                [],
                |row| row.get(0)
            )
        );
    }

    #[test]
    fn create_or_get_version_legacy_database() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute("ATTACH DATABASE 'file::memory:' as persistent;", [])
            .unwrap();
        // A legacy (version 0) database is detected if the keyentry table exists but no
        // version table.
        conn.execute(
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
        .unwrap();

        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let version = create_or_get_version(&tx, 3).unwrap();
            tx.commit().unwrap();
            // In the legacy case, version 0 must be returned.
            assert_eq!(version, 0);
        }

        // Was the version table created as expected?
        assert_eq!(
            Ok("version".to_owned()),
            conn.query_row(
                "SELECT name FROM persistent.sqlite_master
                 WHERE type = 'table' AND name = 'version';",
                [],
                |row| row.get(0),
            )
        );

        // There is exactly one row in the version table.
        assert_eq!(
            Ok(1),
            conn.query_row("SELECT COUNT(id) from persistent.version;", [], |row| row
                .get(0))
        );

        // The version must be set to 0
        assert_eq!(
            Ok(0),
            conn.query_row(
                "SELECT version from persistent.version WHERE id = 0;",
                [],
                |row| row.get(0)
            )
        );

        // Will subsequent calls to create_or_get_version still return the same version even
        // if the current version changes.
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let version = create_or_get_version(&tx, 5).unwrap();
            tx.commit().unwrap();
            assert_eq!(version, 0);
        }

        // There is still exactly one row in the version table.
        assert_eq!(
            Ok(1),
            conn.query_row("SELECT COUNT(id) from persistent.version;", [], |row| row
                .get(0))
        );

        // Bump the version.
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            update_version(&tx, 5).unwrap();
            tx.commit().unwrap();
        }

        // Now the version should have changed.
        {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let version = create_or_get_version(&tx, 7).unwrap();
            tx.commit().unwrap();
            assert_eq!(version, 5);
        }

        // There is still exactly one row in the version table.
        assert_eq!(
            Ok(1),
            conn.query_row("SELECT COUNT(id) from persistent.version;", [], |row| row
                .get(0))
        );

        // The version must be set to 5
        assert_eq!(
            Ok(5),
            conn.query_row(
                "SELECT version from persistent.version WHERE id = 0;",
                [],
                |row| row.get(0)
            )
        );
    }
}
