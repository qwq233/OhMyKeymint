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

//! This module implements the unique id rotation privacy feature. Certain system components
//! have the ability to include a per-app unique id into the key attestation. The key rotation
//! feature assures that the unique id is rotated on factory reset at least once in a 30 day
//! key rotation period.
//!
//! It is assumed that the timestamp file does not exist after a factory reset. So the creation
//! time of the timestamp file provides a lower bound for the time since factory reset.

use crate::err as ks_err;

use anyhow::{Context, Result};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const ID_ROTATION_PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60); // Thirty days.
static TIMESTAMP_FILE_NAME: &str = "timestamp";

/// The IdRotationState stores the path to the timestamp file for deferred usage. The data
/// partition is usually not available when Keystore 2.0 starts up. So this object is created
/// and passed down to the users of the feature which can then query the timestamp on demand.
#[derive(Debug, Clone)]
pub struct IdRotationState {
    /// We consider the time of last factory reset to be the point in time when this timestamp file
    /// is created.
    timestamp_path: PathBuf,
}

impl IdRotationState {
    /// Creates a new IdRotationState. It holds the path to the timestamp file for deferred usage.
    pub fn new(keystore_db_path: &Path) -> Self {
        let mut timestamp_path = keystore_db_path.to_owned();
        timestamp_path.push(TIMESTAMP_FILE_NAME);
        Self { timestamp_path }
    }

    /// Returns true iff a factory reset has occurred since the last ID rotation.
    pub fn had_factory_reset_since_id_rotation(
        &self,
        creation_datetime: &SystemTime,
    ) -> Result<bool> {
        match fs::metadata(&self.timestamp_path) {
            Ok(metadata) => {
                // For Tag::UNIQUE_ID, temporal counter value is defined as Tag::CREATION_DATETIME
                // divided by 2592000000, dropping any remainder. Temporal counter value is
                // effectively the index of the ID rotation period that we are currently in, with
                // each ID rotation period being 30 days.
                let temporal_counter_value = creation_datetime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .context(ks_err!("Failed to get epoch time"))?
                    .as_millis()
                    / ID_ROTATION_PERIOD.as_millis();

                // Calculate the beginning of the current ID rotation period, which is also the
                // last time ID was rotated.
                let id_rotation_time: SystemTime = SystemTime::UNIX_EPOCH
                    .checked_add(ID_ROTATION_PERIOD * temporal_counter_value.try_into()?)
                    .context(ks_err!("Failed to get ID rotation time."))?;

                let factory_reset_time = metadata
                    .modified()
                    .context(ks_err!("File creation time not supported."))?;

                Ok(id_rotation_time <= factory_reset_time)
            }
            Err(e) => match e.kind() {
                ErrorKind::NotFound => {
                    fs::File::create(&self.timestamp_path)
                        .context(ks_err!("Failed to create timestamp file."))?;
                    Ok(true)
                }
                _ => Err(e).context(ks_err!("Failed to open timestamp file.")),
            },
        }
        .context(ks_err!())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use nix::sys::stat::utimes;
    use nix::sys::time::{TimeVal, TimeValLike};
    use std::thread::sleep;
    use tempfile::TempDir;

    static TEMP_DIR_NAME: &str = "test_had_factory_reset_since_id_rotation_";

    fn set_up() -> (TempDir, PathBuf, IdRotationState) {
        let temp_dir = tempfile::Builder::new()
            .prefix(TEMP_DIR_NAME)
            .tempdir()
            .expect("Failed to create temp dir.");
        let mut timestamp_file_path = temp_dir.path().to_owned();
        timestamp_file_path.push(TIMESTAMP_FILE_NAME);
        let id_rotation_state = IdRotationState::new(temp_dir.path());

        (temp_dir, timestamp_file_path, id_rotation_state)
    }

    #[test]
    fn test_timestamp_creation() {
        let (_temp_dir, timestamp_file_path, id_rotation_state) = set_up();
        let creation_datetime = SystemTime::now();

        // The timestamp file should not exist.
        assert!(!timestamp_file_path.exists());

        // Trigger timestamp file creation one second later.
        sleep(Duration::new(1, 0));
        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        // Now the timestamp file should exist.
        assert!(timestamp_file_path.exists());

        let metadata = fs::metadata(&timestamp_file_path).unwrap();
        assert!(metadata.modified().unwrap() > creation_datetime);
    }

    #[test]
    fn test_existing_timestamp() {
        let (_temp_dir, timestamp_file_path, id_rotation_state) = set_up();

        // Let's start with at a known point in time, so that it's easier to control which ID
        // rotation period we're in.
        let mut creation_datetime = SystemTime::UNIX_EPOCH;

        // Create timestamp file and backdate it back to Unix epoch.
        fs::File::create(&timestamp_file_path).unwrap();
        let mtime = TimeVal::seconds(0);
        let atime = TimeVal::seconds(0);
        utimes(&timestamp_file_path, &atime, &mtime).unwrap();

        // Timestamp file was backdated to the very beginning of the current ID rotation period.
        // So, this should return true.
        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        // Move time forward, but stay in the same ID rotation period.
        creation_datetime += Duration::from_millis(1);

        // We should still return true because we're in the same ID rotation period.
        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        // Move time to the next ID rotation period.
        creation_datetime += ID_ROTATION_PERIOD;

        // Now we should see false.
        assert!(!id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());

        // Move timestamp to the future. This shouldn't ever happen, but even in this edge case ID
        // must be rotated.
        let mtime = TimeVal::seconds((ID_ROTATION_PERIOD.as_secs() * 10).try_into().unwrap());
        let atime = TimeVal::seconds((ID_ROTATION_PERIOD.as_secs() * 10).try_into().unwrap());
        utimes(&timestamp_file_path, &atime, &mtime).unwrap();
        assert!(id_rotation_state
            .had_factory_reset_since_id_rotation(&creation_datetime)
            .unwrap());
    }
}
