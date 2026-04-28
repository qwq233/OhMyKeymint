use std::{
    fs,
    io::ErrorKind,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};

use crate::err;

const ID_ROTATION_PERIOD: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const TIMESTAMP_FILE_NAME: &str = "timestamp";

#[cfg(target_os = "android")]
const KEYSTORE_DATA_PATH: &str = "/data/misc/keystore/omk/data";

#[cfg(not(target_os = "android"))]
const KEYSTORE_DATA_PATH: &str = "./omk/data";

#[derive(Debug, Clone)]
pub struct IdRotationState {
    timestamp_path: PathBuf,
}

impl IdRotationState {
    pub fn new_default() -> Self {
        let mut timestamp_path = PathBuf::from(KEYSTORE_DATA_PATH);
        timestamp_path.push(TIMESTAMP_FILE_NAME);
        Self { timestamp_path }
    }

    pub fn had_factory_reset_since_id_rotation(
        &self,
        creation_datetime: &SystemTime,
    ) -> Result<bool> {
        match fs::metadata(&self.timestamp_path) {
            Ok(metadata) => {
                let temporal_counter_value = creation_datetime
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .context(err!("Failed to get epoch time"))?
                    .as_millis()
                    / ID_ROTATION_PERIOD.as_millis();
                let id_rotation_time = SystemTime::UNIX_EPOCH
                    .checked_add(ID_ROTATION_PERIOD * temporal_counter_value.try_into()?)
                    .context(err!("Failed to get ID rotation time"))?;
                let factory_reset_time = metadata
                    .modified()
                    .context(err!("File creation time not supported"))?;
                Ok(id_rotation_time <= factory_reset_time)
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                if let Some(parent) = self.timestamp_path.parent() {
                    fs::create_dir_all(parent)
                        .context(err!("Failed to create ID rotation timestamp directory"))?;
                }
                fs::File::create(&self.timestamp_path)
                    .context(err!("Failed to create ID rotation timestamp file"))?;
                Ok(true)
            }
            Err(error) => Err(error).context(err!("Failed to open ID rotation timestamp file")),
        }
        .context(err!())
    }
}
