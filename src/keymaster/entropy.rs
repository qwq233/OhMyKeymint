use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{error, warn};

use crate::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::err;
use crate::keymaster::crypto::generate_random_data;
use crate::keymaster::keymint_device::get_keymint_wrapper;
use crate::keymaster::security_level_manager;

const ENTROPY_SIZE: usize = 64;
const MIN_FEED_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
struct FeederInfo {
    last_feed: HashMap<SecurityLevel, Instant>,
}

pub fn register_feeder() {
    crate::global::ASYNC_TASK.add_idle(|shelf| {
        let info = shelf.get_mut::<FeederInfo>();
        let now = Instant::now();
        let devices_to_feed = [SecurityLevel::TRUSTED_ENVIRONMENT, SecurityLevel::STRONGBOX]
            .iter()
            .filter(|level| {
                info.last_feed
                    .get(level)
                    .is_none_or(|last| now.duration_since(*last) > MIN_FEED_INTERVAL)
                    && security_level_manager::was_operation_performed(**level)
            })
            .filter_map(|level| match get_keymint_wrapper(*level) {
                Ok(device) => Some((device, *level)),
                Err(e) => {
                    warn!("failed to get KeyMint device for entropy feed: {e:#}");
                    None
                }
            })
            .collect::<Vec<_>>();

        if devices_to_feed.is_empty() {
            return;
        }

        let data = match get_entropy(devices_to_feed.len() * ENTROPY_SIZE) {
            Ok(data) => data,
            Err(e) => {
                error!("failed to retrieve entropy for KeyMint device: {e:#}");
                return;
            }
        };

        for (i, (km_dev, security_level)) in devices_to_feed.iter().enumerate() {
            let offset = i * ENTROPY_SIZE;
            let sub_data = &data[offset..offset + ENTROPY_SIZE];
            if let Err(e) = km_dev.addRngEntropy(sub_data) {
                error!("Failed to feed entropy to KeyMint device: {e:?}");
            } else {
                security_level_manager::reset(*security_level);
                info.last_feed.insert(*security_level, now);
            }
        }
    });
}

fn get_entropy(size: usize) -> Result<Vec<u8>> {
    generate_random_data(size).context(err!("Retrieving entropy for KeyMint device"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_entropy_size() {
        for size in [0, 1, 4, 8, 256, 4096] {
            let data = get_entropy(size).expect("failed to get entropy");
            assert_eq!(data.len(), size);
        }
    }

    #[test]
    fn test_entropy_uniqueness() {
        let mut seen = HashSet::new();
        for _ in 0..8 {
            assert!(seen.insert(get_entropy(16).expect("failed to get entropy")));
        }
    }
}
