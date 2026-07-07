#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AidlVersionHash {
    pub version: i32,
    pub hash: &'static str,
}

pub const AIDL_GET_INTERFACE_HASH_TRANSACTION: u32 = 0x00ff_fffe;
pub const AIDL_GET_INTERFACE_VERSION_TRANSACTION: u32 = 0x00ff_ffff;

pub const AID_ROOT: u32 = 0;
pub const AID_SYSTEM: u32 = 1000;
pub const AID_KEYSTORE: u32 = 1017;
pub const KEYSTORE_UID: libc::uid_t = AID_KEYSTORE as libc::uid_t;
pub const KEYSTORE_GID: libc::gid_t = AID_KEYSTORE as libc::gid_t;

pub const ANDROID_SYSTEM_KEYSTORE2_LATEST_AIDL_VERSION: i32 = 6;

pub const ANDROID_SYSTEM_KEYSTORE2_AIDL_VERSION_HASHES: &[AidlVersionHash] = &[
    AidlVersionHash {
        version: 1,
        hash: "19e8b65277839bad0ab335c781e3c652324920ce",
    },
    AidlVersionHash {
        version: 2,
        hash: "7e8ea78246ea548d1258bf24990c4d67beca2873",
    },
    AidlVersionHash {
        version: 3,
        hash: "4f1c704008e5687ed0d6f1590464aed39fc7f64e",
    },
    AidlVersionHash {
        version: 4,
        hash: "5648acc9b43590ef0a775b6f5c553831c20cccc4",
    },
    AidlVersionHash {
        version: 5,
        hash: "98d815116c190250e9e5a1d9182cea8126fd0e97",
    },
    AidlVersionHash {
        version: 6,
        hash: "b115fcb5d111eb616a65f0f32e0c2cef131575ec",
    },
];

pub fn android_system_keystore2_aidl_hash(version: i32) -> Option<&'static str> {
    ANDROID_SYSTEM_KEYSTORE2_AIDL_VERSION_HASHES
        .iter()
        .find(|entry| entry.version == version)
        .map(|entry| entry.hash)
}

pub fn android_system_keystore2_aidl_version_for_android_major(android_major: i32) -> Option<i32> {
    match android_major {
        12 => Some(1),
        13 => Some(2),
        14 => Some(3),
        15 => Some(4),
        16 => Some(5),
        17 => Some(6),
        value if value >= 17 => Some(ANDROID_SYSTEM_KEYSTORE2_LATEST_AIDL_VERSION),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn android_system_keystore2_hashes_cover_all_frozen_versions() {
        let versions: Vec<i32> = ANDROID_SYSTEM_KEYSTORE2_AIDL_VERSION_HASHES
            .iter()
            .map(|entry| entry.version)
            .collect();
        assert_eq!(versions, vec![1, 2, 3, 4, 5, 6]);

        let unique_versions: HashSet<i32> = versions.iter().copied().collect();
        assert_eq!(unique_versions.len(), versions.len());

        for entry in ANDROID_SYSTEM_KEYSTORE2_AIDL_VERSION_HASHES {
            assert_eq!(
                android_system_keystore2_aidl_hash(entry.version),
                Some(entry.hash)
            );
            assert_eq!(entry.hash.len(), 40);
            assert!(entry.hash.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn android_major_maps_to_keystore2_aidl_version() {
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(11),
            None
        );
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(12),
            Some(1)
        );
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(13),
            Some(2)
        );
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(14),
            Some(3)
        );
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(15),
            Some(4)
        );
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(16),
            Some(5)
        );
        assert_eq!(
            android_system_keystore2_aidl_version_for_android_major(17),
            Some(6)
        );
    }
}
