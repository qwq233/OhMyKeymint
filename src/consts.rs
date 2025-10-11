/// Magic prefix used by the km_compat C++ code to mark a key that is owned by an
/// underlying Keymaster hardware device that has been wrapped by km_compat. (The
/// final zero byte indicates that the blob is not software emulated.)
pub const KEYMASTER_BLOB_HW_PREFIX: &[u8] = b"pKMblob\x00";

/// Magic prefix used by the km_compat C++ code to mark a key that is owned by an
/// software emulation device that has been wrapped by km_compat. (The final one
/// byte indicates that the blob is software emulated.)
pub const KEYMASTER_BLOB_SW_PREFIX: &[u8] = b"pKMblob\x01";
