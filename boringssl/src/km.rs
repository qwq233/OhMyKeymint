use std::vec;
use std::vec::Vec;

use crate::{error::Error, zvec::ZVec};
use bssl_sys::EVP_MAX_MD_SIZE;
use foreign_types::{ForeignType, ForeignTypeRef};
use kmr_common::crypto::Rng;
use openssl::{
    ec::{EcGroup, EcKey, EcPoint, EcPointRef},
    hash::MessageDigest,
    nid::Nid,
    pkcs5::pbkdf2_hmac,
    pkey::Private,
    symm::{Cipher, Crypter, Mode},
};

/// Length of the expected initialization vector.
pub const GCM_IV_LENGTH: usize = 12;
/// Length of the expected AEAD TAG.
pub const TAG_LENGTH: usize = 16;
/// Length of an AES 256 key in bytes.
pub const AES_256_KEY_LENGTH: usize = 32;
/// Length of an AES 128 key in bytes.
pub const AES_128_KEY_LENGTH: usize = 16;
/// Length of the expected salt for key from password generation.
pub const SALT_LENGTH: usize = 16;
/// Length of an HMAC-SHA256 tag in bytes.
pub const HMAC_SHA256_LEN: usize = 32;
/// Length of the GCM tag in bytes.
pub const GCM_TAG_LENGTH: usize = 128 / 8;
/// Length of ECDH P-521 output in bytes.
pub const ECDH_P521_OUTPUT_LEN: usize = 66;

/// Older versions of keystore incorrectly truncated ECDH P-521 outputs to the following length.
/// Retain the ability to decrypt keys that were stored in the database using the old method.
pub const LEGACY_TRUNCATED_ECDH_OUTPUT_LEN: usize = 32;

/// AES-GCM encryption result: `(ciphertext, iv, tag)`.
pub type AesGcmEncryption = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Older versions of keystore produced IVs with four extra
/// ignored zero bytes at the end; recognise and trim those.
pub const LEGACY_IV_LENGTH: usize = 16;

/// Generate an AES256 key, essentially 32 random bytes from the underlying
/// boringssl library discretely stuffed into a ZVec.
pub fn generate_aes256_key() -> Result<ZVec, Error> {
    let mut key = ZVec::new(AES_256_KEY_LENGTH)?;
    // Safety: key has the same length as the requested number of random bytes.
    if randomBytes(key.as_mut_ptr(), AES_256_KEY_LENGTH) {
        Ok(key)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

/// Generate a salt.
pub fn generate_salt() -> Result<Vec<u8>, Error> {
    generate_random_data(SALT_LENGTH)
}

/// Generate random data of the given size.
pub fn generate_random_data(size: usize) -> Result<Vec<u8>, Error> {
    let mut data = vec![0; size];
    // Safety: data has the same length as the requested number of random bytes.
    if randomBytes(data.as_mut_ptr(), size) {
        Ok(data)
    } else {
        Err(Error::RandomNumberGenerationFailed)
    }
}

#[allow(non_snake_case)]
fn randomBytes(buf: *mut u8, len: usize) -> bool {
    let mut rng = crate::rng::BoringRng;
    rng.fill_bytes(unsafe { std::slice::from_raw_parts_mut(buf, len) });
    true
}

/// Perform HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    kmr_common::crypto::hmac_sha256(&crate::hmac::BoringHmac, key, msg)
        .map_err(|_| Error::HmacSha256Failed)
}

/// Uses AES GCM to decipher a message given an initialization vector, aead tag, and key.
/// This function accepts 128 and 256-bit keys and uses AES128 and AES256 respectively based
/// on the key length.
/// This function returns the plaintext message in a ZVec because it is assumed that
/// it contains sensitive information that should be zeroed from memory before its buffer is
/// freed. Input key is taken as a slice for flexibility, but it is recommended that it is held
/// in a ZVec as well.
pub fn aes_gcm_decrypt(data: &[u8], iv: &[u8], tag: &[u8], key: &[u8]) -> Result<ZVec, Error> {
    // Old versions of aes_gcm_encrypt produced 16 byte IVs, but the last four bytes were ignored
    // so trim these to the correct size.
    let iv = match iv.len() {
        GCM_IV_LENGTH => iv,
        LEGACY_IV_LENGTH => &iv[..GCM_IV_LENGTH],
        _ => return Err(Error::InvalidIvLength),
    };
    if tag.len() != TAG_LENGTH {
        return Err(Error::InvalidAeadTagLength);
    }

    match key.len() {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        32 => Cipher::aes_256_gcm(),
        _ => return Err(Error::InvalidKeyLength),
    };

    let mut crypter =
        Crypter::new(cipher, Mode::Decrypt, key, Some(iv)).map_err(|_| Error::DecryptionFailed)?;

    crypter.pad(false);
    crypter.set_tag(tag).map_err(|_| Error::DecryptionFailed)?;

    let mut result = ZVec::new(data.len() + cipher.block_size())?;
    let count = crypter
        .update(data, &mut result)
        .map_err(|_| Error::DecryptionFailed)?;
    let final_count = crypter
        .finalize(&mut result[count..])
        .map_err(|_| Error::DecryptionFailed)?;
    let total_count = count + final_count;
    if total_count != data.len() {
        return Err(Error::DecryptionFailed);
    }
    result.reduce_len(total_count);
    Ok(result)
}

/// Uses AES GCM to encrypt a message given a key.
/// This function accepts 128 and 256-bit keys and uses AES128 and AES256 respectively based on
/// the key length. The function generates an initialization vector. The return value is a tuple
/// of `(ciphertext, iv, tag)`.
pub fn aes_gcm_encrypt(plaintext: &[u8], key: &[u8]) -> Result<AesGcmEncryption, Error> {
    let mut iv = vec![0; GCM_IV_LENGTH];
    // Safety: iv is GCM_IV_LENGTH bytes long.
    if !randomBytes(iv.as_mut_ptr(), GCM_IV_LENGTH) {
        return Err(Error::RandomNumberGenerationFailed);
    }

    match key.len() {
        AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
        _ => return Err(Error::InvalidKeyLength),
    }

    let mut ciphertext: Vec<u8> = vec![0; plaintext.len()];
    let mut tag: Vec<u8> = vec![0; TAG_LENGTH];
    // Safety: The first two arguments must point to buffers with a size given by the third
    // argument. We pass the length of the key buffer along with the key.
    // The `iv` buffer must be 12 bytes and the `tag` buffer 16, which we check above.
    match AES_gcm_encrypt(plaintext, &mut ciphertext, key, &iv, &mut tag) {
        Ok(()) => Ok((ciphertext, iv, tag)),
        Err(_) => Err(Error::EncryptionFailed),
    }
}

#[allow(non_snake_case)]
fn AES_gcm_encrypt(
    input: &[u8],
    output: &mut [u8],
    key: &[u8],
    iv: &[u8],
    tag: &mut [u8],
) -> Result<(), openssl::error::ErrorStack> {
    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        32 => Cipher::aes_256_gcm(),
        _ => return Err(openssl::error::ErrorStack::get()),
    };

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv))?;

    crypter.pad(false);

    let mut encrypted = vec![0u8; input.len() + cipher.block_size()];
    let mut count = crypter.update(input, &mut encrypted)?;
    count += crypter.finalize(&mut encrypted[count..])?;

    encrypted.truncate(count);

    if encrypted.len() != input.len() {
        return Err(openssl::error::ErrorStack::get());
    }

    output[..encrypted.len()].copy_from_slice(&encrypted);

    crypter.get_tag(tag)?;

    Ok(())
}

fn pbkdf2(key: &mut [u8], password: &[u8], salt: &[u8]) -> Result<(), openssl::error::ErrorStack> {
    let iterations = 8192;

    let digest = if key.len() == AES_128_KEY_LENGTH {
        MessageDigest::sha1()
    } else {
        MessageDigest::sha256()
    };

    pbkdf2_hmac(password, salt, iterations, digest, key)
}

/// A high-entropy synthetic password from which an AES key may be derived.
pub enum Password<'a> {
    /// Borrow an existing byte array
    Ref(&'a [u8]),
    /// Use an owned ZVec to store the key
    Owned(ZVec),
}

impl<'a> From<&'a [u8]> for Password<'a> {
    fn from(pw: &'a [u8]) -> Self {
        Self::Ref(pw)
    }
}

impl<'a> Password<'a> {
    fn get_key(&'a self) -> &'a [u8] {
        match self {
            Self::Ref(b) => b,
            Self::Owned(z) => z,
        }
    }

    /// Derives a key from the given password and salt, using PBKDF2 with 8192 iterations.
    ///
    /// The salt length must be 16 bytes, and the output key length must be 16 or 32 bytes.
    ///
    /// This function exists only for backwards compatibility reasons.  Keystore now receives only
    /// high-entropy synthetic passwords, which do not require key stretching.
    pub fn derive_key_pbkdf2(&self, salt: &[u8], out_len: usize) -> Result<ZVec, Error> {
        if salt.len() != SALT_LENGTH {
            return Err(Error::InvalidSaltLength);
        }
        match out_len {
            AES_128_KEY_LENGTH | AES_256_KEY_LENGTH => {}
            _ => return Err(Error::InvalidKeyLength),
        }

        let pw = self.get_key();
        let mut result = ZVec::new(out_len)?;

        // Call pbkdf2 with the correct arguments.
        pbkdf2(&mut result, pw, salt).map_err(|_| Error::EncryptionFailed)?;

        Ok(result)
    }

    /// Derives a key from the given high-entropy synthetic password and salt, using HKDF.
    pub fn derive_key_hkdf(&self, salt: &[u8], out_len: usize) -> Result<ZVec, Error> {
        let prk = hkdf_extract(self.get_key(), salt)?;
        let info = [];
        hkdf_expand(out_len, &prk, &info)
    }

    /// Reproduce the accidental KDF used by older OhMyKeymint builds.
    #[doc(hidden)]
    pub fn derive_key_omk_legacy(&self, salt: &[u8], out_len: usize) -> Result<ZVec, Error> {
        let prk = omk_legacy_kdf_extract(self.get_key(), salt)?;
        omk_legacy_kdf_expand(out_len, &prk, &[])
    }

    /// Try to make another Password object with the same data.
    pub fn try_clone(&self) -> Result<Password<'static>, Error> {
        Ok(Password::Owned(ZVec::try_from(self.get_key())?))
    }
}

/// Calls the boringssl HKDF_extract function.
pub fn hkdf_extract(secret: &[u8], salt: &[u8]) -> Result<ZVec, Error> {
    let max_size: usize = EVP_MAX_MD_SIZE.try_into().unwrap();
    let mut buf = ZVec::new(max_size)?;

    let mut out_len = 0;
    // Safety: HKDF_extract writes at most EVP_MAX_MD_SIZE bytes.
    // Secret and salt point to valid buffers.
    let result = unsafe {
        bssl_sys::HKDF_extract(
            buf.as_mut_ptr(),
            &mut out_len,
            bssl_sys::EVP_sha256(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };
    if result != 1 {
        return Err(Error::HKDFExtractFailed);
    }
    // According to the boringssl API, this should never happen.
    if out_len > max_size {
        return Err(Error::HKDFExtractFailed);
    }
    // HKDF_extract may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    buf.reduce_len(out_len);
    Ok(buf)
}

/// Calls the boringssl HKDF_expand function.
pub fn hkdf_expand(out_len: usize, prk: &[u8], info: &[u8]) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(out_len)?;
    // Safety: HKDF_expand writes out_len bytes to the buffer.
    // prk and info are valid buffers.
    let result = unsafe {
        bssl_sys::HKDF_expand(
            buf.as_mut_ptr(),
            out_len,
            bssl_sys::EVP_sha256(),
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    if result != 1 {
        return Err(Error::HKDFExpandFailed);
    }
    Ok(buf)
}

/// Reproduce the accidental PBKDF2-based extract used by older OhMyKeymint builds.
#[doc(hidden)]
pub fn omk_legacy_kdf_extract(secret: &[u8], salt: &[u8]) -> Result<ZVec, Error> {
    let max_size: usize = EVP_MAX_MD_SIZE.try_into().unwrap();
    let mut buf = ZVec::new(max_size)?;
    pbkdf2_hmac(secret, salt, 1, MessageDigest::sha256(), &mut buf)
        .map_err(|_| Error::HKDFExtractFailed)?;
    Ok(buf)
}

/// Reproduce the accidental PBKDF2-based expand used by older OhMyKeymint builds.
#[doc(hidden)]
pub fn omk_legacy_kdf_expand(out_len: usize, prk: &[u8], info: &[u8]) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(out_len)?;
    pbkdf2_hmac(prk, info, 1, MessageDigest::sha256(), &mut buf)
        .map_err(|_| Error::HKDFExpandFailed)?;
    Ok(buf)
}

/// P-521 ECDH private key used by legacy KeyMaster message encryption.
pub struct ECKey(EcKey<Private>);

/// An owned EC_POINT object.
pub struct OwnedECPoint(EcPoint);

impl OwnedECPoint {
    /// Get the wrapped EC_POINT object.
    pub fn get_point(&self) -> &EcPointRef {
        &self.0
    }
}

/// Selects how the ECDH P-521 output is used.
#[derive(Clone, Copy)]
pub enum EcdhComputeKeyVersion {
    /// Use only the first 32 bytes of the ECDH P-521 output.  This does not follow cryptographic
    /// best practices.  The code is retained only to allow decrypting existing keys.
    LegacyTruncated,
    /// Use the full 66 bytes of the ECDH P-521 output.
    Current,
}

/// Calls the boringssl ECDH_compute_key function.
pub fn ecdh_compute_key(
    pub_key: &EcPointRef,
    priv_key: &ECKey,
    version: EcdhComputeKeyVersion,
) -> Result<ZVec, Error> {
    let mut buf = ZVec::new(ECDH_P521_OUTPUT_LEN)?;
    // Safety: ECDH_compute_key writes at most buf.len() bytes, and both keys are valid objects.
    let result = unsafe {
        bssl_sys::ECDH_compute_key(
            buf.as_mut_ptr().cast(),
            buf.len(),
            pub_key.as_ptr(),
            priv_key.0.as_ptr(),
            None,
        )
    };
    if result == -1 {
        return Err(Error::ECDHComputeKeyFailed);
    }
    let out_len = result.try_into().unwrap();
    // According to the boringssl API, this should never happen.
    if out_len > buf.len() {
        return Err(Error::ECDHComputeKeyFailed);
    }
    // ECDH_compute_key may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    buf.reduce_len(out_len);

    // If attempting the legacy key decryption method, further truncate the output.
    match version {
        EcdhComputeKeyVersion::LegacyTruncated => buf.reduce_len(LEGACY_TRUNCATED_ECDH_OUTPUT_LEN),
        EcdhComputeKeyVersion::Current => (),
    }
    Ok(buf)
}

/// Calls the boringssl EC_KEY_generate_key function.
pub fn ec_key_generate_key() -> Result<ECKey, Error> {
    let group =
        EcGroup::from_curve_name(Nid::SECP521R1).map_err(|_| Error::ECKEYGenerateKeyFailed)?;
    let ec_key: EcKey<openssl::pkey::Private> =
        EcKey::generate(&group).map_err(|_| Error::ECKEYGenerateKeyFailed)?;

    Ok(ECKey(ec_key))
}

#[allow(non_snake_case)]
unsafe fn ECKEYMarshalPrivateKey(key: *const ffi::EC_KEY, buf: *mut u8, len: usize) -> usize {
    let mut cbb = std::mem::MaybeUninit::<ffi::CBB>::uninit();
    if ffi::CBB_init_fixed(cbb.as_mut_ptr(), buf, len) != 1 {
        return 0;
    }
    let mut cbb = cbb.assume_init();
    let flags = (ffi::EC_PKEY_NO_PARAMETERS | ffi::EC_PKEY_NO_PUBKEY) as u32;
    if ffi::EC_KEY_marshal_private_key(&mut cbb, key, flags) != 1 {
        return 0;
    }
    let mut written_len = 0usize;
    if ffi::CBB_finish(&mut cbb, std::ptr::null_mut(), &mut written_len) != 1 {
        return 0;
    }
    written_len
}

#[allow(non_snake_case)]
unsafe fn ECKEYParsePrivateKey(buf: *const u8, len: usize) -> *mut ffi::EC_KEY {
    let group = ffi::EC_GROUP_new_by_curve_name(ffi::NID_secp521r1);
    if group.is_null() {
        return std::ptr::null_mut();
    }

    let mut cbs = std::mem::MaybeUninit::<ffi::CBS>::uninit();
    ffi::CBS_init(cbs.as_mut_ptr(), buf, len);
    let mut cbs = cbs.assume_init();
    let key = ffi::EC_KEY_parse_private_key(&mut cbs, group);
    ffi::EC_GROUP_free(group);

    if key.is_null() || ffi::CBS_len(&cbs) != 0 {
        if !key.is_null() {
            ffi::EC_KEY_free(key);
        }
        return std::ptr::null_mut();
    }

    key
}

/// Calls the boringssl EC_KEY_marshal_private_key function.
pub fn ec_key_marshal_private_key(key: &ECKey) -> Result<ZVec, Error> {
    let len = 73; // Empirically observed length of private key
    let mut buf = ZVec::new(len)?;
    // Safety: the key is valid.
    // This will not write past the specified length of the buffer; if the
    // len above is too short, it returns 0.
    let written_len =
        unsafe { ECKEYMarshalPrivateKey(key.0.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    if written_len == len {
        Ok(buf)
    } else {
        Err(Error::ECKEYMarshalPrivateKeyFailed)
    }
}

/// Calls the boringssl EC_KEY_parse_private_key function.
pub fn ec_key_parse_private_key(buf: &[u8]) -> Result<ECKey, Error> {
    // Safety: this will not read past the specified length of the buffer.
    // It fails if less than the whole buffer is consumed.
    let priv_key = unsafe { ECKEYParsePrivateKey(buf.as_ptr(), buf.len()) };
    if priv_key.is_null() {
        Err(Error::ECKEYParsePrivateKeyFailed)
    } else {
        // Safety: `priv_key` is a valid EC_KEY returned by BoringSSL.
        Ok(ECKey(unsafe { EcKey::from_ptr(priv_key) }))
    }
}

/// Calls the boringssl EC_KEY_get0_public_key function.
pub fn ec_key_get0_public_key(key: &ECKey) -> &EcPointRef {
    key.0.public_key()
}

pub fn ec_point_point_to_oct(point: &EcPointRef) -> Result<Vec<u8>, Error> {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).map_err(|_| Error::ECPoint2OctFailed)?;

    // We fix the length to 133 (1 + 2 * field_elem_size), as we get an error if it's too small.
    let len = 133;
    let mut buf = vec![0; len];

    let mut ctx = openssl::bn::BigNumContext::new().map_err(|_| Error::ECPoint2OctFailed)?;
    let bytes = point
        .to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .map_err(|_| Error::ECPoint2OctFailed)?;
    if buf.len() < bytes.len() {
        return Err(Error::ECPoint2OctFailed);
    }
    buf.as_mut_slice()[..bytes.len()].copy_from_slice(&bytes);

    Ok(buf)
}

/// Calls the boringssl EC_POINT_oct2point function.
pub fn ec_point_oct_to_point(buf: &[u8]) -> Result<OwnedECPoint, Error> {
    // Safety: The buffer is valid.
    let group = EcGroup::from_curve_name(Nid::SECP521R1).map_err(|_| Error::ECPoint2OctFailed)?;
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|_| Error::ECPoint2OctFailed)?;
    let ec_point =
        EcPoint::from_bytes(&group, buf, &mut ctx).map_err(|_| Error::ECPoint2OctFailed)?;

    Ok(OwnedECPoint(ec_point))
}
