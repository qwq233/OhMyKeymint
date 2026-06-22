use std::vec;
use std::vec::Vec;

use crate::{error::Error, zvec::ZVec};
use ffi::EVP_MAX_MD_SIZE;
use foreign_types::ForeignType;
use kmr_common::crypto::Rng;
use openssl::{
    ec::{EcGroup, EcKey, EcPoint, EcPointRef},
    hash::MessageDigest,
    nid::Nid,
    pkcs5::pbkdf2_hmac,
    pkey::{PKey, Private},
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

    let mut result = vec![0; data.len()];

    // Safety: The first two arguments must point to buffers with a size given by the third
    // argument. We pass the length of the key buffer along with the key.
    // The `iv` buffer must be 12 bytes and the `tag` buffer 16, which we check above.
    match AES_gcm_decrypt(data, result.as_mut_slice(), key, iv, tag) {
        true => Ok(ZVec::try_from(result.as_slice())?),
        false => Err(Error::DecryptionFailed),
    }
}

#[allow(non_snake_case)]
fn AES_gcm_decrypt(input: &[u8], output: &mut [u8], key: &[u8], iv: &[u8], tag: &[u8]) -> bool {
    let cipher = match key.len() {
        16 => Cipher::aes_128_gcm(),
        32 => Cipher::aes_256_gcm(),
        _ => return false,
    };

    let mut crypter = match Crypter::new(cipher, Mode::Decrypt, key, Some(iv)) {
        Ok(c) => c,
        Err(_) => return false,
    };

    crypter.pad(false);

    if crypter.set_tag(tag).is_err() {
        return false;
    }

    let mut decrypted = vec![0u8; input.len() + cipher.block_size()];

    let count = match crypter.update(input, &mut decrypted) {
        Ok(count) => count,
        Err(_) => return false,
    };

    let final_count = match crypter.finalize(&mut decrypted[count..]) {
        Ok(count) => count,
        Err(_) => return false, // 标签验证失败或其他错误
    };

    let total_count = count + final_count;

    if total_count != input.len() {
        return false;
    }

    output[..total_count].copy_from_slice(&decrypted[..total_count]);

    true
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
        let mut result = vec![0; out_len];

        // Call pbkdf2 with the correct arguments.
        pbkdf2(result.as_mut_slice(), pw, salt).map_err(|_| Error::EncryptionFailed)?;

        Ok(ZVec::try_from(result.as_slice())?)
    }

    /// Derives a key from the given high-entropy synthetic password and salt, using HKDF.
    pub fn derive_key_hkdf(&self, salt: &[u8], out_len: usize) -> Result<ZVec, Error> {
        let prk = hkdf_extract(self.get_key(), salt)?;
        let info = [];
        hkdf_expand(out_len, &prk, &info)
    }

    /// Try to make another Password object with the same data.
    pub fn try_clone(&self) -> Result<Password<'static>, Error> {
        Ok(Password::Owned(ZVec::try_from(self.get_key())?))
    }
}

/// Calls the boringssl HKDF_extract function.
pub fn hkdf_extract(secret: &[u8], salt: &[u8]) -> Result<ZVec, Error> {
    let max_size: usize = EVP_MAX_MD_SIZE.try_into().unwrap();
    let mut buf = vec![0; max_size];

    let mut out_len = 0;
    // Safety: HKDF_extract writes at most EVP_MAX_MD_SIZE bytes.
    // Secret and salt point to valid buffers.
    let result = { hkdf_extract_rs(buf.as_mut_slice(), &mut out_len, secret, salt) };
    if !result {
        return Err(Error::HKDFExtractFailed);
    }
    // According to the boringssl API, this should never happen.
    if out_len > max_size {
        return Err(Error::HKDFExtractFailed);
    }
    // HKDF_extract may write fewer than the maximum number of bytes, so we
    // truncate the buffer.
    let mut buf = ZVec::try_from(buf)?;
    buf.reduce_len(out_len);
    Ok(buf)
}

fn hkdf_extract_rs(out_key: &mut [u8], out_len: &mut usize, secret: &[u8], salt: &[u8]) -> bool {
    let digest = MessageDigest::sha256();

    match openssl::pkcs5::pbkdf2_hmac(secret, salt, 1, digest, out_key) {
        Ok(_) => {
            *out_len = out_key.len();
            true
        }
        Err(_) => false,
    }
}

/// Calls the boringssl HKDF_expand function.
pub fn hkdf_expand(out_len: usize, prk: &[u8], info: &[u8]) -> Result<ZVec, Error> {
    let mut buf = vec![0; out_len];
    // Safety: HKDF_expand writes out_len bytes to the buffer.
    // prk and info are valid buffers.
    let result = hkdf_expand_rs(buf.as_mut_slice(), prk, info);
    if !result {
        return Err(Error::HKDFExpandFailed);
    }
    Ok(ZVec::try_from(buf.as_slice())?)
}

fn hkdf_expand_rs(out_key: &mut [u8], prk: &[u8], info: &[u8]) -> bool {
    let digest = MessageDigest::sha256();

    openssl::pkcs5::pbkdf2_hmac(prk, info, 1, digest, out_key).is_ok()
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

/// Calls the boringssl ECDH_compute_key function.
pub fn ecdh_compute_key(pub_key: &EcPointRef, priv_key: &ECKey) -> Result<ZVec, Error> {
    let group =
        EcGroup::from_curve_name(Nid::SECP521R1).map_err(|_| Error::ECDHComputeKeyFailed)?;
    let peer_key =
        EcKey::from_public_key(&group, pub_key).map_err(|_| Error::ECDHComputeKeyFailed)?;
    let peer_pkey = PKey::from_ec_key(peer_key).map_err(|_| Error::ECDHComputeKeyFailed)?;
    let private_pkey =
        PKey::from_ec_key(priv_key.0.clone()).map_err(|_| Error::ECDHComputeKeyFailed)?;
    let mut deriver =
        openssl::derive::Deriver::new(&private_pkey).map_err(|_| Error::ECDHComputeKeyFailed)?;
    deriver
        .set_peer(&peer_pkey)
        .map_err(|_| Error::ECDHComputeKeyFailed)?;
    let secret = deriver
        .derive_to_vec()
        .map_err(|_| Error::ECDHComputeKeyFailed)?;
    Ok(ZVec::try_from(secret.as_slice())?)
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
    let len = 73; // Empirically observed length of private key.
    let mut buf = ZVec::new(len)?;
    // Safety: the key is valid.
    // This will not write past the specified length of the buffer; if the
    // len above is too short, it returns 0.
    let written_len =
        unsafe { ECKEYMarshalPrivateKey(key.0.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    if written_len != len {
        return Err(Error::ECKEYMarshalPrivateKeyFailed);
    }
    Ok(buf)
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
