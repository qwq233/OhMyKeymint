use anyhow::{Context, Result};
use kmr_crypto_boring::{km::*, zvec::ZVec};

use crate::err;

pub struct ECDHPrivateKey(ECKey);

impl ECDHPrivateKey {
    /// Randomly generate a fresh keypair.
    pub fn generate() -> Result<ECDHPrivateKey> {
        ec_key_generate_key()
            .map(ECDHPrivateKey)
            .context(err!("generation failed"))
    }

    /// Deserialize bytes into an ECDH keypair
    pub fn from_private_key(buf: &[u8]) -> Result<ECDHPrivateKey> {
        ec_key_parse_private_key(buf)
            .map(ECDHPrivateKey)
            .context(err!("parsing failed"))
    }

    /// Serialize the ECDH key into bytes
    pub fn private_key(&self) -> Result<ZVec> {
        ec_key_marshal_private_key(&self.0).context(err!("marshalling failed"))
    }

    /// Generate the serialization of the corresponding public key
    pub fn public_key(&self) -> Result<Vec<u8>> {
        let point = ec_key_get0_public_key(&self.0);
        ec_point_point_to_oct(point.get_point()).context(err!("marshalling failed"))
    }

    /// Use ECDH to agree an AES key with another party whose public key we have.
    /// Sender and recipient public keys are passed separately because they are
    /// switched in encryption vs decryption.
    fn agree_key(
        &self,
        salt: &[u8],
        other_public_key: &[u8],
        sender_public_key: &[u8],
        recipient_public_key: &[u8],
    ) -> Result<ZVec> {
        let hkdf = hkdf_extract(sender_public_key, salt)
            .context(err!("hkdf_extract on sender_public_key failed"))?;
        let hkdf = hkdf_extract(recipient_public_key, &hkdf)
            .context(err!("hkdf_extract on recipient_public_key failed"))?;
        let other_public_key = ec_point_oct_to_point(other_public_key)
            .context(err!("ec_point_oct_to_point failed"))?;
        let secret = ecdh_compute_key(other_public_key.get_point(), &self.0)
            .context(err!("ecdh_compute_key failed"))?;
        let prk = hkdf_extract(&secret, &hkdf).context(err!("hkdf_extract on secret failed"))?;

        let aes_key = hkdf_expand(AES_256_KEY_LENGTH, &prk, b"AES-256-GCM key")
            .context(err!("hkdf_expand failed"))?;
        Ok(aes_key)
    }

    /// Encrypt a message to the party with the given public key
    pub fn encrypt_message(
        recipient_public_key: &[u8],
        message: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let sender_key = Self::generate().context(err!("generate failed"))?;
        let sender_public_key = sender_key.public_key().context(err!("public_key failed"))?;
        let salt = generate_salt().context(err!("generate_salt failed"))?;
        let aes_key = sender_key
            .agree_key(
                &salt,
                recipient_public_key,
                &sender_public_key,
                recipient_public_key,
            )
            .context(err!("agree_key failed"))?;
        let (ciphertext, iv, tag) =
            aes_gcm_encrypt(message, &aes_key).context(err!("aes_gcm_encrypt failed"))?;
        Ok((sender_public_key, salt, iv, ciphertext, tag))
    }

    /// Decrypt a message sent to us
    pub fn decrypt_message(
        &self,
        sender_public_key: &[u8],
        salt: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Result<ZVec> {
        let recipient_public_key = self.public_key()?;
        let aes_key = self
            .agree_key(
                salt,
                sender_public_key,
                sender_public_key,
                &recipient_public_key,
            )
            .context(err!("agree_key failed"))?;
        aes_gcm_decrypt(ciphertext, iv, tag, &aes_key).context(err!("aes_gcm_decrypt failed"))
    }
}
