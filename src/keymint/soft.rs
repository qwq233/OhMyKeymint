//
// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Software-only trait implementations using fake keys.

use kmr_common::{
    crypto,
    crypto::{Hkdf, Rng, Sha256},
    Error,
};
use kmr_crypto_boring::{hmac::BoringHmac, rng::BoringRng, sha256::BoringSha256};
use kmr_ta::device::RetrieveKeyMaterial;
use rand::{rngs::StdRng, Rng as RandRng, SeedableRng};

/// Domain separator mixed into the StrongBox wrapping-key seed so TEE cannot unwrap
/// StrongBox keyblobs (and the reverse). The TEE path stays on the raw seed.
const STRONGBOX_WRAP_DOMAIN: &[u8] = b"omk-strongbox-wrap-v1";

/// Root key retrieval using hard-coded fake keys.
pub struct Keys {
    root_kek_seed: [u8; 32],
    kak_seed: [u8; 32],
    wrap_domain: Option<&'static [u8]>,
}

impl Keys {
    /// Creates a new TEE `Keys` instance with the given seeds.
    pub fn new(root_kek_seed: [u8; 32], kak_seed: [u8; 32]) -> Self {
        Self {
            root_kek_seed,
            kak_seed,
            wrap_domain: None,
        }
    }

    /// Creates a StrongBox `Keys` instance. Shared-secret/KAK material is unchanged
    /// so auth tokens still verify across security levels; only key wrapping differs.
    pub fn strongbox(root_kek_seed: [u8; 32], kak_seed: [u8; 32]) -> Self {
        Self {
            root_kek_seed,
            kak_seed,
            wrap_domain: Some(STRONGBOX_WRAP_DOMAIN),
        }
    }
}

fn wrap_seed(root_kek_seed: [u8; 32], wrap_domain: Option<&[u8]>) -> Result<[u8; 32], Error> {
    let Some(domain) = wrap_domain else {
        return Ok(root_kek_seed);
    };
    let mut input = Vec::with_capacity(root_kek_seed.len() + domain.len());
    input.extend_from_slice(&root_kek_seed);
    input.extend_from_slice(domain);
    BoringSha256.hash(&input)
}

impl RetrieveKeyMaterial for Keys {
    fn root_kek(&self, _context: &[u8]) -> Result<crypto::OpaqueOr<crypto::hmac::Key>, Error> {
        // TEE matches `MASTER_KEY` in system/keymaster/key_blob_utils/software_keyblobs.cpp.
        // StrongBox uses a domain-separated seed so the two TAs cannot unwrap each other.
        let seed = wrap_seed(self.root_kek_seed, self.wrap_domain)?;
        let mut rng = StdRng::from_seed(seed);
        let mut key = [0; 16];
        RandRng::fill_bytes(&mut rng, &mut key);

        Ok(crypto::hmac::Key::new(key.to_vec()).into())
    }
    fn kak(&self) -> Result<crypto::OpaqueOr<crypto::aes::Key>, Error> {
        // Matches `kFakeKeyAgreementKey` in
        // system/keymaster/km_openssl/soft_keymaster_enforcement.cpp.
        let mut rng = StdRng::from_seed(self.kak_seed);
        let mut key = [0; 32];
        RandRng::fill_bytes(&mut rng, &mut key);

        Ok(crypto::aes::Key::Aes256(key).into())
    }
}

/// Implementation of key derivation using a random fake key.
pub struct Derive {
    hbk: Vec<u8>,
}

impl Default for Derive {
    fn default() -> Self {
        // Use random data as an emulation of a hardware-backed key.
        let mut hbk = vec![0; 32];
        let mut rng = BoringRng;
        rng.fill_bytes(&mut hbk);
        Self { hbk }
    }
}

impl crate::keymint::rpc::DeriveBytes for Derive {
    fn derive_bytes(&self, context: &[u8], output_len: usize) -> Result<Vec<u8>, Error> {
        BoringHmac.hkdf(&[], &self.hbk, context, output_len)
    }
}

/// RPC artifact retrieval using software fake key.
pub type RpcArtifacts = crate::keymint::rpc::Artifacts<Derive>;

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_ta::device::RetrieveKeyMaterial;

    fn unwrap_explicit_hmac(key: crypto::OpaqueOr<crypto::hmac::Key>) -> Vec<u8> {
        match key {
            crypto::OpaqueOr::Explicit(ref key) => key.0.clone(),
            crypto::OpaqueOr::Opaque(_) => panic!("expected explicit HMAC key"),
        }
    }

    fn unwrap_explicit_aes(key: crypto::OpaqueOr<crypto::aes::Key>) -> Vec<u8> {
        match key {
            crypto::OpaqueOr::Explicit(crypto::aes::Key::Aes256(bytes)) => bytes.to_vec(),
            crypto::OpaqueOr::Explicit(_) => panic!("expected AES-256 key"),
            crypto::OpaqueOr::Opaque(_) => panic!("expected explicit AES key"),
        }
    }

    #[test]
    fn strongbox_wrapping_key_differs_from_tee() {
        let seed = [0x11u8; 32];
        let kak = [0x22u8; 32];
        assert_ne!(
            unwrap_explicit_hmac(Keys::new(seed, kak).root_kek(&[]).unwrap()),
            unwrap_explicit_hmac(Keys::strongbox(seed, kak).root_kek(&[]).unwrap())
        );
        assert_eq!(
            unwrap_explicit_aes(Keys::new(seed, kak).kak().unwrap()),
            unwrap_explicit_aes(Keys::strongbox(seed, kak).kak().unwrap())
        );
    }

    #[test]
    fn tee_wrapping_key_is_stable_for_the_same_seed() {
        let seed = [0x33u8; 32];
        let kak = [0x44u8; 32];
        assert_eq!(
            unwrap_explicit_hmac(Keys::new(seed, kak).root_kek(&[]).unwrap()),
            unwrap_explicit_hmac(Keys::new(seed, kak).root_kek(&[]).unwrap())
        );
    }
}
