// Copyright 2022, The Android Open Source Project
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

use kmr_common::{crypto, keyblob};
use kmr_wire::keymint;
use std::collections::HashMap;
use std::fmt::Write;

/// Combined schema, with CBOR-encoded examples of specific types.
#[derive(Default)]
struct AccumulatedSchema {
    schema: String,
    samples: HashMap<String, Vec<u8>>,
}

impl AccumulatedSchema {
    /// Add a new type to the accumulated schema, along with a sample instance of the type.
    fn add<T: kmr_wire::AsCborValue>(&mut self, sample: T) {
        if let (Some(name), Some(schema)) = (<T>::cddl_typename(), <T>::cddl_schema()) {
            self.add_name_schema(&name, &schema);
            self.samples.insert(name, sample.into_vec().unwrap());
        } else {
            eprintln!("No CDDL typename+schema for {}", std::any::type_name::<T>());
        }
    }

    /// Add the given name = schema to the accumulated schema.
    fn add_name_schema(&mut self, name: &str, schema: &str) {
        let _ = writeln!(self.schema, "{} = {}", name, schema);
    }

    /// Check that all of the sample type instances match their CDDL schema.
    ///
    /// This method is a no-op if the `cddl-cat` feature is not enabled.
    fn check(&self) {
        // TODO: enable this if/when cddl-cat supports tagged CBOR items (which are used in the
        // EncryptedKeyBlob encoding)
        #[cfg(feature = "cddl-cat")]
        for (name, data) in &self.samples {
            if let Err(e) = cddl_cat::validate_cbor_bytes(&name, &self.schema, &data) {
                eprintln!("Failed to validate sample data for {} against CDDL: {:?}", name, e);
            }
        }
    }
}

impl std::fmt::Display for AccumulatedSchema {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.schema)
    }
}

fn main() {
    // CDDL for encrypted keyblobs, top-down.
    let mut schema = AccumulatedSchema::default();

    schema.add(keyblob::EncryptedKeyBlob::V1(keyblob::EncryptedKeyBlobV1 {
        characteristics: vec![],
        key_derivation_input: [0u8; 32],
        kek_context: vec![],
        encrypted_key_material: coset::CoseEncrypt0Builder::new()
            .protected(
                coset::HeaderBuilder::new().algorithm(coset::iana::Algorithm::A256GCM).build(),
            )
            .ciphertext(vec![1, 2, 3])
            .build(),
        secure_deletion_slot: Some(keyblob::SecureDeletionSlot(1)),
    }));
    schema.add(keyblob::Version::V1);
    schema.add(keyblob::EncryptedKeyBlobV1 {
        characteristics: vec![],
        key_derivation_input: [0u8; 32],
        kek_context: vec![],
        encrypted_key_material: coset::CoseEncrypt0Builder::new()
            .protected(
                coset::HeaderBuilder::new().algorithm(coset::iana::Algorithm::A256GCM).build(),
            )
            .ciphertext(vec![1, 2, 3])
            .build(),
        secure_deletion_slot: Some(keyblob::SecureDeletionSlot(1)),
    });
    schema.add(keymint::KeyCharacteristics {
        security_level: keymint::SecurityLevel::TrustedEnvironment,
        authorizations: vec![],
    });
    // From RFC 8152.
    schema.add_name_schema(
        "Cose_Encrypt0",
        "[ protected: bstr, unprotected: { * (int / tstr) => any }, ciphertext: bstr / nil ]",
    );

    schema.add(crypto::KeyMaterial::Aes(crypto::aes::Key::Aes128([0u8; 16]).into()));
    schema.add(keyblob::SecureDeletionSlot(1));
    schema.add(keyblob::SecureDeletionData {
        factory_reset_secret: [0; 32],
        secure_deletion_secret: [0; 16],
    });
    schema.add(keyblob::RootOfTrustInfo {
        verified_boot_key: vec![0; 32],
        device_boot_locked: false,
        verified_boot_state: keymint::VerifiedBootState::Unverified,
    });
    schema.add(keymint::VerifiedBootState::Unverified);

    schema.add(keymint::SecurityLevel::TrustedEnvironment);
    schema.add(keymint::KeyParam::CreationDatetime(keymint::DateTime {
        ms_since_epoch: 22_593_600_000,
    }));
    schema.add(keymint::Tag::NoAuthRequired);

    schema.add(keymint::Algorithm::Ec);
    schema.add(keymint::BlockMode::Ecb);
    schema.add(keymint::Digest::None);
    schema.add(keymint::EcCurve::Curve25519);
    schema.add(crypto::CurveType::Nist);
    schema.add(keymint::KeyOrigin::Generated);
    schema.add(keymint::KeyPurpose::Sign);
    schema.add(keymint::HardwareAuthenticatorType::Fingerprint);
    schema.add(keymint::PaddingMode::None);

    schema.add(keymint::DateTime { ms_since_epoch: 22_593_600_000 });
    schema.add(kmr_wire::KeySizeInBits(256));
    schema.add(kmr_wire::RsaExponent(65537));

    println!(
   "; encrypted_key_material is AES-GCM encrypted with:\n\
    ; - key derived as described below\n\
    ; - plaintext is the CBOR-serialization of `KeyMaterial`\n\
    ; - nonce value is fixed, all zeroes\n\
    ; - no additional data\n\
    ;\n\
    ; Key derivation uses HKDF (RFC 5869) with HMAC-SHA256 to generate an AES-256 key:\n\
    ; - input keying material = a root key held in hardware\n\
    ; - salt = absent\n\
    ; - info = the following three or four chunks of context data concatenated:\n\
    ;    - content of `EncryptedKeyBlob.key_derivation_input` (a random nonce)\n\
    ;    - CBOR-serialization of `EncryptedKeyBlob.characteristics`\n\
    ;    - CBOR-serialized array of additional hidden `KeyParam` items associated with the key, specifically:\n\
    ;        - [Tag_ApplicationId, bstr] if required\n\
    ;        - [Tag_ApplicationData, bstr] if required\n\
    ;        - [Tag_RootOfTrust, bstr .cbor RootOfTrustInfo]\n\
    ;    - (if secure storage is available) CBOR serialization of the `SecureDeletionData` structure, with:\n\
    ;        - `factory_reset_secret` always populated\n\
    ;        - `secure_deletion_secret` populated with:\n\
    ;           - all zeroes (if `EncryptedKeyBlob.secure_deletion_slot` is empty)\n\
    ;           - the contents of the slot (if `EncryptedKeyBlob.secure_deletion_slot` is non-empty)",
    );
    println!("{}", schema);
    schema.check();
}
