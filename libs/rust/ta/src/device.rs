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

//! Traits representing access to device-specific information and functionality.

use crate::coset::{iana, AsCborValue, CoseSign1Builder, HeaderBuilder};
use kmr_common::{
    crypto, crypto::aes, crypto::hmac, crypto::KeyMaterial, crypto::OpaqueOr, keyblob, log_unimpl,
    unimpl, Error,
};
use kmr_wire::{keymint, rpc, secureclock::TimeStampToken, CborError};
use log::error;

use crate::rkp::serialize_cbor;

/// Context used to derive the hardware backed key for computing HMAC in
/// IRemotelyProvisionedComponent.
pub const RPC_HMAC_KEY_CONTEXT: &[u8] = b"Key to MAC public keys";

/// Length (in bytes) of the HMAC key used in IRemotelyProvisionedComponent.
pub const RPC_HMAC_KEY_LEN: usize = 32;

/// Combined collection of trait implementations that must be provided.
pub struct Implementation {
    /// Retrieval of root key material.
    pub keys: Box<dyn RetrieveKeyMaterial>,

    /// Retrieval of attestation certificate signing information.
    pub sign_info: Option<Box<dyn RetrieveCertSigningInfo>>,

    /// Retrieval of attestation ID information.
    pub attest_ids: Option<Box<dyn RetrieveAttestationIds>>,

    /// Secure deletion secret manager.  If not available, rollback-resistant
    /// keys will not be supported.
    pub sdd_mgr: Option<Box<dyn keyblob::SecureDeletionSecretManager>>,

    /// Retrieval of bootloader status.
    pub bootloader: Box<dyn BootloaderStatus>,

    /// Storage key wrapping. If not available `convertStorageKeyToEphemeral()` will not be
    /// supported
    pub sk_wrapper: Option<Box<dyn StorageKeyWrapper>>,

    /// Trusted user presence indicator.
    pub tup: Box<dyn TrustedUserPresence>,

    /// Legacy key conversion handling.
    pub legacy_key: Option<Box<dyn keyblob::LegacyKeyHandler>>,

    /// Retrieval of artifacts related to the device implementation of IRemotelyProvisionedComponent
    /// (IRPC) HAL.
    pub rpc: Box<dyn RetrieveRpcArtifacts>,
}

/// Functionality related to retrieval of device-specific key material, and its subsequent use.
/// The caller is generally expected to drop the key material as soon as it is done with it.
pub trait RetrieveKeyMaterial {
    /// Retrieve the root key used for derivation of a per-keyblob key encryption key (KEK), passing
    /// in any opaque context.
    fn root_kek(&self, context: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error>;

    /// Retrieve any opaque (but non-confidential) context needed for future calls to `root_kek`.
    /// Context should not include confidential data (it will be stored in the clear).
    fn kek_context(&self) -> Result<Vec<u8>, Error> {
        // Default implementation is to have an empty KEK retrieval context.
        Ok(Vec::new())
    }

    /// Retrieve the key agreement key used for shared secret negotiation.
    fn kak(&self) -> Result<OpaqueOr<aes::Key>, Error>;

    /// Install the device HMAC agreed by shared secret negotiation into hardware (optional).
    fn hmac_key_agreed(&self, _key: &crypto::hmac::Key) -> Option<Box<dyn DeviceHmac>> {
        // By default, use a software implementation that holds the key in memory.
        None
    }

    /// Retrieve the hardware backed secret used for UNIQUE_ID generation.
    fn unique_id_hbk(&self, ckdf: &dyn crypto::Ckdf) -> Result<crypto::hmac::Key, Error> {
        // By default, use CKDF on the key agreement secret to derive a key.
        let unique_id_label = b"UniqueID HBK 32B";
        ckdf.ckdf(&self.kak()?, unique_id_label, &[], 32)
            .map(crypto::hmac::Key::new)
    }

    /// Build the HMAC input for a [`TimeStampToken`].  The default implementation produces
    /// data that matches the `ISecureClock` AIDL specification; this method should only be
    /// overridden for back-compatibility reasons.
    fn timestamp_token_mac_input(&self, token: &TimeStampToken) -> Result<Vec<u8>, Error> {
        crate::clock::timestamp_token_mac_input(token)
    }
}

/// Device HMAC calculation.
pub trait DeviceHmac {
    /// Calculate the HMAC over the data using the agreed device HMAC key.
    fn hmac(&self, imp: &dyn crypto::Hmac, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Returns the key used for HMAC'ing data if available
    fn get_hmac_key(&self) -> Option<crypto::hmac::Key> {
        // By default we assume that the implementation cannot return a key
        None
    }
}

/// Identification of which attestation signing key is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningKey {
    /// Use a batch key that is shared across multiple devices (to prevent the keys being used as
    /// device identifiers).
    Batch,
    /// Use a device-unique key for signing. Only supported for StrongBox.
    DeviceUnique,
}

/// Indication of preferred attestation signing algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningAlgorithm {
    /// Prefer to sign with an elliptic curve key.
    Ec,
    /// Prefer to sign with an RSA key.
    Rsa,
}

/// Indication of required signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SigningKeyType {
    /// Indicates the preferred type of signing key.
    pub which: SigningKey,
    /// Indicates what is going to be signed, to allow implementations to (optionally) use EC / RSA
    /// signing keys for EC / RSA keys respectively.
    pub algo_hint: SigningAlgorithm,
}

/// Retrieval of attestation certificate signing information.  The caller is expected to drop key
/// material after use, but may cache public key material.
pub trait RetrieveCertSigningInfo {
    /// Return the signing key material for the specified `key_type`.  The `algo_hint` parameter
    /// indicates what is going to be signed, to allow implementations to (optionally) use EC / RSA
    /// signing keys for EC /RSA keys respectively.
    fn signing_key(&self, key_type: SigningKeyType) -> Result<KeyMaterial, Error>;

    /// Return the certificate chain associated with the specified signing key, where:
    /// - `chain[0]` holds the public key that corresponds to `signing_key`, and which is signed
    ///   by...
    /// - the keypair described by the second entry `chain[1]`, which in turn is signed by...
    /// - ...
    /// - the final certificate in the chain should be a self-signed cert holding a Google root.
    fn cert_chain(&self, key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error>;
}

/// Retrieval of attestation ID information.  This information will not change (so the caller can
/// cache this information after first invocation).
pub trait RetrieveAttestationIds {
    /// Return the attestation IDs associated with the device, if available.
    fn get(&self) -> Result<crate::AttestationIdInfo, Error>;

    /// Destroy all attestation IDs associated with the device.
    fn destroy_all(&mut self) -> Result<(), Error>;
}

/// Bootloader status.
pub trait BootloaderStatus {
    /// Indication of whether bootloader processing is complete
    fn done(&self) -> bool {
        // By default assume that the bootloader is done before KeyMint starts.
        true
    }
}

/// The trait that represents the device specific integration points required for the
/// implementation of IRemotelyProvisionedComponent (IRPC) HAL.
/// Note: The devices only supporting IRPC V3+ may ignore the optional IRPC V2 specific types in
/// the method signatures.
pub trait RetrieveRpcArtifacts {
    /// Retrieve secret bytes (of the given output length) derived from a hardware backed key.
    /// For a given context, the output is deterministic.
    fn derive_bytes_from_hbk(
        &self,
        hkdf: &dyn crypto::Hkdf,
        context: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, Error>;

    /// Compute HMAC_SHA256 over the given input using a key derived from hardware.
    fn compute_hmac_sha256(
        &self,
        hmac: &dyn crypto::Hmac,
        hkdf: &dyn crypto::Hkdf,
        input: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let secret = self.derive_bytes_from_hbk(hkdf, RPC_HMAC_KEY_CONTEXT, RPC_HMAC_KEY_LEN)?;
        crypto::hmac_sha256(hmac, &secret, input)
    }

    /// Retrieve the information about the DICE chain belonging to the IRPC HAL implementation.
    fn get_dice_info(&self, test_mode: rpc::TestMode) -> Result<DiceInfo, Error>;

    /// Sign the input data with the CDI leaf private key of the IRPC HAL implementation. In IRPC V2,
    /// the `data` to be signed is the `SignedMac_structure` in ProtectedData.aidl, when signing
    /// the ephemeral MAC key used to authenticate the public keys. In IRPC V3, the `data` to be
    /// signed is the `SignedDataSigStruct`.
    /// If a particular implementation would like to return the signature in a COSE_Sign1 message,
    /// they can mark this unimplemented and override the default implementation in the
    /// `sign_data_in_cose_sign1` method below.
    ///
    /// The signature produced by this method should be in a format suitable for COSE structures:
    /// - Ed25519 signatures are encoded as-is.
    /// - NIST signatures are encoded as (r||s), with each value left-padded with zeroes to
    ///   the coordinate length.  Note that this is a *different* format than is emitted by
    ///   the `kmr_common::crypto::Ec` trait.
    ///
    /// (The `kmr_common::crypto::ec::to_cose_signature()` function can help with this.)
    fn sign_data(
        &self,
        ec: &dyn crypto::Ec,
        data: &[u8],
        rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error>;

    /// Sign the payload and return a COSE_Sign1 message. In IRPC V2, the `payload` is the MAC Key.
    /// In IRPC V3, the `payload` is the `Data` that the `SignedData` is parameterized with (i.e. a
    /// CBOR array containing `challenge` and `CsrPayload`).
    fn sign_data_in_cose_sign1(
        &self,
        ec: &dyn crypto::Ec,
        signing_algorithm: &CsrSigningAlgorithm,
        payload: &[u8],
        _aad: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        let cose_sign_algorithm = match signing_algorithm {
            CsrSigningAlgorithm::ES256 => iana::Algorithm::ES256,
            CsrSigningAlgorithm::ES384 => iana::Algorithm::ES384,
            CsrSigningAlgorithm::EdDSA => iana::Algorithm::EdDSA,
        };
        // Construct `SignedData`
        let protected = HeaderBuilder::new().algorithm(cose_sign_algorithm).build();
        let signed_data = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.to_vec())
            .try_create_signature(&[], |input| self.sign_data(ec, input, None))?
            .build();
        let signed_data_cbor = signed_data.to_cbor_value().map_err(CborError::from)?;
        serialize_cbor(&signed_data_cbor)
    }
}

/// Information about the DICE chain belonging to the implementation of the IRPC HAL.
#[derive(Clone)]
pub struct DiceInfo {
    /// Public dice artifacts.
    pub pub_dice_artifacts: PubDiceArtifacts,
    /// Algorithm used for signing CSRs.
    pub signing_algorithm: CsrSigningAlgorithm,
    /// Test-mode CDI private key.
    ///
    /// This is only relevant for IRPC HAL V2 when `test_mode` is true. This is ignored in all other
    /// cases. The optional test CDI private key may be set here, if the device implementers
    /// do not want to cache the test CDI private key across the calls to the `get_dice_info` and
    ///`sign_data` methods when creating the CSR.
    pub rpc_v2_test_cdi_priv: Option<RpcV2TestCDIPriv>,
}

/// Algorithm used to sign with the CDI leaf private key.
#[derive(Clone, Copy, Debug)]
pub enum CsrSigningAlgorithm {
    /// Sign with P-256 EC key.
    ES256,
    /// Sign with P-384 EC key.
    ES384,
    /// Sign with Ed25519 key.
    EdDSA,
}

/// Public DICE artifacts.
#[derive(Clone, Debug)]
pub struct PubDiceArtifacts {
    /// Certificates for the UDS Pub encoded in CBOR as per `AdditionalDKSignatures` structure in
    /// ProtectedData.aidl for IRPC HAL version 2 and as per `UdsCerts` structure in IRPC HAL
    /// version 3.
    pub uds_certs: Vec<u8>,
    /// UDS Pub and the DICE certificates encoded in CBOR/COSE as per the `Bcc` structure
    /// defined in ProtectedData.aidl for IRPC HAL version 2 and as per `DiceCertChain` structure
    /// in IRPC HAL version 3.
    pub dice_cert_chain: Vec<u8>,
}

/// Enum distinguishing the two modes of operation for IRPC HAL V2, allowing an optional context
/// information to be passed in for the test mode.
pub enum RpcV2Req<'a> {
    /// IRPC v2 request in production mode.
    Production,
    /// An opaque blob may be passed in for the test mode, if it was returned by the TA in
    /// `RkpV2TestCDIPriv.context` in order to link the two requests: `get_dice_info` and `sign_data`
    /// related to the same CSR.
    Test(&'a [u8]),
}

/// Struct encapsulating the optional CDI private key and the optional opaque context that may be
/// returned with `DiceInfo` in IRPC V2 test mode.
#[derive(Clone)]
pub struct RpcV2TestCDIPriv {
    /// Test-mode CDI private key, if available.
    pub test_cdi_priv: Option<OpaqueOr<crypto::ec::Key>>,
    /// An optional opaque blob set by the TA, if the TA wants a mechanism to relate the
    /// two requests: `get_dice_info` and `sign_data` related to the same CSR.
    pub context: Vec<u8>,
}

/// Marker implementation for implementations that do not support `BOOTLOADER_ONLY` keys, which
/// always indicates that bootloader processing is complete.
pub struct BootloaderDone;
impl BootloaderStatus for BootloaderDone {}

/// Trusted user presence indicator.
pub trait TrustedUserPresence {
    /// Indication of whether user presence is detected, via a mechanism in the current secure
    /// environment.
    fn available(&self) -> bool {
        // By default assume that trusted user presence is not supported.
        false
    }
}

/// Marker implementation to indicate that trusted user presence is not supported.
pub struct TrustedPresenceUnsupported;
impl TrustedUserPresence for TrustedPresenceUnsupported {}

/// Storage key wrapping.
pub trait StorageKeyWrapper {
    /// Wrap the provided key material using an ephemeral storage key.
    fn ephemeral_wrap(&self, key_material: &KeyMaterial) -> Result<Vec<u8>, Error>;
}

// No-op implementations for the non-optional device traits. These implementations are only
// intended for convenience during the process of porting the KeyMint code to a new environment.

/// Stub implementation of [`RetrieveKeyMaterial`].
pub struct NoOpRetrieveKeyMaterial;
impl RetrieveKeyMaterial for NoOpRetrieveKeyMaterial {
    fn root_kek(&self, _context: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error> {
        unimpl!();
    }

    fn kak(&self) -> Result<OpaqueOr<aes::Key>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`RetrieveCertSigningInfo`].
pub struct NoOpRetrieveCertSigningInfo;
impl RetrieveCertSigningInfo for NoOpRetrieveCertSigningInfo {
    fn signing_key(&self, _key_type: SigningKeyType) -> Result<KeyMaterial, Error> {
        unimpl!();
    }

    fn cert_chain(&self, _key_type: SigningKeyType) -> Result<Vec<keymint::Certificate>, Error> {
        unimpl!();
    }
}

/// Stub implementation of [`RetrieveRpcArtifacts`].
pub struct NoOpRetrieveRpcArtifacts;
impl RetrieveRpcArtifacts for NoOpRetrieveRpcArtifacts {
    fn derive_bytes_from_hbk(
        &self,
        _hkdf: &dyn crypto::Hkdf,
        _context: &[u8],
        _output_len: usize,
    ) -> Result<Vec<u8>, Error> {
        unimpl!();
    }

    fn get_dice_info<'a>(&self, _test_mode: rpc::TestMode) -> Result<DiceInfo, Error> {
        unimpl!();
    }

    fn sign_data(
        &self,
        _ec: &dyn crypto::Ec,
        _data: &[u8],
        _rpc_v2: Option<RpcV2Req>,
    ) -> Result<Vec<u8>, Error> {
        unimpl!();
    }
}
