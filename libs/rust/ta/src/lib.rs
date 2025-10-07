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

//! KeyMint trusted application (TA) implementation.

use core::cmp::Ordering;
use core::mem::size_of;
use core::{cell::RefCell, convert::TryFrom};
use device::DiceInfo;
use kmr_common::{
    crypto::{self, hmac, OpaqueOr},
    get_bool_tag_value,
    keyblob::{self, RootOfTrustInfo, SecureDeletionSlot},
    km_err, tag, try_to_vec, vec_try, vec_try_with_capacity, Error, FallibleAllocExt,
};
use kmr_wire::{
    coset::TaggedCborSerializable,
    keymint::{
        Digest, ErrorCode, HardwareAuthToken, KeyCharacteristics, KeyMintHardwareInfo, KeyOrigin,
        KeyParam, SecurityLevel, Tag, VerifiedBootState, NEXT_MESSAGE_SIGNAL_FALSE,
        NEXT_MESSAGE_SIGNAL_TRUE,
    },
    rpc,
    rpc::{EekCurve, IRPC_V2, IRPC_V3},
    sharedsecret::SharedSecretParameters,
    *,
};
use log::{debug, error, info, trace, warn};
use std::collections::BTreeMap;
use std::rc::Rc;

mod cert;
mod clock;
pub mod device;
pub mod keys;
mod operation;
pub mod rkp;
mod secret;

use keys::KeyImport;
use operation::{OpHandle, Operation};

#[cfg(test)]
mod tests;

/// Possible KeyMint HAL versions
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMintHalVersion {
    /// V4 adds support for attestation of module information.
    V4 = 400,
    /// V3 adds support for attestation of second IMEI value.
    V3 = 300,
    /// V2 adds support for curve 25519 and root-of-trust transfer.
    V2 = 200,
    /// V1 is the initial version of the KeyMint HAL.
    V1 = 100,
}

/// Version code for current KeyMint.
pub const KEYMINT_CURRENT_VERSION: KeyMintHalVersion = KeyMintHalVersion::V4;

/// Maximum number of parallel operations supported when running as TEE.
const MAX_TEE_OPERATIONS: usize = 16;

/// Maximum number of parallel operations supported when running as StrongBox.
const MAX_STRONGBOX_OPERATIONS: usize = 4;

/// Maximum number of keys whose use count can be tracked.
const MAX_USE_COUNTED_KEYS: usize = 32;

/// Tags allowed in `KeyMintTa::additional_attestation_info`.
const ALLOWED_ADDITIONAL_ATTESTATION_TAGS: &[Tag] = &[Tag::ModuleHash];

/// Per-key ID use count.
struct UseCount {
    key_id: KeyId,
    count: u64,
}

/// Attestation chain information.
struct AttestationChainInfo {
    /// Chain of certificates from intermediate to root.
    chain: Vec<keymint::Certificate>,
    /// Subject field from the first certificate in the chain, as an ASN.1 DER encoded `Name` (cf
    /// RFC 5280 s4.1.2.4).
    issuer: Vec<u8>,
}

/// KeyMint device implementation, running in secure environment.
pub struct KeyMintTa {
    /**
     * State that is fixed on construction.
     */

    /// Trait objects that hold this device's implementations of the abstract cryptographic
    /// functionality traits.
    imp: crypto::Implementation,

    /// Trait objects that hold this device's implementations of per-device functionality.
    dev: device::Implementation,

    /// Information about this particular KeyMint implementation's hardware.
    hw_info: HardwareInfo,

    /// Information about the implementation of the IRemotelyProvisionedComponent (IRPC) HAL.
    rpc_info: RpcInfo,

    /// The version of the HAL AIDL interface specification that this TA acts as.
    aidl_version: KeyMintHalVersion,

    /**
     * State that is set after the TA starts, but latched thereafter.
     */

    /// Parameters for shared secret negotiation.
    shared_secret_params: Option<SharedSecretParameters>,

    /// Information provided by the bootloader once at start of day.
    boot_info: Option<keymint::BootInfo>,
    rot_data: Option<Vec<u8>>,

    /// Information provided by the HAL service once at start of day.
    hal_info: Option<HalInfo>,

    /// Additional information to attest to, provided by Android. Refer to
    /// `IKeyMintDevice::setAdditionalAttestationInfo()`.
    additional_attestation_info: Vec<KeyParam>,

    /// Attestation chain information, retrieved on first use.
    attestation_chain_info: RefCell<BTreeMap<device::SigningKeyType, AttestationChainInfo>>,

    /// Attestation ID information, fixed forever for a device, but retrieved on first use.
    attestation_id_info: RefCell<Option<Rc<AttestationIdInfo>>>,

    /// Public DICE artifacts (UDS certs and the DICE chain) included in the certificate signing
    /// requests (CSR) and the algorithm used to sign the CSR for IRemotelyProvisionedComponent
    /// (IRPC) HAL. Fixed for a device. Retrieved on first use.
    ///
    /// Note: This information is cached only in the implementations of IRPC HAL V3 and
    /// IRPC HAL V2 in production mode.
    dice_info: RefCell<Option<Rc<DiceInfo>>>,

    /// Whether the device is still in early-boot.
    in_early_boot: bool,

    /// Device HMAC implementation which uses the `ISharedSecret` negotiated key.
    device_hmac: Option<Box<dyn device::DeviceHmac>>,

    /**
     * State that changes during operation.
     */

    /// Challenge for root-of-trust transfer (StrongBox only).
    rot_challenge: [u8; 16],

    /// The operation table.
    operations: Vec<Option<Operation>>,

    /// Use counts for keys where this is tracked.
    use_count: [Option<UseCount>; MAX_USE_COUNTED_KEYS],

    /// Operation handle of the (single) in-flight operation that requires trusted user presence.
    presence_required_op: Option<OpHandle>,
}

/// A helper method that can be used by the TA for processing the responses to be sent to the
/// HAL service. Splits large response messages into multiple parts based on the capacity of the
/// channel from the TA to the HAL. One element in the returned response array consists of:
/// <next_msg_signal + response data> where next_msg_signal is a byte whose value is 1 if there are
/// more messages in the response array following this one. This signal should be used by the HAL
/// side to decide whether or not to wait for more messages. Implementation of this method must be
/// in sync with its counterpart in the `kmr-hal` crate.
pub fn split_rsp(mut rsp_data: &[u8], max_size: usize) -> Result<Vec<Vec<u8>>, Error> {
    if rsp_data.is_empty() || max_size < 2 {
        return Err(km_err!(
            InvalidArgument,
            "response data is empty or max size: {} is invalid",
            max_size
        ));
    }
    // Need to allocate one byte for the more_msg_signal.
    let allowed_msg_length = max_size - 1;
    let mut num_of_splits = rsp_data.len() / allowed_msg_length;
    if rsp_data.len() % allowed_msg_length > 0 {
        num_of_splits += 1;
    }
    let mut split_rsp = vec_try_with_capacity!(num_of_splits)?;
    while rsp_data.len() > allowed_msg_length {
        let mut rsp = vec_try_with_capacity!(allowed_msg_length + 1)?;
        rsp.push(NEXT_MESSAGE_SIGNAL_TRUE);
        rsp.extend_from_slice(&rsp_data[..allowed_msg_length]);
        trace!("Current response size with signalling byte: {}", rsp.len());
        split_rsp.push(rsp);
        rsp_data = &rsp_data[allowed_msg_length..];
    }
    let mut last_rsp = vec_try_with_capacity!(rsp_data.len() + 1)?;
    last_rsp.push(NEXT_MESSAGE_SIGNAL_FALSE);
    last_rsp.extend_from_slice(rsp_data);
    split_rsp.push(last_rsp);
    Ok(split_rsp)
}

/// Hardware information.
#[derive(Clone, Debug)]
pub struct HardwareInfo {
    // Fields that correspond to the HAL `KeyMintHardwareInfo` type.
    /// Security level that this KeyMint implementation is running at.
    pub security_level: SecurityLevel,
    /// Version number.
    pub version_number: i32,
    /// KeyMint implementation name.
    pub impl_name: &'static str,
    /// Author of KeyMint implementation.
    pub author_name: &'static str,
    /// Unique identifier for this KeyMint.
    pub unique_id: &'static str,
    // The `timestamp_token_required` field in `KeyMintHardwareInfo` is skipped here because it gets
    // set depending on whether a local clock is available.
}

/// Information required to construct the structures defined in RpcHardwareInfo.aidl
/// and DeviceInfo.aidl, for IRemotelyProvisionedComponent (IRPC) HAL V2.
#[derive(Debug)]
pub struct RpcInfoV2 {
    // Fields used in `RpcHardwareInfo.aidl`:
    /// Author of KeyMint implementation.
    pub author_name: &'static str,
    /// EEK curve supported by this implementation.
    pub supported_eek_curve: EekCurve,
    /// Unique identifier for this KeyMint.
    pub unique_id: &'static str,
    /// Indication of whether secure boot is enforced for the processor running this code.
    /// Used as `DeviceInfo.fused`.
    pub fused: bool,
}

/// Information required to construct the structures defined in RpcHardwareInfo.aidl
/// and DeviceInfo.aidl, for IRemotelyProvisionedComponent (IRPC) HAL V3.
#[derive(Debug)]
pub struct RpcInfoV3 {
    // Fields used in `RpcHardwareInfo.aidl`:
    /// Author of KeyMint implementation.
    pub author_name: &'static str,
    /// Unique identifier for this KeyMint.
    pub unique_id: &'static str,
    /// Indication of whether secure boot is enforced for the processor running this code.
    /// Used as `DeviceInfo.fused`.
    pub fused: bool,
    /// Supported number of keys in a CSR.
    pub supported_num_of_keys_in_csr: i32,
}

/// Enum to distinguish the set of information required for different versions of IRPC HAL
/// implementations
#[derive(Debug)]
pub enum RpcInfo {
    /// Information for v2 of the IRPC HAL.
    V2(RpcInfoV2),
    /// Information for v3 of the IRPC HAL.
    V3(RpcInfoV3),
}

impl RpcInfo {
    /// Indicate the HAL version of RPC information.
    pub fn get_version(&self) -> i32 {
        match self {
            RpcInfo::V2(_) => IRPC_V2,
            RpcInfo::V3(_) => IRPC_V3,
        }
    }
}

/// Information provided once at service start by the HAL service, describing
/// the state of the userspace operating system (which may change from boot to
/// boot, e.g. for running GSI).
#[derive(Clone, Copy, Debug)]
pub struct HalInfo {
    /// OS version.
    pub os_version: u32,
    /// OS patchlevel, in YYYYMM format.
    pub os_patchlevel: u32,
    /// Vendor patchlevel, in YYYYMMDD format
    pub vendor_patchlevel: u32,
}

/// Identifier for a keyblob.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct KeyId([u8; 32]);

impl KeyMintTa {
    /// Create a new [`KeyMintTa`] instance.
    pub fn new(
        hw_info: HardwareInfo,
        rpc_info: RpcInfo,
        imp: crypto::Implementation,
        dev: device::Implementation,
    ) -> Self {
        let max_operations = if hw_info.security_level == SecurityLevel::Strongbox {
            MAX_STRONGBOX_OPERATIONS
        } else {
            MAX_TEE_OPERATIONS
        };
        Self {
            imp,
            dev,
            in_early_boot: true,
            device_hmac: None,
            rot_challenge: [0; 16],
            // Work around Rust limitation that `vec![None; n]` doesn't work.
            operations: (0..max_operations).map(|_| None).collect(),
            use_count: Default::default(),
            presence_required_op: None,
            shared_secret_params: None,
            hw_info,
            rpc_info,
            aidl_version: KEYMINT_CURRENT_VERSION,
            boot_info: None,
            rot_data: None,
            hal_info: None,
            attestation_chain_info: RefCell::new(BTreeMap::new()),
            attestation_id_info: RefCell::new(None),
            dice_info: RefCell::new(None),
            additional_attestation_info: Vec::new(),
        }
    }

    /// Returns key used to sign auth tokens
    pub fn get_hmac_key(&self) -> Option<hmac::Key> {
        match &self.device_hmac {
            Some(device_hmac) => device_hmac.get_hmac_key(),
            None => None,
        }
    }

    /// Indicate whether the current device is acting as a StrongBox instance.
    pub fn is_strongbox(&self) -> bool {
        self.hw_info.security_level == SecurityLevel::Strongbox
    }

    /// Indicate whether the current device has secure storage available.
    fn secure_storage_available(&self) -> kmr_common::tag::SecureStorage {
        if self.dev.sdd_mgr.is_some() {
            kmr_common::tag::SecureStorage::Available
        } else {
            kmr_common::tag::SecureStorage::Unavailable
        }
    }

    /// Return the device's boot information.
    fn boot_info(&self) -> Result<&keymint::BootInfo, Error> {
        self.boot_info
            .as_ref()
            .ok_or_else(|| km_err!(HardwareNotYetAvailable, "no boot info available"))
    }

    /// Return a copy of the device's boot information, with the verified boot key
    /// hashed (if necessary).
    fn boot_info_hashed_key(&self) -> Result<keymint::BootInfo, Error> {
        let mut boot_info = self.boot_info()?.clone();
        if boot_info.verified_boot_key.len() > 32 {
            // It looks like we have the actual key, not a hash thereof.  Change that.
            boot_info.verified_boot_key =
                try_to_vec(&self.imp.sha256.hash(&boot_info.verified_boot_key)?)?;
        }
        Ok(boot_info)
    }

    /// Parse and decrypt an encrypted key blob, allowing through keys that require upgrade due to
    /// patchlevel updates.  Keys that appear to be in a legacy format may still emit a
    /// [`ErrorCode::KeyRequiresUpgrade`] error.
    fn keyblob_parse_decrypt_backlevel(
        &self,
        key_blob: &[u8],
        params: &[KeyParam],
    ) -> Result<(keyblob::PlaintextKeyBlob, Option<SecureDeletionSlot>), Error> {
        let encrypted_keyblob = match keyblob::EncryptedKeyBlob::new(key_blob) {
            Ok(k) => k,
            Err(e) => {
                // We might have failed to parse the keyblob because it is in some prior format.
                if let Some(old_key) = self.dev.legacy_key.as_ref() {
                    if old_key.is_legacy_key(key_blob, params, self.boot_info()?) {
                        return Err(km_err!(
                            KeyRequiresUpgrade,
                            "legacy key detected, request upgrade"
                        ));
                    }
                }
                return Err(e);
            }
        };
        let hidden = tag::hidden(params, self.root_of_trust()?)?;
        let sdd_slot = encrypted_keyblob.secure_deletion_slot();
        let root_kek = self.root_kek(encrypted_keyblob.kek_context())?;
        let keyblob = keyblob::decrypt(
            match &self.dev.sdd_mgr {
                None => None,
                Some(mr) => Some(&**mr),
            },
            &*self.imp.aes,
            &*self.imp.hkdf,
            &root_kek,
            encrypted_keyblob,
            hidden,
        )?;
        Ok((keyblob, sdd_slot))
    }

    /// Parse and decrypt an encrypted key blob, detecting keys that require upgrade.
    fn keyblob_parse_decrypt(
        &self,
        key_blob: &[u8],
        params: &[KeyParam],
    ) -> Result<(keyblob::PlaintextKeyBlob, Option<SecureDeletionSlot>), Error> {
        let (keyblob, slot) = self.keyblob_parse_decrypt_backlevel(key_blob, params)?;

        // Check all of the patchlevels and versions to see if key upgrade is required.
        fn check(v: &u32, curr: u32, name: &str) -> Result<(), Error> {
            match (*v).cmp(&curr) {
                Ordering::Less => Err(km_err!(
                    KeyRequiresUpgrade,
                    "keyblob with old {} {} needs upgrade to current {}",
                    name,
                    v,
                    curr
                )),
                Ordering::Equal => Ok(()),
                Ordering::Greater => Err(km_err!(
                    InvalidKeyBlob,
                    "keyblob with future {} {} (current {})",
                    name,
                    v,
                    curr
                )),
            }
        }

        let key_chars = keyblob.characteristics_at(self.hw_info.security_level)?;
        for param in key_chars {
            match param {
                KeyParam::OsVersion(v) => {
                    if let Some(hal_info) = &self.hal_info {
                        if hal_info.os_version == 0 {
                            // Special case: upgrades to OS version zero are always allowed.
                            if *v != 0 {
                                warn!("requesting upgrade to OS version 0");
                                return Err(km_err!(
                                    KeyRequiresUpgrade,
                                    "keyblob with OS version {} needs upgrade to current version 0",
                                    v,
                                ));
                            }
                        } else {
                            check(v, hal_info.os_version, "OS version")?;
                        }
                    } else {
                        error!(
                            "OS version not available, can't check for upgrade from {}",
                            v
                        );
                    }
                }
                KeyParam::OsPatchlevel(v) => {
                    if let Some(hal_info) = &self.hal_info {
                        check(v, hal_info.os_patchlevel, "OS patchlevel")?;
                    } else {
                        error!(
                            "OS patchlevel not available, can't check for upgrade from {}",
                            v
                        );
                    }
                }
                KeyParam::VendorPatchlevel(v) => {
                    if let Some(hal_info) = &self.hal_info {
                        check(v, hal_info.vendor_patchlevel, "vendor patchlevel")?;
                    } else {
                        error!(
                            "vendor patchlevel not available, can't check for upgrade from {}",
                            v
                        );
                    }
                }
                KeyParam::BootPatchlevel(v) => {
                    if let Some(boot_info) = &self.boot_info {
                        check(v, boot_info.boot_patchlevel, "boot patchlevel")?;
                    } else {
                        error!(
                            "boot patchlevel not available, can't check for upgrade from {}",
                            v
                        );
                    }
                }
                _ => {}
            }
        }
        Ok((keyblob, slot))
    }

    /// Generate a unique identifier for a keyblob.
    fn key_id(&self, keyblob: &[u8]) -> Result<KeyId, Error> {
        let mut hmac_op = self
            .imp
            .hmac
            .begin(crypto::hmac::Key(vec_try![0; 16]?).into(), Digest::Sha256)?;
        hmac_op.update(keyblob)?;
        let tag = hmac_op.finish()?;

        Ok(KeyId(tag.try_into().map_err(|_e| {
            km_err!(
                SecureHwCommunicationFailed,
                "wrong size output from HMAC-SHA256"
            )
        })?))
    }

    /// Increment the use count for the given key ID, failing if `max_uses` is reached.
    fn update_use_count(&mut self, key_id: KeyId, max_uses: u32) -> Result<(), Error> {
        let mut free_idx = None;
        let mut slot_idx = None;
        for idx in 0..self.use_count.len() {
            match &self.use_count[idx] {
                None if free_idx.is_none() => free_idx = Some(idx),
                None => {}
                Some(UseCount {
                    key_id: k,
                    count: _count,
                }) if *k == key_id => {
                    slot_idx = Some(idx);
                    break;
                }
                Some(_) => {}
            }
        }
        if slot_idx.is_none() {
            // First use of this key ID; use a free slot if available.
            if let Some(idx) = free_idx {
                self.use_count[idx] = Some(UseCount { key_id, count: 0 });
                slot_idx = Some(idx);
            }
        }

        if let Some(idx) = slot_idx {
            let c = self.use_count[idx].as_mut().unwrap(); // safe: code above guarantees
            if c.count >= max_uses as u64 {
                Err(km_err!(
                    KeyMaxOpsExceeded,
                    "use count {} >= limit {}",
                    c.count,
                    max_uses
                ))
            } else {
                c.count += 1;
                Ok(())
            }
        } else {
            Err(km_err!(
                TooManyOperations,
                "too many use-counted keys already in play"
            ))
        }
    }

    /// Configure the boot-specific root of trust info.  KeyMint implementors should call this
    /// method when this information arrives from the bootloader (which happens in an
    /// implementation-specific manner).
    pub fn set_boot_info(&mut self, boot_info: keymint::BootInfo) -> Result<(), Error> {
        if !self.in_early_boot {
            error!(
                "Rejecting attempt to set boot info {:?} after early boot",
                boot_info
            );
            return Err(km_err!(
                EarlyBootEnded,
                "attempt to set boot info to {boot_info:?} after early boot"
            ));
        }
        if let Some(existing_boot_info) = &self.boot_info {
            if *existing_boot_info == boot_info {
                warn!(
                    "Boot info already set, ignoring second attempt to set same values {:?}",
                    boot_info
                );
            } else {
                return Err(km_err!(
                    RootOfTrustAlreadySet,
                    "attempt to set boot info to {:?} but already set to {:?}",
                    boot_info,
                    existing_boot_info
                ));
            }
        } else {
            info!("Setting boot_info to {:?}", boot_info);
            let rot_info = RootOfTrustInfo {
                verified_boot_key: boot_info.verified_boot_key.clone(),
                device_boot_locked: boot_info.device_boot_locked,
                verified_boot_state: boot_info.verified_boot_state,
            };
            self.boot_info = Some(boot_info);
            self.rot_data =
                Some(rot_info.into_vec().map_err(|e| {
                    km_err!(EncodingError, "failed to encode root-of-trust: {:?}", e)
                })?);
        }
        Ok(())
    }

    /// Check if HAL-derived information has been set. This is used as an
    /// indication that we are past the boot stage.
    pub fn is_hal_info_set(&self) -> bool {
        self.hal_info.is_some()
    }

    /// Configure the HAL-derived information, learnt from the userspace
    /// operating system.
    pub fn set_hal_info(&mut self, hal_info: HalInfo) {
        if self.hal_info.is_none() {
            info!("Setting hal_info to {:?}", hal_info);
            self.hal_info = Some(hal_info);
        } else {
            warn!(
                "Hal info already set to {:?}, ignoring new values {:?}",
                self.hal_info, hal_info
            );
        }
    }

    /// Configure the version of the HAL that this TA should act as.
    pub fn set_hal_version(&mut self, aidl_version: u32) -> Result<(), Error> {
        let aidl_version = match aidl_version {
            100 => KeyMintHalVersion::V1,
            200 => KeyMintHalVersion::V2,
            300 => KeyMintHalVersion::V3,
            400 => KeyMintHalVersion::V4,
            _ => {
                return Err(km_err!(
                    InvalidArgument,
                    "unsupported HAL version {}",
                    aidl_version
                ))
            }
        };
        if aidl_version == self.aidl_version {
            debug!("Set aidl_version to existing version {aidl_version:?}");
        } else if cfg!(feature = "downgrade") {
            info!(
                "Change aidl_version from {:?} to {:?}",
                self.aidl_version, aidl_version
            );
            self.aidl_version = aidl_version;
        } else {
            // Only allow HAL-triggered downgrade if the "downgrade" feature is enabled.
            warn!(
                "Ignoring request to change aidl_version from {:?} to {:?}",
                self.aidl_version, aidl_version
            );
        }
        Ok(())
    }

    /// Configure attestation IDs externally.
    pub fn set_attestation_ids(&self, ids: AttestationIdInfo) {
        if self.dev.attest_ids.is_some() {
            error!("Attempt to set attestation IDs externally");
        } else if self.attestation_id_info.borrow().is_some() {
            error!("Attempt to set attestation IDs when already set");
        } else {
            warn!("Setting attestation IDs directly");
            *self.attestation_id_info.borrow_mut() = Some(Rc::new(ids));
        }
    }

    /// Retrieve the attestation ID information for the device, if available.
    fn get_attestation_ids(&self) -> Option<Rc<AttestationIdInfo>> {
        if self.attestation_id_info.borrow().is_none() {
            if let Some(get_ids_impl) = self.dev.attest_ids.as_ref() {
                // Attestation IDs are not populated, but we have a trait implementation that
                // may provide them.
                match get_ids_impl.get() {
                    Ok(ids) => *self.attestation_id_info.borrow_mut() = Some(Rc::new(ids)),
                    Err(e) => error!("Failed to retrieve attestation IDs: {:?}", e),
                }
            }
        }
        self.attestation_id_info.borrow().as_ref().cloned()
    }

    /// Retrieve the DICE info for the device, if available.
    fn get_dice_info(&self) -> Option<Rc<DiceInfo>> {
        if self.dice_info.borrow().is_none() {
            // DICE info is not populated, but we have a trait method that
            // may provide them.
            match self.dev.rpc.get_dice_info(rpc::TestMode(false)) {
                Ok(dice_info) => *self.dice_info.borrow_mut() = Some(Rc::new(dice_info)),
                Err(e) => error!("Failed to retrieve DICE info: {:?}", e),
            }
        }
        self.dice_info.borrow().as_ref().cloned()
    }

    /// Process a single serialized request, returning a serialized response.
    pub fn process(&mut self, req_data: &[u8]) -> Vec<u8> {
        let (req_code, rsp) = match PerformOpReq::from_slice(req_data) {
            Ok(req) => {
                trace!("-> TA: received request {:?}", req.code());
                (Some(req.code()), self.process_req(req))
            }
            Err(e) => {
                error!("failed to decode CBOR request: {:?}", e);
                // We need to report the error to the HAL, but we don't know whether the request was
                // for the `IRemotelyProvisionedComponent` or for one of the other HALs, so we don't
                // know what numbering space the error codes are expected to be in.  Assume the
                // shared KeyMint `ErrorCode` space.
                (None, error_rsp(ErrorCode::EncodingError as i32))
            }
        };
        trace!("<- TA: send response {:?} rc {}", req_code, rsp.error_code);
        match rsp.into_vec() {
            Ok(rsp_data) => rsp_data,
            Err(e) => {
                error!("failed to encode CBOR response: {:?}", e);
                invalid_cbor_rsp_data().to_vec()
            }
        }
    }

    /// Process a single request, returning a [`PerformOpResponse`].
    ///
    /// Select the appropriate method based on the request type, and use the
    /// request fields as parameters to the method.  In the opposite direction,
    /// build a response message from the values returned by the method.
    pub fn process_req(&mut self, req: PerformOpReq) -> PerformOpResponse {
        match req {
            // Internal messages.
            PerformOpReq::SetBootInfo(req) => {
                let verified_boot_state = match VerifiedBootState::try_from(req.verified_boot_state)
                {
                    Ok(state) => state,
                    Err(e) => return op_error_rsp(SetBootInfoRequest::CODE, Error::Cbor(e)),
                };
                match self.set_boot_info(keymint::BootInfo {
                    verified_boot_key: req.verified_boot_key,
                    device_boot_locked: req.device_boot_locked,
                    verified_boot_state,
                    verified_boot_hash: req.verified_boot_hash,
                    boot_patchlevel: req.boot_patchlevel,
                }) {
                    Ok(_) => op_ok_rsp(PerformOpRsp::SetBootInfo(SetBootInfoResponse {})),
                    Err(e) => op_error_rsp(SetBootInfoRequest::CODE, e),
                }
            }
            PerformOpReq::SetHalInfo(req) => {
                self.set_hal_info(HalInfo {
                    os_version: req.os_version,
                    os_patchlevel: req.os_patchlevel,
                    vendor_patchlevel: req.vendor_patchlevel,
                });
                op_ok_rsp(PerformOpRsp::SetHalInfo(SetHalInfoResponse {}))
            }
            PerformOpReq::SetAttestationIds(req) => {
                self.set_attestation_ids(req.ids);
                op_ok_rsp(PerformOpRsp::SetAttestationIds(
                    SetAttestationIdsResponse {},
                ))
            }
            PerformOpReq::SetHalVersion(req) => match self.set_hal_version(req.aidl_version) {
                Ok(_) => op_ok_rsp(PerformOpRsp::SetHalVersion(SetHalVersionResponse {})),
                Err(e) => op_error_rsp(SetHalVersionRequest::CODE, e),
            },

            // ISharedSecret messages.
            PerformOpReq::SharedSecretGetSharedSecretParameters(_req) => {
                match self.get_shared_secret_params() {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::SharedSecretGetSharedSecretParameters(
                        GetSharedSecretParametersResponse { ret },
                    )),
                    Err(e) => op_error_rsp(GetSharedSecretParametersRequest::CODE, e),
                }
            }
            PerformOpReq::SharedSecretComputeSharedSecret(req) => {
                match self.compute_shared_secret(&req.params) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::SharedSecretComputeSharedSecret(
                        ComputeSharedSecretResponse { ret },
                    )),
                    Err(e) => op_error_rsp(ComputeSharedSecretRequest::CODE, e),
                }
            }

            // ISecureClock messages.
            PerformOpReq::SecureClockGenerateTimeStamp(req) => {
                match self.generate_timestamp(req.challenge) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::SecureClockGenerateTimeStamp(
                        GenerateTimeStampResponse { ret },
                    )),
                    Err(e) => op_error_rsp(GenerateTimeStampRequest::CODE, e),
                }
            }

            // IKeyMintDevice messages.
            PerformOpReq::DeviceGetHardwareInfo(_req) => match self.get_hardware_info() {
                Ok(ret) => op_ok_rsp(PerformOpRsp::DeviceGetHardwareInfo(
                    GetHardwareInfoResponse { ret },
                )),
                Err(e) => op_error_rsp(GetHardwareInfoRequest::CODE, e),
            },
            PerformOpReq::DeviceAddRngEntropy(req) => match self.add_rng_entropy(&req.data) {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::DeviceAddRngEntropy(AddRngEntropyResponse {})),
                Err(e) => op_error_rsp(AddRngEntropyRequest::CODE, e),
            },
            PerformOpReq::DeviceGenerateKey(req) => {
                match self.generate_key(&req.key_params, req.attestation_key) {
                    Ok(ret) => {
                        op_ok_rsp(PerformOpRsp::DeviceGenerateKey(GenerateKeyResponse { ret }))
                    }
                    Err(e) => op_error_rsp(GenerateKeyRequest::CODE, e),
                }
            }
            PerformOpReq::DeviceImportKey(req) => {
                match self.import_key(
                    &req.key_params,
                    req.key_format,
                    &req.key_data,
                    req.attestation_key,
                    KeyImport::NonWrapped,
                ) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::DeviceImportKey(ImportKeyResponse { ret })),
                    Err(e) => op_error_rsp(ImportKeyRequest::CODE, e),
                }
            }
            PerformOpReq::DeviceImportWrappedKey(req) => {
                match self.import_wrapped_key(
                    &req.wrapped_key_data,
                    &req.wrapping_key_blob,
                    &req.masking_key,
                    &req.unwrapping_params,
                    req.password_sid,
                    req.biometric_sid,
                ) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::DeviceImportWrappedKey(
                        ImportWrappedKeyResponse { ret },
                    )),
                    Err(e) => op_error_rsp(ImportWrappedKeyRequest::CODE, e),
                }
            }
            PerformOpReq::DeviceUpgradeKey(req) => {
                match self.upgrade_key(&req.key_blob_to_upgrade, req.upgrade_params) {
                    Ok(ret) => {
                        op_ok_rsp(PerformOpRsp::DeviceUpgradeKey(UpgradeKeyResponse { ret }))
                    }
                    Err(e) => op_error_rsp(UpgradeKeyRequest::CODE, e),
                }
            }
            PerformOpReq::DeviceDeleteKey(req) => match self.delete_key(&req.key_blob) {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::DeviceDeleteKey(DeleteKeyResponse {})),
                Err(e) => op_error_rsp(DeleteKeyRequest::CODE, e),
            },
            PerformOpReq::DeviceDeleteAllKeys(_req) => match self.delete_all_keys() {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::DeviceDeleteAllKeys(DeleteAllKeysResponse {})),
                Err(e) => op_error_rsp(DeleteAllKeysRequest::CODE, e),
            },
            PerformOpReq::DeviceDestroyAttestationIds(_req) => match self.destroy_attestation_ids()
            {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::DeviceDestroyAttestationIds(
                    DestroyAttestationIdsResponse {},
                )),
                Err(e) => op_error_rsp(DestroyAttestationIdsRequest::CODE, e),
            },
            PerformOpReq::DeviceBegin(req) => {
                match self.begin_operation(req.purpose, &req.key_blob, req.params, req.auth_token) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::DeviceBegin(BeginResponse { ret })),
                    Err(e) => op_error_rsp(BeginRequest::CODE, e),
                }
            }
            PerformOpReq::DeviceEarlyBootEnded(_req) => match self.early_boot_ended() {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::DeviceEarlyBootEnded(
                    EarlyBootEndedResponse {},
                )),
                Err(e) => op_error_rsp(EarlyBootEndedRequest::CODE, e),
            },
            PerformOpReq::DeviceConvertStorageKeyToEphemeral(req) => {
                match self.convert_storage_key_to_ephemeral(&req.storage_key_blob) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::DeviceConvertStorageKeyToEphemeral(
                        ConvertStorageKeyToEphemeralResponse { ret },
                    )),
                    Err(e) => op_error_rsp(ConvertStorageKeyToEphemeralRequest::CODE, e),
                }
            }
            PerformOpReq::DeviceGetKeyCharacteristics(req) => {
                match self.get_key_characteristics(&req.key_blob, req.app_id, req.app_data) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::DeviceGetKeyCharacteristics(
                        GetKeyCharacteristicsResponse { ret },
                    )),
                    Err(e) => op_error_rsp(GetKeyCharacteristicsRequest::CODE, e),
                }
            }
            PerformOpReq::GetRootOfTrustChallenge(_req) => match self.get_root_of_trust_challenge()
            {
                Ok(ret) => op_ok_rsp(PerformOpRsp::GetRootOfTrustChallenge(
                    GetRootOfTrustChallengeResponse { ret },
                )),
                Err(e) => op_error_rsp(GetRootOfTrustChallengeRequest::CODE, e),
            },
            PerformOpReq::GetRootOfTrust(req) => match self.get_root_of_trust(&req.challenge) {
                Ok(ret) => op_ok_rsp(PerformOpRsp::GetRootOfTrust(GetRootOfTrustResponse { ret })),
                Err(e) => op_error_rsp(GetRootOfTrustRequest::CODE, e),
            },
            PerformOpReq::SendRootOfTrust(req) => {
                match self.send_root_of_trust(&req.root_of_trust) {
                    Ok(_ret) => {
                        op_ok_rsp(PerformOpRsp::SendRootOfTrust(SendRootOfTrustResponse {}))
                    }
                    Err(e) => op_error_rsp(SendRootOfTrustRequest::CODE, e),
                }
            }
            PerformOpReq::SetAdditionalAttestationInfo(req) => {
                match self.set_additional_attestation_info(req.info) {
                    Ok(_ret) => op_ok_rsp(PerformOpRsp::SetAdditionalAttestationInfo(
                        SetAdditionalAttestationInfoResponse {},
                    )),
                    Err(e) => op_error_rsp(SetAdditionalAttestationInfoRequest::CODE, e),
                }
            }

            // IKeyMintOperation messages.
            PerformOpReq::OperationUpdateAad(req) => match self.op_update_aad(
                OpHandle(req.op_handle),
                &req.input,
                req.auth_token,
                req.timestamp_token,
            ) {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::OperationUpdateAad(UpdateAadResponse {})),
                Err(e) => op_error_rsp(UpdateAadRequest::CODE, e),
            },
            PerformOpReq::OperationUpdate(req) => {
                match self.op_update(
                    OpHandle(req.op_handle),
                    &req.input,
                    req.auth_token,
                    req.timestamp_token,
                ) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::OperationUpdate(UpdateResponse { ret })),
                    Err(e) => op_error_rsp(UpdateRequest::CODE, e),
                }
            }
            PerformOpReq::OperationFinish(req) => {
                match self.op_finish(
                    OpHandle(req.op_handle),
                    req.input.as_deref(),
                    req.signature.as_deref(),
                    req.auth_token,
                    req.timestamp_token,
                    req.confirmation_token.as_deref(),
                ) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::OperationFinish(FinishResponse { ret })),
                    Err(e) => op_error_rsp(FinishRequest::CODE, e),
                }
            }
            PerformOpReq::OperationAbort(req) => match self.op_abort(OpHandle(req.op_handle)) {
                Ok(_ret) => op_ok_rsp(PerformOpRsp::OperationAbort(AbortResponse {})),
                Err(e) => op_error_rsp(AbortRequest::CODE, e),
            },

            // IRemotelyProvisionedComponentOperation messages.
            PerformOpReq::RpcGetHardwareInfo(_req) => match self.get_rpc_hardware_info() {
                Ok(ret) => op_ok_rsp(PerformOpRsp::RpcGetHardwareInfo(
                    GetRpcHardwareInfoResponse { ret },
                )),
                Err(e) => op_error_rsp(GetRpcHardwareInfoRequest::CODE, e),
            },
            PerformOpReq::RpcGenerateEcdsaP256KeyPair(req) => {
                match self.generate_ecdsa_p256_keypair(rpc::TestMode(req.test_mode)) {
                    Ok((pubkey, ret)) => op_ok_rsp(PerformOpRsp::RpcGenerateEcdsaP256KeyPair(
                        GenerateEcdsaP256KeyPairResponse {
                            maced_public_key: pubkey,
                            ret,
                        },
                    )),
                    Err(e) => op_error_rsp(GenerateEcdsaP256KeyPairRequest::CODE, e),
                }
            }
            PerformOpReq::RpcGenerateCertificateRequest(req) => {
                match self.generate_cert_req(
                    rpc::TestMode(req.test_mode),
                    req.keys_to_sign,
                    &req.endpoint_encryption_cert_chain,
                    &req.challenge,
                ) {
                    Ok((device_info, protected_data, ret)) => {
                        op_ok_rsp(PerformOpRsp::RpcGenerateCertificateRequest(
                            GenerateCertificateRequestResponse {
                                device_info,
                                protected_data,
                                ret,
                            },
                        ))
                    }
                    Err(e) => op_error_rsp(GenerateCertificateRequestRequest::CODE, e),
                }
            }
            PerformOpReq::RpcGenerateCertificateV2Request(req) => {
                match self.generate_cert_req_v2(req.keys_to_sign, &req.challenge) {
                    Ok(ret) => op_ok_rsp(PerformOpRsp::RpcGenerateCertificateV2Request(
                        GenerateCertificateRequestV2Response { ret },
                    )),
                    Err(e) => op_error_rsp(GenerateCertificateRequestV2Request::CODE, e),
                }
            }
        }
    }

    fn add_rng_entropy(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > 2048 {
            return Err(km_err!(
                InvalidInputLength,
                "entropy size {} too large",
                data.len()
            ));
        };

        info!("add {} bytes of entropy", data.len());
        self.imp.rng.add_entropy(data);
        Ok(())
    }

    fn early_boot_ended(&mut self) -> Result<(), Error> {
        info!("early boot ended");
        self.in_early_boot = false;
        Ok(())
    }

    pub fn get_hardware_info(&self) -> Result<KeyMintHardwareInfo, Error> {
        Ok(KeyMintHardwareInfo {
            version_number: self.hw_info.version_number,
            security_level: self.hw_info.security_level,
            key_mint_name: self.hw_info.impl_name.to_string(),
            key_mint_author_name: self.hw_info.author_name.to_string(),
            timestamp_token_required: self.imp.clock.is_none(),
        })
    }

    fn delete_key(&mut self, keyblob: &[u8]) -> Result<(), Error> {
        // Parse the keyblob. It cannot be decrypted, because hidden parameters are not available
        // (there is no `params` for them to arrive in).
        if let Ok(keyblob::EncryptedKeyBlob::V1(encrypted_keyblob)) =
            keyblob::EncryptedKeyBlob::new(keyblob)
        {
            // We have to trust that any secure deletion slot in the keyblob is valid, because the
            // key can't be decrypted.
            if let (Some(sdd_mgr), Some(slot)) = (
                &mut self.dev.sdd_mgr,
                encrypted_keyblob.secure_deletion_slot,
            ) {
                if let Err(e) = sdd_mgr.delete_secret(slot) {
                    error!("failed to delete secure deletion slot: {:?}", e);
                }
            }
        } else {
            // We might have failed to parse the keyblob because it is in some prior format.
            if let Some(old_key) = self.dev.legacy_key.as_mut() {
                if let Err(e) = old_key.delete_legacy_key(keyblob) {
                    error!("failed to parse keyblob as legacy : {:?}, ignoring", e);
                }
            } else {
                error!("failed to parse keyblob, ignoring");
            }
        }

        Ok(())
    }

    fn delete_all_keys(&mut self) -> Result<(), Error> {
        if let Some(sdd_mgr) = &mut self.dev.sdd_mgr {
            error!("secure deleting all keys -- device likely to need factory reset!");
            sdd_mgr.delete_all();
        }
        Ok(())
    }

    fn destroy_attestation_ids(&mut self) -> Result<(), Error> {
        match self.dev.attest_ids.as_mut() {
            Some(attest_ids) => {
                // Drop any cached copies too.
                *self.attestation_id_info.borrow_mut() = None;
                error!("destroying all device attestation IDs!");
                attest_ids.destroy_all()
            }
            None => {
                error!("destroying device attestation IDs requested but not supported");
                Err(km_err!(
                    Unimplemented,
                    "no attestation ID functionality available"
                ))
            }
        }
    }

    fn get_root_of_trust_challenge(&mut self) -> Result<[u8; 16], Error> {
        if !self.is_strongbox() {
            return Err(km_err!(
                Unimplemented,
                "root-of-trust challenge only for StrongBox"
            ));
        }
        self.imp.rng.fill_bytes(&mut self.rot_challenge[..]);
        Ok(self.rot_challenge)
    }

    fn get_root_of_trust(&mut self, challenge: &[u8]) -> Result<Vec<u8>, Error> {
        if self.is_strongbox() {
            return Err(km_err!(
                Unimplemented,
                "root-of-trust retrieval not for StrongBox"
            ));
        }
        let payload = self
            .boot_info_hashed_key()?
            .to_tagged_vec()
            .map_err(|_e| km_err!(EncodingError, "Failed to CBOR-encode RootOfTrust"))?;

        let mac0 = coset::CoseMac0Builder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(coset::iana::Algorithm::HMAC_256_256)
                    .build(),
            )
            .payload(payload)
            .try_create_tag(challenge, |data| self.device_hmac(data))?
            .build();
        mac0.to_tagged_vec()
            .map_err(|_e| km_err!(EncodingError, "Failed to CBOR-encode RootOfTrust"))
    }

    fn send_root_of_trust(&mut self, root_of_trust: &[u8]) -> Result<(), Error> {
        if !self.is_strongbox() {
            return Err(km_err!(
                Unimplemented,
                "root-of-trust delivery only for StrongBox"
            ));
        }
        let mac0 = coset::CoseMac0::from_tagged_slice(root_of_trust)
            .map_err(|_e| km_err!(InvalidArgument, "Failed to CBOR-decode CoseMac0"))?;
        mac0.verify_tag(&self.rot_challenge, |tag, data| {
            match self.verify_device_hmac(data, tag) {
                Ok(true) => Ok(()),
                Ok(false) => Err(km_err!(
                    VerificationFailed,
                    "HMAC verification of RootOfTrust failed"
                )),
                Err(e) => Err(e),
            }
        })?;
        let payload = mac0
            .payload
            .ok_or_else(|| km_err!(InvalidArgument, "Missing payload in CoseMac0"))?;
        let boot_info = keymint::BootInfo::from_tagged_slice(&payload)
            .map_err(|_e| km_err!(InvalidArgument, "Failed to CBOR-decode RootOfTrust"))?;
        if self.boot_info.is_none() {
            info!("Setting boot_info to TEE-provided {:?}", boot_info);
            self.boot_info = Some(boot_info);
        } else {
            info!(
                "Ignoring TEE-provided RootOfTrust {:?} as already set",
                boot_info
            );
        }
        Ok(())
    }

    fn set_additional_attestation_info(&mut self, info: Vec<KeyParam>) -> Result<(), Error> {
        for param in info {
            let tag = param.tag();
            if !ALLOWED_ADDITIONAL_ATTESTATION_TAGS.contains(&tag) {
                warn!("ignoring non-allowlisted tag: {tag:?}");
                continue;
            }
            match self
                .additional_attestation_info
                .iter()
                .find(|&x| x.tag() == tag)
            {
                Some(value) if value == &param => {
                    warn!(
                        concat!(
                            "additional attestation info for: {:?} already set, ignoring repeated",
                            " attempt to set same info"
                        ),
                        param
                    );
                    continue;
                }
                Some(value) => {
                    return Err(set_additional_attestation_info_err(
                        tag,
                        format!(
                            concat!(
                            "attempt to set additional attestation info for: {:?}, but that tag",
                            " already has a different value set: {:?}"
                        ),
                            param, value
                        ),
                    ));
                }
                None => {
                    self.additional_attestation_info.push(param.clone());
                }
            }
        }
        Ok(())
    }

    fn convert_storage_key_to_ephemeral(&self, keyblob: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(sk_wrapper) = &self.dev.sk_wrapper {
            // Parse and decrypt the keyblob. Note that there is no way to provide extra hidden
            // params on the API.
            let (keyblob, _) = self.keyblob_parse_decrypt(keyblob, &[])?;

            // Check that the keyblob is indeed a storage key.
            let chars = keyblob.characteristics_at(self.hw_info.security_level)?;
            if !get_bool_tag_value!(chars, StorageKey)? {
                return Err(km_err!(
                    InvalidArgument,
                    "attempting to convert non-storage key"
                ));
            }

            // Now that we've got the key material, use a device-specific method to re-wrap it
            // with an ephemeral key.
            sk_wrapper.ephemeral_wrap(&keyblob.key_material)
        } else {
            Err(km_err!(Unimplemented, "storage key wrapping unavailable"))
        }
    }

    fn get_key_characteristics(
        &self,
        key_blob: &[u8],
        app_id: Vec<u8>,
        app_data: Vec<u8>,
    ) -> Result<Vec<KeyCharacteristics>, Error> {
        // Parse and decrypt the keyblob, which requires extra hidden params.
        let mut params = vec_try_with_capacity!(2)?;
        if !app_id.is_empty() {
            params.push(KeyParam::ApplicationId(app_id)); // capacity enough
        }
        if !app_data.is_empty() {
            params.push(KeyParam::ApplicationData(app_data)); // capacity enough
        }
        let (keyblob, _) = self.keyblob_parse_decrypt(key_blob, &params)?;
        Ok(keyblob.characteristics)
    }

    /// Generate an HMAC-SHA256 value over the data using the device's HMAC key (if available).
    fn device_hmac(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.device_hmac {
            Some(traitobj) => traitobj.hmac(&*self.imp.hmac, data),
            None => {
                error!("HMAC requested but no key available!");
                Err(km_err!(HardwareNotYetAvailable, "HMAC key not agreed"))
            }
        }
    }

    /// Verify an HMAC-SHA256 value over the data using the device's HMAC key (if available).
    fn verify_device_hmac(&self, data: &[u8], mac: &[u8]) -> Result<bool, Error> {
        let remac = self.device_hmac(data)?;
        Ok(self.imp.compare.eq(mac, &remac))
    }

    /// Return the root of trust that is bound into keyblobs.
    fn root_of_trust(&self) -> Result<&[u8], Error> {
        match &self.rot_data {
            Some(data) => Ok(data),
            None => Err(km_err!(
                HardwareNotYetAvailable,
                "No root-of-trust info available"
            )),
        }
    }

    /// Return the root key used for key encryption.
    fn root_kek(&self, context: &[u8]) -> Result<OpaqueOr<hmac::Key>, Error> {
        self.dev.keys.root_kek(context)
    }

    /// Add KeyMint-generated tags to the provided [`KeyCharacteristics`].
    fn add_keymint_tags(
        &self,
        chars: &mut Vec<KeyCharacteristics>,
        origin: KeyOrigin,
    ) -> Result<(), Error> {
        for kc in chars {
            if kc.security_level == self.hw_info.security_level {
                kc.authorizations.try_push(KeyParam::Origin(origin))?;
                if let Some(hal_info) = &self.hal_info {
                    kc.authorizations.try_extend_from_slice(&[
                        KeyParam::OsVersion(hal_info.os_version),
                        KeyParam::OsPatchlevel(hal_info.os_patchlevel),
                        KeyParam::VendorPatchlevel(hal_info.vendor_patchlevel),
                    ])?;
                }
                if let Some(boot_info) = &self.boot_info {
                    kc.authorizations
                        .try_push(KeyParam::BootPatchlevel(boot_info.boot_patchlevel))?;
                }
                return Ok(());
            }
        }
        Err(km_err!(
            InvalidArgument,
            "no characteristics at our security level {:?}",
            self.hw_info.security_level
        ))
    }
}

/// Create an OK response structure with the given inner response message.
fn op_ok_rsp(rsp: PerformOpRsp) -> PerformOpResponse {
    // Zero is OK in any context.
    PerformOpResponse {
        error_code: 0,
        rsp: Some(rsp),
    }
}

/// Create a response structure with the given error code.
fn error_rsp(error_code: i32) -> PerformOpResponse {
    PerformOpResponse {
        error_code,
        rsp: None,
    }
}

/// Create a response structure with the given error.
fn op_error_rsp(op: KeyMintOperation, err: Error) -> PerformOpResponse {
    warn!("failing {:?} request with error {:?}", op, err);
    if kmr_wire::is_rpc_operation(op) {
        // The IRemotelyProvisionedComponent HAL uses a different error space than the
        // other HALs.
        let rpc_err: rpc::ErrorCode = match err {
            Error::Cbor(_) | Error::Der(_) | Error::Alloc(_) => rpc::ErrorCode::Failed,
            Error::Hal(_, _) => {
                error!("encountered non-RKP error on RKP method! {:?}", err);
                rpc::ErrorCode::Failed
            }
            Error::Rpc(e, _) => e,
        };
        error_rsp(rpc_err as i32)
    } else {
        let hal_err = match err {
            Error::Cbor(_) | Error::Der(_) => ErrorCode::InvalidArgument,
            Error::Hal(e, _) => e,
            Error::Rpc(_, _) => {
                error!("encountered RKP error on non-RKP method! {:?}", err);
                ErrorCode::InvalidArgument
            }
            Error::Alloc(_) => ErrorCode::MemoryAllocationFailed,
        };
        error_rsp(hal_err as i32)
    }
}

/// Create an Error for [`KeyMintTa::set_additional_attestation_info`] failure that corresponds to
/// the specified tag.
fn set_additional_attestation_info_err(tag: Tag, err_msg: String) -> Error {
    match tag {
        Tag::ModuleHash => km_err!(ModuleHashAlreadySet, "{}", err_msg),
        _ => km_err!(InvalidTag, "unexpected tag: {tag:?}"),
    }
}

/// Hand-encoded [`PerformOpResponse`] data for [`ErrorCode::UNKNOWN_ERROR`].
/// Does not perform CBOR serialization (and so is suitable for error reporting if/when
/// CBOR serialization fails).
fn invalid_cbor_rsp_data() -> [u8; 5] {
    [
        0x82, // 2-arr
        0x39, // nint, len 2
        0x03, // 0x3e7(999)
        0xe7, // = -1000
        0x80, // 0-arr
    ]
}

/// Build the HMAC input for a [`HardwareAuthToken`]
pub fn hardware_auth_token_mac_input(token: &HardwareAuthToken) -> Result<Vec<u8>, Error> {
    let mut result = vec_try_with_capacity!(
        size_of::<u8>() + // version=0 (BE)
        size_of::<i64>() + // challenge (Host)
        size_of::<i64>() + // user_id (Host)
        size_of::<i64>() + // authenticator_id (Host)
        size_of::<i32>() + // authenticator_type (BE)
        size_of::<i64>() // timestamp (BE)
    )?;
    result.extend_from_slice(&0u8.to_be_bytes()[..]);
    result.extend_from_slice(&token.challenge.to_ne_bytes()[..]);
    result.extend_from_slice(&token.user_id.to_ne_bytes()[..]);
    result.extend_from_slice(&token.authenticator_id.to_ne_bytes()[..]);
    result.extend_from_slice(&(token.authenticator_type as i32).to_be_bytes()[..]);
    result.extend_from_slice(&token.timestamp.milliseconds.to_be_bytes()[..]);
    Ok(result)
}
