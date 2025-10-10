// Copyright 2021, The Android Open Source Project
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

//! This is the metrics store module of keystore. It does the following tasks:
//! 1. Processes the data about keystore events asynchronously, and
//!    stores them in an in-memory store.
//! 2. Returns the collected metrics when requested by the statsd proxy.

use crate::keymaster::error::anyhow_error_to_serialized_error;
use crate::global::DB;
use crate::keymaster::key_parameter::KeyParameterValue as KsKeyParamValue;
use crate::err;
use crate::keymaster::operation::Outcome;
use crate::watchdog as wd;
use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel,
};
use crate::android::security::metrics::{
    Algorithm::Algorithm as MetricsAlgorithm, AtomID::AtomID, CrashStats::CrashStats,
    EcCurve::EcCurve as MetricsEcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType as MetricsHardwareAuthenticatorType,
    KeyCreationWithAuthInfo::KeyCreationWithAuthInfo,
    KeyCreationWithGeneralInfo::KeyCreationWithGeneralInfo,
    KeyCreationWithPurposeAndModesInfo::KeyCreationWithPurposeAndModesInfo,
    KeyOperationWithGeneralInfo::KeyOperationWithGeneralInfo,
    KeyOperationWithPurposeAndModesInfo::KeyOperationWithPurposeAndModesInfo,
    KeyOrigin::KeyOrigin as MetricsKeyOrigin, Keystore2AtomWithOverflow::Keystore2AtomWithOverflow,
    KeystoreAtom::KeystoreAtom, KeystoreAtomPayload::KeystoreAtomPayload,
    Outcome::Outcome as MetricsOutcome, Purpose::Purpose as MetricsPurpose,
    RkpError::RkpError as MetricsRkpError, RkpErrorStats::RkpErrorStats,
    SecurityLevel::SecurityLevel as MetricsSecurityLevel, Storage::Storage as MetricsStorage,
};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

// Note: Crash events are recorded at keystore restarts, based on the assumption that keystore only
// gets restarted after a crash, during a boot cycle.
const KEYSTORE_CRASH_COUNT_PROPERTY: &str = "keystore.omk.crash_count";

/// Singleton for MetricsStore.
pub static METRICS_STORE: LazyLock<MetricsStore> = LazyLock::new(Default::default);

/// MetricsStore stores the <atom object, count> as <key, value> in the inner hash map,
/// indexed by the atom id, in the outer hash map.
/// There can be different atom objects with the same atom id based on the values assigned to the
/// fields of the atom objects. When an atom object with a particular combination of field values is
/// inserted, we first check if that atom object is in the inner hash map. If one exists, count
/// is inceremented. Otherwise, the atom object is inserted with count = 1. Note that count field
/// of the atom object itself is set to 0 while the object is stored in the hash map. When the atom
/// objects are queried by the atom id, the corresponding atom objects are retrieved, cloned, and
/// the count field of the cloned objects is set to the corresponding value field in the inner hash
/// map before the query result is returned.
#[derive(Default)]
pub struct MetricsStore {
    metrics_store: Mutex<HashMap<AtomID, HashMap<KeystoreAtomPayload, i32>>>,
}

impl std::fmt::Debug for MetricsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let store = self.metrics_store.lock().unwrap();
        let mut atom_ids: Vec<&AtomID> = store.keys().collect();
        atom_ids.sort();
        for atom_id in atom_ids {
            writeln!(f, "  {} : [", atom_id.show())?;
            let data = store.get(atom_id).unwrap();
            let mut payloads: Vec<&KeystoreAtomPayload> = data.keys().collect();
            payloads.sort();
            for payload in payloads {
                let count = data.get(payload).unwrap();
                writeln!(f, "    {} => count={count}", payload.show())?;
            }
            writeln!(f, "  ]")?;
        }
        Ok(())
    }
}

impl MetricsStore {
    /// There are some atoms whose maximum cardinality exceeds the cardinality limits tolerated
    /// by statsd. Statsd tolerates cardinality between 200-300. Therefore, the in-memory storage
    /// limit for a single atom is set to 250. If the number of atom objects created for a
    /// particular atom exceeds this limit, an overflow atom object is created to track the ID of
    /// such atoms.
    const SINGLE_ATOM_STORE_MAX_SIZE: usize = 250;

    /// Return a vector of atom objects with the given atom ID, if one exists in the metrics_store.
    /// If any atom object does not exist in the metrics_store for the given atom ID, return an
    /// empty vector.
    pub fn get_atoms(&self, atom_id: AtomID) -> Result<Vec<KeystoreAtom>> {
        // StorageStats is an original pulled atom (i.e. not a pushed atom converted to a
        // pulled atom). Therefore, it is handled separately.
        if AtomID::STORAGE_STATS == atom_id {
            let _wp = wd::watch("MetricsStore::get_atoms calling pull_storage_stats");
            return pull_storage_stats();
        }

        // Process keystore crash stats.
        if AtomID::CRASH_STATS == atom_id {
            let _wp = wd::watch("MetricsStore::get_atoms calling read_keystore_crash_count");
            return match read_keystore_crash_count()? {
                Some(count) => Ok(vec![KeystoreAtom {
                    payload: KeystoreAtomPayload::CrashStats(CrashStats {
                        count_of_crash_events: count,
                    }),
                    ..Default::default()
                }]),
                None => Err(anyhow!("Crash count property is not set")),
            };
        }

        let metrics_store_guard = self.metrics_store.lock().unwrap();
        metrics_store_guard.get(&atom_id).map_or(Ok(Vec::<KeystoreAtom>::new()), |atom_count_map| {
            Ok(atom_count_map
                .iter()
                .map(|(atom, count)| KeystoreAtom { payload: atom.clone(), count: *count })
                .collect())
        })
    }

    /// Insert an atom object to the metrics_store indexed by the atom ID.
    fn insert_atom(&self, atom_id: AtomID, atom: KeystoreAtomPayload) {
        let mut metrics_store_guard = self.metrics_store.lock().unwrap();
        let atom_count_map = metrics_store_guard.entry(atom_id).or_default();
        if atom_count_map.len() < MetricsStore::SINGLE_ATOM_STORE_MAX_SIZE {
            let atom_count = atom_count_map.entry(atom).or_insert(0);
            *atom_count += 1;
        } else {
            // Insert an overflow atom
            let overflow_atom_count_map =
                metrics_store_guard.entry(AtomID::KEYSTORE2_ATOM_WITH_OVERFLOW).or_default();

            if overflow_atom_count_map.len() < MetricsStore::SINGLE_ATOM_STORE_MAX_SIZE {
                let overflow_atom = Keystore2AtomWithOverflow { atom_id };
                let atom_count = overflow_atom_count_map
                    .entry(KeystoreAtomPayload::Keystore2AtomWithOverflow(overflow_atom))
                    .or_insert(0);
                *atom_count += 1;
            } else {
                // This is a rare case, if at all.
                log::error!("In insert_atom: Maximum storage limit reached for overflow atom.")
            }
        }
    }
}

/// Log key creation events to be sent to statsd.
pub fn log_key_creation_event_stats<U>(
    sec_level: SecurityLevel,
    key_params: &[KeyParameter],
    result: &Result<U>,
) {
    let (
        key_creation_with_general_info,
        key_creation_with_auth_info,
        key_creation_with_purpose_and_modes_info,
    ) = process_key_creation_event_stats(sec_level, key_params, result);

    METRICS_STORE
        .insert_atom(AtomID::KEY_CREATION_WITH_GENERAL_INFO, key_creation_with_general_info);
    METRICS_STORE.insert_atom(AtomID::KEY_CREATION_WITH_AUTH_INFO, key_creation_with_auth_info);
    METRICS_STORE.insert_atom(
        AtomID::KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO,
        key_creation_with_purpose_and_modes_info,
    );
}

// Process the statistics related to key creations and return the three atom objects related to key
// creations: i) KeyCreationWithGeneralInfo ii) KeyCreationWithAuthInfo
// iii) KeyCreationWithPurposeAndModesInfo
fn process_key_creation_event_stats<U>(
    sec_level: SecurityLevel,
    key_params: &[KeyParameter],
    result: &Result<U>,
) -> (KeystoreAtomPayload, KeystoreAtomPayload, KeystoreAtomPayload) {
    // In the default atom objects, fields represented by bitmaps and i32 fields
    // will take 0, except error_code which defaults to 1 indicating NO_ERROR and key_size,
    // and auth_time_out which defaults to -1.
    // The boolean fields are set to false by default.
    // Some keymint enums do have 0 as an enum variant value. In such cases, the corresponding
    // enum variant value in atoms.proto is incremented by 1, in order to have 0 as the reserved
    // value for unspecified fields.
    let mut key_creation_with_general_info = KeyCreationWithGeneralInfo {
        algorithm: MetricsAlgorithm::ALGORITHM_UNSPECIFIED,
        key_size: -1,
        ec_curve: MetricsEcCurve::EC_CURVE_UNSPECIFIED,
        key_origin: MetricsKeyOrigin::ORIGIN_UNSPECIFIED,
        error_code: 1,
        // Default for bool is false (for attestation_requested field).
        ..Default::default()
    };

    let mut key_creation_with_auth_info = KeyCreationWithAuthInfo {
        user_auth_type: MetricsHardwareAuthenticatorType::AUTH_TYPE_UNSPECIFIED,
        log10_auth_key_timeout_seconds: -1,
        security_level: MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
    };

    let mut key_creation_with_purpose_and_modes_info = KeyCreationWithPurposeAndModesInfo {
        algorithm: MetricsAlgorithm::ALGORITHM_UNSPECIFIED,
        // Default for i32 is 0 (for the remaining bitmap fields).
        ..Default::default()
    };

    if let Err(ref e) = result {
        key_creation_with_general_info.error_code = anyhow_error_to_serialized_error(e).0;
    }

    key_creation_with_auth_info.security_level = process_security_level(sec_level);

    for key_param in key_params.iter().map(KsKeyParamValue::from) {
        match key_param {
            KsKeyParamValue::Algorithm(a) => {
                let algorithm = match a {
                    Algorithm::RSA => MetricsAlgorithm::RSA,
                    Algorithm::EC => MetricsAlgorithm::EC,
                    Algorithm::AES => MetricsAlgorithm::AES,
                    Algorithm::TRIPLE_DES => MetricsAlgorithm::TRIPLE_DES,
                    Algorithm::HMAC => MetricsAlgorithm::HMAC,
                    _ => MetricsAlgorithm::ALGORITHM_UNSPECIFIED,
                };
                key_creation_with_general_info.algorithm = algorithm;
                key_creation_with_purpose_and_modes_info.algorithm = algorithm;
            }
            KsKeyParamValue::KeySize(s) => {
                key_creation_with_general_info.key_size = s;
            }
            KsKeyParamValue::KeyOrigin(o) => {
                key_creation_with_general_info.key_origin = match o {
                    KeyOrigin::GENERATED => MetricsKeyOrigin::GENERATED,
                    KeyOrigin::DERIVED => MetricsKeyOrigin::DERIVED,
                    KeyOrigin::IMPORTED => MetricsKeyOrigin::IMPORTED,
                    KeyOrigin::RESERVED => MetricsKeyOrigin::RESERVED,
                    KeyOrigin::SECURELY_IMPORTED => MetricsKeyOrigin::SECURELY_IMPORTED,
                    _ => MetricsKeyOrigin::ORIGIN_UNSPECIFIED,
                }
            }
            KsKeyParamValue::HardwareAuthenticatorType(a) => {
                key_creation_with_auth_info.user_auth_type = match a {
                    HardwareAuthenticatorType::NONE => MetricsHardwareAuthenticatorType::NONE,
                    HardwareAuthenticatorType::PASSWORD => {
                        MetricsHardwareAuthenticatorType::PASSWORD
                    }
                    HardwareAuthenticatorType::FINGERPRINT => {
                        MetricsHardwareAuthenticatorType::FINGERPRINT
                    }
                    HardwareAuthenticatorType::ANY => MetricsHardwareAuthenticatorType::ANY,
                    _ => MetricsHardwareAuthenticatorType::AUTH_TYPE_UNSPECIFIED,
                }
            }
            KsKeyParamValue::AuthTimeout(t) => {
                key_creation_with_auth_info.log10_auth_key_timeout_seconds =
                    f32::log10(t as f32) as i32;
            }
            KsKeyParamValue::PaddingMode(p) => {
                compute_padding_mode_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.padding_mode_bitmap,
                    p,
                );
            }
            KsKeyParamValue::Digest(d) => {
                // key_creation_with_purpose_and_modes_info.digest_bitmap =
                compute_digest_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.digest_bitmap,
                    d,
                );
            }
            KsKeyParamValue::BlockMode(b) => {
                compute_block_mode_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.block_mode_bitmap,
                    b,
                );
            }
            KsKeyParamValue::KeyPurpose(k) => {
                compute_purpose_bitmap(
                    &mut key_creation_with_purpose_and_modes_info.purpose_bitmap,
                    k,
                );
            }
            KsKeyParamValue::EcCurve(e) => {
                key_creation_with_general_info.ec_curve = match e {
                    EcCurve::P_224 => MetricsEcCurve::P_224,
                    EcCurve::P_256 => MetricsEcCurve::P_256,
                    EcCurve::P_384 => MetricsEcCurve::P_384,
                    EcCurve::P_521 => MetricsEcCurve::P_521,
                    EcCurve::CURVE_25519 => MetricsEcCurve::CURVE_25519,
                    _ => MetricsEcCurve::EC_CURVE_UNSPECIFIED,
                }
            }
            KsKeyParamValue::AttestationChallenge(_) => {
                key_creation_with_general_info.attestation_requested = true;
            }
            _ => {}
        }
    }
    if key_creation_with_general_info.algorithm == MetricsAlgorithm::EC {
        // Do not record key sizes if Algorithm = EC, in order to reduce cardinality.
        key_creation_with_general_info.key_size = -1;
    }

    (
        KeystoreAtomPayload::KeyCreationWithGeneralInfo(key_creation_with_general_info),
        KeystoreAtomPayload::KeyCreationWithAuthInfo(key_creation_with_auth_info),
        KeystoreAtomPayload::KeyCreationWithPurposeAndModesInfo(
            key_creation_with_purpose_and_modes_info,
        ),
    )
}

/// Log key operation events to be sent to statsd.
pub fn log_key_operation_event_stats(
    sec_level: SecurityLevel,
    key_purpose: KeyPurpose,
    op_params: &[KeyParameter],
    op_outcome: &Outcome,
    key_upgraded: bool,
) {
    let (key_operation_with_general_info, key_operation_with_purpose_and_modes_info) =
        process_key_operation_event_stats(
            sec_level,
            key_purpose,
            op_params,
            op_outcome,
            key_upgraded,
        );
    METRICS_STORE
        .insert_atom(AtomID::KEY_OPERATION_WITH_GENERAL_INFO, key_operation_with_general_info);
    METRICS_STORE.insert_atom(
        AtomID::KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO,
        key_operation_with_purpose_and_modes_info,
    );
}

// Process the statistics related to key operations and return the two atom objects related to key
// operations: i) KeyOperationWithGeneralInfo ii) KeyOperationWithPurposeAndModesInfo
fn process_key_operation_event_stats(
    sec_level: SecurityLevel,
    key_purpose: KeyPurpose,
    op_params: &[KeyParameter],
    op_outcome: &Outcome,
    key_upgraded: bool,
) -> (KeystoreAtomPayload, KeystoreAtomPayload) {
    let mut key_operation_with_general_info = KeyOperationWithGeneralInfo {
        outcome: MetricsOutcome::OUTCOME_UNSPECIFIED,
        error_code: 1,
        security_level: MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
        // Default for bool is false (for key_upgraded field).
        ..Default::default()
    };

    let mut key_operation_with_purpose_and_modes_info = KeyOperationWithPurposeAndModesInfo {
        purpose: MetricsPurpose::KEY_PURPOSE_UNSPECIFIED,
        // Default for i32 is 0 (for the remaining bitmap fields).
        ..Default::default()
    };

    key_operation_with_general_info.security_level = process_security_level(sec_level);

    key_operation_with_general_info.key_upgraded = key_upgraded;

    key_operation_with_purpose_and_modes_info.purpose = match key_purpose {
        KeyPurpose::ENCRYPT => MetricsPurpose::ENCRYPT,
        KeyPurpose::DECRYPT => MetricsPurpose::DECRYPT,
        KeyPurpose::SIGN => MetricsPurpose::SIGN,
        KeyPurpose::VERIFY => MetricsPurpose::VERIFY,
        KeyPurpose::WRAP_KEY => MetricsPurpose::WRAP_KEY,
        KeyPurpose::AGREE_KEY => MetricsPurpose::AGREE_KEY,
        KeyPurpose::ATTEST_KEY => MetricsPurpose::ATTEST_KEY,
        _ => MetricsPurpose::KEY_PURPOSE_UNSPECIFIED,
    };

    key_operation_with_general_info.outcome = match op_outcome {
        Outcome::Unknown | Outcome::Dropped => MetricsOutcome::DROPPED,
        Outcome::Success => MetricsOutcome::SUCCESS,
        Outcome::Abort => MetricsOutcome::ABORT,
        Outcome::Pruned => MetricsOutcome::PRUNED,
        Outcome::ErrorCode(e) => {
            key_operation_with_general_info.error_code = e.0;
            MetricsOutcome::ERROR
        }
    };

    for key_param in op_params.iter().map(KsKeyParamValue::from) {
        match key_param {
            KsKeyParamValue::PaddingMode(p) => {
                compute_padding_mode_bitmap(
                    &mut key_operation_with_purpose_and_modes_info.padding_mode_bitmap,
                    p,
                );
            }
            KsKeyParamValue::Digest(d) => {
                compute_digest_bitmap(
                    &mut key_operation_with_purpose_and_modes_info.digest_bitmap,
                    d,
                );
            }
            KsKeyParamValue::BlockMode(b) => {
                compute_block_mode_bitmap(
                    &mut key_operation_with_purpose_and_modes_info.block_mode_bitmap,
                    b,
                );
            }
            _ => {}
        }
    }

    (
        KeystoreAtomPayload::KeyOperationWithGeneralInfo(key_operation_with_general_info),
        KeystoreAtomPayload::KeyOperationWithPurposeAndModesInfo(
            key_operation_with_purpose_and_modes_info,
        ),
    )
}

fn process_security_level(sec_level: SecurityLevel) -> MetricsSecurityLevel {
    match sec_level {
        SecurityLevel::SOFTWARE => MetricsSecurityLevel::SECURITY_LEVEL_SOFTWARE,
        SecurityLevel::TRUSTED_ENVIRONMENT => {
            MetricsSecurityLevel::SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        }
        SecurityLevel::STRONGBOX => MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX,
        SecurityLevel::KEYSTORE => MetricsSecurityLevel::SECURITY_LEVEL_KEYSTORE,
        _ => MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
    }
}

fn compute_padding_mode_bitmap(padding_mode_bitmap: &mut i32, padding_mode: PaddingMode) {
    match padding_mode {
        PaddingMode::NONE => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::NONE_BIT_POSITION as i32;
        }
        PaddingMode::RSA_OAEP => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::RSA_OAEP_BIT_POS as i32;
        }
        PaddingMode::RSA_PSS => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::RSA_PSS_BIT_POS as i32;
        }
        PaddingMode::RSA_PKCS1_1_5_ENCRYPT => {
            *padding_mode_bitmap |=
                1 << PaddingModeBitPosition::RSA_PKCS1_1_5_ENCRYPT_BIT_POS as i32;
        }
        PaddingMode::RSA_PKCS1_1_5_SIGN => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::RSA_PKCS1_1_5_SIGN_BIT_POS as i32;
        }
        PaddingMode::PKCS7 => {
            *padding_mode_bitmap |= 1 << PaddingModeBitPosition::PKCS7_BIT_POS as i32;
        }
        _ => {}
    }
}

fn compute_digest_bitmap(digest_bitmap: &mut i32, digest: Digest) {
    match digest {
        Digest::NONE => {
            *digest_bitmap |= 1 << DigestBitPosition::NONE_BIT_POSITION as i32;
        }
        Digest::MD5 => {
            *digest_bitmap |= 1 << DigestBitPosition::MD5_BIT_POS as i32;
        }
        Digest::SHA1 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_1_BIT_POS as i32;
        }
        Digest::SHA_2_224 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_224_BIT_POS as i32;
        }
        Digest::SHA_2_256 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_256_BIT_POS as i32;
        }
        Digest::SHA_2_384 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_384_BIT_POS as i32;
        }
        Digest::SHA_2_512 => {
            *digest_bitmap |= 1 << DigestBitPosition::SHA_2_512_BIT_POS as i32;
        }
        _ => {}
    }
}

fn compute_block_mode_bitmap(block_mode_bitmap: &mut i32, block_mode: BlockMode) {
    match block_mode {
        BlockMode::ECB => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::ECB_BIT_POS as i32;
        }
        BlockMode::CBC => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::CBC_BIT_POS as i32;
        }
        BlockMode::CTR => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::CTR_BIT_POS as i32;
        }
        BlockMode::GCM => {
            *block_mode_bitmap |= 1 << BlockModeBitPosition::GCM_BIT_POS as i32;
        }
        _ => {}
    }
}

fn compute_purpose_bitmap(purpose_bitmap: &mut i32, purpose: KeyPurpose) {
    match purpose {
        KeyPurpose::ENCRYPT => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::ENCRYPT_BIT_POS as i32;
        }
        KeyPurpose::DECRYPT => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::DECRYPT_BIT_POS as i32;
        }
        KeyPurpose::SIGN => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::SIGN_BIT_POS as i32;
        }
        KeyPurpose::VERIFY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::VERIFY_BIT_POS as i32;
        }
        KeyPurpose::WRAP_KEY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::WRAP_KEY_BIT_POS as i32;
        }
        KeyPurpose::AGREE_KEY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::AGREE_KEY_BIT_POS as i32;
        }
        KeyPurpose::ATTEST_KEY => {
            *purpose_bitmap |= 1 << KeyPurposeBitPosition::ATTEST_KEY_BIT_POS as i32;
        }
        _ => {}
    }
}

pub(crate) fn pull_storage_stats() -> Result<Vec<KeystoreAtom>> {
    let mut atom_vec: Vec<KeystoreAtom> = Vec::new();
    let mut append = |stat| {
        match stat {
            Ok(s) => atom_vec.push(KeystoreAtom {
                payload: KeystoreAtomPayload::StorageStats(s),
                ..Default::default()
            }),
            Err(error) => {
                log::error!("pull_metrics_callback: Error getting storage stat: {}", error)
            }
        };
    };
    DB.with(|db| {
        let mut db = db.borrow_mut();
        append(db.get_storage_stat(MetricsStorage::DATABASE));
        append(db.get_storage_stat(MetricsStorage::KEY_ENTRY));
        append(db.get_storage_stat(MetricsStorage::KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX));
        append(db.get_storage_stat(MetricsStorage::BLOB_ENTRY));
        append(db.get_storage_stat(MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::KEY_PARAMETER));
        append(db.get_storage_stat(MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::KEY_METADATA));
        append(db.get_storage_stat(MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX));
        append(db.get_storage_stat(MetricsStorage::GRANT));
        append(db.get_storage_stat(MetricsStorage::AUTH_TOKEN));
        append(db.get_storage_stat(MetricsStorage::BLOB_METADATA));
        append(db.get_storage_stat(MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX));
    });
    Ok(atom_vec)
}

/// Log error events related to Remote Key Provisioning (RKP).
pub fn log_rkp_error_stats(rkp_error: MetricsRkpError, sec_level: &SecurityLevel) {
    let rkp_error_stats = KeystoreAtomPayload::RkpErrorStats(RkpErrorStats {
        rkpError: rkp_error,
        security_level: process_security_level(*sec_level),
    });
    METRICS_STORE.insert_atom(AtomID::RKP_ERROR_STATS, rkp_error_stats);
}

/// This function tries to read and update the system property: keystore.crash_count.
/// If the property is absent, it sets the property with value 0. If the property is present, it
/// increments the value. This helps tracking keystore crashes internally.
pub fn update_keystore_crash_sysprop() {
    let new_count = match read_keystore_crash_count() {
        Ok(Some(count)) => count + 1,
        // If the property is absent, then this is the first start up during the boot.
        // Proceed to write the system property with value 0.
        Ok(None) => 0,
        Err(error) => {
            log::warn!(
                concat!(
                    "In update_keystore_crash_sysprop: ",
                    "Failed to read the existing system property due to: {:?}.",
                    "Therefore, keystore crashes will not be logged."
                ),
                error
            );
            return;
        }
    };
    if let Err(e) =
        rsproperties::set(KEYSTORE_CRASH_COUNT_PROPERTY, &new_count.to_string())
    {
        log::error!(
            concat!(
                "In update_keystore_crash_sysprop:: ",
                "Failed to write the system property due to error: {:?}"
            ),
            e
        );
    }
}

/// Read the system property: keystore.crash_count.
pub fn read_keystore_crash_count() -> Result<Option<i32>> {
    let sp: std::result::Result<String, rsproperties::Error> = rsproperties::get(KEYSTORE_CRASH_COUNT_PROPERTY);
    match sp {
        Ok(count_str) => {
            let count = count_str.parse::<i32>()?;
            Ok(Some(count))
        }
        Err(rsproperties::Error::NotFound(_)) => Ok(None),
        Err(e) => Err(e).context(err!("Failed to read crash count property.")),
    }
}

/// Enum defining the bit position for each padding mode. Since padding mode can be repeatable, it
/// is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
enum PaddingModeBitPosition {
    ///Bit position in the PaddingMode bitmap for NONE.
    NONE_BIT_POSITION = 0,
    ///Bit position in the PaddingMode bitmap for RSA_OAEP.
    RSA_OAEP_BIT_POS = 1,
    ///Bit position in the PaddingMode bitmap for RSA_PSS.
    RSA_PSS_BIT_POS = 2,
    ///Bit position in the PaddingMode bitmap for RSA_PKCS1_1_5_ENCRYPT.
    RSA_PKCS1_1_5_ENCRYPT_BIT_POS = 3,
    ///Bit position in the PaddingMode bitmap for RSA_PKCS1_1_5_SIGN.
    RSA_PKCS1_1_5_SIGN_BIT_POS = 4,
    ///Bit position in the PaddingMode bitmap for RSA_PKCS7.
    PKCS7_BIT_POS = 5,
}

/// Enum defining the bit position for each digest type. Since digest can be repeatable in
/// key parameters, it is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
enum DigestBitPosition {
    ///Bit position in the Digest bitmap for NONE.
    NONE_BIT_POSITION = 0,
    ///Bit position in the Digest bitmap for MD5.
    MD5_BIT_POS = 1,
    ///Bit position in the Digest bitmap for SHA1.
    SHA_1_BIT_POS = 2,
    ///Bit position in the Digest bitmap for SHA_2_224.
    SHA_2_224_BIT_POS = 3,
    ///Bit position in the Digest bitmap for SHA_2_256.
    SHA_2_256_BIT_POS = 4,
    ///Bit position in the Digest bitmap for SHA_2_384.
    SHA_2_384_BIT_POS = 5,
    ///Bit position in the Digest bitmap for SHA_2_512.
    SHA_2_512_BIT_POS = 6,
}

/// Enum defining the bit position for each block mode type. Since block mode can be repeatable in
/// key parameters, it is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
enum BlockModeBitPosition {
    ///Bit position in the BlockMode bitmap for ECB.
    ECB_BIT_POS = 1,
    ///Bit position in the BlockMode bitmap for CBC.
    CBC_BIT_POS = 2,
    ///Bit position in the BlockMode bitmap for CTR.
    CTR_BIT_POS = 3,
    ///Bit position in the BlockMode bitmap for GCM.
    GCM_BIT_POS = 4,
}

/// Enum defining the bit position for each key purpose. Since key purpose can be repeatable in
/// key parameters, it is represented using a bitmap.
#[allow(non_camel_case_types)]
#[repr(i32)]
enum KeyPurposeBitPosition {
    ///Bit position in the KeyPurpose bitmap for Encrypt.
    ENCRYPT_BIT_POS = 1,
    ///Bit position in the KeyPurpose bitmap for Decrypt.
    DECRYPT_BIT_POS = 2,
    ///Bit position in the KeyPurpose bitmap for Sign.
    SIGN_BIT_POS = 3,
    ///Bit position in the KeyPurpose bitmap for Verify.
    VERIFY_BIT_POS = 4,
    ///Bit position in the KeyPurpose bitmap for Wrap Key.
    WRAP_KEY_BIT_POS = 5,
    ///Bit position in the KeyPurpose bitmap for Agree Key.
    AGREE_KEY_BIT_POS = 6,
    ///Bit position in the KeyPurpose bitmap for Attest Key.
    ATTEST_KEY_BIT_POS = 7,
}

/// The various metrics-related types are not defined in this crate, so the orphan
/// trait rule means that `std::fmt::Debug` cannot be implemented for them.
/// Instead, create our own local trait that generates a debug string for a type.
trait Summary {
    fn show(&self) -> String;
}

/// Implement the [`Summary`] trait for AIDL-derived pseudo-enums, mapping named enum values to
/// specified short names, all padded with spaces to the specified width (to allow improved
/// readability when printed in a group).
macro_rules! impl_summary_enum {
    {  $enum:ident, $width:literal, $( $variant:ident => $short:literal ),+ $(,)? } => {
        impl Summary for $enum{
            fn show(&self) -> String {
                match self.0 {
                    $(
                        x if x == Self::$variant.0 => format!(concat!("{:",
                                                                      stringify!($width),
                                                                      "}"),
                                                              $short),
                    )*
                    v => format!("Unknown({})", v),
                }
            }
        }
    }
}

impl_summary_enum!(AtomID, 14,
    STORAGE_STATS => "STORAGE",
    KEYSTORE2_ATOM_WITH_OVERFLOW => "OVERFLOW",
    KEY_CREATION_WITH_GENERAL_INFO => "KEYGEN_GENERAL",
    KEY_CREATION_WITH_AUTH_INFO => "KEYGEN_AUTH",
    KEY_CREATION_WITH_PURPOSE_AND_MODES_INFO => "KEYGEN_MODES",
    KEY_OPERATION_WITH_PURPOSE_AND_MODES_INFO => "KEYOP_MODES",
    KEY_OPERATION_WITH_GENERAL_INFO => "KEYOP_GENERAL",
    RKP_ERROR_STATS => "RKP_ERR",
    CRASH_STATS => "CRASH",
);

impl_summary_enum!(MetricsStorage, 28,
    STORAGE_UNSPECIFIED => "UNSPECIFIED",
    KEY_ENTRY => "KEY_ENTRY",
    KEY_ENTRY_ID_INDEX => "KEY_ENTRY_ID_IDX" ,
    KEY_ENTRY_DOMAIN_NAMESPACE_INDEX => "KEY_ENTRY_DOMAIN_NS_IDX" ,
    BLOB_ENTRY => "BLOB_ENTRY",
    BLOB_ENTRY_KEY_ENTRY_ID_INDEX => "BLOB_ENTRY_KEY_ENTRY_ID_IDX" ,
    KEY_PARAMETER => "KEY_PARAMETER",
    KEY_PARAMETER_KEY_ENTRY_ID_INDEX => "KEY_PARAM_KEY_ENTRY_ID_IDX" ,
    KEY_METADATA => "KEY_METADATA",
    KEY_METADATA_KEY_ENTRY_ID_INDEX => "KEY_META_KEY_ENTRY_ID_IDX" ,
    GRANT => "GRANT",
    AUTH_TOKEN => "AUTH_TOKEN",
    BLOB_METADATA => "BLOB_METADATA",
    BLOB_METADATA_BLOB_ENTRY_ID_INDEX => "BLOB_META_BLOB_ENTRY_ID_IDX" ,
    METADATA => "METADATA",
    DATABASE => "DATABASE",
    LEGACY_STORAGE => "LEGACY_STORAGE",
);

impl_summary_enum!(MetricsAlgorithm, 4,
    ALGORITHM_UNSPECIFIED => "NONE",
    RSA => "RSA",
    EC => "EC",
    AES => "AES",
    TRIPLE_DES => "DES",
    HMAC => "HMAC",
);

impl_summary_enum!(MetricsEcCurve, 5,
    EC_CURVE_UNSPECIFIED => "NONE",
    P_224 => "P-224",
    P_256 => "P-256",
    P_384 => "P-384",
    P_521 => "P-521",
    CURVE_25519 => "25519",
);

impl_summary_enum!(MetricsKeyOrigin, 10,
    ORIGIN_UNSPECIFIED => "UNSPEC",
    GENERATED => "GENERATED",
    DERIVED => "DERIVED",
    IMPORTED => "IMPORTED",
    RESERVED => "RESERVED",
    SECURELY_IMPORTED => "SEC-IMPORT",
);

impl_summary_enum!(MetricsSecurityLevel, 9,
    SECURITY_LEVEL_UNSPECIFIED => "UNSPEC",
    SECURITY_LEVEL_SOFTWARE => "SOFTWARE",
    SECURITY_LEVEL_TRUSTED_ENVIRONMENT => "TEE",
    SECURITY_LEVEL_STRONGBOX => "STRONGBOX",
    SECURITY_LEVEL_KEYSTORE => "KEYSTORE",
);

// Metrics values for HardwareAuthenticatorType are broken -- the AIDL type is a bitmask
// not an enum, so offseting the enum values by 1 doesn't work.
impl_summary_enum!(MetricsHardwareAuthenticatorType, 6,
    AUTH_TYPE_UNSPECIFIED => "UNSPEC",
    NONE => "NONE",
    PASSWORD => "PASSWD",
    FINGERPRINT => "FPRINT",
    ANY => "ANY",
);

impl_summary_enum!(MetricsPurpose, 7,
    KEY_PURPOSE_UNSPECIFIED => "UNSPEC",
    ENCRYPT => "ENCRYPT",
    DECRYPT => "DECRYPT",
    SIGN => "SIGN",
    VERIFY => "VERIFY",
    WRAP_KEY => "WRAPKEY",
    AGREE_KEY => "AGREEKY",
    ATTEST_KEY => "ATTESTK",
);

impl_summary_enum!(MetricsOutcome, 7,
    OUTCOME_UNSPECIFIED => "UNSPEC",
    DROPPED => "DROPPED",
    SUCCESS => "SUCCESS",
    ABORT => "ABORT",
    PRUNED => "PRUNED",
    ERROR => "ERROR",
);

impl_summary_enum!(MetricsRkpError, 6,
    RKP_ERROR_UNSPECIFIED => "UNSPEC",
    OUT_OF_KEYS => "OOKEYS",
    FALL_BACK_DURING_HYBRID => "FALLBK",
);

/// Convert an argument into a corresponding format clause.  (This is needed because
/// macro expansion text for repeated inputs needs to mention one of the repeated
/// inputs.)
macro_rules! format_clause {
    {  $ignored:ident } => { "{}" }
}

/// Generate code to print a string corresponding to a bitmask, where the given
/// enum identifies which bits mean what.  If additional bits (not included in
/// the enum variants) are set, include the whole bitmask in the output so no
/// information is lost.
macro_rules! show_enum_bitmask {
    {  $v:expr, $enum:ident, $( $variant:ident => $short:literal ),+ $(,)? } => {
        {
            let v: i32 = $v;
            let mut displayed_mask = 0i32;
            $(
                displayed_mask |= 1 << $enum::$variant as i32;
            )*
            let undisplayed_mask = !displayed_mask;
            let undisplayed = v & undisplayed_mask;
            let extra = if undisplayed == 0 {
                "".to_string()
            } else {
                format!("(full:{v:#010x})")
            };
            format!(
                concat!( $( format_clause!($variant), )* "{}"),
                $(
                    if v & 1 << $enum::$variant as i32 != 0 { $short } else { "-" },
                )*
                extra
            )
        }
    }
}

fn show_purpose(v: i32) -> String {
    show_enum_bitmask!(v, KeyPurposeBitPosition,
        ATTEST_KEY_BIT_POS => "A",
        AGREE_KEY_BIT_POS => "G",
        WRAP_KEY_BIT_POS => "W",
        VERIFY_BIT_POS => "V",
        SIGN_BIT_POS => "S",
        DECRYPT_BIT_POS => "D",
        ENCRYPT_BIT_POS => "E",
    )
}

fn show_padding(v: i32) -> String {
    show_enum_bitmask!(v, PaddingModeBitPosition,
        PKCS7_BIT_POS => "7",
        RSA_PKCS1_1_5_SIGN_BIT_POS => "S",
        RSA_PKCS1_1_5_ENCRYPT_BIT_POS => "E",
        RSA_PSS_BIT_POS => "P",
        RSA_OAEP_BIT_POS => "O",
        NONE_BIT_POSITION => "N",
    )
}

fn show_digest(v: i32) -> String {
    show_enum_bitmask!(v, DigestBitPosition,
        SHA_2_512_BIT_POS => "5",
        SHA_2_384_BIT_POS => "3",
        SHA_2_256_BIT_POS => "2",
        SHA_2_224_BIT_POS => "4",
        SHA_1_BIT_POS => "1",
        MD5_BIT_POS => "M",
        NONE_BIT_POSITION => "N",
    )
}

fn show_blockmode(v: i32) -> String {
    show_enum_bitmask!(v, BlockModeBitPosition,
        GCM_BIT_POS => "G",
        CTR_BIT_POS => "T",
        CBC_BIT_POS => "C",
        ECB_BIT_POS => "E",
    )
}

impl Summary for KeystoreAtomPayload {
    fn show(&self) -> String {
        match self {
            KeystoreAtomPayload::StorageStats(v) => {
                format!("{} sz={} unused={}", v.storage_type.show(), v.size, v.unused_size)
            }
            KeystoreAtomPayload::KeyCreationWithGeneralInfo(v) => {
                format!(
                    "{} ksz={:>4} crv={} {} rc={:4} attest? {}",
                    v.algorithm.show(),
                    v.key_size,
                    v.ec_curve.show(),
                    v.key_origin.show(),
                    v.error_code,
                    if v.attestation_requested { "Y" } else { "N" }
                )
            }
            KeystoreAtomPayload::KeyCreationWithAuthInfo(v) => {
                format!(
                    "auth={} log(time)={:3} sec={}",
                    v.user_auth_type.show(),
                    v.log10_auth_key_timeout_seconds,
                    v.security_level.show()
                )
            }
            KeystoreAtomPayload::KeyCreationWithPurposeAndModesInfo(v) => {
                format!(
                    "{} purpose={} padding={} digest={} blockmode={}",
                    v.algorithm.show(),
                    show_purpose(v.purpose_bitmap),
                    show_padding(v.padding_mode_bitmap),
                    show_digest(v.digest_bitmap),
                    show_blockmode(v.block_mode_bitmap),
                )
            }
            KeystoreAtomPayload::KeyOperationWithGeneralInfo(v) => {
                format!(
                    "{} {:>8} upgraded? {} sec={}",
                    v.outcome.show(),
                    v.error_code,
                    if v.key_upgraded { "Y" } else { "N" },
                    v.security_level.show()
                )
            }
            KeystoreAtomPayload::KeyOperationWithPurposeAndModesInfo(v) => {
                format!(
                    "{} padding={} digest={} blockmode={}",
                    v.purpose.show(),
                    show_padding(v.padding_mode_bitmap),
                    show_digest(v.digest_bitmap),
                    show_blockmode(v.block_mode_bitmap)
                )
            }
            KeystoreAtomPayload::RkpErrorStats(v) => {
                format!("{} sec={}", v.rkpError.show(), v.security_level.show())
            }
            KeystoreAtomPayload::CrashStats(v) => {
                format!("count={}", v.count_of_crash_events)
            }
            KeystoreAtomPayload::Keystore2AtomWithOverflow(v) => {
                format!("atom={}", v.atom_id.show())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enum_show() {
        let algo = MetricsAlgorithm::RSA;
        assert_eq!("RSA ", algo.show());
        let algo = MetricsAlgorithm(42);
        assert_eq!("Unknown(42)", algo.show());
    }

    #[test]
    fn test_enum_bitmask_show() {
        let mut modes = 0i32;
        compute_block_mode_bitmap(&mut modes, BlockMode::ECB);
        compute_block_mode_bitmap(&mut modes, BlockMode::CTR);

        assert_eq!(show_blockmode(modes), "-T-E");

        // Add some bits not covered by the enum of valid bit positions.
        modes |= 0xa0;
        assert_eq!(show_blockmode(modes), "-T-E(full:0x000000aa)");
        modes |= 0x300;
        assert_eq!(show_blockmode(modes), "-T-E(full:0x000003aa)");
    }
}
