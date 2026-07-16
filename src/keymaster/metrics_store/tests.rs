// Copyright 2020, The Android Open Source Project
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

use super::*;
use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, HardwareAuthenticatorType::HardwareAuthenticatorType as AuthType,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, MlDsaVariant::MlDsaVariant,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use crate::android::security::metrics::{
    Algorithm::Algorithm as MetricsAlgorithm,
    HardwareAuthenticatorType::HardwareAuthenticatorType as MetricsAuthType,
    SecurityLevel::SecurityLevel as MetricsSecurityLevel,
};

#[test]
fn test_round_latency_logic() {
    let test_cases = [
        (0, 0), // <= 10ms: nearest 5ms
        (2, 0),
        (3, 5),
        (5, 5),
        (7, 5),
        (8, 10),
        (10, 10),
        (11, 10), // 10-100ms: nearest 10ms
        (14, 10),
        (15, 20),
        (94, 90),
        (95, 100),
        (100, 100),
        (101, 100), // > 100ms: 50ms step
        (124, 100),
        (125, 150),
        (974, 950),
        (975, 1000),
        (1000, 1000), // 1s-10s: 500ms steps
        (1249, 1000),
        (1250, 1500),
        (12345, 10000), // 10s+: 5000ms steps
    ];

    for (input, expected) in test_cases {
        assert_eq!(
            round_latency(Duration::from_millis(input)),
            expected,
            "Failed rounding for {}ms",
            input
        );
    }
}

#[test]
fn test_crash_count_record_is_per_boot() {
    let record = "boot-a\n2\n";

    assert_eq!(parse_crash_count_record(record, "boot-a").unwrap(), Some(2));
    assert_eq!(parse_crash_count_record(record, "boot-b").unwrap(), None);
}

#[test]
fn test_enum_show() {
    let algo = MetricsAlgorithm::RSA;
    assert_eq!("RSA    ", algo.show());
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

fn create_key_param_with_auth_type(auth_type: AuthType) -> KeyParameter {
    KeyParameter {
        tag: Tag::USER_AUTH_TYPE,
        value: KeyParameterValue::HardwareAuthenticatorType(auth_type),
    }
}

#[test]
fn test_user_auth_type() {
    let test_cases = [
        (vec![], MetricsAuthType::NO_AUTH_TYPE),
        (vec![AuthType::NONE], MetricsAuthType::NONE),
        (vec![AuthType::PASSWORD], MetricsAuthType::PASSWORD),
        (vec![AuthType::FINGERPRINT], MetricsAuthType::FINGERPRINT),
        (
            vec![AuthType(AuthType::PASSWORD.0 | AuthType::FINGERPRINT.0)],
            MetricsAuthType::PASSWORD_OR_FINGERPRINT,
        ),
        (vec![AuthType::ANY], MetricsAuthType::ANY),
        // 7 is the "next" undefined HardwareAuthenticatorType enum tag number, so
        // force this test to fail and be updated if someone adds a new enum value.
        (vec![AuthType(7)], MetricsAuthType::AUTH_TYPE_UNSPECIFIED),
        (vec![AuthType(123)], MetricsAuthType::AUTH_TYPE_UNSPECIFIED),
        (
            // In practice, Tag::USER_AUTH_TYPE isn't a repeatable tag. It's allowed
            // to appear once for auth-bound keys and contains the binary OR of the
            // applicable auth types. However, this test case repeats the tag more
            // than once in order to unit test the logic that constructs the atom.
            vec![AuthType::ANY, AuthType(123), AuthType::PASSWORD],
            // The last auth type wins.
            MetricsAuthType::PASSWORD,
        ),
    ];
    for (auth_types, expected) in test_cases {
        let key_params: Vec<_> = auth_types
            .iter()
            .map(|a| create_key_param_with_auth_type(*a))
            .collect();
        let (_, atom_with_auth_info, _, _) = process_key_creation_event_stats(
            0,
            SecurityLevel::TRUSTED_ENVIRONMENT,
            &key_params,
            KeyOrigin::GENERATED,
            &Ok(()),
        );
        assert!(matches!(
            atom_with_auth_info,
            KeystoreAtomPayload::KeyCreationWithAuthInfo(a) if a.user_auth_type == expected
        ));
    }
}

fn create_key_param_with_auth_timeout(timeout: i32) -> KeyParameter {
    KeyParameter {
        tag: Tag::AUTH_TIMEOUT,
        value: KeyParameterValue::Integer(timeout),
    }
}

#[test]
fn test_log_auth_timeout_seconds() {
    let test_cases = [
        (vec![], -1),
        (vec![-1], 0),
        // The metrics code computes the value of this field for a timeout `t` with
        // `f32::log10(t as f32) as i32`. The result of f32::log10(0 as f32) is `-inf`.
        // Casting this to i32 means it gets "rounded" to i32::MIN, which is -2147483648.
        (vec![0], -2147483648),
        (vec![1], 0),
        (vec![9], 0),
        (vec![10], 1),
        (vec![999], 2),
        (
            // In practice, Tag::AUTH_TIMEOUT isn't a repeatable tag. It's allowed to
            // appear once for auth-bound keys. However, this test case repeats the
            // tag more than once in order to unit test the logic that constructs the
            // atom.
            vec![1, 0, 10],
            // The last timeout wins.
            1,
        ),
    ];
    for (timeouts, expected) in test_cases {
        let key_params: Vec<_> = timeouts
            .iter()
            .map(|t| create_key_param_with_auth_timeout(*t))
            .collect();
        let (_, atom_with_auth_info, _, _) = process_key_creation_event_stats(
            0,
            SecurityLevel::TRUSTED_ENVIRONMENT,
            &key_params,
            KeyOrigin::GENERATED,
            &Ok(()),
        );
        assert!(matches!(
            atom_with_auth_info,
            KeystoreAtomPayload::KeyCreationWithAuthInfo(a)
                if a.log10_auth_key_timeout_seconds == expected
        ));
    }
}

#[test]
fn test_security_level() {
    let test_cases = [
        (
            SecurityLevel::SOFTWARE,
            MetricsSecurityLevel::SECURITY_LEVEL_SOFTWARE,
        ),
        (
            SecurityLevel::TRUSTED_ENVIRONMENT,
            MetricsSecurityLevel::SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        ),
        (
            SecurityLevel::STRONGBOX,
            MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX,
        ),
        (
            SecurityLevel::KEYSTORE,
            MetricsSecurityLevel::SECURITY_LEVEL_KEYSTORE,
        ),
        (
            SecurityLevel(123),
            MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED,
        ),
    ];
    for (security_level, expected) in test_cases {
        let (_, atom_with_auth_info, _, _) =
            process_key_creation_event_stats(0, security_level, &[], KeyOrigin::GENERATED, &Ok(()));
        assert!(matches!(
            atom_with_auth_info,
            KeystoreAtomPayload::KeyCreationWithAuthInfo(a)
                if a.security_level == expected
        ));
    }
}

fn create_key_param_with_algorithm(algorithm: Algorithm) -> KeyParameter {
    KeyParameter {
        tag: Tag::ALGORITHM,
        value: KeyParameterValue::Algorithm(algorithm),
    }
}

fn create_key_param_with_mldsa_variant(variant: MlDsaVariant) -> KeyParameter {
    KeyParameter {
        tag: Tag::ML_DSA_VARIANT,
        value: KeyParameterValue::MlDsaVariant(variant),
    }
}

#[test]
fn test_algorithm() {
    let test_cases: &[(&[KeyParameter], MetricsAlgorithm)] = &[
        (&[], MetricsAlgorithm::ALGORITHM_UNSPECIFIED),
        (
            &[create_key_param_with_algorithm(Algorithm::RSA)],
            MetricsAlgorithm::RSA,
        ),
        (
            &[create_key_param_with_algorithm(Algorithm::EC)],
            MetricsAlgorithm::EC,
        ),
        (
            &[create_key_param_with_algorithm(Algorithm::AES)],
            MetricsAlgorithm::AES,
        ),
        (
            &[create_key_param_with_algorithm(Algorithm::TRIPLE_DES)],
            MetricsAlgorithm::TRIPLE_DES,
        ),
        (
            &[create_key_param_with_algorithm(Algorithm::HMAC)],
            MetricsAlgorithm::HMAC,
        ),
        // Lots of test cases for ML-DSA: the algorithm is determined from the
        // MlDsaVariant parameter, not the Algorithm parameter.
        (
            &[create_key_param_with_algorithm(Algorithm::ML_DSA)],
            MetricsAlgorithm::ALGORITHM_UNSPECIFIED,
        ),
        (
            &[create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_65)],
            MetricsAlgorithm::ML_DSA_65,
        ),
        (
            &[create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_87)],
            MetricsAlgorithm::ML_DSA_87,
        ),
        (
            &[
                create_key_param_with_algorithm(Algorithm::ML_DSA),
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_65),
            ],
            MetricsAlgorithm::ML_DSA_65,
        ),
        (
            &[
                create_key_param_with_algorithm(Algorithm::ML_DSA),
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_87),
            ],
            MetricsAlgorithm::ML_DSA_87,
        ),
        (
            &[
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_65),
                create_key_param_with_algorithm(Algorithm::ML_DSA),
            ],
            MetricsAlgorithm::ML_DSA_65,
        ),
        (
            &[
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_87),
                create_key_param_with_algorithm(Algorithm::ML_DSA),
            ],
            MetricsAlgorithm::ML_DSA_87,
        ),
        (
            &[
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_87),
                create_key_param_with_algorithm(Algorithm::RSA),
            ],
            MetricsAlgorithm::RSA,
        ),
        (
            &[
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_65),
                create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_87),
            ],
            MetricsAlgorithm::ML_DSA_87,
        ),
    ];
    for (key_params, expected) in test_cases {
        let (atom_with_general_info, _, atom_with_purpose_and_modes, _) =
            process_key_creation_event_stats(
                0,
                SecurityLevel::SOFTWARE,
                key_params,
                KeyOrigin::GENERATED,
                &Ok(()),
            );
        assert!(matches!(
            atom_with_general_info,
            KeystoreAtomPayload::KeyCreationWithGeneralInfo(a)
                if a.algorithm == *expected
        ));
        assert!(matches!(
            atom_with_purpose_and_modes,
            KeystoreAtomPayload::KeyCreationWithPurposeAndModesInfo(a)
                if a.algorithm == *expected
        ));
    }
}

#[test]
fn test_log_key_creation_per_uid() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let uid = 12345;
    let sec_level = SecurityLevel::TRUSTED_ENVIRONMENT;
    let params = vec![create_key_param_with_algorithm(Algorithm::RSA)];

    let find_creation_atom = |a: &KeystoreAtom| {
        if let KeystoreAtomPayload::KeyCreationPerUid(ref payload) = a.payload {
            payload.uid == uid
                && payload.security_level
                    == MetricsSecurityLevel::SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                && payload.algorithm == MetricsAlgorithm::RSA
        } else {
            false
        }
    };

    // Log once
    log_key_creation_event_stats(uid, sec_level, &params, KeyOrigin::GENERATED, &Ok(()));
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_CREATION_PER_UID)
        .unwrap();
    let atom = atoms
        .iter()
        .find(|a| find_creation_atom(a))
        .expect("Atom should be present");
    let initial_count = atom.count;
    assert!(initial_count >= 1);

    // Log again and check count increases
    log_key_creation_event_stats(uid, sec_level, &params, KeyOrigin::GENERATED, &Ok(()));
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_CREATION_PER_UID)
        .unwrap();
    let atom = atoms
        .iter()
        .find(|a| find_creation_atom(a))
        .expect("Atom should be present");
    assert_eq!(atom.count, initial_count + 1);
}

#[test]
fn test_log_key_creation_per_uid_verify_fields() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let uid = 67890;
    let sec_level = SecurityLevel::STRONGBOX;
    let params = vec![
        create_key_param_with_algorithm(Algorithm::EC),
        create_key_param_with_auth_type(AuthType::FINGERPRINT),
        KeyParameter {
            tag: Tag::ATTESTATION_CHALLENGE,
            value: KeyParameterValue::Blob(vec![1, 2, 3]),
        },
    ];

    log_key_creation_event_stats(uid, sec_level, &params, KeyOrigin::GENERATED, &Ok(()));
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_CREATION_PER_UID)
        .unwrap();
    let _ = atoms
        .iter()
        .find(|a| {
            if let KeystoreAtomPayload::KeyCreationPerUid(ref payload) = a.payload {
                payload.uid == uid
                    && payload.security_level == MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX
                    && payload.algorithm == MetricsAlgorithm::EC
                    && payload.user_auth_type == MetricsAuthType::FINGERPRINT
                    && payload.attestation_requested
            } else {
                false
            }
        })
        .expect("Atom should be present");
}

#[test]
fn test_log_key_operation_per_uid() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let uid = 54321;
    let sec_level = SecurityLevel::STRONGBOX;

    let find_operation_atom = |a: &KeystoreAtom| {
        if let KeystoreAtomPayload::KeyOperationPerUid(ref payload) = a.payload {
            payload.uid == uid
                && payload.security_level == MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX
        } else {
            false
        }
    };

    // Log once
    log_key_operation_event_stats(
        uid,
        sec_level,
        KeyPurpose::SIGN,
        &[],
        &Outcome::Success,
        false,
        false,
    );
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_OPERATION_PER_UID)
        .unwrap();
    let atom = atoms
        .iter()
        .find(|a| find_operation_atom(a))
        .expect("Atom should be present");
    let initial_count = atom.count;
    assert!(initial_count >= 1);

    // Log again and check count increases
    log_key_operation_event_stats(
        uid,
        sec_level,
        KeyPurpose::SIGN,
        &[],
        &Outcome::Success,
        false,
        false,
    );
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_OPERATION_PER_UID)
        .unwrap();
    let atom = atoms
        .iter()
        .find(|a| find_operation_atom(a))
        .expect("Atom should be present");
    assert_eq!(atom.count, initial_count + 1);
}

#[test]
fn test_log_operation_latency_aggregation() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let params = vec![create_key_param_with_algorithm(Algorithm::RSA)];
    let sec_level = SecurityLevel::TRUSTED_ENVIRONMENT;

    // Log same operation twice.
    log_operation_latency(
        MetricsOperationType::GENERATE_KEY,
        sec_level,
        &params,
        true,
        Duration::from_millis(150),
    );
    log_operation_latency(
        MetricsOperationType::GENERATE_KEY,
        sec_level,
        &params,
        true,
        Duration::from_millis(150),
    );

    // Log different bucket.
    log_operation_latency(
        MetricsOperationType::GENERATE_KEY,
        sec_level,
        &params,
        true,
        Duration::from_millis(1500),
    );

    let atoms = METRICS_STORE.get_atoms(AtomID::OPERATION_LATENCY).unwrap();

    let mut count_150 = 0;
    let mut count_1500 = 0;

    for atom in atoms {
        if let KeystoreAtomPayload::OperationLatency(ref op) = atom.payload {
            if op.latency_ms == 150 {
                count_150 += atom.count;
            } else if op.latency_ms == 1500 {
                count_1500 += atom.count;
            }
        }
    }

    assert!(count_150 >= 2);
    assert!(count_1500 >= 1);
}

#[test]
fn test_log_operation_latency_outcomes() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let params = vec![create_key_param_with_algorithm(Algorithm::RSA)];
    let sec_level = SecurityLevel::TRUSTED_ENVIRONMENT;

    // Test Success
    log_operation_latency(
        MetricsOperationType::ENTIRE_OPERATION,
        sec_level,
        &params,
        true,
        Duration::from_millis(5),
    );

    // Test Failure
    log_operation_latency(
        MetricsOperationType::ENTIRE_OPERATION,
        sec_level,
        &params,
        false,
        Duration::from_millis(5),
    );

    let atoms = METRICS_STORE.get_atoms(AtomID::OPERATION_LATENCY).unwrap();

    let mut success_found = false;
    let mut failure_found = false;

    for atom in atoms {
        if let KeystoreAtomPayload::OperationLatency(ref op) = atom.payload {
            if op.operation_type == MetricsOperationType::ENTIRE_OPERATION {
                if op.is_success {
                    success_found = true;
                } else {
                    failure_found = true;
                }
            }
        }
    }

    assert!(success_found, "Success outcome not found");
    assert!(failure_found, "Failure outcome not found");
}

#[test]
fn test_log_operation_latency_eccurve() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let params = vec![
        create_key_param_with_algorithm(Algorithm::EC),
        KeyParameter {
            tag: Tag::EC_CURVE,
            value: KeyParameterValue::EcCurve(EcCurve::P_256),
        },
    ];

    log_operation_latency(
        MetricsOperationType::GENERATE_KEY,
        SecurityLevel::TRUSTED_ENVIRONMENT,
        &params,
        true,
        Duration::from_millis(50),
    );

    let atoms = METRICS_STORE.get_atoms(AtomID::OPERATION_LATENCY).unwrap();
    let found = atoms.iter().any(|atom| {
        matches!(atom.payload, KeystoreAtomPayload::OperationLatency(ref op)
            if op.algorithm == MetricsAlgorithm::EC && op.ec_curve == MetricsEcCurve::P_256)
    });
    assert!(found, "EC_CURVE P_256 not reported correctly");
}

#[test]
fn test_log_operation_latency_mldsa() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let params = vec![
        create_key_param_with_algorithm(Algorithm::ML_DSA),
        create_key_param_with_mldsa_variant(MlDsaVariant::ML_DSA_65),
    ];

    log_operation_latency(
        MetricsOperationType::GENERATE_KEY,
        SecurityLevel::TRUSTED_ENVIRONMENT,
        &params,
        true,
        Duration::from_millis(50),
    );

    let atoms = METRICS_STORE.get_atoms(AtomID::OPERATION_LATENCY).unwrap();
    let found = atoms.iter().any(|atom| {
        matches!(atom.payload, KeystoreAtomPayload::OperationLatency(ref op)
            if op.algorithm == MetricsAlgorithm::ML_DSA_65)
    });
    assert!(found, "ML_DSA_65 algorithm variant not reported correctly");
}

#[test]
fn test_round_streaming_logic() {
    let test_cases = [
        (0, 0),
        (5, 5),
        (10, 10),
        (11, 11),
        (19, 19),
        (20, 20),
        (21, 20), // > 20: step is 10
        (25, 30),
        (94, 90),
        (100, 100),
        (101, 100), // > 100: step is 100
        (104, 100),
        (105, 100),
        (124, 100),
        (150, 200),
        (949, 900),
        (1000, 1000),
        (1024, 1000), // > 1000: step is 1000
        (10239, 10000),
        (100000, 100000),
    ];

    for (input, expected) in test_cases {
        assert_eq!(
            round_logarithmic(input as u64, 10, 1, 20),
            expected as i64,
            "Failed rounding for {input}",
        );
    }
}

#[test]
fn test_log_key_operation_streaming_stats() {
    if !crate::keymaster::flags::atoms_v2() {
        return;
    }

    let algorithm = MetricsAlgorithm::RSA;
    let is_success = true;

    // Log once with call count below threshold (5 < 20)
    log_key_operation_streaming_stats(algorithm, is_success, 5, 1024);
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_OPERATION_STREAMING_STATS)
        .unwrap();
    let find_atom = |a: &KeystoreAtom| {
        if let KeystoreAtomPayload::KeyOperationStreamingStats(ref payload) = a.payload {
            payload.call_count == 5 && payload.total_input_bytes == 1000
        } else {
            false
        }
    };
    let atom = atoms
        .iter()
        .find(|a| find_atom(a))
        .expect("Atom should be present");
    let initial_count = atom.count;
    assert!(initial_count >= 1);

    // Log again and check count increases
    log_key_operation_streaming_stats(algorithm, is_success, 5, 1024);
    let atoms = METRICS_STORE
        .get_atoms(AtomID::KEY_OPERATION_STREAMING_STATS)
        .unwrap();
    let atom = atoms
        .iter()
        .find(|a| find_atom(a))
        .expect("Atom should be present");
    assert_eq!(atom.count, initial_count + 1);
}
