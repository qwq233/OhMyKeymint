use std::ffi::{c_char, c_int, CString};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use der::{Decode, Encode, Reader, SliceReader};
use hex::encode as hex_encode;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, UnparsedPublicKey, VerificationAlgorithm};
use rsbinder::{hub, ExceptionCode, Status, StatusCode, Strong};
use x509_cert::Certificate;

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, SecurityLevel::SecurityLevel, Tag::Tag,
};
use crate::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse,
    Domain::Domain,
    IKeystoreSecurityLevel::{transactions as security_tx, IKeystoreSecurityLevel},
    IKeystoreService::{transactions as service_tx, IKeystoreService},
    KeyDescriptor::KeyDescriptor,
    KeyEntryResponse::KeyEntryResponse,
    KeyMetadata::KeyMetadata,
    ResponseCode::ResponseCode,
};
use crate::aosp_tamper::classify::{
    alias_is_strictly_after_cursor, aliases_contain_all, binder_chain_has_issue,
    filter_outlier_pairs, list_entries_batched_cursor_echoed,
    list_entries_batched_expected_next_missing, list_entries_batched_view,
    metadata_key_is_normalized, metadata_shape_is_valid, native_flags_have_issue,
    paired_diff_series, pure_cert_top_level_security_level_exposed, timing_side_channel_suspicious,
    BinderChainView, MetadataKeyView, MetadataShapeView, NativeTraceFlags, PureCertLevelView,
};
use crate::aosp_tamper::model::{ProbeOutput, ProbeRow, ScoredCategory, SignalLevel};
use crate::aosp_tamper::native;
use crate::aosp_tamper::parcel::{
    classify_missing_key_reply, classify_service_specific_reply, generate_mode_fingerprint_matched,
    parse_generate_key_reply, ServiceSpecificReplyFingerprint,
};
use crate::aosp_tamper::score;
use crate::attestation::{
    ensure_octet_string, ensure_sequence, extract_attestation_challenge_from_leaf_certificate,
    extract_verified_boot_hash_from_leaf_certificate, parse_tlv, TlvClass, ANDROID_ATTESTATION_OID,
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const OVERSIZED_CHALLENGE_SIZES: [usize; 3] = [256, 512, 4096];
const TIMING_WARMUP_COUNT: usize = 5;
const TIMING_SAMPLE_COUNT: usize = 1000;
const TIMING_ANOMALY_SAMPLE_COUNT: usize = 12;
const PRUNING_OPERATION_COUNT: usize = 18;
const OVERSIZED_OPERATION_INPUT: usize = 0x8001;
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_RSA_WITH_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_WITH_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_WITH_SHA512: &str = "1.2.840.113549.1.1.13";
const APP_LIST_IGNORED_NAMESPACE: i64 = i64::MIN + 0x4b32;
const RAW_ERROR_UPDATE_CERT_DER_B64: &str = concat!(
    "MIIBrDCCAVKgAwIBAgIUEDMxnKtJLyq85qO8+47LPYIKctAwCgYIKoZIzj0EAwIw",
    "TTEeMBwGA1UEAwwVRWx0YXZpbmVNYXJrZXItS2V5Ym94MR4wHAYDVQQKDBVFbHRh",
    "dmluZSBEdWNrRGV0ZWN0b3IxCzAJBgNVBAYTAlVTMB4XDTI2MDMxNTA3MDExOVoX",
    "DTM2MDMxMzA3MDExOVowTTEeMBwGA1UEAwwVRWx0YXZpbmVNYXJrZXItS2V5Ym94",
    "MR4wHAYDVQQKDBVFbHRhdmluZSBEdWNrRGV0ZWN0b3IxCzAJBgNVBAYTAlVTMFkw",
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE27fIn5FqZMiCjrzJVb+cbrldYjQXnRDD",
    "u++w8FC7vkOs8+iXvGYEQU66Iz18/OxQrw/DtXCWIaaV9soPfMTiyKMQMA4wDAYD",
    "VR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiEArLJ6IUmlCAo5qDxUMaC5xS/X",
    "yEAI3GWQyzWBtHoJSA4CIFxNM3we4MxMk0Zk/UEhUz+Nmp2kyb6nNNgUj7yj1JxI"
);
const IMPORT_MARKER_SUBJECT: &str = "EltavineMarker-Keybox";

pub fn run_probe(quick: bool) -> Result<ProbeOutput> {
    rsbinder::ProcessState::init_default();

    let service: Strong<dyn IKeystoreService> = hub::get_interface(KEYSTORE_SERVICE)
        .context("failed to connect to android.system.keystore2.IKeystoreService/default")?;
    let tee = service
        .getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("failed to get TRUSTED_ENVIRONMENT security level")?;
    let probe = BlindProbe {
        service,
        tee,
        quick,
    };
    Ok(probe.run())
}

struct BlindProbe {
    service: Strong<dyn IKeystoreService>,
    tee: Strong<dyn IKeystoreSecurityLevel>,
    quick: bool,
}

impl BlindProbe {
    fn run(&self) -> ProbeOutput {
        let mut rows = Vec::new();
        let mut advisory_rows = Vec::new();

        rows.push(self.probe_challenge());
        let (boot_consistency, boot_consistency_advisory) = self.probe_boot_consistency();
        if let Some(row) = boot_consistency {
            rows.push(row);
        }
        if let Some(row) = boot_consistency_advisory {
            advisory_rows.push(row);
        }
        rows.push(self.probe_oversized_challenge());
        rows.push(self.probe_key_pair_consistency());
        rows.push(self.probe_certificate_chain());
        advisory_rows.push(self.probe_der_attestation_sanity());
        rows.push(self.probe_keystore2_reply_fingerprint());
        rows.push(self.probe_generate_mode_fingerprint());
        advisory_rows.push(self.probe_raw_error_matrix());

        let (metadata_key, metadata_shape) = self.probe_metadata_semantics();
        rows.push(metadata_key);
        rows.push(metadata_shape);
        rows.push(self.probe_entry_listing());
        rows.push(self.probe_list_entries_batched());
        rows.push(self.probe_operation_security_level());

        let (pure_cert_level, pure_cert_metadata) = self.probe_pure_certificate_security_level();
        advisory_rows.push(pure_cert_level);
        advisory_rows.push(pure_cert_metadata);
        rows.push(self.probe_pure_certificate_follow_up());

        rows.push(self.probe_update_path());
        rows.push(self.probe_operation_path());
        rows.push(self.probe_binder_chain());
        rows.push(self.probe_alias_lifecycle());
        rows.push(self.probe_alias_isolation());
        rows.push(self.probe_attestation_route_marker());
        advisory_rows.push(self.probe_attestation_issuer_dn());
        rows.push(self.probe_timing_side_channel());
        let (native_row, native_advisory_rows) = self.probe_native();
        advisory_rows.push(native_row);
        advisory_rows.extend(native_advisory_rows);

        advisory_rows.push(self.probe_aes_gcm_operation());
        advisory_rows.push(self.probe_import_marker());
        advisory_rows.push(self.probe_strongbox_tier());
        advisory_rows.push(self.probe_dual_algorithm_attestation());
        advisory_rows.push(self.probe_timing_anomaly());
        advisory_rows.push(self.probe_operation_pruning());

        score::evaluate(rows, advisory_rows)
    }

    fn probe_challenge(&self) -> ProbeRow {
        let alias = unique_alias("challenge");
        let descriptor = app_descriptor(&alias);
        let challenge = b"blind-aosp-challenge".to_vec();
        let result =
            self.tee
                .generateKey(&descriptor, None, &attested_ec_params(&challenge), 0, &[]);
        let _ = self.service.deleteKey(&descriptor);

        match result {
            Ok(metadata) => match metadata.certificate.as_deref() {
                Some(leaf) => match extract_attestation_challenge_from_leaf_certificate(leaf) {
                    Ok(parsed) if parsed == challenge => {
                        let vbhash = extract_verified_boot_hash_from_leaf_certificate(leaf)
                            .map(hex_encode)
                            .unwrap_or_else(|_| "unavailable".into());
                        scored_row(
                            "Challenge",
                            format!("challenge matched; verifiedBootHash={vbhash}"),
                            SignalLevel::Pass,
                            ScoredCategory::PolicyHard,
                        )
                    }
                    Ok(parsed) => scored_row(
                        "Challenge",
                        format!(
                            "challenge mismatch: requested={}B returned={}B",
                            challenge.len(),
                            parsed.len()
                        ),
                        SignalLevel::Fail,
                        ScoredCategory::PolicyHard,
                    ),
                    Err(error) => scored_row(
                        "Challenge",
                        format!("attestation challenge was not comparable: {error:#}"),
                        SignalLevel::Broken,
                        ScoredCategory::PolicyHard,
                    ),
                },
                None => scored_row(
                    "Challenge",
                    "attestation leaf certificate missing".to_string(),
                    SignalLevel::Broken,
                    ScoredCategory::PolicyHard,
                ),
            },
            Err(status) => scored_row(
                "Challenge",
                format!(
                    "attested key generation failed: {}",
                    describe_status(&status)
                ),
                SignalLevel::Broken,
                ScoredCategory::PolicyHard,
            ),
        }
    }

    fn probe_boot_consistency(&self) -> (Option<ProbeRow>, Option<ProbeRow>) {
        let alias = unique_alias("boot-consistency");
        let descriptor = app_descriptor(&alias);
        let generated = self.tee.generateKey(
            &descriptor,
            None,
            &attested_ec_params(b"boot-consistency"),
            0,
            &[],
        );
        let _ = self.service.deleteKey(&descriptor);

        match generated {
            Ok(metadata) => match metadata.certificate.as_deref() {
                Some(leaf) => match inspect_boot_consistency(leaf) {
                    Ok(observation) if observation.comparison_performed => (
                        Some(scored_row(
                            "Boot consistency",
                            observation.detail,
                            if observation.hard_anomaly {
                                SignalLevel::Fail
                            } else {
                                SignalLevel::Pass
                            },
                            ScoredCategory::PolicyHard,
                        )),
                        None,
                    ),
                    Ok(observation) => (
                        None,
                        Some(advisory_row(
                            "Boot consistency",
                            observation.detail,
                            if observation.runtime_props_available {
                                SignalLevel::Info
                            } else {
                                SignalLevel::Unavailable
                            },
                        )),
                    ),
                    Err(error) => (
                        None,
                        Some(advisory_row(
                            "Boot consistency",
                            format!("probe unavailable: {error:#}"),
                            SignalLevel::Unavailable,
                        )),
                    ),
                },
                None => (
                    None,
                    Some(advisory_row(
                        "Boot consistency",
                        "attestation leaf certificate missing".to_string(),
                        SignalLevel::Unavailable,
                    )),
                ),
            },
            Err(status) => (
                None,
                Some(advisory_row(
                    "Boot consistency",
                    format!(
                        "attested key generation failed: {}",
                        describe_status(&status)
                    ),
                    SignalLevel::Unavailable,
                )),
            ),
        }
    }

    fn probe_oversized_challenge(&self) -> ProbeRow {
        let mut accepted_sizes = Vec::new();
        for size in OVERSIZED_CHALLENGE_SIZES {
            let alias = unique_alias(&format!("oversized-{size}"));
            let descriptor = app_descriptor(&alias);
            let challenge = vec![0x5a; size];
            let accepted = self
                .tee
                .generateKey(&descriptor, None, &attested_ec_params(&challenge), 0, &[])
                .is_ok();
            let _ = self.service.deleteKey(&descriptor);
            if accepted {
                accepted_sizes.push(size);
            }
        }

        if accepted_sizes.is_empty() {
            scored_row(
                "Oversized challenge",
                format!(
                    "rejected sizes {}",
                    OVERSIZED_CHALLENGE_SIZES
                        .iter()
                        .map(|size| format!("{size}B"))
                        .collect::<Vec<_>>()
                        .join(" / ")
                ),
                SignalLevel::Pass,
                ScoredCategory::PolicySoft,
            )
        } else {
            scored_row(
                "Oversized challenge",
                format!(
                    "accepted sizes {}",
                    accepted_sizes
                        .iter()
                        .map(|size| format!("{size}B"))
                        .collect::<Vec<_>>()
                        .join(" / ")
                ),
                SignalLevel::Warn,
                ScoredCategory::PolicySoft,
            )
        }
    }

    fn probe_keystore2_reply_fingerprint(&self) -> ProbeRow {
        let alias = unique_alias("missing-key");
        let descriptor = app_descriptor(&alias);
        match self.raw_service_reply(service_tx::r#getKeyEntry, |parcel| {
            parcel.write(&descriptor)
        }) {
            Ok(raw_reply) => {
                let parsed = classify_missing_key_reply(&raw_reply);
                let level = if parsed.native_style_response {
                    SignalLevel::Info
                } else {
                    SignalLevel::Fail
                };
                scored_row(
                    "Keystore2",
                    parsed.detail,
                    level,
                    ScoredCategory::Supplementary,
                )
            }
            Err(error) => scored_row(
                "Keystore2",
                format!("raw getKeyEntry capture failed: {error:#}"),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
        }
    }

    fn probe_raw_error_matrix(&self) -> ProbeRow {
        if self.quick {
            return advisory_row(
                "Raw error matrix",
                "skipped by --quick".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let missing_alias = unique_alias("raw-missing");
        let missing_descriptor = app_descriptor(&missing_alias);
        let marker_cert = match marker_certificate_der() {
            Ok(cert) => cert,
            Err(error) => {
                return advisory_row(
                    "Raw error matrix",
                    format!("marker certificate unavailable: {error:#}"),
                    SignalLevel::Unavailable,
                );
            }
        };

        let params = sign_operation_params(false);
        let cases = [
            RawReplyCapture {
                label: "getKeyEntry",
                expected_error_code: ResponseCode::KEY_NOT_FOUND.0,
                raw: self.raw_service_reply(service_tx::r#getKeyEntry, |parcel| {
                    parcel.write(&missing_descriptor)
                }),
            },
            RawReplyCapture {
                label: "deleteKey",
                expected_error_code: ResponseCode::KEY_NOT_FOUND.0,
                raw: self.raw_service_reply(service_tx::r#deleteKey, |parcel| {
                    parcel.write(&missing_descriptor)
                }),
            },
            RawReplyCapture {
                label: "updateSubcomponent",
                expected_error_code: ResponseCode::KEY_NOT_FOUND.0,
                raw: self.raw_service_reply(service_tx::r#updateSubcomponent, |parcel| {
                    parcel.write(&missing_descriptor)?;
                    parcel.write(&Option::<Vec<u8>>::Some(marker_cert.clone()))?;
                    parcel.write(&Option::<Vec<u8>>::None)
                }),
            },
            RawReplyCapture {
                label: "createOperation",
                expected_error_code: ResponseCode::KEY_NOT_FOUND.0,
                raw: self.raw_security_level_reply(security_tx::r#createOperation, |parcel| {
                    parcel.write(&missing_descriptor)?;
                    parcel.write(&params)?;
                    parcel.write(&false)
                }),
            },
        ];

        let mut observations = Vec::new();
        let mut unavailable = 0usize;
        let mut suspicious = false;
        for case in cases {
            match case.raw {
                Ok(bytes) => {
                    let fingerprint =
                        classify_service_specific_reply(&bytes, Some(case.expected_error_code));
                    suspicious |= raw_reply_fingerprint_suspicious(&fingerprint);
                    observations.push(format!(
                        "{}={}",
                        case.label,
                        raw_reply_case_label(&fingerprint)
                    ));
                }
                Err(error) => {
                    unavailable += 1;
                    observations.push(format!("{}=captureErr({error:#})", case.label));
                }
            }
        }

        advisory_row(
            "Raw error matrix",
            format!("{}; unavailable={unavailable}", observations.join(", ")),
            if unavailable == observations.len() {
                SignalLevel::Unavailable
            } else if suspicious {
                SignalLevel::Warn
            } else {
                SignalLevel::Info
            },
        )
    }

    fn probe_key_pair_consistency(&self) -> ProbeRow {
        let alias = unique_alias("pair-consistency");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let entry = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());
        let leaf = entry
            .as_ref()
            .and_then(|entry| entry.metadata.certificate.as_deref())
            .or_else(|| {
                generated
                    .as_ref()
                    .ok()
                    .and_then(|metadata| metadata.certificate.as_deref())
            });
        let key_descriptor = entry
            .as_ref()
            .map(|entry| entry.metadata.key.clone())
            .unwrap_or_else(|| descriptor.clone());
        let payload = b"blind-aosp-pair-probe";
        let signature = sign_payload(self, &key_descriptor, payload);
        let _ = self.service.deleteKey(&descriptor);

        match (leaf, signature) {
            (Some(leaf), Ok(signature)) => {
                match verify_signature_with_certificate(leaf, payload, &signature) {
                    Ok(true) => scored_row(
                        "Key pair consistency",
                        "leaf certificate public key validated a fresh signature".to_string(),
                        SignalLevel::Pass,
                        ScoredCategory::PolicyHard,
                    ),
                    Ok(false) => scored_row(
                        "Key pair consistency",
                        "leaf certificate public key failed to verify a fresh signature"
                            .to_string(),
                        SignalLevel::Fail,
                        ScoredCategory::PolicyHard,
                    ),
                    Err(error) => scored_row(
                        "Key pair consistency",
                        format!("signature verification was unavailable: {error:#}"),
                        SignalLevel::Broken,
                        ScoredCategory::PolicyHard,
                    ),
                }
            }
            (None, _) => scored_row(
                "Key pair consistency",
                "leaf certificate missing after key generation".to_string(),
                SignalLevel::Broken,
                ScoredCategory::PolicyHard,
            ),
            (_, Err(error)) => scored_row(
                "Key pair consistency",
                format!("signing operation failed: {error:#}"),
                SignalLevel::Broken,
                ScoredCategory::PolicyHard,
            ),
        }
    }

    fn probe_certificate_chain(&self) -> ProbeRow {
        let alias = unique_alias("chain-integrity");
        let descriptor = app_descriptor(&alias);
        let generated = self.tee.generateKey(
            &descriptor,
            None,
            &attested_ec_params(b"chain-integrity"),
            0,
            &[],
        );
        let chain = generated
            .as_ref()
            .ok()
            .and_then(|metadata| collect_chain_der(metadata).ok());
        let _ = self.service.deleteKey(&descriptor);

        match chain {
            Some(chain) => match inspect_certificate_chain(&chain) {
                Ok(inspection) => scored_row(
                    "Certificate chain",
                    inspection.detail,
                    match inspection.verdict {
                        CertificateChainVerdict::Pass => SignalLevel::Pass,
                        CertificateChainVerdict::Fail => SignalLevel::Fail,
                        CertificateChainVerdict::Unavailable => SignalLevel::Unavailable,
                    },
                    ScoredCategory::PolicyHard,
                ),
                Err(error) => scored_row(
                    "Certificate chain",
                    format!("probe failed: {error:#}"),
                    SignalLevel::Broken,
                    ScoredCategory::PolicyHard,
                ),
            },
            None => scored_row(
                "Certificate chain",
                "certificate chain was unavailable after attested key generation".to_string(),
                SignalLevel::Broken,
                ScoredCategory::PolicyHard,
            ),
        }
    }

    fn probe_der_attestation_sanity(&self) -> ProbeRow {
        let alias = unique_alias("der-sanity");
        let descriptor = app_descriptor(&alias);
        let challenge = b"der-attestation-sanity";
        let generated =
            self.tee
                .generateKey(&descriptor, None, &attested_ec_params(challenge), 0, &[]);
        let fetched = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());
        let inspection = generated
            .as_ref()
            .map_err(|status| anyhow!("generateKey failed: {}", describe_status(status)))
            .and_then(collect_chain_der)
            .and_then(|generated_chain| {
                let fetched_chain = fetched
                    .as_ref()
                    .map(collect_chain_der_from_response)
                    .transpose()?;
                inspect_der_attestation_sanity(
                    &generated_chain,
                    fetched_chain.as_deref(),
                    challenge,
                )
            });
        let _ = self.service.deleteKey(&descriptor);

        match inspection {
            Ok(inspection) => advisory_row(
                "DER attestation sanity",
                inspection.detail,
                if inspection.ok {
                    SignalLevel::Info
                } else {
                    SignalLevel::Warn
                },
            ),
            Err(error) => advisory_row(
                "DER attestation sanity",
                format!("probe unavailable: {error:#}"),
                SignalLevel::Unavailable,
            ),
        }
    }

    fn probe_generate_mode_fingerprint(&self) -> ProbeRow {
        let alias = unique_alias("generate-mode");
        let descriptor = app_descriptor(&alias);
        let params = signing_ec_params();
        let raw_reply = self.raw_security_level_reply(security_tx::r#generateKey, |parcel| {
            parcel.write(&descriptor)?;
            parcel.write(&Option::<KeyDescriptor>::None)?;
            parcel.write(&params)?;
            parcel.write(&0i32)?;
            parcel.write(&Vec::<u8>::new())
        });
        let _ = self.service.deleteKey(&descriptor);

        match raw_reply {
            Ok(bytes) => {
                let parsed = parse_generate_key_reply(&bytes);
                if !parsed.parse_succeeded {
                    return scored_row(
                        "Generate-mode fingerprint",
                        parsed.detail,
                        SignalLevel::Unavailable,
                        ScoredCategory::Supplementary,
                    );
                }
                let matched = generate_mode_fingerprint_matched(&parsed);
                scored_row(
                    "Generate-mode fingerprint",
                    parsed.detail,
                    if matched {
                        SignalLevel::Fail
                    } else {
                        SignalLevel::Info
                    },
                    ScoredCategory::Supplementary,
                )
            }
            Err(error) => scored_row(
                "Generate-mode fingerprint",
                format!("raw generateKey capture failed: {error:#}"),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
        }
    }

    fn probe_metadata_semantics(&self) -> (ProbeRow, ProbeRow) {
        let alias = unique_alias("metadata");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let response = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());
        let _ = self.service.deleteKey(&descriptor);

        match response {
            Some(entry) => {
                let key_view = MetadataKeyView {
                    domain_is_key_id: entry.metadata.key.domain == Domain::KEY_ID,
                    alias_present: entry.metadata.key.alias.is_some(),
                };
                let shape_view = MetadataShapeView {
                    modification_time_ms: entry.metadata.modificationTimeMs,
                    has_origin_authorization: entry
                        .metadata
                        .authorizations
                        .iter()
                        .any(|authorization| authorization.keyParameter.tag == Tag::ORIGIN),
                };
                (
                    scored_row(
                        "Metadata key",
                        format!(
                            "domain={:?}, alias={}",
                            entry.metadata.key.domain,
                            entry.metadata.key.alias.as_deref().unwrap_or("null")
                        ),
                        if metadata_key_is_normalized(key_view) {
                            SignalLevel::Pass
                        } else {
                            SignalLevel::Fail
                        },
                        ScoredCategory::Supplementary,
                    ),
                    scored_row(
                        "Metadata shape",
                        format!(
                            "modificationTimeMs={}, hasOrigin={}",
                            entry.metadata.modificationTimeMs, shape_view.has_origin_authorization
                        ),
                        if metadata_shape_is_valid(shape_view) {
                            SignalLevel::Pass
                        } else {
                            SignalLevel::Fail
                        },
                        ScoredCategory::Supplementary,
                    ),
                )
            }
            None => {
                let reason = generated
                    .err()
                    .map(|status| describe_status(&status))
                    .unwrap_or_else(|| "getKeyEntry failed".into());
                (
                    scored_row(
                        "Metadata key",
                        format!("probe unavailable: {reason}"),
                        SignalLevel::Unavailable,
                        ScoredCategory::Supplementary,
                    ),
                    scored_row(
                        "Metadata shape",
                        format!("probe unavailable: {reason}"),
                        SignalLevel::Unavailable,
                        ScoredCategory::Supplementary,
                    ),
                )
            }
        }
    }

    fn probe_entry_listing(&self) -> ProbeRow {
        let prefix = unique_alias("entry-listing");
        let alias0 = format!("{prefix}_00");
        let alias1 = format!("{prefix}_01");
        let descriptor0 = app_descriptor(&alias0);
        let descriptor1 = app_descriptor(&alias1);

        let before_count = match self
            .service
            .getNumberOfEntries(Domain::APP, APP_LIST_IGNORED_NAMESPACE)
        {
            Ok(count) => count,
            Err(status) => {
                return scored_row(
                    "Entry listing",
                    format!(
                        "getNumberOfEntries(APP) failed: {}",
                        describe_status(&status)
                    ),
                    SignalLevel::Unavailable,
                    ScoredCategory::Supplementary,
                );
            }
        };

        let generated0 = self
            .tee
            .generateKey(&descriptor0, None, &signing_ec_params(), 0, &[]);
        let generated1 = self
            .tee
            .generateKey(&descriptor1, None, &signing_ec_params(), 0, &[]);
        let after_create_count = self
            .service
            .getNumberOfEntries(Domain::APP, APP_LIST_IGNORED_NAMESPACE)
            .ok();
        let listed = self
            .service
            .listEntries(Domain::APP, APP_LIST_IGNORED_NAMESPACE);
        let aliases = listed
            .as_ref()
            .ok()
            .map(|entries| descriptor_aliases(entries));
        let count_grew = after_create_count
            .map(|count| count >= before_count.saturating_add(2))
            .unwrap_or(false);
        let contains_both = aliases
            .as_ref()
            .map(|aliases| aliases_contain_all(aliases, &[&alias0, &alias1]))
            .unwrap_or(false);
        let lexically_ordered = aliases
            .as_ref()
            .and_then(|aliases| alias_positions(aliases, &alias0, &alias1))
            .map(|(left, right)| left < right)
            .unwrap_or(false)
            && alias_is_strictly_after_cursor(&alias1, &alias0);

        let _ = self.service.deleteKey(&descriptor0);
        let _ = self.service.deleteKey(&descriptor1);
        let cleanup_removed = self.service.getKeyEntry(&descriptor0).is_err()
            && self.service.getKeyEntry(&descriptor1).is_err();
        let after_cleanup_count = self
            .service
            .getNumberOfEntries(Domain::APP, APP_LIST_IGNORED_NAMESPACE)
            .ok();
        let cleanup_count_ok = after_cleanup_count
            .map(|count| count <= before_count)
            .unwrap_or(false);

        let available = generated0.is_ok()
            && generated1.is_ok()
            && after_create_count.is_some()
            && listed.is_ok()
            && after_cleanup_count.is_some();
        let all_ok = available
            && count_grew
            && contains_both
            && lexically_ordered
            && cleanup_removed
            && cleanup_count_ok;
        scored_row(
            "Entry listing",
            format!(
                "created0={}, created1={}, beforeCount={}, afterCreateCount={}, listedBoth={}, lexicalOrder={}, cleanupRemoved={}, afterCleanupCount={}",
                generated0.is_ok(),
                generated1.is_ok(),
                before_count,
                option_i32_label(after_create_count),
                contains_both,
                lexically_ordered,
                cleanup_removed,
                option_i32_label(after_cleanup_count)
            ),
            if !available {
                SignalLevel::Unavailable
            } else if all_ok {
                SignalLevel::Pass
            } else {
                SignalLevel::Fail
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_list_entries_batched(&self) -> ProbeRow {
        let prefix = unique_alias("batched-listing");
        let alias0 = format!("{prefix}_00");
        let alias1 = format!("{prefix}_01");
        let descriptor0 = app_descriptor(&alias0);
        let descriptor1 = app_descriptor(&alias1);

        let generated0 = self
            .tee
            .generateKey(&descriptor0, None, &signing_ec_params(), 0, &[]);
        let generated1 = self
            .tee
            .generateKey(&descriptor1, None, &signing_ec_params(), 0, &[]);
        if let Err(status) = generated0.as_ref() {
            let detail = format!("first key generation failed: {}", describe_status(status));
            let _ = self.service.deleteKey(&descriptor0);
            let _ = self.service.deleteKey(&descriptor1);
            return scored_row(
                "Batched listing",
                detail,
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            );
        }
        if let Err(status) = generated1.as_ref() {
            let detail = format!("second key generation failed: {}", describe_status(status));
            let _ = self.service.deleteKey(&descriptor0);
            let _ = self.service.deleteKey(&descriptor1);
            return scored_row(
                "Batched listing",
                detail,
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            );
        }
        let listed = self.service.listEntriesBatched(
            Domain::APP,
            APP_LIST_IGNORED_NAMESPACE,
            Some(alias0.as_str()),
        );
        let aliases = listed
            .as_ref()
            .ok()
            .map(|entries| descriptor_aliases(entries));
        let view = aliases
            .as_ref()
            .map(|aliases| list_entries_batched_view(aliases, &alias0, &alias1));

        let _ = self.service.deleteKey(&descriptor0);
        let _ = self.service.deleteKey(&descriptor1);

        match (listed, aliases, view) {
            (Ok(_), Some(aliases), Some(view)) => {
                let cursor_echoed = list_entries_batched_cursor_echoed(view);
                let expected_next_missing = list_entries_batched_expected_next_missing(view);
                scored_row(
                    "Batched listing",
                    format!(
                        "cursorEchoed={}, expectedNextMissing={}, returnedAliases={}",
                        cursor_echoed,
                        expected_next_missing,
                        aliases.len()
                    ),
                    if !cursor_echoed && !expected_next_missing {
                        SignalLevel::Pass
                    } else {
                        SignalLevel::Fail
                    },
                    ScoredCategory::Supplementary,
                )
            }
            (Err(status), _, _) if status_is_unknown_transaction(&status) => scored_row(
                "Batched listing",
                "listEntriesBatched unavailable on this API surface".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
            (Err(status), _, _) => scored_row(
                "Batched listing",
                format!("listEntriesBatched failed: {}", describe_status(&status)),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
            _ => scored_row(
                "Batched listing",
                "probe unavailable: listEntriesBatched returned no comparable aliases".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
        }
    }

    fn probe_operation_security_level(&self) -> ProbeRow {
        let alias = unique_alias("operation-level");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let entry = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());

        let row = match entry {
            Some(entry) => {
                let leaf = entry.metadata.certificate.as_deref();
                let key_descriptor = entry.metadata.key.clone();
                match (leaf, entry.iSecurityLevel.as_ref()) {
                    (Some(leaf), Some(entry_level)) => {
                        let entry_payload = b"blind-entry-security-level";
                        let cached_payload = b"blind-cached-security-level";
                        let entry_signature =
                            sign_payload_with_level(entry_level, &key_descriptor, entry_payload);
                        let cached_signature =
                            sign_payload_with_level(&self.tee, &key_descriptor, cached_payload);
                        let entry_verified = entry_signature.as_ref().ok().and_then(|signature| {
                            verify_signature_with_certificate(leaf, entry_payload, signature).ok()
                        });
                        let cached_verified =
                            cached_signature.as_ref().ok().and_then(|signature| {
                                verify_signature_with_certificate(leaf, cached_payload, signature)
                                    .ok()
                            });
                        let entry_operation_ok = entry_signature.is_ok();
                        let cached_operation_ok = cached_signature.is_ok();
                        let comparable = entry_operation_ok || cached_operation_ok;
                        let equivalent = entry_operation_ok == cached_operation_ok
                            && entry_verified == cached_verified;
                        scored_row(
                            "Operation security level",
                            format!(
                                "entryLevelPresent=true, entryOperationOk={}, cachedOperationOk={}, entrySignatureVerified={}, cachedSignatureVerified={}, equivalent={}",
                                entry_operation_ok,
                                cached_operation_ok,
                                bool_label(entry_verified),
                                bool_label(cached_verified),
                                equivalent
                            ),
                            if !comparable {
                                SignalLevel::Unavailable
                            } else if equivalent {
                                SignalLevel::Pass
                            } else {
                                SignalLevel::Fail
                            },
                            ScoredCategory::Supplementary,
                        )
                    }
                    (None, _) => scored_row(
                        "Operation security level",
                        "leaf certificate missing for verification".to_string(),
                        SignalLevel::Unavailable,
                        ScoredCategory::Supplementary,
                    ),
                    (_, None) => scored_row(
                        "Operation security level",
                        "getKeyEntry returned no iSecurityLevel".to_string(),
                        SignalLevel::Fail,
                        ScoredCategory::Supplementary,
                    ),
                }
            }
            None => scored_row(
                "Operation security level",
                generated
                    .err()
                    .map(|status| format!("generateKey failed: {}", describe_status(&status)))
                    .unwrap_or_else(|| "getKeyEntry failed".to_string()),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
        };
        let _ = self.service.deleteKey(&descriptor);
        row
    }

    fn probe_pure_certificate_security_level(&self) -> (ProbeRow, ProbeRow) {
        let source_alias = unique_alias("pure-cert-source");
        let source_descriptor = app_descriptor(&source_alias);
        let generated = self.tee.generateKey(
            &source_descriptor,
            None,
            &attested_ec_params(b"pure-cert"),
            0,
            &[],
        );
        let full_chain = generated.as_ref().ok().and_then(full_chain_blob);
        let _ = self.service.deleteKey(&source_descriptor);

        let Some(full_chain) = full_chain else {
            return (
                advisory_row(
                    "Pure cert level",
                    "unable to build certificate-only entry payload".to_string(),
                    SignalLevel::Unavailable,
                ),
                advisory_row(
                    "Pure cert metadata",
                    "metadata.keySecurityLevel unavailable".to_string(),
                    SignalLevel::Unavailable,
                ),
            );
        };

        let alias = unique_alias("pure-cert");
        let descriptor = app_descriptor(&alias);
        let inserted =
            self.service
                .updateSubcomponent(&descriptor, None, Some(full_chain.as_slice()));
        let response = inserted
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());
        let _ = self.service.deleteKey(&descriptor);

        match response {
            Some(entry) => {
                let view = PureCertLevelView {
                    top_level_security_level_present: entry.iSecurityLevel.is_some(),
                    metadata_security_level_present: true,
                };
                (
                    advisory_row(
                        "Pure cert level",
                        format!(
                            "topLevelPresent={}, metadataLevel={:?}",
                            view.top_level_security_level_present, entry.metadata.keySecurityLevel
                        ),
                        if pure_cert_top_level_security_level_exposed(view) {
                            SignalLevel::Warn
                        } else {
                            SignalLevel::Info
                        },
                    ),
                    advisory_row(
                        "Pure cert metadata",
                        format!(
                            "metadata.keySecurityLevel={:?}",
                            entry.metadata.keySecurityLevel
                        ),
                        SignalLevel::Info,
                    ),
                )
            }
            None => {
                let detail = inserted
                    .err()
                    .map(|status| describe_status(&status))
                    .unwrap_or_else(|| "getKeyEntry failed".into());
                (
                    advisory_row(
                        "Pure cert level",
                        format!("probe unavailable: {detail}"),
                        SignalLevel::Unavailable,
                    ),
                    advisory_row(
                        "Pure cert metadata",
                        format!("probe unavailable: {detail}"),
                        SignalLevel::Unavailable,
                    ),
                )
            }
        }
    }

    fn probe_pure_certificate_follow_up(&self) -> ProbeRow {
        let source_alias = unique_alias("pure-cert-follow-source");
        let source_descriptor = app_descriptor(&source_alias);
        let generated = self.tee.generateKey(
            &source_descriptor,
            None,
            &attested_ec_params(b"pure-cert-follow-up"),
            0,
            &[],
        );
        let full_chain = generated.as_ref().ok().and_then(full_chain_blob);
        let _ = self.service.deleteKey(&source_descriptor);

        let Some(full_chain) = full_chain else {
            return scored_row(
                "Pure cert follow-up",
                "unable to build certificate-only entry payload".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::PolicyHard,
            );
        };

        let alias = unique_alias("pure-cert-follow");
        let descriptor = app_descriptor(&alias);
        let inserted =
            self.service
                .updateSubcomponent(&descriptor, None, Some(full_chain.as_slice()));
        let response = inserted
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());

        let row = match response {
            Some(entry) => {
                let minimal = self.create_sign_operation(&entry.metadata.key, false);
                let minimal_label = result_label(&minimal);
                let compat = minimal
                    .as_ref()
                    .err()
                    .map(|_| self.create_sign_operation(&entry.metadata.key, true));
                let compat_label = compat
                    .as_ref()
                    .map(result_label)
                    .unwrap_or_else(|| "skipped".to_string());
                let succeeded = minimal
                    .as_ref()
                    .ok()
                    .and_then(|response| response.iOperation.as_ref())
                    .is_some()
                    || compat
                        .as_ref()
                        .and_then(|result| result.as_ref().ok())
                        .and_then(|response| response.iOperation.as_ref())
                        .is_some();
                if let Ok(response) = minimal {
                    if let Some(operation) = response.iOperation {
                        let _ = operation.abort();
                    }
                }
                if let Some(Ok(response)) = compat {
                    if let Some(operation) = response.iOperation {
                        let _ = operation.abort();
                    }
                }
                scored_row(
                    "Pure cert follow-up",
                    format!(
                        "minimal={}, compat={}, operationSucceeded={}",
                        minimal_label, compat_label, succeeded
                    ),
                    if succeeded {
                        SignalLevel::Fail
                    } else {
                        SignalLevel::Pass
                    },
                    ScoredCategory::PolicyHard,
                )
            }
            None => scored_row(
                "Pure cert follow-up",
                inserted
                    .err()
                    .map(|status| format!("insert failed: {}", describe_status(&status)))
                    .unwrap_or_else(|| "probe unavailable: getKeyEntry failed".to_string()),
                SignalLevel::Unavailable,
                ScoredCategory::PolicyHard,
            ),
        };
        let _ = self.service.deleteKey(&descriptor);
        row
    }

    fn probe_update_path(&self) -> ProbeRow {
        let alias = unique_alias("update");
        let descriptor = app_descriptor(&alias);
        let generated = self.tee.generateKey(
            &descriptor,
            None,
            &attested_ec_params(b"update-path"),
            0,
            &[],
        );
        let existing_update_ok = match generated.as_ref() {
            Ok(metadata) => self
                .service
                .updateSubcomponent(
                    &descriptor,
                    metadata.certificate.as_deref(),
                    metadata.certificateChain.as_deref(),
                )
                .is_ok(),
            Err(_) => false,
        };
        let full_chain = generated.as_ref().ok().and_then(full_chain_blob);
        let cert_alias = unique_alias("update-cert");
        let cert_descriptor = app_descriptor(&cert_alias);
        let insert_update_ok = full_chain.as_ref().map(|chain| {
            self.service
                .updateSubcomponent(&cert_descriptor, None, Some(chain.as_slice()))
                .is_ok()
        });
        let _ = self.service.deleteKey(&descriptor);
        let _ = self.service.deleteKey(&cert_descriptor);

        let failed = generated.is_err()
            || !existing_update_ok
            || insert_update_ok
                .as_ref()
                .map(|result| !*result)
                .unwrap_or(true);
        scored_row(
            "Update path",
            format!(
                "existingUpdate={}, certInsert={}",
                if existing_update_ok { "ok" } else { "err" },
                match insert_update_ok.as_ref() {
                    Some(true) => "ok",
                    Some(false) => "err",
                    None => "unavailable",
                }
            ),
            if failed {
                SignalLevel::Fail
            } else {
                SignalLevel::Pass
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_operation_path(&self) -> ProbeRow {
        let alias = unique_alias("operation");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let key_descriptor = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok())
            .map(|entry| entry.metadata.key)
            .unwrap_or_else(|| descriptor.clone());

        let minimal = self.create_sign_operation(&key_descriptor, false);
        let (operation_descriptor, compat_fallback_used) = if minimal.is_ok() {
            (key_descriptor.clone(), false)
        } else {
            (key_descriptor.clone(), true)
        };

        let update_aad_ok =
            self.probe_update_aad_rejection(&operation_descriptor, compat_fallback_used);
        let oversized_update_ok =
            self.probe_oversized_update_rejection(&operation_descriptor, compat_fallback_used);
        let abort_invalidates_ok =
            self.probe_abort_invalidates_handle(&operation_descriptor, compat_fallback_used);

        let _ = self.service.deleteKey(&descriptor);

        let all_ok = update_aad_ok.unwrap_or(false)
            && oversized_update_ok.unwrap_or(false)
            && abort_invalidates_ok.unwrap_or(false);
        let available = update_aad_ok.is_some()
            && oversized_update_ok.is_some()
            && abort_invalidates_ok.is_some();
        scored_row(
            "Operation path",
            format!(
                "updateAadServiceSpecific={}, oversizedUpdateRejected={}, abortInvalidatedHandle={}, compatFallback={}",
                bool_label(update_aad_ok),
                bool_label(oversized_update_ok),
                bool_label(abort_invalidates_ok),
                compat_fallback_used
            ),
            if !available {
                SignalLevel::Unavailable
            } else if all_ok {
                SignalLevel::Pass
            } else {
                SignalLevel::Fail
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_binder_chain(&self) -> ProbeRow {
        let cycle1 = self.run_binder_chain_cycle(&unique_alias("binder-cycle-1"));
        let cycle2 = self.run_binder_chain_cycle(&unique_alias("binder-cycle-2"));

        match (cycle1, cycle2) {
            (Ok(first), Ok(second)) => {
                let view = BinderChainView {
                    generate_matches_get: first.generate_matches_get && second.generate_matches_get,
                    repeated_consistent: first.generate_matches_get == second.generate_matches_get
                        && first.suspicious_leaf_issuer_spki == second.suspicious_leaf_issuer_spki,
                    delete_removed_alias: first.delete_removed_alias && second.delete_removed_alias,
                    suspicious_leaf_issuer_spki: first.suspicious_leaf_issuer_spki
                        || second.suspicious_leaf_issuer_spki,
                };
                scored_row(
                    "Binder chain",
                    format!(
                        "cycle1Match={}, cycle2Match={}, repeatedConsistent={}, deleteRemoved={}, suspiciousLeafIssuerSpki={}",
                        first.generate_matches_get,
                        second.generate_matches_get,
                        view.repeated_consistent,
                        view.delete_removed_alias,
                        view.suspicious_leaf_issuer_spki
                    ),
                    if binder_chain_has_issue(view) {
                        SignalLevel::Fail
                    } else {
                        SignalLevel::Pass
                    },
                    ScoredCategory::Supplementary,
                )
            }
            (Err(error), _) | (_, Err(error)) => scored_row(
                "Binder chain",
                format!("probe unavailable: {error:#}"),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
        }
    }

    fn probe_attestation_issuer_dn(&self) -> ProbeRow {
        let alias = unique_alias("issuer-dn");
        let descriptor = app_descriptor(&alias);
        let generated =
            self.tee
                .generateKey(&descriptor, None, &attested_ec_params(b"issuer-dn"), 0, &[]);
        let row = match generated {
            Ok(_) => match self.service.getKeyEntry(&descriptor) {
                Ok(entry) => match collect_chain_der_from_response(&entry)
                    .and_then(|chain| summarize_issuer_dns(&chain))
                {
                    Ok(summary) => {
                        advisory_row("Attestation issuer DN", summary, SignalLevel::Info)
                    }
                    Err(error) => advisory_row(
                        "Attestation issuer DN",
                        format!("issuer summary unavailable: {error:#}"),
                        SignalLevel::Unavailable,
                    ),
                },
                Err(status) => advisory_row(
                    "Attestation issuer DN",
                    format!("getKeyEntry failed: {}", describe_status(&status)),
                    SignalLevel::Unavailable,
                ),
            },
            Err(status) => advisory_row(
                "Attestation issuer DN",
                format!("generateKey failed: {}", describe_status(&status)),
                SignalLevel::Unavailable,
            ),
        };
        let _ = self.service.deleteKey(&descriptor);
        row
    }

    fn probe_timing_side_channel(&self) -> ProbeRow {
        if self.quick {
            return scored_row(
                "Timing side-channel",
                "skipped by --quick".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            );
        }

        let attested_alias = unique_alias("timing-attested");
        let non_attested_alias = unique_alias("timing-plain");
        let attested_descriptor = app_descriptor(&attested_alias);
        let plain_descriptor = app_descriptor(&non_attested_alias);

        let attested = self
            .tee
            .generateKey(
                &attested_descriptor,
                None,
                &attested_ec_params(b"timing-side-channel"),
                0,
                &[],
            )
            .is_ok();
        let plain = self
            .tee
            .generateKey(&plain_descriptor, None, &signing_ec_params(), 0, &[])
            .is_ok();
        if !(attested && plain) {
            let _ = self.service.deleteKey(&attested_descriptor);
            let _ = self.service.deleteKey(&plain_descriptor);
            return scored_row(
                "Timing side-channel",
                "probe keys could not be generated".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            );
        }

        for _ in 0..TIMING_WARMUP_COUNT {
            let _ = self.service.getKeyEntry(&attested_descriptor);
            let _ = self.service.getKeyEntry(&plain_descriptor);
        }

        let mut attested_samples = Vec::new();
        let mut plain_samples = Vec::new();
        for _ in 0..TIMING_SAMPLE_COUNT {
            if let Some(sample) = measure_get_key_entry_millis(&self.service, &attested_descriptor)
            {
                attested_samples.push(sample);
            }
            if let Some(sample) = measure_get_key_entry_millis(&self.service, &plain_descriptor) {
                plain_samples.push(sample);
            }
        }

        let _ = self.service.deleteKey(&attested_descriptor);
        let _ = self.service.deleteKey(&plain_descriptor);

        let filtered = filter_outlier_pairs(&attested_samples, &plain_samples);
        if filtered.attested_samples.is_empty() || filtered.non_attested_samples.is_empty() {
            return scored_row(
                "Timing side-channel",
                "paired timing samples were unavailable".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            );
        }

        let avg_attested = average(&filtered.attested_samples);
        let avg_plain = average(&filtered.non_attested_samples);
        let diff_ms = avg_attested - avg_plain;
        let suspicious = timing_side_channel_suspicious(diff_ms);
        let paired_count =
            paired_diff_series(&filtered.attested_samples, &filtered.non_attested_samples).len();
        scored_row(
            "Timing side-channel",
            format!(
                "avgAttested={avg_attested:.3}ms, avgPlain={avg_plain:.3}ms, diff={diff_ms:.3}ms, warmup={}, samples={paired_count}",
                TIMING_WARMUP_COUNT
            ),
            if suspicious {
                SignalLevel::Warn
            } else {
                SignalLevel::Info
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_native(&self) -> (ProbeRow, Vec<ProbeRow>) {
        let result = native::inspect(self.quick);
        let flags = NativeTraceFlags {
            got_mismatch: result.got_mismatch.unwrap_or(false),
            text_mismatch: result.text_mismatch.unwrap_or(false),
            honeypot_anomaly: result.honeypot_anomaly.unwrap_or(false),
        };
        let level = if native_flags_have_issue(flags) {
            SignalLevel::Fail
        } else if result.got_mismatch.is_none()
            && result.text_mismatch.is_none()
            && result.honeypot_anomaly.is_none()
        {
            SignalLevel::Unavailable
        } else {
            SignalLevel::Info
        };
        (
            advisory_row("Native", result.detail, level),
            result.advisory_rows,
        )
    }

    fn probe_alias_lifecycle(&self) -> ProbeRow {
        let alias = unique_alias("lifecycle");
        let descriptor = app_descriptor(&alias);
        let first = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let first_read_ok = first
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok())
            .is_some();
        let first_spki = first
            .as_ref()
            .ok()
            .and_then(|metadata| metadata.certificate.as_deref())
            .and_then(|leaf| leaf_subject_spki(leaf).ok());
        let delete_result = self.service.deleteKey(&descriptor);
        let deleted_read_rejected = self.service.getKeyEntry(&descriptor).is_err();
        let second = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let second_spki = second
            .as_ref()
            .ok()
            .and_then(|metadata| metadata.certificate.as_deref())
            .and_then(|leaf| leaf_subject_spki(leaf).ok());
        let _ = self.service.deleteKey(&descriptor);

        let create_ok = first.is_ok();
        let delete_ok = delete_result.is_ok();
        let spki_changed = first_spki
            .as_ref()
            .zip(second_spki.as_ref())
            .map(|(left, right)| left != right);
        let all_ok = create_ok
            && first_read_ok
            && delete_ok
            && deleted_read_rejected
            && spki_changed.unwrap_or(false);
        scored_row(
            "Alias lifecycle",
            format!(
                "created={}, firstRead={}, deleted={}, deletedReadRejected={}, regeneratedFreshMaterial={}",
                create_ok,
                first_read_ok,
                delete_ok,
                deleted_read_rejected,
                bool_label(spki_changed)
            ),
            if all_ok {
                SignalLevel::Pass
            } else if create_ok {
                SignalLevel::Fail
            } else {
                SignalLevel::Unavailable
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_alias_isolation(&self) -> ProbeRow {
        let alias_a = unique_alias("isolation-a");
        let alias_b = unique_alias("isolation-b");
        let descriptor_a = app_descriptor(&alias_a);
        let descriptor_b = app_descriptor(&alias_b);

        let generated_a = self
            .tee
            .generateKey(&descriptor_a, None, &signing_ec_params(), 0, &[]);
        let generated_b = self
            .tee
            .generateKey(&descriptor_b, None, &signing_ec_params(), 0, &[]);
        let read_a_before = generated_a
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor_a).ok());
        let read_b_before = generated_b
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor_b).ok());
        let spki_a = read_a_before
            .as_ref()
            .and_then(|entry| entry.metadata.certificate.as_deref())
            .and_then(|leaf| leaf_subject_spki(leaf).ok());
        let spki_b = read_b_before
            .as_ref()
            .and_then(|entry| entry.metadata.certificate.as_deref())
            .and_then(|leaf| leaf_subject_spki(leaf).ok());

        let delete_a = self.service.deleteKey(&descriptor_a);
        let read_a_after_delete_rejected = self.service.getKeyEntry(&descriptor_a).is_err();
        let read_b_after_delete_ok = self.service.getKeyEntry(&descriptor_b).is_ok();
        let delete_b = self.service.deleteKey(&descriptor_b);

        let distinct_material = spki_a
            .as_ref()
            .zip(spki_b.as_ref())
            .map(|(left, right)| left != right);
        let all_ok = generated_a.is_ok()
            && generated_b.is_ok()
            && read_a_before.is_some()
            && read_b_before.is_some()
            && delete_a.is_ok()
            && read_a_after_delete_rejected
            && read_b_after_delete_ok
            && delete_b.is_ok()
            && distinct_material.unwrap_or(false);

        scored_row(
            "Alias isolation",
            format!(
                "createdA={}, createdB={}, readA={}, readB={}, deleteA={}, readAAfterDeleteRejected={}, readBAfterDelete={}, deleteB={}, distinctMaterial={}",
                generated_a.is_ok(),
                generated_b.is_ok(),
                read_a_before.is_some(),
                read_b_before.is_some(),
                delete_a.is_ok(),
                read_a_after_delete_rejected,
                read_b_after_delete_ok,
                delete_b.is_ok(),
                bool_label(distinct_material)
            ),
            if all_ok {
                SignalLevel::Pass
            } else if generated_a.is_ok() || generated_b.is_ok() {
                SignalLevel::Fail
            } else {
                SignalLevel::Unavailable
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_attestation_route_marker(&self) -> ProbeRow {
        let alias = unique_alias("route-marker");
        let descriptor = app_descriptor(&alias);
        let generated = self.tee.generateKey(
            &descriptor,
            None,
            &attested_ec_params(b"route-marker"),
            0,
            &[],
        );
        let row = match generated {
            Ok(metadata) => {
                let chain = collect_chain_der(&metadata);
                match chain {
                    Ok(chain) => {
                        let system_ca_marker = chain_has_droid_ca_marker(&chain);
                        let issuer_summary = summarize_issuer_dns(&chain).unwrap_or_else(|error| {
                            format!("issuer summary unavailable: {error:#}")
                        });
                        scored_row(
                            "Attestation route marker",
                            if system_ca_marker {
                                format!("system CA marker detected; {issuer_summary}")
                            } else {
                                format!("systemCaDetected=false; {issuer_summary}")
                            },
                            if system_ca_marker {
                                SignalLevel::Fail
                            } else {
                                SignalLevel::Pass
                            },
                            ScoredCategory::PolicyHard,
                        )
                    }
                    Err(error) => scored_row(
                        "Attestation route marker",
                        format!("probe unavailable: {error:#}"),
                        SignalLevel::Unavailable,
                        ScoredCategory::PolicyHard,
                    ),
                }
            }
            Err(status) => scored_row(
                "Attestation route marker",
                format!("generateKey failed: {}", describe_status(&status)),
                SignalLevel::Unavailable,
                ScoredCategory::PolicyHard,
            ),
        };
        let _ = self.service.deleteKey(&descriptor);
        row
    }

    fn probe_aes_gcm_operation(&self) -> ProbeRow {
        let alias = unique_alias("aes-gcm");
        let descriptor = app_descriptor(&alias);
        let result = self.run_aes_gcm_operation(&descriptor);
        let _ = self.service.deleteKey(&descriptor);

        match result {
            Ok(observation) => advisory_row(
                "AES-GCM operation",
                observation.detail,
                if observation.operation_finished
                    && observation.ciphertext_bytes > 0
                    && observation.nonce_len.is_some()
                    && observation.decrypt_matches
                {
                    SignalLevel::Info
                } else {
                    SignalLevel::Warn
                },
            ),
            Err(error) => advisory_row(
                "AES-GCM operation",
                format!("probe unavailable: {error:#}"),
                SignalLevel::Unavailable,
            ),
        }
    }

    fn probe_import_marker(&self) -> ProbeRow {
        let alias = unique_alias("import-marker");
        let descriptor = app_descriptor(&alias);
        let private_key = match import_marker_private_key_der() {
            Ok(key) => key,
            Err(error) => {
                return advisory_row(
                    "Import marker",
                    format!("marker key unavailable: {error:#}"),
                    SignalLevel::Unavailable,
                );
            }
        };
        let certificate = match marker_certificate_der() {
            Ok(cert) => cert,
            Err(error) => {
                return advisory_row(
                    "Import marker",
                    format!("marker certificate unavailable: {error:#}"),
                    SignalLevel::Unavailable,
                );
            }
        };

        let imported =
            self.tee
                .importKey(&descriptor, None, &imported_ec_params(), 0, &private_key);
        let row = match imported {
            Ok(_) => {
                let updated = self.service.updateSubcomponent(
                    &descriptor,
                    Some(certificate.as_slice()),
                    None,
                );
                match updated.and_then(|_| self.service.getKeyEntry(&descriptor)) {
                    Ok(entry) => {
                        let fetched_cert = entry.metadata.certificate.as_deref();
                        let der_preserved = fetched_cert == Some(certificate.as_slice());
                        let subject = fetched_cert
                            .and_then(|cert| Certificate::from_der(cert).ok())
                            .map(|cert| cert.tbs_certificate.subject.to_string());
                        let subject_preserved = subject
                            .as_deref()
                            .map(|subject| subject.contains(IMPORT_MARKER_SUBJECT))
                            .unwrap_or(false);
                        advisory_row(
                            "Import marker",
                            format!(
                                "imported=true, certDerPreserved={}, subjectPreserved={}",
                                der_preserved, subject_preserved
                            ),
                            if der_preserved && subject_preserved {
                                SignalLevel::Info
                            } else {
                                SignalLevel::Warn
                            },
                        )
                    }
                    Err(status) => advisory_row(
                        "Import marker",
                        format!("update/fetch failed: {}", describe_status(&status)),
                        SignalLevel::Unavailable,
                    ),
                }
            }
            Err(status) => advisory_row(
                "Import marker",
                format!("import unavailable: {}", describe_status(&status)),
                SignalLevel::Unavailable,
            ),
        };
        let _ = self.service.deleteKey(&descriptor);
        row
    }

    fn probe_strongbox_tier(&self) -> ProbeRow {
        if self.quick {
            return advisory_row(
                "StrongBox tier",
                "skipped by --quick".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let strongbox = match self.service.getSecurityLevel(SecurityLevel::STRONGBOX) {
            Ok(strongbox) => strongbox,
            Err(status) => {
                return advisory_row(
                    "StrongBox tier",
                    format!("StrongBox unavailable: {}", describe_status(&status)),
                    SignalLevel::Unavailable,
                );
            }
        };

        let alias = unique_alias("strongbox");
        let descriptor = app_descriptor(&alias);
        let generated = strongbox.generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let fetched = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok());
        let _ = self.service.deleteKey(&descriptor);

        match (generated, fetched) {
            (Ok(metadata), Some(entry)) => advisory_row(
                "StrongBox tier",
                format!(
                    "generateOk=true, generatedLevel={:?}, fetchedLevel={:?}, entryLevelPresent={}",
                    metadata.keySecurityLevel,
                    entry.metadata.keySecurityLevel,
                    entry.iSecurityLevel.is_some()
                ),
                SignalLevel::Info,
            ),
            (Err(status), _) => advisory_row(
                "StrongBox tier",
                format!("StrongBox generation failed: {}", describe_status(&status)),
                SignalLevel::Warn,
            ),
            (Ok(metadata), None) => advisory_row(
                "StrongBox tier",
                format!(
                    "generateOk=true, generatedLevel={:?}, getKeyEntry unavailable",
                    metadata.keySecurityLevel
                ),
                SignalLevel::Unavailable,
            ),
        }
    }

    fn probe_dual_algorithm_attestation(&self) -> ProbeRow {
        if self.quick {
            return advisory_row(
                "Dual algorithm attestation",
                "skipped by --quick".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let ec_alias = unique_alias("dual-ec");
        let rsa_alias = unique_alias("dual-rsa");
        let ec_descriptor = app_descriptor(&ec_alias);
        let rsa_descriptor = app_descriptor(&rsa_alias);
        let ec = self.tee.generateKey(
            &ec_descriptor,
            None,
            &attested_ec_params(b"dual-algorithm-ec"),
            0,
            &[],
        );
        let rsa = self.tee.generateKey(
            &rsa_descriptor,
            None,
            &attested_rsa_params(b"dual-algorithm-rsa"),
            0,
            &[],
        );
        let row = match (ec.as_ref(), rsa.as_ref()) {
            (Ok(ec_metadata), Ok(rsa_metadata)) => {
                let ec_chain = collect_chain_der(ec_metadata);
                let rsa_chain = collect_chain_der(rsa_metadata);
                match (ec_chain, rsa_chain) {
                    (Ok(ec_chain), Ok(rsa_chain)) => {
                        let ec_leaf_sig_oid = certificate_signature_oid(ec_chain.first());
                        let rsa_leaf_sig_oid = certificate_signature_oid(rsa_chain.first());
                        let chains_equal = ec_chain == rsa_chain;
                        advisory_row(
                            "Dual algorithm attestation",
                            format!(
                                "ecCerts={}, rsaCerts={}, ecLeafSigOid={}, rsaLeafSigOid={}, chainsEqual={}",
                                ec_chain.len(),
                                rsa_chain.len(),
                                ec_leaf_sig_oid.unwrap_or_else(|| "unavailable".to_string()),
                                rsa_leaf_sig_oid.unwrap_or_else(|| "unavailable".to_string()),
                                chains_equal
                            ),
                            if chains_equal {
                                SignalLevel::Warn
                            } else {
                                SignalLevel::Info
                            },
                        )
                    }
                    (Err(error), _) | (_, Err(error)) => advisory_row(
                        "Dual algorithm attestation",
                        format!("chain collection unavailable: {error:#}"),
                        SignalLevel::Unavailable,
                    ),
                }
            }
            (Err(status), _) => advisory_row(
                "Dual algorithm attestation",
                format!("EC attestation unavailable: {}", describe_status(status)),
                SignalLevel::Unavailable,
            ),
            (_, Err(status)) => advisory_row(
                "Dual algorithm attestation",
                format!("RSA attestation unavailable: {}", describe_status(status)),
                SignalLevel::Unavailable,
            ),
        };
        let _ = self.service.deleteKey(&ec_descriptor);
        let _ = self.service.deleteKey(&rsa_descriptor);
        row
    }

    fn probe_timing_anomaly(&self) -> ProbeRow {
        if self.quick {
            return advisory_row(
                "Timing anomaly",
                "skipped by --quick".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let alias = unique_alias("timing-anomaly");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let key_descriptor = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok())
            .map(|entry| entry.metadata.key)
            .unwrap_or_else(|| descriptor.clone());

        if generated.is_err() {
            let _ = self.service.deleteKey(&descriptor);
            return advisory_row(
                "Timing anomaly",
                "probe key generation failed".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let mut samples = Vec::new();
        for warmup_index in 0..TIMING_WARMUP_COUNT {
            let payload = format!("warmup-{warmup_index}").into_bytes();
            let _ = self.measure_sign_operation_micros(&key_descriptor, &payload, false);
        }
        for index in 0..TIMING_ANOMALY_SAMPLE_COUNT {
            let payload = format!("timing-sample-{index}").into_bytes();
            if let Some(sample) =
                self.measure_sign_operation_micros(&key_descriptor, &payload, false)
            {
                samples.push(sample);
            }
        }
        let _ = self.service.deleteKey(&descriptor);

        if samples.is_empty() {
            return advisory_row(
                "Timing anomaly",
                "timing samples were unavailable".to_string(),
                SignalLevel::Unavailable,
            );
        }

        samples.sort_by(|left, right| left.partial_cmp(right).unwrap());
        let median = samples[samples.len() / 2];
        let mean = average(&samples);
        let variance = samples
            .iter()
            .map(|sample| {
                let delta = sample - mean;
                delta * delta
            })
            .sum::<f64>()
            / samples.len() as f64;
        let cv = if mean > 0.0 {
            variance.sqrt() / mean
        } else {
            0.0
        };
        let jitter_ratio = if samples.first().copied().unwrap_or(0.0) > 0.0 {
            (samples.last().copied().unwrap_or(median) - samples[0]) / samples[0]
        } else {
            0.0
        };
        let suspicious = median < 100.0 || (median < 200.0 && cv < 0.10 && jitter_ratio < 0.15);

        advisory_row(
            "Timing anomaly",
            format!(
                "median={}us, cv={cv:.2}, jitter={jitter_ratio:.2}",
                median as i32
            ),
            if suspicious {
                SignalLevel::Warn
            } else {
                SignalLevel::Info
            },
        )
    }

    fn probe_operation_pruning(&self) -> ProbeRow {
        if self.quick {
            return advisory_row(
                "Operation pruning",
                "skipped by --quick".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let alias = unique_alias("pruning");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let key_descriptor = generated
            .as_ref()
            .ok()
            .and_then(|_| self.service.getKeyEntry(&descriptor).ok())
            .map(|entry| entry.metadata.key)
            .unwrap_or_else(|| descriptor.clone());

        if generated.is_err() {
            let _ = self.service.deleteKey(&descriptor);
            return advisory_row(
                "Operation pruning",
                "probe key generation failed".to_string(),
                SignalLevel::Unavailable,
            );
        }

        let params = sign_operation_params(false);
        let mut operations = Vec::new();
        for _ in 0..PRUNING_OPERATION_COUNT {
            match self.tee.createOperation(&key_descriptor, &params, false) {
                Ok(response) => {
                    if let Some(operation) = response.iOperation {
                        operations.push(operation);
                    }
                }
                Err(_) => break,
            }
        }

        let mut invalidated = 0usize;
        for operation in &operations {
            match operation.update(b"prune") {
                Ok(_) => {
                    let _ = operation.abort();
                }
                Err(status) if status_is_invalid_operation_handle(&status) => {
                    invalidated += 1;
                }
                Err(_) => {}
            }
        }

        let _ = self.service.deleteKey(&descriptor);
        let suspicious = operations.len() >= PRUNING_OPERATION_COUNT && invalidated == 0;
        advisory_row(
            "Operation pruning",
            format!(
                "operationsCreated={}, invalidatedOperations={invalidated}",
                operations.len()
            ),
            if suspicious {
                SignalLevel::Warn
            } else {
                SignalLevel::Info
            },
        )
    }

    fn raw_service_reply<F>(&self, transaction: u32, write_args: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&mut rsbinder::Parcel) -> rsbinder::Result<()>,
    {
        let binder = self.service.as_binder();
        let proxy = binder
            .as_proxy()
            .context("IKeystoreService binder was unexpectedly local")?;
        let mut data = proxy.prepare_transact(true)?;
        write_args(&mut data)?;
        let reply = proxy
            .submit_transact(transaction, &data, rsbinder::FLAG_CLEAR_BUF)?
            .ok_or_else(|| anyhow!("service transaction returned no reply"))?;
        Ok(parcel_bytes(&reply))
    }

    fn raw_security_level_reply<F>(&self, transaction: u32, write_args: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&mut rsbinder::Parcel) -> rsbinder::Result<()>,
    {
        let binder = self.tee.as_binder();
        let proxy = binder
            .as_proxy()
            .context("IKeystoreSecurityLevel binder was unexpectedly local")?;
        let mut data = proxy.prepare_transact(true)?;
        write_args(&mut data)?;
        let reply = proxy
            .submit_transact(transaction, &data, rsbinder::FLAG_CLEAR_BUF)?
            .ok_or_else(|| anyhow!("security level transaction returned no reply"))?;
        Ok(parcel_bytes(&reply))
    }

    fn create_sign_operation(
        &self,
        key_descriptor: &KeyDescriptor,
        compat: bool,
    ) -> rsbinder::status::Result<CreateOperationResponse> {
        self.tee
            .createOperation(key_descriptor, &sign_operation_params(compat), false)
    }

    fn run_aes_gcm_operation(&self, descriptor: &KeyDescriptor) -> Result<AesGcmObservation> {
        self.tee
            .generateKey(descriptor, None, &aes_gcm_key_params(), 0, &[])
            .context("generateKey failed")?;
        let key_descriptor = self
            .service
            .getKeyEntry(descriptor)
            .map(|entry| entry.metadata.key)
            .unwrap_or_else(|_| descriptor.clone());
        let response = self
            .tee
            .createOperation(&key_descriptor, &aes_gcm_encrypt_operation_params(), false)
            .context("encrypt createOperation failed")?;
        let nonce = response_nonce(&response);
        let nonce_len = nonce.as_ref().map(Vec::len);
        let operation = response
            .iOperation
            .context("encrypt createOperation returned no IKeystoreOperation")?;

        let operation_result = (|| -> Result<AesGcmObservation> {
            let plaintext = b"blind-aosp-aes-gcm";
            let aad = b"blind-aad";
            operation
                .updateAad(aad)
                .context("encrypt updateAad failed")?;
            let update = operation
                .update(plaintext)
                .context("encrypt update failed")?;
            let finish = operation
                .finish(None, None)
                .context("encrypt finish failed")?;
            let ciphertext = concat_operation_outputs(update, finish);
            let nonce = nonce.context("encrypt response did not return a nonce")?;
            let decrypt_response = self
                .tee
                .createOperation(
                    &key_descriptor,
                    &aes_gcm_decrypt_operation_params(&nonce),
                    false,
                )
                .context("decrypt createOperation failed")?;
            let decrypt_operation = decrypt_response
                .iOperation
                .context("decrypt createOperation returned no IKeystoreOperation")?;
            decrypt_operation
                .updateAad(aad)
                .context("decrypt updateAad failed")?;
            let decrypt_update = decrypt_operation
                .update(&ciphertext)
                .context("decrypt update failed")?;
            let decrypt_finish = decrypt_operation
                .finish(None, None)
                .context("decrypt finish failed")?;
            let decrypted = concat_operation_outputs(decrypt_update, decrypt_finish);
            let decrypt_matches = aes_gcm_round_trip_matches(plaintext, &decrypted);
            Ok(AesGcmObservation {
                operation_finished: true,
                ciphertext_bytes: ciphertext.len(),
                nonce_len,
                decrypt_matches,
                detail: format!(
                    "ciphertext={}B, nonceLen={}, decryptMatches={}",
                    ciphertext.len(),
                    nonce_len
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "missing".to_string()),
                    decrypt_matches
                ),
            })
        })();

        if operation_result.is_err() {
            let _ = operation.abort();
        }
        operation_result
    }

    fn probe_update_aad_rejection(
        &self,
        key_descriptor: &KeyDescriptor,
        compat_fallback: bool,
    ) -> Option<bool> {
        self.create_sign_operation(key_descriptor, compat_fallback)
            .ok()
            .and_then(|response| response.iOperation)
            .map(|operation| {
                let result = match operation.updateAad(b"aad") {
                    Ok(_) => false,
                    Err(status) => status.exception_code() == ExceptionCode::ServiceSpecific,
                };
                let _ = operation.abort();
                result
            })
    }

    fn probe_oversized_update_rejection(
        &self,
        key_descriptor: &KeyDescriptor,
        compat_fallback: bool,
    ) -> Option<bool> {
        self.create_sign_operation(key_descriptor, compat_fallback)
            .ok()
            .and_then(|response| response.iOperation)
            .map(|operation| {
                let payload = vec![0x41; OVERSIZED_OPERATION_INPUT];
                let result = match operation.update(&payload) {
                    Ok(_) => false,
                    Err(status) => status.exception_code() == ExceptionCode::ServiceSpecific,
                };
                let _ = operation.abort();
                result
            })
    }

    fn probe_abort_invalidates_handle(
        &self,
        key_descriptor: &KeyDescriptor,
        compat_fallback: bool,
    ) -> Option<bool> {
        self.create_sign_operation(key_descriptor, compat_fallback)
            .ok()
            .and_then(|response| response.iOperation)
            .map(|operation| {
                let _ = operation.abort();
                match operation.update(b"after-abort") {
                    Ok(_) => false,
                    Err(status) => status_is_invalid_operation_handle(&status),
                }
            })
    }

    fn run_binder_chain_cycle(&self, alias: &str) -> Result<BinderChainCycle> {
        let descriptor = app_descriptor(alias);
        let metadata = self
            .tee
            .generateKey(
                &descriptor,
                None,
                &attested_ec_params(b"binder-chain"),
                0,
                &[],
            )
            .context("generateKey failed")?;
        let generated_chain = collect_chain_der(&metadata)?;
        let entry = self
            .service
            .getKeyEntry(&descriptor)
            .context("getKeyEntry failed")?;
        let fetched_chain = collect_chain_der_from_response(&entry)?;
        self.service
            .deleteKey(&descriptor)
            .context("deleteKey failed")?;
        let delete_removed_alias = self.service.getKeyEntry(&descriptor).is_err();
        Ok(BinderChainCycle {
            generate_matches_get: generated_chain == fetched_chain,
            suspicious_leaf_issuer_spki: leaf_issuer_spki_matches(&generated_chain)?,
            delete_removed_alias,
        })
    }

    fn measure_sign_operation_micros(
        &self,
        key_descriptor: &KeyDescriptor,
        payload: &[u8],
        compat: bool,
    ) -> Option<f64> {
        let start = Instant::now();
        let response = self.create_sign_operation(key_descriptor, compat).ok()?;
        let operation = response.iOperation?;
        if operation.update(payload).is_err() {
            return None;
        }
        if operation.finish(None, None).is_err() {
            return None;
        }
        Some(start.elapsed().as_secs_f64() * 1_000_000.0)
    }
}

#[derive(Debug, Clone, Copy)]
struct BinderChainCycle {
    generate_matches_get: bool,
    suspicious_leaf_issuer_spki: bool,
    delete_removed_alias: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DerSanityInspection {
    ok: bool,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AesGcmObservation {
    operation_finished: bool,
    ciphertext_bytes: usize,
    nonce_len: Option<usize>,
    decrypt_matches: bool,
    detail: String,
}

fn scored_row(
    label: impl Into<String>,
    value: impl Into<String>,
    level: SignalLevel,
    category: ScoredCategory,
) -> ProbeRow {
    ProbeRow::new(label, value, level, Some(category))
}

fn advisory_row(
    label: impl Into<String>,
    value: impl Into<String>,
    level: SignalLevel,
) -> ProbeRow {
    ProbeRow::new(label, value, level, None)
}

fn unique_alias(label: &str) -> String {
    format!(
        "blind_probe_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    )
}

fn app_descriptor(alias: &str) -> KeyDescriptor {
    KeyDescriptor {
        domain: Domain::APP,
        alias: Some(alias.to_string()),
        ..Default::default()
    }
}

fn kp(tag: Tag, value: KeyParameterValue) -> KeyParameter {
    KeyParameter { tag, value }
}

fn signing_ec_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::EC)),
        kp(Tag::EC_CURVE, KeyParameterValue::EcCurve(EcCurve::P_256)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(256)),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        kp(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
    ]
}

fn attested_ec_params(challenge: &[u8]) -> Vec<KeyParameter> {
    let mut params = signing_ec_params();
    params.push(kp(
        Tag::ATTESTATION_CHALLENGE,
        KeyParameterValue::Blob(challenge.to_vec()),
    ));
    params
}

fn imported_ec_params() -> Vec<KeyParameter> {
    signing_ec_params()
}

fn attested_rsa_params(challenge: &[u8]) -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::RSA)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(2048)),
        kp(
            Tag::RSA_PUBLIC_EXPONENT,
            KeyParameterValue::LongInteger(65_537),
        ),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        kp(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::RSA_PKCS1_1_5_SIGN),
        ),
        kp(
            Tag::ATTESTATION_CHALLENGE,
            KeyParameterValue::Blob(challenge.to_vec()),
        ),
    ]
}

fn sign_operation_params(compat: bool) -> Vec<KeyParameter> {
    let mut params = vec![
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
        ),
        kp(Tag::DIGEST, KeyParameterValue::Digest(Digest::SHA_2_256)),
    ];
    if compat {
        params.push(kp(
            Tag::ALGORITHM,
            KeyParameterValue::Algorithm(Algorithm::EC),
        ));
    }
    params
}

fn aes_gcm_key_params() -> Vec<KeyParameter> {
    vec![
        kp(Tag::ALGORITHM, KeyParameterValue::Algorithm(Algorithm::AES)),
        kp(Tag::KEY_SIZE, KeyParameterValue::Integer(128)),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        ),
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
        ),
        kp(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        kp(Tag::MIN_MAC_LENGTH, KeyParameterValue::Integer(128)),
    ]
}

fn aes_gcm_encrypt_operation_params() -> Vec<KeyParameter> {
    vec![
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT),
        ),
        kp(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        kp(Tag::MAC_LENGTH, KeyParameterValue::Integer(128)),
    ]
}

fn aes_gcm_decrypt_operation_params(nonce: &[u8]) -> Vec<KeyParameter> {
    vec![
        kp(
            Tag::PURPOSE,
            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
        ),
        kp(
            Tag::BLOCK_MODE,
            KeyParameterValue::BlockMode(BlockMode::GCM),
        ),
        kp(
            Tag::PADDING,
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
        ),
        kp(Tag::MAC_LENGTH, KeyParameterValue::Integer(128)),
        kp(Tag::NONCE, KeyParameterValue::Blob(nonce.to_vec())),
    ]
}

fn response_nonce(response: &CreateOperationResponse) -> Option<Vec<u8>> {
    response
        .parameters
        .as_ref()?
        .keyParameter
        .iter()
        .find_map(|param| {
            (param.tag == Tag::NONCE).then(|| match &param.value {
                KeyParameterValue::Blob(bytes) => Some(bytes.clone()),
                _ => None,
            })?
        })
}

fn concat_operation_outputs(update: Option<Vec<u8>>, finish: Option<Vec<u8>>) -> Vec<u8> {
    let mut output = update.unwrap_or_default();
    if let Some(finish) = finish {
        output.extend_from_slice(&finish);
    }
    output
}

fn aes_gcm_round_trip_matches(expected_plaintext: &[u8], decrypted: &[u8]) -> bool {
    expected_plaintext == decrypted
}

fn parcel_bytes(parcel: &rsbinder::Parcel) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(parcel.as_ptr(), parcel.data_size()) }.to_vec()
}

fn status_is_unknown_transaction(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::UnknownTransaction
}

fn status_is_invalid_operation_handle(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::ServiceSpecific
        && status.service_specific_error() == ErrorCode::INVALID_OPERATION_HANDLE.0
}

fn describe_status(status: &Status) -> String {
    format!(
        "exception={:?}, serviceSpecific={}, transactionError={:?}",
        status.exception_code(),
        status.service_specific_error(),
        status.transaction_error()
    )
}

fn collect_chain_der_from_response(response: &KeyEntryResponse) -> Result<Vec<Vec<u8>>> {
    collect_chain_der(&response.metadata)
}

fn collect_chain_der(metadata: &KeyMetadata) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    if let Some(leaf) = metadata.certificate.as_ref() {
        certs.push(leaf.clone());
    }

    let mut remaining = metadata.certificateChain.as_deref().unwrap_or_default();
    while !remaining.is_empty() {
        let mut reader =
            SliceReader::new(remaining).context("failed to create DER reader for chain bytes")?;
        let _ = Certificate::decode(&mut reader).context("failed to decode chain certificate")?;
        let remaining_len = usize::try_from(reader.remaining_len())
            .context("failed to convert DER remaining length to usize")?;
        let consumed = remaining
            .len()
            .checked_sub(remaining_len)
            .ok_or_else(|| anyhow!("chain reader consumed more data than available"))?;
        certs.push(remaining[..consumed].to_vec());
        remaining = &remaining[consumed..];
    }

    Ok(certs)
}

fn inspect_der_attestation_sanity(
    generated_chain: &[Vec<u8>],
    fetched_chain: Option<&[Vec<u8>]>,
    expected_challenge: &[u8],
) -> Result<DerSanityInspection> {
    if generated_chain.is_empty() {
        bail!("generated certificate chain was empty");
    }

    for (index, certificate_der) in generated_chain.iter().enumerate() {
        let mut reader = SliceReader::new(certificate_der)
            .with_context(|| format!("failed to create DER reader for cert {index}"))?;
        let _ = Certificate::decode(&mut reader)
            .with_context(|| format!("failed to decode DER certificate {index}"))?;
        if reader.remaining_len() != der::Length::ZERO {
            bail!("certificate {index} had trailing DER bytes");
        }
    }

    let leaf = generated_chain
        .first()
        .ok_or_else(|| anyhow!("generated certificate chain was empty"))?;
    let certificate = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    let extension_present = find_attestation_extension(&certificate).is_ok();
    let challenge = extract_attestation_challenge_from_leaf_certificate(leaf)
        .context("failed to extract attestation challenge")?;
    let challenge_matches = challenge == expected_challenge;
    let fetched_matches = fetched_chain
        .map(|chain| chain == generated_chain)
        .unwrap_or(false);
    let fetched_count = fetched_chain.map_or(0, |chain| chain.len());
    let ok = extension_present && challenge_matches && fetched_matches;

    Ok(DerSanityInspection {
        ok,
        detail: format!(
            "generatedCerts={}, fetchedCerts={}, fetchedMatches={}, attestationExtension={}, challengeMatches={}",
            generated_chain.len(),
            fetched_count,
            fetched_matches,
            extension_present,
            challenge_matches
        ),
    })
}

fn summarize_issuer_dns(chain: &[Vec<u8>]) -> Result<String> {
    if chain.is_empty() {
        return Err(anyhow!("certificate chain was empty"));
    }

    let mut parts = Vec::with_capacity(chain.len());
    for (index, certificate_der) in chain.iter().enumerate() {
        let certificate = Certificate::from_der(certificate_der)
            .with_context(|| format!("failed to parse certificate at chain index {index}"))?;
        parts.push(format!(
            "cert{index}.issuer={}",
            certificate.tbs_certificate.issuer
        ));
    }

    Ok(format!("certCount={}, {}", chain.len(), parts.join(" | ")))
}

fn chain_has_droid_ca_marker(chain: &[Vec<u8>]) -> bool {
    chain.iter().any(|certificate_der| {
        Certificate::from_der(certificate_der)
            .map(|certificate| {
                let subject = certificate.tbs_certificate.subject.to_string();
                let issuer = certificate.tbs_certificate.issuer.to_string();
                subject.contains("Droid CA") || issuer.contains("Droid CA")
            })
            .unwrap_or(false)
    })
}

fn full_chain_blob(metadata: &KeyMetadata) -> Option<Vec<u8>> {
    if metadata.certificate.is_none() && metadata.certificateChain.is_none() {
        return None;
    }
    let mut blob = Vec::new();
    if let Some(leaf) = metadata.certificate.as_ref() {
        blob.extend_from_slice(leaf);
    }
    if let Some(chain) = metadata.certificateChain.as_ref() {
        blob.extend_from_slice(chain);
    }
    Some(blob)
}

fn leaf_issuer_spki_matches(chain: &[Vec<u8>]) -> Result<bool> {
    if chain.len() < 2 {
        return Ok(false);
    }
    let leaf = Certificate::from_der(&chain[0]).context("failed to parse leaf certificate")?;
    let issuer = Certificate::from_der(&chain[1]).context("failed to parse issuer certificate")?;
    let leaf_spki = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode leaf SPKI")?;
    let issuer_spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode issuer SPKI")?;
    Ok(leaf_spki == issuer_spki)
}

fn sign_payload(
    probe: &BlindProbe,
    key_descriptor: &KeyDescriptor,
    payload: &[u8],
) -> Result<Vec<u8>> {
    sign_payload_with_level(&probe.tee, key_descriptor, payload)
}

fn sign_payload_with_level(
    level: &Strong<dyn IKeystoreSecurityLevel>,
    key_descriptor: &KeyDescriptor,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let response = level
        .createOperation(key_descriptor, &sign_operation_params(false), false)
        .or_else(|_| level.createOperation(key_descriptor, &sign_operation_params(true), false))
        .context("createOperation failed for both minimal and compatibility params")?;
    let operation = response
        .iOperation
        .context("createOperation returned no IKeystoreOperation")?;
    operation.update(payload).context("update() failed")?;
    let signature = operation
        .finish(None, None)
        .context("finish() failed")?
        .context("finish() returned no signature bytes")?;
    Ok(signature)
}

fn leaf_subject_spki(leaf: &[u8]) -> Result<Vec<u8>> {
    let certificate = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode leaf SPKI")
}

fn result_label<T>(result: &rsbinder::status::Result<T>) -> String {
    match result {
        Ok(_) => "ok".to_string(),
        Err(status) => format!("err({})", describe_status(status)),
    }
}

fn inspect_boot_consistency(leaf: &[u8]) -> Result<BootConsistencyObservation> {
    let certificate = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    let extension = find_attestation_extension(&certificate)?;
    let root = parse_root_of_trust(extension)?;
    let runtime_property = read_system_property("ro.boot.vbmeta.digest");
    let runtime_props_available = runtime_property.is_ok();
    let runtime_vbmeta_digest = runtime_property
        .ok()
        .flatten()
        .and_then(|value| normalize_hex(Some(value.as_str())));
    let attested_boot_hash = normalize_hex(Some(hex_encode(&root.verified_boot_hash).as_str()));
    let compare_runtime_digest = matches!(
        root.verified_boot_state,
        ParsedBootState::Verified | ParsedBootState::SelfSigned
    );
    let verified_boot_hash_all_zeros =
        compare_runtime_digest && is_all_zero_hex(&hex_encode(&root.verified_boot_hash));
    let verified_boot_key_all_zeros =
        compare_runtime_digest && is_all_zero_hex(&hex_encode(&root.verified_boot_key));
    let vbmeta_digest_missing_while_attested_hash_present = compare_runtime_digest
        && attested_boot_hash.is_some()
        && runtime_props_available
        && runtime_vbmeta_digest.is_none();
    let vbmeta_digest_mismatch = compare_runtime_digest
        && attested_boot_hash.is_some()
        && runtime_vbmeta_digest.is_some()
        && attested_boot_hash != runtime_vbmeta_digest;
    let comparison_performed =
        compare_runtime_digest && attested_boot_hash.is_some() && runtime_vbmeta_digest.is_some();
    let hard_anomaly = vbmeta_digest_mismatch
        || vbmeta_digest_missing_while_attested_hash_present
        || verified_boot_hash_all_zeros
        || verified_boot_key_all_zeros;

    let detail = if vbmeta_digest_mismatch {
        "attested verifiedBootHash did not match ro.boot.vbmeta.digest".to_string()
    } else if vbmeta_digest_missing_while_attested_hash_present {
        "attested verifiedBootHash was present but ro.boot.vbmeta.digest was empty".to_string()
    } else if verified_boot_hash_all_zeros {
        "attested verifiedBootHash was all zeros".to_string()
    } else if verified_boot_key_all_zeros {
        "attested verifiedBootKey was all zeros".to_string()
    } else if !runtime_props_available {
        "ro.boot.vbmeta.digest was unavailable to the current process".to_string()
    } else if !compare_runtime_digest {
        format!(
            "boot state {:?} recorded without runtime vbmeta comparison",
            root.verified_boot_state
        )
    } else if attested_boot_hash.is_none() {
        "attestation did not expose verifiedBootHash for runtime comparison".to_string()
    } else if runtime_vbmeta_digest.is_none() {
        "runtime vbmeta digest was unavailable for comparison".to_string()
    } else {
        "attested verifiedBootHash matched ro.boot.vbmeta.digest".to_string()
    };

    Ok(BootConsistencyObservation {
        comparison_performed,
        runtime_props_available,
        hard_anomaly,
        detail,
    })
}

fn find_attestation_extension(certificate: &Certificate) -> Result<&[u8]> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| anyhow!("attestation leaf had no extensions"))?;
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == ANDROID_ATTESTATION_OID)
        .ok_or_else(|| anyhow!("Android attestation extension missing"))?;
    Ok(extension.extn_value.as_bytes())
}

fn parse_root_of_trust(bytes: &[u8]) -> Result<RootOfTrustView> {
    let (top_level, rest) = parse_tlv(bytes)?;
    ensure_sequence(top_level, "attestation extension")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after attestation extension");
    }

    let mut fields = top_level.value;
    for _ in 0..6 {
        let (_, next) = parse_tlv(fields)?;
        fields = next;
    }
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (hardware_enforced, rest) = parse_tlv(fields)?;
    ensure_sequence(hardware_enforced, "hardwareEnforced")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after hardwareEnforced");
    }

    let mut authorizations = hardware_enforced.value;
    while !authorizations.is_empty() {
        let (field, next) = parse_tlv(authorizations)?;
        authorizations = next;
        if field.class != TlvClass::ContextSpecific || field.tag_number != 704 {
            continue;
        }

        let (root, rest) = parse_tlv(field.value)?;
        ensure_sequence(root, "RootOfTrust")?;
        if !rest.is_empty() {
            bail!("unexpected trailing data after RootOfTrust");
        }
        let mut root_fields = root.value;
        let (verified_boot_key, next) = parse_tlv(root_fields)?;
        ensure_octet_string(verified_boot_key, "RootOfTrust.verifiedBootKey")?;
        root_fields = next;
        let (device_locked, next) = parse_tlv(root_fields)?;
        let device_locked = parse_boolean(device_locked, "RootOfTrust.deviceLocked")?;
        root_fields = next;
        let (verified_boot_state, next) = parse_tlv(root_fields)?;
        let verified_boot_state =
            parse_boot_state(verified_boot_state, "RootOfTrust.verifiedBootState")?;
        root_fields = next;
        let (verified_boot_hash, rest) = parse_tlv(root_fields)?;
        ensure_octet_string(verified_boot_hash, "RootOfTrust.verifiedBootHash")?;
        if !rest.is_empty() {
            bail!("unexpected trailing data after RootOfTrust.verifiedBootHash");
        }
        return Ok(RootOfTrustView {
            verified_boot_key: verified_boot_key.value.to_vec(),
            device_locked,
            verified_boot_state,
            verified_boot_hash: verified_boot_hash.value.to_vec(),
        });
    }

    bail!("RootOfTrust tag 704 missing from authorization list")
}

fn parse_boolean(field: crate::attestation::Tlv<'_>, label: &str) -> Result<bool> {
    if field.class != TlvClass::Universal || field.constructed || field.tag_number != 1 {
        bail!("{label} was not a DER BOOLEAN");
    }
    match field.value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        [value] => Ok(*value != 0),
        _ => bail!("{label} used an invalid BOOLEAN encoding"),
    }
}

fn parse_boot_state(field: crate::attestation::Tlv<'_>, label: &str) -> Result<ParsedBootState> {
    if field.class != TlvClass::Universal || field.constructed || field.tag_number != 10 {
        bail!("{label} was not a DER ENUMERATED");
    }
    let value = field
        .value
        .iter()
        .fold(0u32, |acc, byte| (acc << 8) | u32::from(*byte));
    Ok(match value {
        0 => ParsedBootState::Verified,
        1 => ParsedBootState::SelfSigned,
        2 => ParsedBootState::Unverified,
        3 => ParsedBootState::Failed,
        _ => ParsedBootState::Unknown,
    })
}

fn read_system_property(name: &str) -> Result<Option<String>> {
    #[cfg(target_os = "android")]
    {
        let c_name = CString::new(name).context("property name contained an interior NUL byte")?;
        let mut buffer = [0 as c_char; 128];
        let len = unsafe { __system_property_get(c_name.as_ptr(), buffer.as_mut_ptr()) };
        if len < 0 {
            bail!("__system_property_get failed for {name}");
        }
        if len == 0 {
            return Ok(None);
        }
        let value = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
            .to_str()
            .context("system property value was not valid UTF-8")?
            .trim()
            .to_string();
        Ok((!value.is_empty()).then_some(value))
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = name;
        bail!("system properties are only supported on Android")
    }
}

fn normalize_hex(raw: Option<&str>) -> Option<String> {
    raw.map(|value| {
        value
            .chars()
            .filter(|ch| !ch.is_whitespace() && *ch != ':')
            .map(|ch| ch.to_ascii_lowercase())
            .collect::<String>()
    })
    .filter(|value| !value.is_empty())
    .filter(|value| value.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn is_all_zero_hex(raw: &str) -> bool {
    let Some(normalized) = normalize_hex(Some(raw)) else {
        return false;
    };
    normalized.chars().all(|ch| ch == '0')
}

fn inspect_certificate_chain(chain: &[Vec<u8>]) -> Result<CertificateChainInspection> {
    if chain.is_empty() {
        bail!("certificate chain was empty");
    }

    let certificates = chain
        .iter()
        .enumerate()
        .map(|(index, der)| {
            Certificate::from_der(der)
                .with_context(|| format!("failed to parse certificate at chain index {index}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let issuer_links_ok = certificates
        .windows(2)
        .all(|pair| pair[0].tbs_certificate.issuer == pair[1].tbs_certificate.subject);
    let algorithm_ids_aligned = certificates.iter().all(algorithm_identifiers_aligned);
    let root_self_issued = certificates
        .last()
        .map(|certificate| {
            certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer
        })
        .unwrap_or(false);

    let mut signatures_supported = true;
    let mut signatures_ok = true;
    for pair in certificates.windows(2) {
        match verify_certificate_signed_by(&pair[0], &pair[1]) {
            Ok(true) => {}
            Ok(false) => {
                signatures_ok = false;
                break;
            }
            Err(_) => {
                signatures_supported = false;
                break;
            }
        }
    }

    Ok(CertificateChainInspection {
        verdict: if !issuer_links_ok || !algorithm_ids_aligned || !signatures_ok {
            CertificateChainVerdict::Fail
        } else if signatures_supported {
            CertificateChainVerdict::Pass
        } else {
            CertificateChainVerdict::Unavailable
        },
        detail: format!(
            "certCount={}, issuerLinks={}, algorithmIdsAligned={}, signaturesVerified={}, rootSelfIssued={}",
            chain.len(),
            issuer_links_ok,
            algorithm_ids_aligned,
            if signatures_supported {
                signatures_ok.to_string()
            } else {
                "unsupported".to_string()
            },
            root_self_issued
        ),
    })
}

fn algorithm_identifiers_aligned(certificate: &Certificate) -> bool {
    certificate.signature_algorithm.oid == certificate.tbs_certificate.signature.oid
}

fn verify_certificate_signed_by(child: &Certificate, issuer: &Certificate) -> Result<bool> {
    let issuer_spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode issuer SPKI")?;
    let tbs = child
        .tbs_certificate
        .to_der()
        .context("failed to encode child TBSCertificate")?;
    let signature = child
        .signature
        .as_bytes()
        .context("certificate signature BIT STRING was not byte-aligned")?;
    verify_signed_message(
        child.signature_algorithm.oid.to_string().as_str(),
        &issuer_spki,
        &tbs,
        signature,
    )
}

fn verify_signature_with_certificate(
    certificate_der: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let certificate =
        Certificate::from_der(certificate_der).context("failed to parse leaf certificate")?;
    let leaf_spki = certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .context("failed to encode leaf SPKI")?;
    verify_with_algorithm(
        &signature::ECDSA_P256_SHA256_ASN1,
        &leaf_spki,
        payload,
        signature,
    )
}

fn verify_signed_message(
    signature_oid: &str,
    spki_der: &[u8],
    message: &[u8],
    signed_bytes: &[u8],
) -> Result<bool> {
    let algorithm = signature_algorithm(signature_oid)?;
    verify_with_algorithm(algorithm, spki_der, message, signed_bytes)
}

fn signature_algorithm(signature_oid: &str) -> Result<&'static dyn VerificationAlgorithm> {
    match signature_oid {
        OID_ECDSA_WITH_SHA256 => Ok(&signature::ECDSA_P256_SHA256_ASN1),
        OID_ECDSA_WITH_SHA384 => Ok(&signature::ECDSA_P384_SHA384_ASN1),
        OID_RSA_WITH_SHA256 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        OID_RSA_WITH_SHA384 => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
        OID_RSA_WITH_SHA512 => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
        other => bail!("unsupported certificate signature algorithm OID {other}"),
    }
}

fn verify_with_algorithm(
    algorithm: &'static dyn VerificationAlgorithm,
    spki_der: &[u8],
    message: &[u8],
    signed_bytes: &[u8],
) -> Result<bool> {
    match UnparsedPublicKey::new(algorithm, spki_der).verify(message, signed_bytes) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn measure_get_key_entry_millis(
    service: &Strong<dyn IKeystoreService>,
    descriptor: &KeyDescriptor,
) -> Option<f64> {
    let start = Instant::now();
    service.getKeyEntry(descriptor).ok()?;
    Some(start.elapsed().as_secs_f64() * 1_000.0)
}

fn average(samples: &[f64]) -> f64 {
    samples.iter().sum::<f64>() / samples.len() as f64
}

fn bool_label(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unavailable",
    }
}

fn option_i32_label(value: Option<i32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_string())
}

fn descriptor_aliases(entries: &[KeyDescriptor]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|descriptor| descriptor.alias.clone())
        .collect()
}

fn alias_positions(aliases: &[String], alias0: &str, alias1: &str) -> Option<(usize, usize)> {
    let pos0 = aliases.iter().position(|alias| alias == alias0)?;
    let pos1 = aliases.iter().position(|alias| alias == alias1)?;
    Some((pos0, pos1))
}

fn raw_reply_fingerprint_suspicious(fingerprint: &ServiceSpecificReplyFingerprint) -> bool {
    fingerprint.java_shortcut_detected
        || !fingerprint.native_style_response
        || !fingerprint.expected_error_matched
}

fn raw_reply_case_label(fingerprint: &ServiceSpecificReplyFingerprint) -> String {
    let shape = if fingerprint.java_shortcut_detected {
        "shortcut"
    } else if fingerprint.native_style_response {
        "native"
    } else {
        "unknown"
    };
    format!(
        "{}({})",
        shape,
        fingerprint
            .error_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    )
}

fn marker_certificate_der() -> Result<Vec<u8>> {
    STANDARD
        .decode(RAW_ERROR_UPDATE_CERT_DER_B64)
        .context("failed to decode marker certificate DER")
}

fn import_marker_private_key_der() -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| anyhow!("failed to generate ephemeral EC marker key"))?;
    Ok(pkcs8.as_ref().to_vec())
}

fn certificate_signature_oid(certificate_der: Option<&Vec<u8>>) -> Option<String> {
    certificate_der
        .and_then(|der| Certificate::from_der(der).ok())
        .map(|certificate| certificate.signature_algorithm.oid.to_string())
}

struct RawReplyCapture {
    label: &'static str,
    expected_error_code: i32,
    raw: Result<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootConsistencyObservation {
    comparison_performed: bool,
    runtime_props_available: bool,
    hard_anomaly: bool,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RootOfTrustView {
    verified_boot_key: Vec<u8>,
    device_locked: bool,
    verified_boot_state: ParsedBootState,
    verified_boot_hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedBootState {
    Verified,
    SelfSigned,
    Unverified,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertificateChainInspection {
    verdict: CertificateChainVerdict,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateChainVerdict {
    Pass,
    Fail,
    Unavailable,
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aosp_tamper::model::{ProbeRow, ScoredCategory, SignalLevel};
    use rcgen::{CertificateParams, CustomExtension, DnType, KeyPair};
    use serde_json::Value;

    #[test]
    fn json_output_fields_stay_stable() {
        let output = score::evaluate(
            vec![ProbeRow::new(
                "Challenge",
                "challenge matched",
                SignalLevel::Pass,
                Some(ScoredCategory::PolicyHard),
            )],
            vec![ProbeRow::new(
                "MODULE_HASH",
                "info",
                SignalLevel::Info,
                None,
            )],
        );
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(
            json.get("headline").and_then(Value::as_str),
            Some(output.headline.as_str())
        );
        assert!(json.get("summary").is_some());
        assert!(json.get("verdict").is_some());
        assert!(json.get("tamper_score").is_some());
        assert!(json.get("policy_hard_count").is_some());
        assert!(json.get("policy_soft_count").is_some());
        assert!(json.get("supplementary_count").is_some());
        assert!(json.get("rows").is_some());
        assert!(json.get("advisory_rows").is_some());
    }

    #[test]
    fn issuer_dn_summary_uses_rfc4514_style_output() {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "Blind Probe Test Issuer");
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let summary = summarize_issuer_dns(&[cert.der().to_vec()]).unwrap();
        assert!(summary.contains("certCount=1"));
        assert!(summary.contains("cert0.issuer=CN=Blind Probe Test Issuer"));
    }

    #[test]
    fn route_marker_detects_droid_ca_only_when_chain_contains_it() {
        let normal = self_signed_cert_der("Blind Probe Test Issuer");
        let droid = self_signed_cert_der("Droid CA");
        assert!(!chain_has_droid_ca_marker(&[normal]));
        assert!(chain_has_droid_ca_marker(&[droid]));
    }

    #[test]
    fn normalize_hex_accepts_colons_and_whitespace() {
        assert_eq!(
            normalize_hex(Some("AA:bb cc\nDD")),
            Some("aabbccdd".to_string())
        );
        assert_eq!(normalize_hex(Some("not-hex")), None);
    }

    #[test]
    fn certificate_chain_inspection_accepts_single_self_issued_root() {
        let cert = self_signed_cert_der("Chain Root");
        let inspection = inspect_certificate_chain(&[cert]).unwrap();
        assert_eq!(inspection.verdict, CertificateChainVerdict::Pass);
        assert!(inspection.detail.contains("rootSelfIssued=true"));
    }

    #[test]
    fn certificate_chain_inspection_rejects_mismatched_issuer_links() {
        let leaf = self_signed_cert_der("Leaf");
        let issuer = self_signed_cert_der("Other");
        let inspection = inspect_certificate_chain(&[leaf, issuer]).unwrap();
        assert_eq!(inspection.verdict, CertificateChainVerdict::Fail);
        assert!(inspection.detail.contains("issuerLinks=false"));
    }

    #[test]
    fn der_sanity_rejects_empty_chain() {
        let error = inspect_der_attestation_sanity(&[], None, b"challenge").unwrap_err();
        assert!(error.to_string().contains("empty"));
    }

    #[test]
    fn der_sanity_rejects_malformed_der() {
        let error =
            inspect_der_attestation_sanity(&[b"not-der".to_vec()], None, b"challenge").unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to decode DER certificate 0"));
    }

    #[test]
    fn der_sanity_rejects_missing_attestation_extension() {
        let leaf = self_signed_cert_der("No Attestation");
        let error = inspect_der_attestation_sanity(
            std::slice::from_ref(&leaf),
            Some(std::slice::from_ref(&leaf)),
            b"challenge",
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to extract attestation challenge"));
    }

    #[test]
    fn der_sanity_reports_challenge_mismatch_without_pinning_issuer() {
        let leaf = build_leaf_with_attestation_extension(b"actual-challenge");
        let inspection = inspect_der_attestation_sanity(
            std::slice::from_ref(&leaf),
            Some(std::slice::from_ref(&leaf)),
            b"expected-challenge",
        )
        .unwrap();
        assert!(!inspection.ok);
        assert!(inspection.detail.contains("attestationExtension=true"));
        assert!(inspection.detail.contains("challengeMatches=false"));
    }

    #[test]
    fn der_sanity_accepts_matching_attestation_extension_and_chain_split() {
        let leaf = build_leaf_with_attestation_extension(b"expected-challenge");
        let inspection = inspect_der_attestation_sanity(
            std::slice::from_ref(&leaf),
            Some(std::slice::from_ref(&leaf)),
            b"expected-challenge",
        )
        .unwrap();
        assert!(inspection.ok);
        assert!(inspection.detail.contains("fetchedMatches=true"));
    }

    #[test]
    fn aes_gcm_params_match_keymint_operation_shape() {
        let key_params = aes_gcm_key_params();
        let encrypt_params = aes_gcm_encrypt_operation_params();
        let decrypt_params = aes_gcm_decrypt_operation_params(&[1, 2, 3, 4]);
        assert!(key_params
            .iter()
            .any(|param| param.tag == Tag::MIN_MAC_LENGTH));
        assert!(key_params.iter().any(|param| {
            param.tag == Tag::PURPOSE
                && matches!(
                    &param.value,
                    KeyParameterValue::KeyPurpose(KeyPurpose::ENCRYPT)
                )
        }));
        assert!(key_params.iter().any(|param| {
            param.tag == Tag::PURPOSE
                && matches!(
                    &param.value,
                    KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT)
                )
        }));
        assert!(encrypt_params
            .iter()
            .any(|param| param.tag == Tag::MAC_LENGTH));
        assert!(decrypt_params.iter().any(|param| param.tag == Tag::NONCE));
        assert!(key_params.iter().any(|param| {
            param.tag == Tag::BLOCK_MODE
                && matches!(&param.value, KeyParameterValue::BlockMode(BlockMode::GCM))
        }));
        assert!(encrypt_params.iter().any(|param| {
            param.tag == Tag::PADDING
                && matches!(
                    &param.value,
                    KeyParameterValue::PaddingMode(PaddingMode::NONE)
                )
        }));
    }

    #[test]
    fn aes_gcm_output_concat_and_round_trip_helpers_match_plaintext() {
        let ciphertext = concat_operation_outputs(Some(vec![1, 2]), Some(vec![3, 4]));
        assert_eq!(ciphertext, [1, 2, 3, 4]);
        assert_eq!(concat_operation_outputs(None, Some(vec![9])), [9]);
        assert!(aes_gcm_round_trip_matches(b"plain", b"plain"));
        assert!(!aes_gcm_round_trip_matches(b"plain", b"other"));
    }

    #[test]
    fn marker_material_decodes_and_subject_is_preserved() {
        let private_key = import_marker_private_key_der().unwrap();
        let certificate = marker_certificate_der().unwrap();
        assert!(private_key.starts_with(&[0x30]));
        let parsed = Certificate::from_der(&certificate).unwrap();
        assert!(parsed
            .tbs_certificate
            .subject
            .to_string()
            .contains(IMPORT_MARKER_SUBJECT));
    }

    fn self_signed_cert_der(common_name: &str) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    fn build_leaf_with_attestation_extension(challenge: &[u8]) -> Vec<u8> {
        let extension = build_test_attestation_extension(challenge);
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                extension,
            ));
        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    fn build_test_attestation_extension(challenge: &[u8]) -> Vec<u8> {
        let software_enforced = encode_tlv(TlvClass::Universal, true, 16, &[]);
        let hardware_enforced = encode_tlv(TlvClass::Universal, true, 16, &[]);
        encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &[
                encode_tlv(TlvClass::Universal, false, 2, &[0x03]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x01]),
                encode_tlv(TlvClass::Universal, false, 2, &[0x64]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x01]),
                encode_tlv(TlvClass::Universal, false, 4, challenge),
                encode_tlv(TlvClass::Universal, false, 4, b"unique"),
                software_enforced,
                hardware_enforced,
            ]
            .concat(),
        )
    }

    fn encode_tlv(class: TlvClass, constructed: bool, tag_number: u32, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let class_bits = match class {
            TlvClass::Universal => 0u8,
            TlvClass::Application => 1u8 << 6,
            TlvClass::ContextSpecific => 2u8 << 6,
            TlvClass::Private => 3u8 << 6,
        };
        let constructed_bit = if constructed { 0x20 } else { 0x00 };
        if tag_number < 31 {
            out.push(class_bits | constructed_bit | tag_number as u8);
        } else {
            out.push(class_bits | constructed_bit | 0x1f);
            let mut stack = Vec::new();
            let mut value_bits = tag_number;
            stack.push((value_bits & 0x7f) as u8);
            value_bits >>= 7;
            while value_bits != 0 {
                stack.push(((value_bits & 0x7f) as u8) | 0x80);
                value_bits >>= 7;
            }
            for byte in stack.iter().rev() {
                out.push(*byte);
            }
        }
        encode_length(value.len(), &mut out);
        out.extend_from_slice(value);
        out
    }

    fn encode_length(length: usize, out: &mut Vec<u8>) {
        if length < 0x80 {
            out.push(length as u8);
            return;
        }

        let bytes = length.to_be_bytes();
        let first_non_zero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let encoded = &bytes[first_non_zero..];
        out.push(0x80 | encoded.len() as u8);
        out.extend_from_slice(encoded);
    }
}
