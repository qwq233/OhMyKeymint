use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use der::{Decode, Encode, Reader, SliceReader};
use hex::encode as hex_encode;
use kmr_common::crypto::Sha256;
use kmr_crypto_boring::sha256::BoringSha256;
use rsbinder::{hub, ExceptionCode, Status, StatusCode, Strong};
use x509_cert::Certificate;

use crate::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose,
    SecurityLevel::SecurityLevel, Tag::Tag,
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
    binder_chain_has_issue, filter_outlier_pairs, list_entries_batched_cursor_echoed,
    list_entries_batched_expected_next_missing, metadata_key_is_normalized,
    metadata_shape_is_valid, native_flags_have_issue, paired_diff_series,
    pure_cert_top_level_security_level_exposed, timing_side_channel_suspicious, BinderChainView,
    ListEntriesBatchedView, MetadataKeyView, MetadataShapeView, NativeTraceFlags,
    PureCertLevelView,
};
use crate::aosp_tamper::model::{ProbeOutput, ProbeRow, ScoredCategory, SignalLevel};
use crate::aosp_tamper::native;
use crate::aosp_tamper::parcel::{
    classify_missing_key_reply, generate_mode_fingerprint_matched, parse_generate_key_reply,
};
use crate::aosp_tamper::score;
use crate::attestation::{
    extract_attestation_challenge_from_leaf_certificate,
    extract_verified_boot_hash_from_leaf_certificate,
};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const OVERSIZED_CHALLENGE_SIZES: [usize; 3] = [256, 512, 4096];
const TIMING_WARMUP_COUNT: usize = 5;
const TIMING_SAMPLE_COUNT: usize = 1000;
const TIMING_ANOMALY_SAMPLE_COUNT: usize = 12;
const PRUNING_OPERATION_COUNT: usize = 18;
const OVERSIZED_OPERATION_INPUT: usize = 0x8001;

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
        rows.push(self.probe_oversized_challenge());
        rows.push(self.probe_keystore2_reply_fingerprint());
        rows.push(self.probe_generate_mode_fingerprint());

        let (metadata_key, metadata_shape) = self.probe_metadata_semantics();
        rows.push(metadata_key);
        rows.push(metadata_shape);

        let (pure_cert_level, pure_cert_metadata) = self.probe_pure_certificate_security_level();
        rows.push(pure_cert_level);
        advisory_rows.push(pure_cert_metadata);

        rows.push(self.probe_list_entries());
        rows.push(self.probe_list_entries_batched());
        rows.push(self.probe_update_path());
        rows.push(self.probe_operation_path());
        rows.push(self.probe_binder_chain());
        rows.push(self.probe_timing_side_channel());
        rows.push(self.probe_native());

        advisory_rows.push(self.probe_timing_anomaly());
        advisory_rows.push(self.probe_operation_pruning());
        advisory_rows.push(self.probe_module_hash());

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
                scored_row(
                    "Pure cert level",
                    "unable to build certificate-only entry payload".to_string(),
                    SignalLevel::Unavailable,
                    ScoredCategory::Supplementary,
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
                    scored_row(
                        "Pure cert level",
                        format!(
                            "topLevelPresent={}, metadataLevel={:?}",
                            view.top_level_security_level_present, entry.metadata.keySecurityLevel
                        ),
                        if pure_cert_top_level_security_level_exposed(view) {
                            SignalLevel::Fail
                        } else {
                            SignalLevel::Pass
                        },
                        ScoredCategory::Supplementary,
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
                    scored_row(
                        "Pure cert level",
                        format!("probe unavailable: {detail}"),
                        SignalLevel::Unavailable,
                        ScoredCategory::Supplementary,
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

    fn probe_list_entries(&self) -> ProbeRow {
        let before_count = self.service.getNumberOfEntries(Domain::APP, 0);
        let alias = unique_alias("list");
        let descriptor = app_descriptor(&alias);
        let generated = self
            .tee
            .generateKey(&descriptor, None, &signing_ec_params(), 0, &[]);
        let list_after_create = self.service.listEntries(Domain::APP, 0);
        let count_after_create = self.service.getNumberOfEntries(Domain::APP, 0);
        let deleted = self.service.deleteKey(&descriptor);
        let list_after_delete = self.service.listEntries(Domain::APP, 0);
        let count_after_delete = self.service.getNumberOfEntries(Domain::APP, 0);

        let outcome = before_count
            .as_ref()
            .ok()
            .copied()
            .zip(count_after_create.as_ref().ok().copied())
            .zip(count_after_delete.as_ref().ok().copied())
            .map(|((before, created), after_delete)| {
                let visible_after_create = list_after_create
                    .as_ref()
                    .map(|entries| alias_present(entries, &alias))
                    .unwrap_or(false);
                let visible_after_delete = list_after_delete
                    .as_ref()
                    .map(|entries| alias_present(entries, &alias))
                    .unwrap_or(true);
                generated.is_ok()
                    && deleted.is_ok()
                    && visible_after_create
                    && !visible_after_delete
                    && created == before + 1
                    && after_delete == before
            });

        scored_row(
            "listEntries",
            format!(
                "generated={}, deleted={}, countBefore={}, countAfterCreate={}, countAfterDelete={}",
                generated.is_ok(),
                deleted.is_ok(),
                before_count
                    .as_ref()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|_| "err".into()),
                count_after_create
                    .as_ref()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|_| "err".into()),
                count_after_delete
                    .as_ref()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|_| "err".into()),
            ),
            match outcome {
                Some(true) => SignalLevel::Pass,
                Some(false) => SignalLevel::Fail,
                None => SignalLevel::Unavailable,
            },
            ScoredCategory::Supplementary,
        )
    }

    fn probe_list_entries_batched(&self) -> ProbeRow {
        let alias0 = unique_alias("batched-0");
        let alias1 = unique_alias("batched-1");
        let descriptor0 = app_descriptor(&alias0);
        let descriptor1 = app_descriptor(&alias1);
        let _ = self
            .tee
            .generateKey(&descriptor0, None, &signing_ec_params(), 0, &[]);
        let _ = self
            .tee
            .generateKey(&descriptor1, None, &signing_ec_params(), 0, &[]);
        let result = self
            .service
            .listEntriesBatched(Domain::APP, 0, Some(alias0.as_str()));
        let _ = self.service.deleteKey(&descriptor0);
        let _ = self.service.deleteKey(&descriptor1);

        match result {
            Ok(entries) => {
                let aliases = entries
                    .iter()
                    .filter_map(|descriptor| descriptor.alias.clone())
                    .collect::<Vec<_>>();
                let view = ListEntriesBatchedView {
                    cursor_echoed: aliases.iter().any(|alias| alias == &alias0),
                    expected_next_missing: !aliases.iter().any(|alias| alias == &alias1),
                };
                let level = if list_entries_batched_cursor_echoed(view) {
                    SignalLevel::Fail
                } else if list_entries_batched_expected_next_missing(view) {
                    SignalLevel::Warn
                } else {
                    SignalLevel::Pass
                };
                scored_row(
                    "listEntriesBatched",
                    format!(
                        "cursorEchoed={}, expectedNextMissing={}, aliasCount={}",
                        view.cursor_echoed,
                        view.expected_next_missing,
                        aliases.len()
                    ),
                    level,
                    ScoredCategory::Supplementary,
                )
            }
            Err(status) if status_is_unknown_transaction(&status) => scored_row(
                "listEntriesBatched",
                "transaction unavailable on this surface".to_string(),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
            Err(status) => scored_row(
                "listEntriesBatched",
                format!("probe failed: {}", describe_status(&status)),
                SignalLevel::Unavailable,
                ScoredCategory::Supplementary,
            ),
        }
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

    fn probe_native(&self) -> ProbeRow {
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
        scored_row(
            "Native",
            result.detail,
            level,
            ScoredCategory::Supplementary,
        )
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

    fn probe_module_hash(&self) -> ProbeRow {
        match self
            .service
            .getSupplementaryAttestationInfo(Tag::MODULE_HASH)
        {
            Ok(der) if der.len() > 32 => {
                let digest = BoringSha256 {}
                    .hash(&der)
                    .map(hex_encode)
                    .unwrap_or_else(|_| "sha256_failed".into());
                advisory_row(
                    "MODULE_HASH",
                    format!("derLen={}, sha256={digest}", der.len()),
                    SignalLevel::Info,
                )
            }
            Ok(der) => advisory_row(
                "MODULE_HASH",
                format!("derLen={} looked too short for module info", der.len()),
                SignalLevel::Warn,
            ),
            Err(status)
                if status_is_info_not_available(&status)
                    || status_is_unknown_transaction(&status) =>
            {
                advisory_row(
                    "MODULE_HASH",
                    format!("not exposed: {}", describe_status(&status)),
                    SignalLevel::Warn,
                )
            }
            Err(status) => advisory_row(
                "MODULE_HASH",
                format!("probe failed: {}", describe_status(&status)),
                SignalLevel::Warn,
            ),
        }
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
        let delete_removed_alias = self
            .service
            .listEntries(Domain::APP, 0)
            .map(|entries| !alias_present(&entries, alias))
            .unwrap_or(false);
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

fn parcel_bytes(parcel: &rsbinder::Parcel) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(parcel.as_ptr(), parcel.data_size()) }.to_vec()
}

fn status_is_unknown_transaction(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::UnknownTransaction
}

fn status_is_info_not_available(status: &Status) -> bool {
    status.exception_code() == ExceptionCode::ServiceSpecific
        && status.service_specific_error() == ResponseCode::INFO_NOT_AVAILABLE.0
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

fn alias_present(entries: &[KeyDescriptor], expected_alias: &str) -> bool {
    entries
        .iter()
        .any(|descriptor| descriptor.alias.as_deref() == Some(expected_alias))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aosp_tamper::model::{ProbeRow, ScoredCategory, SignalLevel};
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
}
