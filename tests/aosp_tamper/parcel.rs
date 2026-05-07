#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplySnapshot {
    pub data_size: usize,
    pub raw_prefix: String,
    pub exception_code: Option<i32>,
    pub second_word: Option<i32>,
    pub trailing_ints: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingKeyReplyFingerprint {
    pub java_hook_detected: bool,
    pub native_style_response: bool,
    pub error_code: Option<i32>,
    pub message_length: Option<i32>,
    pub detail: String,
    pub raw_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpecificReplyFingerprint {
    pub java_shortcut_detected: bool,
    pub native_style_response: bool,
    pub error_code: Option<i32>,
    pub expected_error_code: Option<i32>,
    pub expected_error_matched: bool,
    pub message_length: Option<i32>,
    pub detail: String,
    pub raw_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateKeyReplyParcelParseResult {
    pub parse_succeeded: bool,
    pub authorization_count: Option<usize>,
    pub last_authorization_sec_level: Option<u32>,
    pub last_authorization_tag: Option<u32>,
    pub last_authorization_union_tag: Option<u32>,
    pub last_authorization_has_unknown_union_tag: bool,
    pub modification_time_ms: Option<u64>,
    pub raw_prefix: String,
    pub detail: String,
}

pub fn raw_prefix(bytes: &[u8], max_bytes: usize) -> String {
    bytes
        .iter()
        .take(max_bytes)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn snapshot_reply(bytes: &[u8]) -> ReplySnapshot {
    let ints = bytes
        .chunks_exact(INT_SIZE_BYTES)
        .map(read_i32_le)
        .collect::<Vec<_>>();
    ReplySnapshot {
        data_size: bytes.len(),
        raw_prefix: raw_prefix(bytes, DEFAULT_PREFIX_BYTES),
        exception_code: ints.first().copied(),
        second_word: ints.get(1).copied(),
        trailing_ints: ints.iter().skip(2).copied().collect(),
    }
}

pub fn classify_missing_key_reply(bytes: &[u8]) -> MissingKeyReplyFingerprint {
    let parsed = classify_service_specific_reply(bytes, Some(RESPONSE_KEY_NOT_FOUND));
    MissingKeyReplyFingerprint {
        java_hook_detected: parsed.java_shortcut_detected,
        native_style_response: parsed.native_style_response,
        error_code: parsed.error_code,
        message_length: parsed.message_length,
        detail: if parsed.java_shortcut_detected {
            "Keystore2 reply skipped the String16 slot and jumped straight to KEY_NOT_FOUND."
                .to_string()
        } else if parsed.native_style_response {
            format!(
                "Native-style Keystore2 reply msgLen={} error={}",
                parsed
                    .message_length
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "n/a".into()),
                parsed
                    .error_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "n/a".into())
            )
        } else {
            parsed.detail
        },
        raw_prefix: parsed.raw_prefix,
    }
}

pub fn classify_service_specific_reply(
    bytes: &[u8],
    expected_error_code: Option<i32>,
) -> ServiceSpecificReplyFingerprint {
    let snapshot = snapshot_reply(bytes);
    if snapshot.data_size < 8 {
        return ServiceSpecificReplyFingerprint {
            java_shortcut_detected: false,
            native_style_response: false,
            error_code: None,
            expected_error_code,
            expected_error_matched: false,
            message_length: None,
            detail: "Binder reply was too small to fingerprint.".to_string(),
            raw_prefix: snapshot.raw_prefix,
        };
    }

    let exception_code = snapshot.exception_code;
    if exception_code != Some(EX_SERVICE_SPECIFIC) {
        return ServiceSpecificReplyFingerprint {
            java_shortcut_detected: false,
            native_style_response: false,
            error_code: None,
            expected_error_code,
            expected_error_matched: false,
            message_length: None,
            detail: match exception_code {
                Some(0) => "Transaction unexpectedly succeeded.".to_string(),
                Some(code) => format!("Binder reply used exception code {code}."),
                None => "Binder reply did not expose an exception code.".to_string(),
            },
            raw_prefix: snapshot.raw_prefix,
        };
    }

    let Some(second_word) = snapshot.second_word else {
        return ServiceSpecificReplyFingerprint {
            java_shortcut_detected: false,
            native_style_response: false,
            error_code: None,
            expected_error_code,
            expected_error_matched: false,
            message_length: None,
            detail: "Binder reply was missing the secondary fingerprint word.".to_string(),
            raw_prefix: snapshot.raw_prefix,
        };
    };

    if Some(second_word) == expected_error_code {
        return ServiceSpecificReplyFingerprint {
            java_shortcut_detected: true,
            native_style_response: false,
            error_code: Some(second_word),
            expected_error_code,
            expected_error_matched: true,
            message_length: None,
            detail: format!(
                "service-specific shortcut response; error={second_word}; rawPrefix={}",
                snapshot.raw_prefix
            ),
            raw_prefix: snapshot.raw_prefix,
        };
    }

    if second_word == STRING16_NULL || second_word >= 0 {
        let error_code =
            service_specific_error_code_from_native_reply(&snapshot, expected_error_code);
        return ServiceSpecificReplyFingerprint {
            java_shortcut_detected: false,
            native_style_response: true,
            error_code,
            expected_error_code,
            expected_error_matched: expected_error_code
                .map(|expected| error_code == Some(expected))
                .unwrap_or(error_code.is_some()),
            message_length: Some(second_word),
            detail: format!(
                "native service-specific response; msgLen={}; error={}",
                second_word,
                error_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "n/a".into())
            ),
            raw_prefix: snapshot.raw_prefix,
        };
    }

    ServiceSpecificReplyFingerprint {
        java_shortcut_detected: false,
        native_style_response: false,
        error_code: None,
        expected_error_code,
        expected_error_matched: false,
        message_length: None,
        detail: format!("Binder reply used an unknown serialization fingerprint ({second_word})."),
        raw_prefix: snapshot.raw_prefix,
    }
}

fn service_specific_error_code_from_native_reply(
    snapshot: &ReplySnapshot,
    expected_error_code: Option<i32>,
) -> Option<i32> {
    if let Some(expected) = expected_error_code {
        if snapshot.trailing_ints.iter().any(|code| *code == expected) {
            return Some(expected);
        }
    }

    if snapshot.second_word == Some(STRING16_NULL) {
        snapshot.trailing_ints.get(1).copied()
    } else {
        snapshot.trailing_ints.last().copied()
    }
}

pub fn parse_generate_key_reply(raw_reply: &[u8]) -> GenerateKeyReplyParcelParseResult {
    let prefix = raw_prefix(raw_reply, DEFAULT_PREFIX_BYTES);
    if raw_reply.len() < MIN_REPLY_BYTES {
        return generate_failure(raw_reply.len(), prefix, "reply_too_short");
    }

    let parse = || -> ResultTuple {
        let exception_code = read_i32_at(raw_reply, 0)?;
        if exception_code != 0 {
            return Err(format!("unexpected_exception_code={exception_code}"));
        }

        let authorization_count = read_u32_at(raw_reply, AUTHORIZATION_COUNT_OFFSET)? as usize;
        if !(1..=MAX_AUTHORIZATION_COUNT).contains(&authorization_count) {
            return Err(format!(
                "authorization_count_out_of_range={authorization_count}"
            ));
        }

        let last_offset = AUTHORIZATION_LOGICAL_START_OFFSET
            + ((authorization_count - 1) * AUTHORIZATION_SLOT_SIZE);
        if raw_reply.len() < last_offset + AUTHORIZATION_SLOT_SIZE {
            return Err("authorization_block_truncated".to_string());
        }

        let last_sec_level = read_u32_at(raw_reply, last_offset)?;
        let last_tag = read_u32_at(raw_reply, last_offset + AUTHORIZATION_TAG_OFFSET)?;
        let last_union_tag = read_u32_at(raw_reply, last_offset + AUTHORIZATION_UNION_TAG_OFFSET)?;
        let final_offset = last_offset + AUTHORIZATION_SLOT_SIZE;
        let modification_time_ms = find_modification_time_signature(raw_reply, final_offset);
        let has_unknown_union_tag = !KNOWN_KEY_PARAMETER_VALUE_UNION_TAGS.contains(&last_union_tag);

        Ok(GenerateKeyReplyParcelParseResult {
            parse_succeeded: true,
            authorization_count: Some(authorization_count),
            last_authorization_sec_level: Some(last_sec_level),
            last_authorization_tag: Some(last_tag),
            last_authorization_union_tag: Some(last_union_tag),
            last_authorization_has_unknown_union_tag: has_unknown_union_tag,
            modification_time_ms,
            raw_prefix: prefix.clone(),
            detail: format!(
                "parseSucceeded=true;reason=ok;rawSize={};rawPrefix={};authorizationCount={};lastAuthorizationSecLevel={};lastAuthorizationTag={};lastAuthorizationUnionTag={};lastAuthorizationHasUnknownUnionTag={};modificationTimeMs={};finalOffset={}",
                raw_reply.len(),
                prefix,
                authorization_count,
                last_sec_level,
                last_tag,
                last_union_tag,
                has_unknown_union_tag,
                modification_time_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".into()),
                final_offset
            ),
        })
    };

    match parse() {
        Ok(parsed) => parsed,
        Err(reason) => generate_failure(raw_reply.len(), prefix, &reason),
    }
}

pub fn generate_mode_fingerprint_matched(parsed: &GenerateKeyReplyParcelParseResult) -> bool {
    parsed.parse_succeeded
        && parsed.last_authorization_sec_level == Some(256)
        && parsed.last_authorization_has_unknown_union_tag
        && parsed.modification_time_ms == Some(TARGET_MODIFICATION_TIME_MS)
}

type ResultTuple = Result<GenerateKeyReplyParcelParseResult, String>;

fn generate_failure(
    size: usize,
    prefix: String,
    reason: &str,
) -> GenerateKeyReplyParcelParseResult {
    GenerateKeyReplyParcelParseResult {
        parse_succeeded: false,
        authorization_count: None,
        last_authorization_sec_level: None,
        last_authorization_tag: None,
        last_authorization_union_tag: None,
        last_authorization_has_unknown_union_tag: false,
        modification_time_ms: None,
        raw_prefix: prefix.clone(),
        detail: format!(
            "parseSucceeded=false;reason={reason};rawSize={size};rawPrefix={prefix};authorizationCount=null;lastAuthorizationSecLevel=null;lastAuthorizationTag=null;lastAuthorizationUnionTag=null;lastAuthorizationHasUnknownUnionTag=null;modificationTimeMs=null;finalOffset=null"
        ),
    }
}

fn read_i32_le(bytes: &[u8]) -> i32 {
    i32::from_le_bytes(bytes.try_into().expect("chunk size is 4"))
}

fn read_i32_at(bytes: &[u8], offset: usize) -> Result<i32, String> {
    if offset + INT_SIZE_BYTES > bytes.len() {
        return Err(format!("int_out_of_bounds@{offset}"));
    }
    Ok(read_i32_le(&bytes[offset..offset + INT_SIZE_BYTES]))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    read_i32_at(bytes, offset).map(|value| value as u32)
}

fn find_modification_time_signature(raw_reply: &[u8], start_offset: usize) -> Option<u64> {
    let search_end = find_first_der_offset(raw_reply, start_offset).unwrap_or(raw_reply.len());
    let mut offset = start_offset;
    while offset + MODIFICATION_TIME_SIGNATURE_PREFIX.len() <= search_end {
        if raw_reply[offset..offset + MODIFICATION_TIME_SIGNATURE_PREFIX.len()]
            == MODIFICATION_TIME_SIGNATURE_PREFIX
        {
            return Some(TARGET_MODIFICATION_TIME_MS);
        }
        offset += INT_SIZE_BYTES;
    }
    None
}

fn find_first_der_offset(raw_reply: &[u8], start_offset: usize) -> Option<usize> {
    let mut offset = start_offset;
    while offset + 1 < raw_reply.len() {
        if raw_reply[offset] == DER_SEQUENCE_PREFIX_0
            && raw_reply[offset + 1] == DER_SEQUENCE_PREFIX_1
        {
            return Some(offset);
        }
        offset += INT_SIZE_BYTES;
    }
    None
}

const DEFAULT_PREFIX_BYTES: usize = 32;
const INT_SIZE_BYTES: usize = 4;
const MAX_AUTHORIZATION_COUNT: usize = 256;
const MIN_REPLY_BYTES: usize = 48;
const AUTHORIZATION_COUNT_OFFSET: usize = 44;
const AUTHORIZATION_LOGICAL_START_OFFSET: usize = 32;
const AUTHORIZATION_SLOT_SIZE: usize = 16;
const AUTHORIZATION_TAG_OFFSET: usize = 4;
const AUTHORIZATION_UNION_TAG_OFFSET: usize = 8;
const TARGET_MODIFICATION_TIME_MS: u64 = 4_294_967_297;
const DER_SEQUENCE_PREFIX_0: u8 = 0x30;
const DER_SEQUENCE_PREFIX_1: u8 = 0x82;
const EX_SERVICE_SPECIFIC: i32 = -8;
const STRING16_NULL: i32 = -1;
const RESPONSE_KEY_NOT_FOUND: i32 = 7;
const KNOWN_KEY_PARAMETER_VALUE_UNION_TAGS: [u32; 15] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
const MODIFICATION_TIME_SIGNATURE_PREFIX: [u8; 16] = [
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_java_hook_style_missing_key_reply() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EX_SERVICE_SPECIFIC.to_le_bytes());
        bytes.extend_from_slice(&RESPONSE_KEY_NOT_FOUND.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        let parsed = classify_missing_key_reply(&bytes);
        assert!(parsed.java_hook_detected);
        assert!(!parsed.native_style_response);
        assert_eq!(parsed.error_code, Some(RESPONSE_KEY_NOT_FOUND));
    }

    #[test]
    fn classifies_native_style_service_specific_reply() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EX_SERVICE_SPECIFIC.to_le_bytes());
        bytes.extend_from_slice(&STRING16_NULL.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&RESPONSE_KEY_NOT_FOUND.to_le_bytes());
        let parsed = classify_missing_key_reply(&bytes);
        assert!(!parsed.java_hook_detected);
        assert!(parsed.native_style_response);
        assert_eq!(parsed.message_length, Some(STRING16_NULL));
    }

    #[test]
    fn classifies_raw_error_matrix_service_specific_shapes() {
        let cases = [
            ("missing-key", RESPONSE_KEY_NOT_FOUND),
            ("delete", RESPONSE_KEY_NOT_FOUND),
            ("update", RESPONSE_KEY_NOT_FOUND),
            ("createOperation", RESPONSE_KEY_NOT_FOUND),
        ];

        for (label, expected_error) in cases {
            let parsed = classify_service_specific_reply(
                &native_service_specific_reply(expected_error),
                Some(expected_error),
            );
            assert!(
                parsed.native_style_response,
                "{label} should keep native Binder Status shape"
            );
            assert!(!parsed.java_shortcut_detected);
            assert_eq!(parsed.error_code, Some(expected_error));
            assert!(parsed.expected_error_matched);
        }
    }

    #[test]
    fn service_specific_classifier_marks_shortcut_and_wrong_error() {
        let shortcut = classify_service_specific_reply(
            &java_shortcut_service_specific_reply(RESPONSE_KEY_NOT_FOUND),
            Some(RESPONSE_KEY_NOT_FOUND),
        );
        assert!(shortcut.java_shortcut_detected);
        assert!(!shortcut.native_style_response);
        assert!(shortcut.expected_error_matched);

        let wrong = classify_service_specific_reply(
            &native_service_specific_reply(20),
            Some(RESPONSE_KEY_NOT_FOUND),
        );
        assert!(wrong.native_style_response);
        assert_eq!(wrong.error_code, Some(20));
        assert!(!wrong.expected_error_matched);
    }

    #[test]
    fn service_specific_classifier_handles_empty_message_slot() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EX_SERVICE_SPECIFIC.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&RESPONSE_KEY_NOT_FOUND.to_le_bytes());

        let parsed = classify_service_specific_reply(&bytes, Some(RESPONSE_KEY_NOT_FOUND));
        assert!(parsed.native_style_response);
        assert_eq!(parsed.message_length, Some(0));
        assert_eq!(parsed.error_code, Some(RESPONSE_KEY_NOT_FOUND));
    }

    #[test]
    fn generate_mode_parser_matches_duck_signature() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&0i32.to_le_bytes());
        bytes[AUTHORIZATION_COUNT_OFFSET..AUTHORIZATION_COUNT_OFFSET + 4]
            .copy_from_slice(&(1i32).to_le_bytes());
        bytes[AUTHORIZATION_LOGICAL_START_OFFSET..AUTHORIZATION_LOGICAL_START_OFFSET + 4]
            .copy_from_slice(&(256i32).to_le_bytes());
        bytes[AUTHORIZATION_LOGICAL_START_OFFSET + AUTHORIZATION_TAG_OFFSET
            ..AUTHORIZATION_LOGICAL_START_OFFSET + AUTHORIZATION_TAG_OFFSET + 4]
            .copy_from_slice(&(0x22i32).to_le_bytes());
        bytes[AUTHORIZATION_LOGICAL_START_OFFSET + AUTHORIZATION_UNION_TAG_OFFSET
            ..AUTHORIZATION_LOGICAL_START_OFFSET + AUTHORIZATION_UNION_TAG_OFFSET + 4]
            .copy_from_slice(&(99i32).to_le_bytes());
        bytes[48..64].copy_from_slice(&MODIFICATION_TIME_SIGNATURE_PREFIX);
        bytes.extend_from_slice(&[DER_SEQUENCE_PREFIX_0, DER_SEQUENCE_PREFIX_1, 0x00, 0x10]);

        let parsed = parse_generate_key_reply(&bytes);
        assert!(parsed.parse_succeeded);
        assert!(generate_mode_fingerprint_matched(&parsed));
    }

    #[test]
    fn generate_mode_parser_distinguishes_non_matches() {
        let mut bytes = vec![0u8; 64];
        bytes[0..4].copy_from_slice(&0i32.to_le_bytes());
        bytes[AUTHORIZATION_COUNT_OFFSET..AUTHORIZATION_COUNT_OFFSET + 4]
            .copy_from_slice(&(1i32).to_le_bytes());
        bytes[AUTHORIZATION_LOGICAL_START_OFFSET..AUTHORIZATION_LOGICAL_START_OFFSET + 4]
            .copy_from_slice(&(0i32).to_le_bytes());
        bytes[AUTHORIZATION_LOGICAL_START_OFFSET + AUTHORIZATION_UNION_TAG_OFFSET
            ..AUTHORIZATION_LOGICAL_START_OFFSET + AUTHORIZATION_UNION_TAG_OFFSET + 4]
            .copy_from_slice(&(4i32).to_le_bytes());

        let parsed = parse_generate_key_reply(&bytes);
        assert!(parsed.parse_succeeded);
        assert!(!generate_mode_fingerprint_matched(&parsed));
    }

    fn native_service_specific_reply(error_code: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EX_SERVICE_SPECIFIC.to_le_bytes());
        bytes.extend_from_slice(&STRING16_NULL.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes.extend_from_slice(&error_code.to_le_bytes());
        bytes
    }

    fn java_shortcut_service_specific_reply(error_code: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&EX_SERVICE_SPECIFIC.to_le_bytes());
        bytes.extend_from_slice(&error_code.to_le_bytes());
        bytes.extend_from_slice(&0i32.to_le_bytes());
        bytes
    }
}
