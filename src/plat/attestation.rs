use anyhow::{anyhow, bail, Context, Result};
use x509_cert::der::{asn1::ObjectIdentifier, Decode};
use x509_cert::Certificate;

pub const ANDROID_ATTESTATION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const ROOT_OF_TRUST_TAG: u32 = 704;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlvClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub class: TlvClass,
    pub constructed: bool,
    pub tag_number: u32,
    pub value: &'a [u8],
}

pub fn extract_attestation_challenge_from_leaf_certificate(leaf: &[u8]) -> Result<Vec<u8>> {
    let certificate = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    let extension = find_attestation_extension(&certificate)?;
    extract_attestation_challenge_from_attestation_extension(extension)
}

pub fn extract_verified_boot_hash_from_leaf_certificate(leaf: &[u8]) -> Result<[u8; 32]> {
    let certificate = Certificate::from_der(leaf).context("failed to parse attestation leaf")?;
    let extension = find_attestation_extension(&certificate)?;
    extract_verified_boot_hash_from_attestation_extension(extension)
}

pub fn extract_attestation_challenge_from_attestation_extension(bytes: &[u8]) -> Result<Vec<u8>> {
    let (challenge, _) = parse_attestation_extension(bytes)?;
    Ok(challenge.to_vec())
}

pub fn extract_verified_boot_hash_from_attestation_extension(bytes: &[u8]) -> Result<[u8; 32]> {
    let (_, hardware_enforced) = parse_attestation_extension(bytes)?;
    extract_verified_boot_hash_from_authorization_list(hardware_enforced)
}

pub fn parse_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if input.is_empty() {
        bail!("unexpected end of DER input");
    }

    let first = input[0];
    let class = match first >> 6 {
        0 => TlvClass::Universal,
        1 => TlvClass::Application,
        2 => TlvClass::ContextSpecific,
        _ => TlvClass::Private,
    };
    let constructed = (first & 0x20) != 0;
    let mut tag_number = u32::from(first & 0x1f);
    let mut offset = 1usize;

    if tag_number == 0x1f {
        tag_number = 0;
        loop {
            if offset >= input.len() {
                bail!("truncated high-tag DER field");
            }
            let byte = input[offset];
            offset += 1;
            tag_number = (tag_number << 7) | u32::from(byte & 0x7f);
            if (byte & 0x80) == 0 {
                break;
            }
        }
    }

    let (length, length_bytes) = parse_der_length(&input[offset..])?;
    offset += length_bytes;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| anyhow!("DER length overflow"))?;
    if end > input.len() {
        bail!("DER field exceeds remaining input");
    }

    Ok((
        Tlv {
            class,
            constructed,
            tag_number,
            value: &input[offset..end],
        },
        &input[end..],
    ))
}

pub fn parse_der_length(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        bail!("missing DER length");
    }
    let first = input[0];
    if (first & 0x80) == 0 {
        return Ok((usize::from(first), 1));
    }

    let count = usize::from(first & 0x7f);
    if count == 0 {
        bail!("indefinite DER lengths are not supported");
    }
    if count > std::mem::size_of::<usize>() || input.len() < count + 1 {
        bail!("invalid DER length encoding");
    }

    let mut value = 0usize;
    for byte in &input[1..=count] {
        value = (value << 8) | usize::from(*byte);
    }
    Ok((value, count + 1))
}

pub fn ensure_sequence(field: Tlv<'_>, label: &str) -> Result<()> {
    if field.class == TlvClass::Universal && field.constructed && field.tag_number == 16 {
        Ok(())
    } else {
        bail!("{label} is not a DER SEQUENCE")
    }
}

pub fn ensure_octet_string(field: Tlv<'_>, label: &str) -> Result<()> {
    if field.class == TlvClass::Universal && !field.constructed && field.tag_number == 4 {
        Ok(())
    } else {
        bail!("{label} is not a DER OCTET STRING")
    }
}

fn find_attestation_extension(certificate: &Certificate) -> Result<&[u8]> {
    let extensions = certificate
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| anyhow!("attestation leaf has no extensions"))?;
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == ANDROID_ATTESTATION_OID)
        .ok_or_else(|| anyhow!("Android attestation extension missing"))?;
    Ok(extension.extn_value.as_bytes())
}

fn parse_attestation_extension(bytes: &[u8]) -> Result<(&[u8], &[u8])> {
    let (top_level, rest) = parse_tlv(bytes)?;
    ensure_sequence(top_level, "attestation extension")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after attestation extension");
    }

    let mut fields = top_level.value;
    for _ in 0..4 {
        let (_, next) = parse_tlv(fields)?;
        fields = next;
    }

    let (challenge, next) = parse_tlv(fields)?;
    ensure_octet_string(challenge, "attestationChallenge")?;
    fields = next;

    let (_, next) = parse_tlv(fields)?;
    fields = next;

    let (_, next) = parse_tlv(fields)?;
    fields = next;

    let (hardware_enforced, rest) = parse_tlv(fields)?;
    ensure_sequence(hardware_enforced, "hardwareEnforced")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after hardwareEnforced");
    }

    Ok((challenge.value, hardware_enforced.value))
}

fn extract_verified_boot_hash_from_authorization_list(mut bytes: &[u8]) -> Result<[u8; 32]> {
    while !bytes.is_empty() {
        let (field, rest) = parse_tlv(bytes)?;
        bytes = rest;
        if field.class == TlvClass::ContextSpecific && field.tag_number == ROOT_OF_TRUST_TAG {
            return extract_verified_boot_hash_from_root_of_trust(field.value);
        }
    }

    Err(anyhow!(
        "RootOfTrust tag 704 missing from authorization list"
    ))
}

fn extract_verified_boot_hash_from_root_of_trust(bytes: &[u8]) -> Result<[u8; 32]> {
    let (sequence, rest) = parse_tlv(bytes)?;
    ensure_sequence(sequence, "RootOfTrust")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after RootOfTrust");
    }

    let mut fields = sequence.value;
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (_, next) = parse_tlv(fields)?;
    fields = next;
    let (verified_boot_hash, rest) = parse_tlv(fields)?;
    ensure_octet_string(verified_boot_hash, "RootOfTrust.verifiedBootHash")?;
    if !rest.is_empty() {
        bail!("unexpected trailing data after verifiedBootHash");
    }
    if verified_boot_hash.value.len() != 32 {
        bail!(
            "verifiedBootHash must be 32 bytes, got {}",
            verified_boot_hash.value.len()
        );
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(verified_boot_hash.value);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, CustomExtension, KeyPair};

    #[test]
    fn extracts_challenge_from_leaf_certificate() {
        let expected = b"blind-aosp-probe".to_vec();
        let leaf = build_leaf_with_attestation_extension(&expected, [0xabu8; 32]);
        let parsed = extract_attestation_challenge_from_leaf_certificate(&leaf).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn extracts_verified_boot_hash_from_leaf_certificate() {
        let expected = [0x5cu8; 32];
        let leaf = build_leaf_with_attestation_extension(b"challenge", expected);
        let parsed = extract_verified_boot_hash_from_leaf_certificate(&leaf).unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn missing_root_of_trust_is_rejected() {
        let extension = encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &[
                encode_tlv(TlvClass::Universal, false, 2, &[0x03]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x01]),
                encode_tlv(TlvClass::Universal, false, 2, &[0x64]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x01]),
                encode_tlv(TlvClass::Universal, false, 4, b"challenge"),
                encode_tlv(TlvClass::Universal, false, 4, b"unique"),
                encode_tlv(TlvClass::Universal, true, 16, &[]),
                encode_tlv(TlvClass::Universal, true, 16, &[]),
            ]
            .concat(),
        );
        let error = extract_verified_boot_hash_from_attestation_extension(&extension).unwrap_err();
        assert!(error
            .to_string()
            .contains("RootOfTrust tag 704 missing from authorization list"));
    }

    #[test]
    fn malformed_leaf_certificate_is_rejected() {
        let error = extract_attestation_challenge_from_leaf_certificate(b"not-der").unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to parse attestation leaf"));
    }

    fn build_leaf_with_attestation_extension(challenge: &[u8], hash: [u8; 32]) -> Vec<u8> {
        let extension = build_test_attestation_extension(challenge, hash);
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
                extension,
            ));
        let key_pair = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    fn build_test_attestation_extension(challenge: &[u8], hash: [u8; 32]) -> Vec<u8> {
        let root_of_trust = encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &[
                encode_tlv(TlvClass::Universal, false, 4, &[0x11; 32]),
                encode_tlv(TlvClass::Universal, false, 1, &[0xff]),
                encode_tlv(TlvClass::Universal, false, 10, &[0x00]),
                encode_tlv(TlvClass::Universal, false, 4, &hash),
            ]
            .concat(),
        );
        let software = encode_tlv(TlvClass::Universal, true, 16, &[]);
        let hardware = encode_tlv(
            TlvClass::Universal,
            true,
            16,
            &encode_tlv(
                TlvClass::ContextSpecific,
                true,
                ROOT_OF_TRUST_TAG,
                &root_of_trust,
            ),
        );

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
                software,
                hardware,
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
