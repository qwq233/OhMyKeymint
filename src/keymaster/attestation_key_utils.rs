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

//! Implements get_attestation_key_info which loads user generated attestation keys.

use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::system::keystore2::{
    Domain::Domain, KeyDescriptor::KeyDescriptor, ResponseCode::ResponseCode,
};
use crate::err as ks_err;
use crate::keymaster::crypto::parse_subject_from_certificate;
use crate::keymaster::db::{BlobMetaData, KeyEntryLoadBits, KeyIdGuard, KeyType, KeystoreDB};
use crate::keymaster::error::{Error, ErrorCode};
use crate::keymaster::permission::{check_key_permission, KeyPerm};
use crate::keymaster::utils::AppUid;
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use anyhow::{Context, Result};

/// KeyMint user generated attestation key information.
pub enum AttestationKeyInfo {
    UserGenerated {
        key_id_guard: KeyIdGuard,
        blob: Vec<u8>,
        blob_metadata: BlobMetaData,
        issuer_subject: Vec<u8>,
    },
}

/// Loads the user generated attestation key from the database if `attest_key_descriptor` is given.
pub fn get_attest_key_info(
    ctx: Option<&CallerInfo>,
    caller_uid: AppUid,
    attest_key_descriptor: Option<&KeyDescriptor>,
    _params: &[KeyParameter],
    db: &mut KeystoreDB,
) -> Result<Option<AttestationKeyInfo>> {
    match attest_key_descriptor {
        None => Ok(None),
        Some(attest_key) => get_user_generated_attestation_key(ctx, attest_key, caller_uid, db)
            .context(ks_err!("Trying to load attest key"))
            .map(Some),
    }
}

fn get_user_generated_attestation_key(
    ctx: Option<&CallerInfo>,
    key: &KeyDescriptor,
    caller_uid: AppUid,
    db: &mut KeystoreDB,
) -> Result<AttestationKeyInfo> {
    let (key_id_guard, blob, cert, blob_metadata) =
        load_attest_key_blob_and_cert(ctx, key, caller_uid, db)
            .context(ks_err!("Failed to load blob and cert"))?;

    let issuer_subject: Vec<u8> = parse_subject_from_certificate(&cert)
        .context(ks_err!("Failed to parse subject from certificate"))?;

    Ok(AttestationKeyInfo::UserGenerated {
        key_id_guard,
        blob,
        issuer_subject,
        blob_metadata,
    })
}

fn load_attest_key_blob_and_cert(
    ctx: Option<&CallerInfo>,
    key: &KeyDescriptor,
    caller_uid: AppUid,
    db: &mut KeystoreDB,
) -> Result<(KeyIdGuard, Vec<u8>, Vec<u8>, BlobMetaData)> {
    match key.domain {
        Domain::BLOB => Err(Error::Km(ErrorCode::INVALID_ARGUMENT))
            .context(ks_err!("Domain::BLOB attestation keys not supported")),
        _ => {
            let (key_id_guard, mut key_entry) = db
                .load_key_entry(
                    key,
                    KeyType::Client,
                    KeyEntryLoadBits::BOTH,
                    caller_uid,
                    |k, av| check_key_permission(KeyPerm::Use, k, av.as_ref(), ctx),
                )
                .context(ks_err!("Failed to load key."))?;

            let (blob, blob_metadata) = key_entry
                .take_key_blob_info()
                .ok_or(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                .context(ks_err!(
                    "Successfully loaded key entry, but KM blob was missing"
                ))?;
            let cert = key_entry
                .take_cert()
                .ok_or(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                .context(ks_err!(
                    "Successfully loaded key entry, but cert was missing"
                ))?;
            Ok((key_id_guard, blob, cert, blob_metadata))
        }
    }
}
