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

//! This module implements IKeystoreAuthorization AIDL interface.

use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
    IKeyMintDevice::IKeyMintDevice, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
};
use crate::android::security::authorization::{
    AuthorizationTokens::AuthorizationTokens, IKeystoreAuthorization::BnKeystoreAuthorization,
    IKeystoreAuthorization::IKeystoreAuthorization, ResponseCode::ResponseCode,
};
use crate::android::system::keystore2::ResponseCode::ResponseCode as KsResponseCode;
use crate::err as ks_err;
use crate::keymaster::async_task::AsyncTask;
use crate::keymaster::crypto::{Password, ZVec};
use crate::keymaster::error::anyhow_error_to_cstring;
use crate::keymaster::error::Error as KeystoreError;
use crate::keymaster::keymint_device::{localize_auth_token_for_omk, KeyMintDevice};
use crate::keymaster::permission::{self, require_forwarded_context, KeystorePerm};
use crate::keymaster::super_key::WipeKeyOption;
use crate::keymaster::utils::{
    check_keystore_permission, key_params_to_aidl, watchdog as wd, AndroidUserId, Challenge,
    SecureUserId,
};
use crate::selinux;
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::top::qwq2333::ohmykeymint::IOhMyAuthorizationService::{
    BnOhMyAuthorizationService, IOhMyAuthorizationService,
};
use crate::{
    global::{DB, ENFORCEMENTS, SUPER_KEY},
    log_client_err,
};
use anyhow::{Context, Result};
use kmr_wire::{
    keymint::{Algorithm as KmAlgorithm, Digest as KmDigest, KeyParam, KeyPurpose as KmKeyPurpose},
    KeySizeInBits,
};
use log::{error, info};
use rsbinder::status::Result as BinderResult;
use rsbinder::{
    hub, DeathRecipient, ExceptionCode, Interface, Status as BinderStatus, StatusCode, Strong,
    WIBinder,
};
use std::{cell::RefCell, collections::HashMap, sync::Arc};

/// This is the Authorization error type, it wraps binder exceptions and the
/// Authorization ResponseCode
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wraps an IKeystoreAuthorization response code as defined by
    /// android.security.authorization AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
}

const AUTH_TOKEN_MAC_LEN: usize = 32;

/// Translate an error into a service specific exception, logging along the way.
///
/// `Error::Rc(x)` variants get mapped onto a service specific error code of `x`.
/// Certain response codes may be returned from keystore/ResponseCode.aidl by the keystore2 modules,
/// which are then converted to the corresponding response codes of android.security.authorization
/// AIDL interface specification.
///
/// `selinux::Error::perm()` is mapped on `ResponseCode::PERMISSION_DENIED`.
///
/// All non `Error` error conditions get mapped onto ResponseCode::SYSTEM_ERROR`.
pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
    log_client_err!(e);
    let root_cause = e.root_cause();
    if let Some(KeystoreError::Rc(ks_rcode)) = root_cause.downcast_ref::<KeystoreError>() {
        let rc = match *ks_rcode {
            // Although currently keystore2/ResponseCode.aidl and
            // authorization/ResponseCode.aidl share the same integer values for the
            // common response codes, this may deviate in the future, hence the
            // conversion here.
            KsResponseCode::SYSTEM_ERROR => ResponseCode::SYSTEM_ERROR.0,
            KsResponseCode::KEY_NOT_FOUND => ResponseCode::KEY_NOT_FOUND.0,
            KsResponseCode::VALUE_CORRUPTED => ResponseCode::VALUE_CORRUPTED.0,
            KsResponseCode::INVALID_ARGUMENT => ResponseCode::INVALID_ARGUMENT.0,
            // If the code paths of IKeystoreAuthorization aidl's methods happen to return
            // other error codes from KsResponseCode in the future, they should be converted
            // as well.
            _ => ResponseCode::SYSTEM_ERROR.0,
        };
        BinderStatus::new_service_specific_error(rc, anyhow_error_to_cstring(&e))
    } else {
        let rc = match root_cause.downcast_ref::<Error>() {
            Some(Error::Rc(rcode)) => rcode.0,
            Some(Error::Binder(_, _)) => ResponseCode::SYSTEM_ERROR.0,
            None => match root_cause.downcast_ref::<selinux::Error>() {
                Some(selinux::Error::PermissionDenied) => ResponseCode::PERMISSION_DENIED.0,
                _ => ResponseCode::SYSTEM_ERROR.0,
            },
        };
        BinderStatus::new_service_specific_error(rc, anyhow_error_to_cstring(&e))
    }
}

/// This struct is defined to implement the `IKeystoreAuthorization` AIDL interface.
pub enum AuthorizationManager {
    /// Device lock notifications are handled synchronously.
    Synchronous,
    /// Device lock notifications are handled asynchronously by a separate thread, started on
    /// demand.
    Asynchronous(Arc<AsyncTask>),
}

/// Implementation of the parts of `IKeystoreAuthorization` that track device lock status.
pub struct DeviceLockState;

/// Pending notifications about the lock state of the device for a user.
#[derive(Debug)]
pub struct LockStateNotification {
    /// Android user that the notification pertains to.
    pub user: AndroidUserId,
    /// Lock state
    pub state: LockState,
}

/// Lock state for a user.
#[derive(Debug)]
pub enum LockState {
    /// Device has been unlocked.
    DeviceUnlocked {
        /// Secret derived from synthetic password, if available.
        password: Option<ZVec>,
    },
    /// Device has been locked.
    DeviceLocked {
        /// SIDs of class 3 biometrics that can unlock the device for the user.
        unlocking_sids: Vec<SecureUserId>,
        /// Whether a weak unlock method can unlock the device for the user.
        weak_unlock_enabled: bool,
    },
    /// User's CE storage has been locked.
    UserStorageLocked,
    /// Weak unlock methods have expired.
    WeakUnlockMethodsExpired,
    /// Non-LSKF unlock methods have expired.
    NonLskfUnlockMethodsExpired,
}

impl DeviceLockState {
    /// Update the lock state based on the given notification.
    fn update(op: LockStateNotification) {
        match op.state {
            LockState::DeviceUnlocked { password } => {
                Self::on_device_unlocked(op.user, password.map(Password::Owned))
            }
            LockState::DeviceLocked {
                unlocking_sids,
                weak_unlock_enabled,
            } => Self::on_device_locked(op.user, &unlocking_sids, weak_unlock_enabled),
            LockState::UserStorageLocked => Self::on_user_storage_locked(op.user),
            LockState::WeakUnlockMethodsExpired => Self::on_weak_unlock_methods_expired(op.user),
            LockState::NonLskfUnlockMethodsExpired => {
                Self::on_non_lskf_unlock_methods_expired(op.user)
            }
        }
    }

    fn on_device_unlocked(user: AndroidUserId, password: Option<Password>) {
        info!(
            "on_device_unlocked({user:?}, password.is_some()={})",
            password.is_some()
        );
        let _wp = wd::watch("DeviceLockState::on_device_unlocked");
        ENFORCEMENTS.set_device_locked(user, false);

        let mut skm = SUPER_KEY.write().unwrap();
        if let Some(password) = password {
            if let Err(e) =
                DB.with(|db| skm.unlock_or_initialize_user(&mut db.borrow_mut(), user, &password))
            {
                error!("Unlock with password failed for {user:?}: {e:?}");
            }
        } else if let Err(e) =
            DB.with(|db| skm.try_unlock_user_with_biometric(&mut db.borrow_mut(), user))
        {
            error!("try_unlock_user_with_biometric failed for {user:?}: {e:?}");
        }
    }

    fn on_device_locked(
        user: AndroidUserId,
        unlocking_sids: &[SecureUserId],
        weak_unlock_enabled: bool,
    ) {
        info!(
            "on_device_locked({user:?}, unlocking_sids={unlocking_sids:?}, weak_unlock_enabled={weak_unlock_enabled})"
        );
        let _wp = wd::watch("DeviceLockState::on_device_locked");
        ENFORCEMENTS.set_device_locked(user, true);
        let mut skm = SUPER_KEY.write().unwrap();
        DB.with(|db| {
            skm.lock_unlocked_device_required_keys(
                &mut db.borrow_mut(),
                user,
                unlocking_sids,
                weak_unlock_enabled,
            );
        });
    }

    fn on_user_storage_locked(user: AndroidUserId) {
        log::info!("on_user_storage_locked({user:?})");
        let _wp = wd::watch("DeviceLockState::on_user_storage_locked");

        // Delete super key in cache, if exists.
        SUPER_KEY.write().unwrap().forget_all_keys_for_user(user);
    }

    fn on_weak_unlock_methods_expired(user: AndroidUserId) {
        info!("on_weak_unlock_methods_expired({user:?})");
        let _wp = wd::watch("DeviceLockState::on_weak_unlock_methods_expired");
        SUPER_KEY
            .write()
            .unwrap()
            .wipe_unlocked_device_required_keys(user, WipeKeyOption::PlaintextOnly);
    }

    fn on_non_lskf_unlock_methods_expired(user: AndroidUserId) {
        info!("on_non_lskf_unlock_methods_expired({user:?})");
        let _wp = wd::watch("DeviceLockState::on_non_lskf_unlock_methods_expired");
        SUPER_KEY
            .write()
            .unwrap()
            .wipe_unlocked_device_required_keys(user, WipeKeyOption::PlaintextAndBiometric);
    }
}

impl AuthorizationManager {
    fn new_manager() -> Self {
        if crate::keymaster::flags::async_lock_state() {
            // Use an `AsyncTask` to handle notifications of authorization state, so Binder
            // invocations can complete swiftly.
            let lock_state_task = Arc::new(AsyncTask::new(std::time::Duration::from_secs(5)));
            ENFORCEMENTS.install_lock_state_task(lock_state_task.clone());

            Self::Asynchronous(lock_state_task)
        } else {
            Self::Synchronous
        }
    }

    /// Create a new instance of Keystore Authorization service.
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreAuthorization>> {
        let mgr = Self::new_manager();
        Ok(BnKeystoreAuthorization::new_binder_with_features(
            mgr,
            crate::sid_features(),
        ))
    }

    pub fn new_omk_binder() -> Result<Strong<dyn IOhMyAuthorizationService>> {
        let mgr = Self::new_manager();
        Ok(BnOhMyAuthorizationService::new_binder_with_features(
            mgr,
            crate::sid_features(),
        ))
    }

    /// Act on a lock state notification.
    fn update_lock_state(&self, op: LockStateNotification) {
        match self {
            Self::Asynchronous(async_task) => {
                // Send the notification to the async task to be acted on there.
                info!("add {op:?} to notification queue");
                async_task.queue_hi(|_shelf| {
                    info!("process {op:?} from notification queue");
                    DeviceLockState::update(op)
                });
            }
            Self::Synchronous => {
                // Act on the notification operation immediately.
                DeviceLockState::update(op)
            }
        }
    }

    fn add_auth_token(
        &self,
        ctx: Option<&CallerInfo>,
        auth_token: &HardwareAuthToken,
    ) -> Result<()> {
        info!(
            "add_auth_token(challenge={}, userId={}, authId={}, authType={:#x}, timestamp={}ms)",
            auth_token.challenge,
            auth_token.userId,
            auth_token.authenticatorId,
            auth_token.authenticatorType.0,
            auth_token.timestamp.milliSeconds,
        );
        if auth_token.userId == 0 {
            error!("Auth token has zero GK SID, indicating an authenticator problem");
        }

        validate_auth_token_shape(auth_token)?;
        if should_skip_mirrored_auth_token_verification(ctx) {
            log::debug!(
                "system auth token MAC verification skipped for mirrored system-successful authType={:#x} challengeTag={:04x}",
                auth_token.authenticatorType.0,
                challenge_tag(auth_token.challenge),
            );
        } else {
            verify_system_auth_token(auth_token)
                .context(ks_err!("system KeyMint did not verify the auth token MAC"))?;
        }

        let localized = localize_auth_token_for_omk(auth_token)
            .context(ks_err!("localizing trusted auth token for OMK"))?;
        ENFORCEMENTS.add_auth_token(localized);
        Ok(())
    }

    fn get_auth_tokens_for_credstore(
        &self,
        challenge: Challenge,
        sid: SecureUserId,
        auth_token_max_age_millis: i64,
    ) -> Result<AuthorizationTokens> {
        // If the challenge is zero, return error
        if challenge.0 == 0 {
            return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                .context(ks_err!("Challenge can not be zero."));
        }
        // Obtain the auth token and the timestamp token from the enforcement module.
        let (auth_token, ts_token) =
            ENFORCEMENTS.get_auth_tokens(challenge, sid, auth_token_max_age_millis)?;
        Ok(AuthorizationTokens {
            authToken: auth_token,
            timestampToken: ts_token,
        })
    }

    fn get_last_auth_time(
        &self,
        sid: SecureUserId,
        auth_types: &[HardwareAuthenticatorType],
    ) -> Result<i64> {
        let mut max_time: i64 = -1;
        for auth_type in auth_types.iter() {
            if let Some(time) = ENFORCEMENTS.get_last_auth_time(sid, *auth_type) {
                if time.milliseconds() > max_time {
                    max_time = time.milliseconds();
                }
            }
        }

        if max_time >= 0 {
            Ok(max_time)
        } else {
            Err(Error::Rc(ResponseCode::NO_AUTH_TOKEN_FOUND))
                .context(ks_err!("No auth token found"))
        }
    }
}

impl Interface for AuthorizationManager {}

fn require_omk_ctx<'a>(
    ctx: Option<&'a CallerInfo>,
    label: &str,
) -> Result<&'a CallerInfo, BinderStatus> {
    require_forwarded_context(ctx, label).map_err(into_logged_binder)
}

fn check_omk_keystore_permission(
    ctx: &CallerInfo,
    perm: KeystorePerm,
    label: &str,
) -> BinderResult<()> {
    permission::check_keystore_permission(perm, Some(ctx))
        .context(label.to_string())
        .map_err(into_logged_binder)
}

fn validate_auth_token_shape(auth_token: &HardwareAuthToken) -> Result<()> {
    if auth_token.mac.len() != AUTH_TOKEN_MAC_LEN {
        return Err(Error::Rc(ResponseCode::SYSTEM_ERROR))
            .context(ks_err!("invalid auth token MAC length"));
    }

    if auth_token.userId == 0 && auth_token.authenticatorId == 0 {
        return Err(Error::Rc(ResponseCode::SYSTEM_ERROR))
            .context(ks_err!("auth token has no secure user id"));
    }

    let auth_type = auth_token.authenticatorType.0;
    let known_auth_types =
        HardwareAuthenticatorType::PASSWORD.0 | HardwareAuthenticatorType::FINGERPRINT.0;
    if auth_type == HardwareAuthenticatorType::NONE.0 || (auth_type & !known_auth_types) != 0 {
        return Err(Error::Rc(ResponseCode::SYSTEM_ERROR))
            .context(ks_err!("unsupported auth token authenticator type"));
    }

    Ok(())
}

fn should_skip_mirrored_auth_token_verification(ctx: Option<&CallerInfo>) -> bool {
    ctx.is_some()
}

thread_local! {
    static SYSTEM_KEYMINT_CACHE: RefCell<Option<HashMap<&'static str, Strong<dyn IKeyMintDevice>>>> =
        const { RefCell::new(None) };
    static SYSTEM_KEYMINT_DEATH: RefCell<Option<HashMap<&'static str, Arc<dyn DeathRecipient>>>> =
        const { RefCell::new(None) };
    static SYSTEM_VERIFIER_KEY_CACHE: RefCell<HashMap<VerifierKeyCacheKey, Vec<u8>>> =
        RefCell::new(HashMap::new());
}

struct SystemKeymintDeath {
    service: &'static str,
}

impl DeathRecipient for SystemKeymintDeath {
    fn binder_died(&self, _who: &WIBinder) {
        clear_system_keymint(self.service);
        log::warn!(
            "system KeyMint verifier service {} died; cache cleared",
            self.service
        );
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct VerifierKeyCacheKey {
    service: &'static str,
    auth_type: i32,
    user_id: i64,
    authenticator_id: i64,
}

struct CachedVerifierKey {
    blob: Vec<u8>,
    reused: bool,
}

const VERIFIER_KEY_SIZE_BITS: i32 = 256;
const VERIFIER_AUTH_TIMEOUT_SECS: i32 = i32::MAX;
const VERIFIER_MAC_LENGTH_BITS: i32 = 256;

fn verify_system_auth_token(auth_token: &HardwareAuthToken) -> Result<()> {
    const SYSTEM_KEYMINT_DEFAULT: &str = "android.hardware.security.keymint.IKeyMintDevice/default";
    const SYSTEM_KEYMINT_STRONGBOX: &str =
        "android.hardware.security.keymint.IKeyMintDevice/strongbox";

    let services = [SYSTEM_KEYMINT_DEFAULT, SYSTEM_KEYMINT_STRONGBOX];
    let key_params = verifier_key_params(auth_token)
        .context(ks_err!("failed to build system verifier key parameters"))?;
    let op_params = key_params_to_aidl(
        &[KeyParam::MacLength(VERIFIER_MAC_LENGTH_BITS as u32)],
        KeyMintDevice::KEY_MINT_V5,
    )
    .context(ks_err!(
        "failed to build system verifier operation parameters"
    ))?;
    let mut saw_rejection = false;
    let mut failures = Vec::new();

    for service in services {
        let keymint = match get_system_keymint(service) {
            Ok(keymint) => keymint,
            Err(error) => {
                failures.push(format!("{service}: connect failed: {error:#}"));
                continue;
            }
        };
        let key_id = VerifierKeyCacheKey::for_token(auth_token, service);

        let key = match get_system_verifier_key(service, &keymint, &key_id, &key_params) {
            Ok(key) => key,
            Err(status) => {
                if is_dead_object_status(&status) {
                    clear_system_keymint(service);
                }
                failures.push(format!(
                    "{service}: verifier key generation failed: {status}"
                ));
                continue;
            }
        };

        match begin_system_verifier(
            service,
            &keymint,
            &key_id,
            key,
            &key_params,
            &op_params,
            auth_token,
        ) {
            Ok(()) => {
                log::info!(
                    "system auth token MAC verified authType={:#x} challengeTag={:04x}",
                    auth_token.authenticatorType.0,
                    challenge_tag(auth_token.challenge),
                );
                return Ok(());
            }
            Err(status) => {
                if is_dead_object_status(&status) {
                    clear_system_keymint(service);
                }
                saw_rejection = true;
                failures.push(format!(
                    "{service}: verifier begin rejected token: {status}"
                ));
            }
        }
    }

    let detail = failures.join("; ");
    if saw_rejection {
        return Err(Error::Rc(ResponseCode::SYSTEM_ERROR))
            .with_context(|| format!("system KeyMint rejected auth token: {detail}"));
    }

    Err(Error::Rc(ResponseCode::SYSTEM_ERROR))
        .with_context(|| format!("no system KeyMint verifier was available: {detail}"))
}

fn verifier_key_params(auth_token: &HardwareAuthToken) -> Result<Vec<KeyParameter>> {
    let mut params = vec![
        KeyParam::Purpose(KmKeyPurpose::Sign),
        KeyParam::Algorithm(KmAlgorithm::Hmac),
        KeyParam::KeySize(KeySizeInBits(VERIFIER_KEY_SIZE_BITS as u32)),
        KeyParam::Digest(KmDigest::Sha256),
        KeyParam::MinMacLength(VERIFIER_MAC_LENGTH_BITS as u32),
        KeyParam::UserAuthType(auth_token.authenticatorType.0 as u32),
        KeyParam::AuthTimeout(VERIFIER_AUTH_TIMEOUT_SECS as u32),
    ];

    if auth_token.userId != 0 {
        params.push(KeyParam::UserSecureId(auth_token.userId as u64));
    }
    if auth_token.authenticatorId != 0 && auth_token.authenticatorId != auth_token.userId {
        params.push(KeyParam::UserSecureId(auth_token.authenticatorId as u64));
    }

    key_params_to_aidl(&params, KeyMintDevice::KEY_MINT_V5)
}

impl VerifierKeyCacheKey {
    fn for_token(auth_token: &HardwareAuthToken, service: &'static str) -> Self {
        Self {
            service,
            auth_type: auth_token.authenticatorType.0,
            user_id: auth_token.userId,
            authenticator_id: auth_token.authenticatorId,
        }
    }
}

fn get_system_keymint(service: &'static str) -> Result<Strong<dyn IKeyMintDevice>> {
    SYSTEM_KEYMINT_CACHE.with(|cache| {
        if let Some(keymint) = cache
            .borrow()
            .as_ref()
            .and_then(|services| services.get(service).cloned())
        {
            return Ok(keymint);
        }

        let keymint: Strong<dyn IKeyMintDevice> =
            hub::get_interface(service).with_context(|| format!("connect {service}"))?;
        let recipient: Arc<dyn DeathRecipient> = Arc::new(SystemKeymintDeath { service });
        keymint
            .as_binder()
            .link_to_death(Arc::downgrade(&recipient))
            .with_context(|| format!("watch {service} death"))?;
        SYSTEM_KEYMINT_DEATH.with(|death| {
            death
                .borrow_mut()
                .get_or_insert_with(HashMap::new)
                .insert(service, recipient);
        });
        cache
            .borrow_mut()
            .get_or_insert_with(HashMap::new)
            .insert(service, keymint.clone());
        Ok(keymint)
    })
}

fn clear_system_keymint(service: &'static str) {
    SYSTEM_KEYMINT_CACHE.with(|cache| {
        if let Some(services) = cache.borrow_mut().as_mut() {
            services.remove(service);
        }
    });
    SYSTEM_KEYMINT_DEATH.with(|death| {
        if let Some(recipients) = death.borrow_mut().as_mut() {
            recipients.remove(service);
        }
    });
    SYSTEM_VERIFIER_KEY_CACHE.with(|cache| {
        cache.borrow_mut().retain(|key, _| key.service != service);
    });
}

fn get_system_verifier_key(
    service: &'static str,
    keymint: &Strong<dyn IKeyMintDevice>,
    key_id: &VerifierKeyCacheKey,
    key_params: &[KeyParameter],
) -> std::result::Result<CachedVerifierKey, BinderStatus> {
    if let Some(blob) = SYSTEM_VERIFIER_KEY_CACHE.with(|cache| cache.borrow().get(key_id).cloned())
    {
        return Ok(CachedVerifierKey { blob, reused: true });
    }

    let key = keymint.generateKey(key_params, None)?;
    let blob = key.keyBlob;
    SYSTEM_VERIFIER_KEY_CACHE.with(|cache| {
        cache.borrow_mut().insert(key_id.clone(), blob.clone());
    });
    log::debug!(
        "system auth token verifier key prepared service={} authType={:#x} sidShape={}",
        service,
        key_id.auth_type,
        sid_shape(key_id),
    );
    Ok(CachedVerifierKey {
        blob,
        reused: false,
    })
}

fn begin_system_verifier(
    service: &'static str,
    keymint: &Strong<dyn IKeyMintDevice>,
    key_id: &VerifierKeyCacheKey,
    key: CachedVerifierKey,
    key_params: &[KeyParameter],
    op_params: &[KeyParameter],
    auth_token: &HardwareAuthToken,
) -> std::result::Result<(), BinderStatus> {
    match begin_system_verifier_once(keymint, &key.blob, op_params, auth_token) {
        Ok(()) => Ok(()),
        Err(_) if key.reused => {
            SYSTEM_VERIFIER_KEY_CACHE.with(|cache| {
                cache.borrow_mut().remove(key_id);
            });
            let fresh = get_system_verifier_key(service, keymint, key_id, key_params)?;
            begin_system_verifier_once(keymint, &fresh.blob, op_params, auth_token)
        }
        Err(status) => Err(status),
    }
}

fn begin_system_verifier_once(
    keymint: &Strong<dyn IKeyMintDevice>,
    key_blob: &[u8],
    op_params: &[KeyParameter],
    auth_token: &HardwareAuthToken,
) -> std::result::Result<(), BinderStatus> {
    let result = keymint.begin(KeyPurpose::SIGN, key_blob, op_params, Some(auth_token))?;
    if let Some(operation) = result.operation {
        let _ = operation.r#abort();
    }
    Ok(())
}

fn is_dead_object_status(status: &BinderStatus) -> bool {
    status.exception_code() == ExceptionCode::TransactionFailed
        && status.transaction_error() == StatusCode::DeadObject
}

fn sid_shape(key_id: &VerifierKeyCacheKey) -> &'static str {
    match (key_id.user_id != 0, key_id.authenticator_id != 0) {
        (true, true) if key_id.user_id != key_id.authenticator_id => "user+authenticator",
        (true, _) => "user",
        (_, true) => "authenticator",
        _ => "none",
    }
}

fn challenge_tag(challenge: i64) -> u16 {
    (challenge as u64 & 0xffff) as u16
}

// The AIDL interface necessarily uses raw integer types for user ID / sid, so convert them to
// internal newtypes as soon as they arrive.
impl IKeystoreAuthorization for AuthorizationManager {
    fn addAuthToken(&self, auth_token: &HardwareAuthToken) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::addAuthToken");
        check_keystore_permission(KeystorePerm::AddAuth)
            .context(ks_err!("caller missing AddAuth permissions"))
            .map_err(into_logged_binder)?;

        self.add_auth_token(None, auth_token)
            .map_err(into_logged_binder)
    }

    fn onDeviceUnlocked(&self, user_id: i32, password: Option<&[u8]>) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onDeviceUnlocked");
        check_keystore_permission(KeystorePerm::Unlock)
            .context(ks_err!("caller missing Unlock permissions"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let password = match password {
            None => None,
            Some(slice) => Some(
                ZVec::try_from(slice)
                    .context("failed to create ZVec!")
                    .map_err(into_logged_binder)?,
            ),
        };
        let op = LockStateNotification {
            user,
            state: LockState::DeviceUnlocked { password },
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onDeviceLocked(
        &self,
        user_id: i32,
        unlocking_sids: &[i64],
        weak_unlock_enabled: bool,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onDeviceLocked");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let unlocking_sids: Vec<_> = unlocking_sids.iter().map(|sid| {
            if *sid == 0 {
                error!("Biometric-unlocking SIDs includes a zero SID, indicating a biometric framework problem");
            }
            SecureUserId(*sid)
        }).collect();
        let op = LockStateNotification {
            user,
            state: LockState::DeviceLocked {
                unlocking_sids,
                weak_unlock_enabled,
            },
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onUserStorageLocked(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreMaintenance::onUserStorageLocked");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification {
            user,
            state: LockState::UserStorageLocked,
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onWeakUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onWeakUnlockMethodsExpired");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification {
            user,
            state: LockState::WeakUnlockMethodsExpired,
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onNonLskfUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onNonLskfUnlockMethodsExpired");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification {
            user,
            state: LockState::NonLskfUnlockMethodsExpired,
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn getAuthTokensForCredStore(
        &self,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> BinderResult<AuthorizationTokens> {
        let _wp = wd::watch("IKeystoreAuthorization::getAuthTokensForCredStore");
        check_keystore_permission(KeystorePerm::GetAuthToken)
            .context(ks_err!("caller missing GetAuthToken permission"))
            .map_err(into_logged_binder)?;

        let sid = SecureUserId(secure_user_id);
        let challenge = Challenge(challenge);
        self.get_auth_tokens_for_credstore(challenge, sid, auth_token_max_age_millis)
            .map_err(into_logged_binder)
    }

    fn getLastAuthTime(
        &self,
        secure_user_id: i64,
        auth_types: &[HardwareAuthenticatorType],
    ) -> BinderResult<i64> {
        let _wp = wd::watch("IKeystoreAuthorization::getLastAuthTime");
        check_keystore_permission(KeystorePerm::GetLastAuthTime)
            .context(ks_err!("caller missing GetLastAuthTime permission"))
            .map_err(into_logged_binder)?;

        let sid = SecureUserId(secure_user_id);
        self.get_last_auth_time(sid, auth_types)
            .map_err(into_logged_binder)
    }
}

#[allow(non_snake_case)]
impl IOhMyAuthorizationService for AuthorizationManager {
    fn addAuthToken(
        &self,
        ctx: Option<&CallerInfo>,
        auth_token: &HardwareAuthToken,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::addAuthToken");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::addAuthToken")?;
        check_omk_keystore_permission(
            ctx,
            KeystorePerm::AddAuth,
            "caller missing AddAuth permissions",
        )?;

        self.add_auth_token(Some(ctx), auth_token)
            .map_err(into_logged_binder)
    }

    fn onDeviceUnlocked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onDeviceUnlocked");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::onDeviceUnlocked")?;
        check_omk_keystore_permission(
            ctx,
            KeystorePerm::Unlock,
            "caller missing Unlock permissions",
        )?;

        let user = AndroidUserId(user_id);
        let password = match password {
            None => None,
            Some(slice) => Some(
                ZVec::try_from(slice)
                    .context("failed to create ZVec!")
                    .map_err(into_logged_binder)?,
            ),
        };
        let op = LockStateNotification {
            user,
            state: LockState::DeviceUnlocked { password },
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onDeviceLocked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        unlocking_sids: &[i64],
        weak_unlock_enabled: bool,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onDeviceLocked");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::onDeviceLocked")?;
        check_omk_keystore_permission(ctx, KeystorePerm::Lock, "caller missing Lock permission")?;

        let user = AndroidUserId(user_id);
        let unlocking_sids: Vec<_> = unlocking_sids.iter().map(|sid| {
            if *sid == 0 {
                error!("Biometric-unlocking SIDs includes a zero SID, indicating a biometric framework problem");
            }
            SecureUserId(*sid)
        }).collect();
        let op = LockStateNotification {
            user,
            state: LockState::DeviceLocked {
                unlocking_sids,
                weak_unlock_enabled,
            },
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onUserStorageLocked(&self, ctx: Option<&CallerInfo>, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onUserStorageLocked");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::onUserStorageLocked")?;
        check_omk_keystore_permission(ctx, KeystorePerm::Lock, "caller missing Lock permission")?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification {
            user,
            state: LockState::UserStorageLocked,
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onWeakUnlockMethodsExpired(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onWeakUnlockMethodsExpired");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::onWeakUnlockMethodsExpired")?;
        check_omk_keystore_permission(ctx, KeystorePerm::Lock, "caller missing Lock permission")?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification {
            user,
            state: LockState::WeakUnlockMethodsExpired,
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onNonLskfUnlockMethodsExpired(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onNonLskfUnlockMethodsExpired");
        let ctx = require_omk_ctx(
            ctx,
            "IOhMyAuthorizationService::onNonLskfUnlockMethodsExpired",
        )?;
        check_omk_keystore_permission(ctx, KeystorePerm::Lock, "caller missing Lock permission")?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification {
            user,
            state: LockState::NonLskfUnlockMethodsExpired,
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn getAuthTokensForCredStore(
        &self,
        ctx: Option<&CallerInfo>,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> BinderResult<AuthorizationTokens> {
        let _wp = wd::watch("IOhMyAuthorizationService::getAuthTokensForCredStore");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::getAuthTokensForCredStore")?;
        check_omk_keystore_permission(
            ctx,
            KeystorePerm::GetAuthToken,
            "caller missing GetAuthToken permission",
        )?;

        let sid = SecureUserId(secure_user_id);
        let challenge = Challenge(challenge);
        self.get_auth_tokens_for_credstore(challenge, sid, auth_token_max_age_millis)
            .map_err(into_logged_binder)
    }

    fn getLastAuthTime(
        &self,
        ctx: Option<&CallerInfo>,
        secure_user_id: i64,
        auth_types: &[HardwareAuthenticatorType],
    ) -> BinderResult<i64> {
        let _wp = wd::watch("IOhMyAuthorizationService::getLastAuthTime");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::getLastAuthTime")?;
        check_omk_keystore_permission(
            ctx,
            KeystorePerm::GetLastAuthTime,
            "caller missing GetLastAuthTime permission",
        )?;

        let sid = SecureUserId(secure_user_id);
        self.get_last_auth_time(sid, auth_types)
            .map_err(into_logged_binder)
    }
}
