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

use crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken;
use crate::android::hardware::security::keymint::HardwareAuthenticatorType::HardwareAuthenticatorType;
use crate::android::hardware::security::keymint::IKeyMintDevice::IKeyMintDevice;
use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::hardware::security::keymint::KeyPurpose::KeyPurpose;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::security::authorization::AuthorizationTokens::AuthorizationTokens;
use crate::android::security::authorization::IKeystoreAuthorization::{
    BnKeystoreAuthorization, IKeystoreAuthorization,
};
use crate::android::security::authorization::ResponseCode::ResponseCode;
use crate::android::security::compat::IKeystoreCompatService::IKeystoreCompatService;
use crate::android::system::keystore2::ResponseCode::ResponseCode as KsResponseCode;
use crate::config::config;
use crate::global::{DB, ENFORCEMENTS, SUPER_KEY};
use crate::keymaster::async_task::AsyncTask;
use crate::keymaster::crypto::{Password, ZVec};
use crate::keymaster::error::{
    anyhow_error_to_cstring, map_binder_status, map_km_error, Error as KeystoreError, ErrorCode,
};
use crate::keymaster::keymint_device::KeyMintDevice;
use crate::keymaster::permission::{self, require_forwarded_context, KeystorePerm};
use crate::keymaster::super_key::WipeKeyOption;
use crate::keymaster::utils::{
    check_keystore_permission, get_interface_once, key_params_to_aidl, watchdog as wd,
    AndroidUserId, Challenge, SecureUserId,
};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::top::qwq2333::ohmykeymint::IOhMyAuthorizationService::{
    BnOhMyAuthorizationService, IOhMyAuthorizationService,
};
use crate::{err as ks_err, log_client_err, selinux};
use anyhow::{Context, Result};
use binder::{
    DeathRecipient, ExceptionCode, IBinder, Interface, Result as BinderResult,
    Status as BinderStatus, StatusCode, Strong,
};
use kmr_wire::keymint::{
    Algorithm as KmAlgorithm, Digest as KmDigest, KeyParam, KeyPurpose as KmKeyPurpose,
};
use kmr_wire::KeySizeInBits;
use log::{error, info};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

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
        BinderStatus::new_service_specific_error_str(rc, anyhow_error_to_cstring(&e))
    } else {
        let rc = match root_cause.downcast_ref::<Error>() {
            Some(Error::Rc(rcode)) => rcode.0,
            Some(Error::Binder(_, _)) => ResponseCode::SYSTEM_ERROR.0,
            None => match root_cause.downcast_ref::<selinux::Error>() {
                Some(selinux::Error::PermissionDenied) => ResponseCode::PERMISSION_DENIED.0,
                _ => ResponseCode::SYSTEM_ERROR.0,
            },
        };
        BinderStatus::new_service_specific_error_str(rc, anyhow_error_to_cstring(&e))
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
            LockState::DeviceLocked { unlocking_sids, weak_unlock_enabled } => {
                Self::on_device_locked(op.user, &unlocking_sids, weak_unlock_enabled)
            }
            LockState::UserStorageLocked => Self::on_user_storage_locked(op.user),
            LockState::WeakUnlockMethodsExpired => Self::on_weak_unlock_methods_expired(op.user),
            LockState::NonLskfUnlockMethodsExpired => {
                Self::on_non_lskf_unlock_methods_expired(op.user)
            }
        }
    }

    fn on_device_unlocked(user: AndroidUserId, password: Option<Password>) {
        info!("on_device_unlocked({user:?}, password.is_some()={})", password.is_some());
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
        Ok(BnKeystoreAuthorization::new_binder(mgr, crate::consts::sid_features()))
    }

    pub fn new_omk_binder() -> Result<Strong<dyn IOhMyAuthorizationService>> {
        let mgr = Self::new_manager();
        Ok(BnOhMyAuthorizationService::new_binder(mgr, crate::consts::sid_features()))
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

    fn add_auth_token(&self, auth_token: &HardwareAuthToken) {
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

        ENFORCEMENTS.add_auth_token(auth_token.clone());
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
        Ok(AuthorizationTokens { authToken: auth_token, timestampToken: ts_token })
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

pub(super) fn verify_auth_token_for_omk(auth_token: &HardwareAuthToken) -> Result<()> {
    if should_skip_system_auth_token_verification() {
        validate_auth_token_shape(auth_token)?;
        log::debug!("system auth token MAC verification explicitly disabled by config");
        Ok(())
    } else {
        verify_system_auth_token(auth_token)
    }
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

fn should_skip_system_auth_token_verification() -> bool {
    match config().read() {
        Ok(config) => config.main.force_skip_system_biometric_hat_verification,
        Err(_) => {
            error!("config lock poisoned while checking HAT verification fallback");
            false
        }
    }
}

thread_local! {
    static SYSTEM_KEYMINT_CACHE: RefCell<Option<HashMap<&'static str, Strong<dyn IKeyMintDevice>>>> =
        RefCell::default();
    static SYSTEM_KEYMINT_DEATH: RefCell<Option<HashMap<&'static str, DeathRecipient>>> =
        RefCell::default();
    static SYSTEM_VERIFIER_KEY_CACHE: RefCell<HashMap<VerifierKeyCacheKey, Vec<u8>>> =
        RefCell::default();
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

    let services = [
        (SYSTEM_KEYMINT_DEFAULT, SecurityLevel::TRUSTED_ENVIRONMENT),
        (SYSTEM_KEYMINT_STRONGBOX, SecurityLevel::STRONGBOX),
    ];
    let key_params = verifier_key_params(auth_token)
        .context(ks_err!("failed to build system verifier key parameters"))?;
    let op_params = key_params_to_aidl(
        &[KeyParam::Digest(KmDigest::Sha256), KeyParam::MacLength(VERIFIER_MAC_LENGTH_BITS as u32)],
        KeyMintDevice::KEY_MINT_V5,
    )
    .context(ks_err!("failed to build system verifier operation parameters"))?;
    let mut failure = None;

    for (service, level) in services {
        let keymint = match get_system_keymint(service, level) {
            Ok(Some(keymint)) => keymint,
            Ok(None) => continue,
            Err(error) => {
                failure = Some(error.context(format!("connect System verifier {service}")));
                continue;
            }
        };
        let key_id = VerifierKeyCacheKey {
            service,
            auth_type: auth_token.authenticatorType.0,
            user_id: auth_token.userId,
            authenticator_id: auth_token.authenticatorId,
        };

        let key = match get_system_verifier_key(service, &keymint, &key_id, &key_params) {
            Ok(key) => key,
            Err(status) => {
                if is_dead_object_status(&status) {
                    clear_system_keymint(service);
                }
                failure = Some(
                    anyhow::Error::new(
                        map_km_error::<()>(Err(status)).expect_err("a failed Binder call"),
                    )
                    .context(format!("generate System verifier key {service}")),
                );
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
                let rejected = status.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                    && status.service_specific_error() == ErrorCode::KEY_USER_NOT_AUTHENTICATED.0;
                let error = anyhow::Error::new(
                    map_km_error::<()>(Err(status)).expect_err("a failed Binder call"),
                )
                .context(format!("System verifier begin {service}"));
                if rejected {
                    return Err(error);
                }
                failure = Some(error);
            }
        }
    }

    Err(failure.expect("the default System verifier was attempted"))
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

fn get_system_keymint(
    service: &'static str,
    level: SecurityLevel,
) -> Result<Option<Strong<dyn IKeyMintDevice>>> {
    SYSTEM_KEYMINT_CACHE.with(|cache| {
        if let Some(keymint) =
            cache.borrow().as_ref().and_then(|services| services.get(service).cloned())
        {
            return Ok(Some(keymint));
        }

        let keymint = if binder::is_declared(service)? {
            get_interface_once(service).with_context(|| format!("connect {service}"))?
        } else {
            let compatibility: Strong<dyn IKeystoreCompatService> =
                get_interface_once("android.security.compat")
                    .context("connect System KeyMint compatibility service")?;
            let Some(keymint) = keymint_from_compatibility(&*compatibility, level)? else {
                return Ok(None);
            };
            keymint
        };
        let mut recipient = DeathRecipient::new(move || {
            clear_system_keymint(service);
            log::warn!("system KeyMint verifier service {} died; cache cleared", service);
        });
        keymint
            .as_binder()
            .link_to_death(&mut recipient)
            .with_context(|| format!("watch {service} death"))?;
        SYSTEM_KEYMINT_DEATH.with(|death| {
            death.borrow_mut().get_or_insert_with(HashMap::new).insert(service, recipient);
        });
        cache.borrow_mut().get_or_insert_with(HashMap::new).insert(service, keymint.clone());
        Ok(Some(keymint))
    })
}

fn keymint_from_compatibility(
    compatibility: &dyn IKeystoreCompatService,
    level: SecurityLevel,
) -> Result<Option<Strong<dyn IKeyMintDevice>>> {
    match compatibility.getKeyMintDevice(level) {
        Ok(keymint) => Ok(Some(keymint)),
        Err(status)
            if level == SecurityLevel::STRONGBOX
                && status.exception_code() == ExceptionCode::TRANSACTION_FAILED
                && status.transaction_error() == StatusCode::NAME_NOT_FOUND =>
        {
            Ok(None)
        }
        Err(status) => map_binder_status(Err(status)).context("get System compatibility KeyMint"),
    }
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
    Ok(CachedVerifierKey { blob, reused: false })
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
        Err(status) if key.reused && verifier_key_needs_refresh(&status) => {
            SYSTEM_VERIFIER_KEY_CACHE.with(|cache| {
                cache.borrow_mut().remove(key_id);
            });
            let fresh = get_system_verifier_key(service, keymint, key_id, key_params)?;
            begin_system_verifier_once(keymint, &fresh.blob, op_params, auth_token)
        }
        Err(status) => Err(status),
    }
}

fn verifier_key_needs_refresh(status: &BinderStatus) -> bool {
    status.exception_code() == ExceptionCode::SERVICE_SPECIFIC
        && matches!(status.service_specific_error(), value if value == ErrorCode::INVALID_KEY_BLOB.0 || value == ErrorCode::KEY_REQUIRES_UPGRADE.0)
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
    status.exception_code() == ExceptionCode::TRANSACTION_FAILED
        && status.transaction_error() == StatusCode::DEAD_OBJECT
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

        self.add_auth_token(auth_token);
        Ok(())
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
        let op = LockStateNotification { user, state: LockState::DeviceUnlocked { password } };
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
            state: LockState::DeviceLocked { unlocking_sids, weak_unlock_enabled },
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
        let op = LockStateNotification { user, state: LockState::UserStorageLocked };
        self.update_lock_state(op);
        Ok(())
    }

    fn onWeakUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onWeakUnlockMethodsExpired");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::WeakUnlockMethodsExpired };
        self.update_lock_state(op);
        Ok(())
    }

    fn onNonLskfUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onNonLskfUnlockMethodsExpired");
        check_keystore_permission(KeystorePerm::Lock)
            .context(ks_err!("caller missing Lock permission"))
            .map_err(into_logged_binder)?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::NonLskfUnlockMethodsExpired };
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
        self.get_last_auth_time(sid, auth_types).map_err(into_logged_binder)
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

        self.add_auth_token(auth_token);
        Ok(())
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
        let op = LockStateNotification { user, state: LockState::DeviceUnlocked { password } };
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
            state: LockState::DeviceLocked { unlocking_sids, weak_unlock_enabled },
        };
        self.update_lock_state(op);
        Ok(())
    }

    fn onUserStorageLocked(&self, ctx: Option<&CallerInfo>, user_id: i32) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onUserStorageLocked");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::onUserStorageLocked")?;
        check_omk_keystore_permission(ctx, KeystorePerm::Lock, "caller missing Lock permission")?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::UserStorageLocked };
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
        let op = LockStateNotification { user, state: LockState::WeakUnlockMethodsExpired };
        self.update_lock_state(op);
        Ok(())
    }

    fn onNonLskfUnlockMethodsExpired(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> BinderResult<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onNonLskfUnlockMethodsExpired");
        let ctx = require_omk_ctx(ctx, "IOhMyAuthorizationService::onNonLskfUnlockMethodsExpired")?;
        check_omk_keystore_permission(ctx, KeystorePerm::Lock, "caller missing Lock permission")?;

        let user = AndroidUserId(user_id);
        let op = LockStateNotification { user, state: LockState::NonLskfUnlockMethodsExpired };
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
        self.get_last_auth_time(sid, auth_types).map_err(into_logged_binder)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::android::hardware::security::keymint::IKeyMintDevice::BnKeyMintDevice;
    use crate::keymaster::keymint_device::{tests as keymint_tests, KeyMintWrapper};
    use std::sync::{Mutex, RwLock};

    static AUTH_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn compatibility_absence_only_means_missing_strongbox_hardware() {
        use crate::android::hardware::security::secureclock::ISecureClock::ISecureClock;
        use crate::android::hardware::security::sharedsecret::ISharedSecret::ISharedSecret;
        struct Compat(Strong<dyn IKeyMintDevice>, Option<fn() -> BinderStatus>);
        impl Interface for Compat {}
        impl IKeystoreCompatService for Compat {
            fn getKeyMintDevice(
                &self,
                _: SecurityLevel,
            ) -> binder::Result<Strong<dyn IKeyMintDevice>> {
                match self.1 {
                    Some(error) => Err(error()),
                    None => Ok(self.0.clone()),
                }
            }
            fn getSecureClock(&self) -> binder::Result<Strong<dyn ISecureClock>> {
                Err(StatusCode::UNKNOWN_TRANSACTION.into())
            }
            fn getSharedSecret(
                &self,
                _: SecurityLevel,
            ) -> binder::Result<Strong<dyn ISharedSecret>> {
                Err(StatusCode::UNKNOWN_TRANSACTION.into())
            }
        }
        let device = BnKeyMintDevice::new_binder(
            keymint_tests::auth_wrapper(&[0x41; 32]),
            binder::BinderFeatures::default(),
        );
        for level in [SecurityLevel::TRUSTED_ENVIRONMENT, SecurityLevel::STRONGBOX] {
            let compatibility = Compat(device.clone(), None);
            assert_eq!(
                keymint_from_compatibility(&compatibility, level).unwrap().unwrap().as_binder(),
                device.as_binder()
            );
            let failures: [fn() -> BinderStatus; 3] = [
                || StatusCode::NAME_NOT_FOUND.into(),
                || StatusCode::DEAD_OBJECT.into(),
                || BinderStatus::new_service_specific_error(-2, None),
            ];
            for failure in failures {
                let status = failure();
                let missing = level == SecurityLevel::STRONGBOX
                    && status.transaction_error() == StatusCode::NAME_NOT_FOUND
                    && status.exception_code() == ExceptionCode::TRANSACTION_FAILED;
                let compatibility = Compat(device.clone(), Some(failure));
                let result = keymint_from_compatibility(&compatibility, level);
                if missing {
                    assert!(result.unwrap().is_none());
                } else {
                    assert_eq!(
                        result.unwrap_err().root_cause().downcast_ref::<KeystoreError>(),
                        Some(&map_binder_status::<()>(Err(status)).unwrap_err())
                    );
                }
            }
        }
    }

    pub(crate) fn with_system_keymint<T>(device: KeyMintWrapper, run: impl FnOnce() -> T) -> T {
        let _guard = AUTH_TEST_LOCK.lock().unwrap();
        crate::config::CONFIG.get_or_init(|| RwLock::new(crate::config::Config::for_tests()));
        let device = BnKeyMintDevice::new_binder(device, binder::BinderFeatures::default());
        let previous = SYSTEM_KEYMINT_CACHE.with(|cache| {
            cache.replace(Some(HashMap::from([
                ("android.hardware.security.keymint.IKeyMintDevice/default", device.clone()),
                ("android.hardware.security.keymint.IKeyMintDevice/strongbox", device),
            ])))
        });
        let keys = SYSTEM_VERIFIER_KEY_CACHE.with(|cache| std::mem::take(&mut *cache.borrow_mut()));
        let omk = keymint_tests::AUTH_TOKEN_WRAPPER
            .replace(Some(keymint_tests::auth_wrapper(&[0x73; 32])));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));
        keymint_tests::AUTH_TOKEN_WRAPPER.replace(omk);
        SYSTEM_KEYMINT_CACHE.with(|cache| {
            cache.replace(previous);
        });
        SYSTEM_VERIFIER_KEY_CACHE.with(|cache| {
            cache.replace(keys);
        });
        match result {
            Ok(value) => value,
            Err(error) => std::panic::resume_unwind(error),
        }
    }

    #[test]
    fn ingestion_caches_original_tokens_including_bad_mac_and_shape() {
        use crate::keymaster::database::perboot::PERBOOT_DB;
        let manager = AuthorizationManager::Synchronous;
        let mut token = keymint_tests::signed_auth_token(37, &[0x41; 32]);
        token.userId = 0x1337_0123;
        for mac in [vec![0; 32], vec![0; 3], Vec::new()] {
            token.mac = mac;
            manager.add_auth_token(&token);
            let cached = PERBOOT_DB
                .find_auth_token_entry(|entry| entry.auth_token().userId == token.userId)
                .unwrap();
            assert_eq!(cached.auth_token(), &token);
        }
    }

    #[test]
    fn verifier_does_not_refresh_authentication_rejections() {
        for code in [ErrorCode::KEY_USER_NOT_AUTHENTICATED, ErrorCode::INVALID_ARGUMENT] {
            assert!(!verifier_key_needs_refresh(&BinderStatus::new_service_specific_error(
                code.0, None
            )));
        }
        for code in [ErrorCode::INVALID_KEY_BLOB, ErrorCode::KEY_REQUIRES_UPGRADE] {
            assert!(verifier_key_needs_refresh(&BinderStatus::new_service_specific_error(
                code.0, None
            )));
        }
        assert!(!verifier_key_needs_refresh(&StatusCode::DEAD_OBJECT.into()));
    }

    #[test]
    fn only_the_explicit_compatibility_switch_bypasses_mac_verification() {
        let system = keymint_tests::auth_wrapper(&[0x41; 32]);
        with_system_keymint(system, || {
            let mut token = keymint_tests::signed_auth_token(37, &[0x41; 32]);
            token.mac[0] ^= 1;
            assert!(!should_skip_system_auth_token_verification());
            let error = verify_auth_token_for_omk(&token).unwrap_err();
            assert!(
                matches!(error.root_cause().downcast_ref::<KeystoreError>(), Some(KeystoreError::Km(code)) if *code == ErrorCode::KEY_USER_NOT_AUTHENTICATED)
            );
            config().write().unwrap().main.force_skip_system_biometric_hat_verification = true;
            let result = verify_auth_token_for_omk(&token);
            config().write().unwrap().main.force_skip_system_biometric_hat_verification = false;
            result.unwrap();
            token.mac.clear();
            assert!(validate_auth_token_shape(&token).is_err());
        });
    }

    #[test]
    fn device_system_verifier_explicitly_rejects_bad_mac() {
        const SERVICE: &str = "android.hardware.security.keymint.IKeyMintDevice/default";
        let device = get_system_keymint(SERVICE, SecurityLevel::TRUSTED_ENVIRONMENT)
            .expect("System verifier lookup")
            .expect("System verifier service must be available");
        let token = keymint_tests::signed_auth_token(0, &[0x41; 32]);
        let params = verifier_key_params(&token).unwrap();
        let id = VerifierKeyCacheKey {
            service: SERVICE,
            auth_type: token.authenticatorType.0,
            user_id: token.userId,
            authenticator_id: token.authenticatorId,
        };
        let key = get_system_verifier_key(SERVICE, &device, &id, &params)
            .expect("System verifier key generation must succeed");
        let op_params = key_params_to_aidl(
            &[KeyParam::Digest(KmDigest::Sha256), KeyParam::MacLength(256)],
            KeyMintDevice::KEY_MINT_V5,
        )
        .unwrap();
        let result = begin_system_verifier_once(&device, &key.blob, &op_params, &token);
        let cleanup = device.deleteKey(&key.blob);
        clear_system_keymint(SERVICE);
        cleanup.expect("temporary verifier key cleanup");
        let status = result.expect_err("an independent test MAC must not authenticate with System");
        assert_eq!(status.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
        assert_eq!(status.service_specific_error(), ErrorCode::KEY_USER_NOT_AUTHENTICATED.0);
    }
}
