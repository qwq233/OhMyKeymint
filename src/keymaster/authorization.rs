use std::{cell::RefCell, collections::HashMap, sync::Arc};

use anyhow::{Context, Result};
use rsbinder::{hub, DeathRecipient, Interface, Status, Strong, WIBinder};

use crate::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
    IKeyMintDevice::IKeyMintDevice, KeyParameter::KeyParameter, KeyPurpose::KeyPurpose,
};
use crate::android::security::authorization::{
    AuthorizationTokens::AuthorizationTokens,
    IKeystoreAuthorization::{BnKeystoreAuthorization, IKeystoreAuthorization},
    ResponseCode::ResponseCode as AuthResponseCode,
};
use crate::config::config;
use crate::err;
use crate::global::{DB, ENFORCEMENTS, SUPER_KEY};
use crate::keymaster::error::{anyhow_error_to_string, is_dead_object_status, KsError};
use crate::keymaster::keymint_device::localize_auth_token_for_omk;
use crate::keymaster::permission::{
    check_forwarded_caller_provenance, check_keystore_permission, KeystorePerm,
};
use crate::keymaster::utils::key_params_to_aidl;
use crate::top::qwq2333::ohmykeymint::{
    CallerInfo::CallerInfo,
    IOhMyAuthorizationService::{BnOhMyAuthorizationService, IOhMyAuthorizationService},
};
use crate::watchdog as wd;
use kmr_wire::{
    keymint::{Algorithm as KmAlgorithm, Digest as KmDigest, KeyParam, KeyPurpose as KmKeyPurpose},
    KeySizeInBits,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
enum AuthorizationError {
    #[error("AuthorizationError::Rc({0:?})")]
    Rc(AuthResponseCode),
}

pub struct AuthorizationManager;

const AUTH_TOKEN_MAC_LEN: usize = 32;

impl AuthorizationManager {
    pub fn new_native_binder() -> Result<Strong<dyn IKeystoreAuthorization>> {
        Ok(BnKeystoreAuthorization::new_binder_with_features(
            Self,
            crate::sid_features(),
        ))
    }

    pub fn new_omk_binder() -> Result<Strong<dyn IOhMyAuthorizationService>> {
        Ok(BnOhMyAuthorizationService::new_binder_with_features(
            Self,
            crate::sid_features(),
        ))
    }

    fn add_auth_token(
        &self,
        ctx: Option<&CallerInfo>,
        auth_token: &HardwareAuthToken,
    ) -> Result<()> {
        check_authorization_permission(KeystorePerm::AddAuth, ctx, "addAuthToken")
            .context(err!("caller missing add_auth permission"))?;
        validate_auth_token_shape(auth_token)?;
        if should_skip_system_biometric_hat_verification(ctx, auth_token) {
            log::warn!(
                "system auth token MAC verification skipped by config for mirrored biometric authType={:#x} challengeTag={:04x}",
                auth_token.authenticatorType.0,
                challenge_tag(auth_token.challenge),
            );
        } else {
            verify_system_auth_token(auth_token)
                .context(err!("system KeyMint did not verify the auth token MAC"))?;
        }

        let localized = localize_auth_token_for_omk(auth_token)
            .context(err!("localizing trusted auth token for OMK"))?;

        log::info!(
            "add_auth_token accepted source={} authType={:#x} challengeTag={:04x}",
            if ctx.is_some() { "mirror" } else { "native" },
            localized.authenticatorType.0,
            challenge_tag(localized.challenge),
        );

        ENFORCEMENTS.add_auth_token(localized);
        Ok(())
    }

    fn on_device_unlocked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> Result<()> {
        check_authorization_permission(KeystorePerm::Unlock, ctx, "onDeviceUnlocked")
            .context(err!("caller missing unlock permission"))?;
        let user_id_u32 = checked_user_id(user_id)?;
        ENFORCEMENTS.set_device_locked(user_id, false);

        let mut super_key = SUPER_KEY.write().unwrap();
        if let Some(password) = password {
            let password = password.into();
            DB.with(|db| {
                super_key.unlock_or_initialize_user(&mut db.borrow_mut(), user_id_u32, &password)
            })
            .context(err!("unlocking user {user_id} with password"))
        } else {
            DB.with(|db| {
                super_key.try_unlock_user_with_biometric(&mut db.borrow_mut(), user_id_u32)
            })
            .context(err!("unlocking user {user_id} with biometric auth token"))
        }
    }

    fn on_device_locked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        unlocking_sids: &[i64],
        weak_unlock_enabled: bool,
    ) -> Result<()> {
        check_authorization_permission(KeystorePerm::Lock, ctx, "onDeviceLocked")
            .context(err!("caller missing lock permission"))?;
        let user_id_u32 = checked_user_id(user_id)?;
        ENFORCEMENTS.set_device_locked(user_id, true);
        DB.with(|db| {
            SUPER_KEY
                .write()
                .unwrap()
                .lock_unlocked_device_required_keys(
                    &mut db.borrow_mut(),
                    user_id_u32,
                    unlocking_sids,
                    weak_unlock_enabled,
                );
        });
        Ok(())
    }

    fn on_user_storage_locked(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_authorization_permission(KeystorePerm::Lock, ctx, "onUserStorageLocked")
            .context(err!("caller missing lock permission"))?;
        let user_id = checked_user_id(user_id)?;
        SUPER_KEY.write().unwrap().forget_all_keys_for_user(user_id);
        Ok(())
    }

    fn on_weak_unlock_methods_expired(&self, ctx: Option<&CallerInfo>, user_id: i32) -> Result<()> {
        check_authorization_permission(KeystorePerm::Lock, ctx, "onWeakUnlockMethodsExpired")
            .context(err!("caller missing lock permission"))?;
        let user_id = checked_user_id(user_id)?;
        SUPER_KEY
            .write()
            .unwrap()
            .wipe_plaintext_unlocked_device_required_keys(user_id);
        Ok(())
    }

    fn on_non_lskf_unlock_methods_expired(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> Result<()> {
        check_authorization_permission(KeystorePerm::Lock, ctx, "onNonLskfUnlockMethodsExpired")
            .context(err!("caller missing lock permission"))?;
        let user_id = checked_user_id(user_id)?;
        SUPER_KEY
            .write()
            .unwrap()
            .wipe_all_unlocked_device_required_keys(user_id);
        Ok(())
    }

    fn get_auth_tokens_for_credstore(
        &self,
        ctx: Option<&CallerInfo>,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> Result<AuthorizationTokens> {
        check_authorization_permission(
            KeystorePerm::GetAuthToken,
            ctx,
            "getAuthTokensForCredStore",
        )
        .context(err!("caller missing get_auth_token permission"))?;
        if challenge == 0 {
            return Err(AuthorizationError::Rc(AuthResponseCode::INVALID_ARGUMENT))
                .context(err!("challenge must not be zero"));
        }

        let (auth_token, timestamp_token) = match ENFORCEMENTS.get_auth_tokens(
            challenge,
            secure_user_id,
            auth_token_max_age_millis,
        ) {
            Ok(tokens) => tokens,
            Err(error)
                if matches!(
                    error.root_cause().downcast_ref::<KsError>(),
                    Some(KsError::Rc(
                        crate::android::system::keystore2::ResponseCode::ResponseCode::KEY_NOT_FOUND
                    ))
                ) =>
            {
                return Err(AuthorizationError::Rc(
                    AuthResponseCode::NO_AUTH_TOKEN_FOUND,
                ))
                .context(err!("no matching auth token found"));
            }
            Err(error) => return Err(error).context(err!("getting auth tokens for credstore")),
        };
        Ok(AuthorizationTokens {
            authToken: auth_token,
            timestampToken: timestamp_token,
        })
    }

    fn get_last_auth_time(
        &self,
        ctx: Option<&CallerInfo>,
        secure_user_id: i64,
        auth_types: &[HardwareAuthenticatorType],
    ) -> Result<i64> {
        check_authorization_permission(KeystorePerm::GetLastAuthTime, ctx, "getLastAuthTime")
            .context(err!("caller missing get_last_auth_time permission"))?;

        let last = auth_types
            .iter()
            .filter_map(|auth_type| ENFORCEMENTS.get_last_auth_time(secure_user_id, *auth_type))
            .map(|time| time.milliseconds())
            .max();

        last.ok_or(AuthorizationError::Rc(
            AuthResponseCode::NO_AUTH_TOKEN_FOUND,
        ))
        .context(err!("no matching auth token found"))
    }
}

fn check_authorization_permission(
    permission: KeystorePerm,
    ctx: Option<&CallerInfo>,
    label: &str,
) -> Result<()> {
    if ctx.is_some() {
        check_forwarded_caller_provenance(label)?;
    }
    check_keystore_permission(permission, ctx)
}

fn checked_user_id(user_id: i32) -> Result<u32> {
    u32::try_from(user_id)
        .map_err(|_| AuthorizationError::Rc(AuthResponseCode::INVALID_ARGUMENT))
        .context(err!("user_id must be non-negative"))
}

fn validate_auth_token_shape(auth_token: &HardwareAuthToken) -> Result<()> {
    if auth_token.mac.len() != AUTH_TOKEN_MAC_LEN {
        return Err(AuthorizationError::Rc(AuthResponseCode::SYSTEM_ERROR))
            .context(err!("invalid auth token MAC length"));
    }

    if auth_token.userId == 0 && auth_token.authenticatorId == 0 {
        return Err(AuthorizationError::Rc(AuthResponseCode::SYSTEM_ERROR))
            .context(err!("auth token has no secure user id"));
    }

    let auth_type = auth_token.authenticatorType.0;
    let known_auth_types =
        HardwareAuthenticatorType::PASSWORD.0 | HardwareAuthenticatorType::FINGERPRINT.0;
    if auth_type == HardwareAuthenticatorType::NONE.0 || (auth_type & !known_auth_types) != 0 {
        return Err(AuthorizationError::Rc(AuthResponseCode::SYSTEM_ERROR))
            .context(err!("unsupported auth token authenticator type"));
    }

    Ok(())
}

fn should_skip_system_biometric_hat_verification(
    ctx: Option<&CallerInfo>,
    auth_token: &HardwareAuthToken,
) -> bool {
    ctx.is_some()
        && force_skip_system_biometric_hat_verification()
        && is_biometric_auth_token(auth_token)
}

fn force_skip_system_biometric_hat_verification() -> bool {
    config()
        .read()
        .map(|config| config.main.force_skip_system_biometric_hat_verification)
        .unwrap_or(false)
}

fn is_biometric_auth_token(auth_token: &HardwareAuthToken) -> bool {
    (auth_token.authenticatorType.0 & HardwareAuthenticatorType::FINGERPRINT.0) != 0
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
        .context(err!("failed to build system verifier key parameters"))?;
    let op_params = key_params_to_aidl(&[KeyParam::MacLength(VERIFIER_MAC_LENGTH_BITS as u32)])
        .context(err!("failed to build system verifier operation parameters"))?;
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
        return Err(AuthorizationError::Rc(AuthResponseCode::SYSTEM_ERROR))
            .with_context(|| format!("system KeyMint rejected auth token: {detail}"));
    }

    Err(AuthorizationError::Rc(AuthResponseCode::SYSTEM_ERROR))
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

    key_params_to_aidl(&params)
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
) -> std::result::Result<CachedVerifierKey, Status> {
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
) -> std::result::Result<(), Status> {
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
) -> std::result::Result<(), Status> {
    let result = keymint.begin(KeyPurpose::SIGN, key_blob, op_params, Some(auth_token))?;
    if let Some(operation) = result.operation {
        let _ = operation.r#abort();
    }
    Ok(())
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

impl Interface for AuthorizationManager {}

#[allow(non_snake_case)]
impl IKeystoreAuthorization for AuthorizationManager {
    fn addAuthToken(&self, auth_token: &HardwareAuthToken) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreAuthorization::addAuthToken");
        self.add_auth_token(None, auth_token)
            .map_err(into_logged_auth_binder)
    }

    fn onDeviceUnlocked(
        &self,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onDeviceUnlocked");
        self.on_device_unlocked(None, user_id, password)
            .map_err(into_logged_auth_binder)
    }

    fn onDeviceLocked(
        &self,
        user_id: i32,
        unlocking_sids: &[i64],
        weak_unlock_enabled: bool,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onDeviceLocked");
        self.on_device_locked(None, user_id, unlocking_sids, weak_unlock_enabled)
            .map_err(into_logged_auth_binder)
    }

    fn onUserStorageLocked(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onUserStorageLocked");
        self.on_user_storage_locked(None, user_id)
            .map_err(into_logged_auth_binder)
    }

    fn onWeakUnlockMethodsExpired(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onWeakUnlockMethodsExpired");
        self.on_weak_unlock_methods_expired(None, user_id)
            .map_err(into_logged_auth_binder)
    }

    fn onNonLskfUnlockMethodsExpired(&self, user_id: i32) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IKeystoreAuthorization::onNonLskfUnlockMethodsExpired");
        self.on_non_lskf_unlock_methods_expired(None, user_id)
            .map_err(into_logged_auth_binder)
    }

    fn getAuthTokensForCredStore(
        &self,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> rsbinder::status::Result<AuthorizationTokens> {
        let _wp = wd::watch("IKeystoreAuthorization::getAuthTokensForCredStore");
        self.get_auth_tokens_for_credstore(
            None,
            challenge,
            secure_user_id,
            auth_token_max_age_millis,
        )
        .map_err(into_logged_auth_binder)
    }

    fn getLastAuthTime(
        &self,
        secure_user_id: i64,
        auth_types: &[HardwareAuthenticatorType],
    ) -> rsbinder::status::Result<i64> {
        let _wp = wd::watch("IKeystoreAuthorization::getLastAuthTime");
        self.get_last_auth_time(None, secure_user_id, auth_types)
            .map_err(into_logged_auth_binder)
    }
}

#[allow(non_snake_case)]
impl IOhMyAuthorizationService for AuthorizationManager {
    fn addAuthToken(
        &self,
        ctx: Option<&CallerInfo>,
        auth_token: &HardwareAuthToken,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::addAuthToken");
        self.add_auth_token(ctx, auth_token)
            .map_err(into_logged_auth_binder)
    }

    fn onDeviceUnlocked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        password: Option<&[u8]>,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onDeviceUnlocked");
        self.on_device_unlocked(ctx, user_id, password)
            .map_err(into_logged_auth_binder)
    }

    fn onDeviceLocked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
        unlocking_sids: &[i64],
        weak_unlock_enabled: bool,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onDeviceLocked");
        self.on_device_locked(ctx, user_id, unlocking_sids, weak_unlock_enabled)
            .map_err(into_logged_auth_binder)
    }

    fn onUserStorageLocked(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onUserStorageLocked");
        self.on_user_storage_locked(ctx, user_id)
            .map_err(into_logged_auth_binder)
    }

    fn onWeakUnlockMethodsExpired(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onWeakUnlockMethodsExpired");
        self.on_weak_unlock_methods_expired(ctx, user_id)
            .map_err(into_logged_auth_binder)
    }

    fn onNonLskfUnlockMethodsExpired(
        &self,
        ctx: Option<&CallerInfo>,
        user_id: i32,
    ) -> rsbinder::status::Result<()> {
        let _wp = wd::watch("IOhMyAuthorizationService::onNonLskfUnlockMethodsExpired");
        self.on_non_lskf_unlock_methods_expired(ctx, user_id)
            .map_err(into_logged_auth_binder)
    }

    fn getAuthTokensForCredStore(
        &self,
        ctx: Option<&CallerInfo>,
        challenge: i64,
        secure_user_id: i64,
        auth_token_max_age_millis: i64,
    ) -> rsbinder::status::Result<AuthorizationTokens> {
        let _wp = wd::watch("IOhMyAuthorizationService::getAuthTokensForCredStore");
        self.get_auth_tokens_for_credstore(
            ctx,
            challenge,
            secure_user_id,
            auth_token_max_age_millis,
        )
        .map_err(into_logged_auth_binder)
    }

    fn getLastAuthTime(
        &self,
        ctx: Option<&CallerInfo>,
        secure_user_id: i64,
        auth_types: &[HardwareAuthenticatorType],
    ) -> rsbinder::status::Result<i64> {
        let _wp = wd::watch("IOhMyAuthorizationService::getLastAuthTime");
        self.get_last_auth_time(ctx, secure_user_id, auth_types)
            .map_err(into_logged_auth_binder)
    }
}

fn into_logged_auth_binder(error: anyhow::Error) -> Status {
    if !matches!(
        error.root_cause().downcast_ref::<AuthorizationError>(),
        Some(AuthorizationError::Rc(
            AuthResponseCode::NO_AUTH_TOKEN_FOUND
        ))
    ) {
        log::error!("{:?}", error);
    }
    into_auth_binder(error)
}

fn into_auth_binder(error: anyhow::Error) -> Status {
    let code = auth_response_code(&error);
    Status::new_service_specific_error(code.0, anyhow_error_to_string(&error))
}

fn auth_response_code(error: &anyhow::Error) -> AuthResponseCode {
    if let Some(error) = error.root_cause().downcast_ref::<AuthorizationError>() {
        return match error {
            AuthorizationError::Rc(code) => *code,
        };
    }

    match error.root_cause().downcast_ref::<KsError>() {
        Some(KsError::Rc(code)) => match *code {
            crate::android::system::keystore2::ResponseCode::ResponseCode::PERMISSION_DENIED => {
                AuthResponseCode::PERMISSION_DENIED
            }
            crate::android::system::keystore2::ResponseCode::ResponseCode::KEY_NOT_FOUND => {
                AuthResponseCode::KEY_NOT_FOUND
            }
            crate::android::system::keystore2::ResponseCode::ResponseCode::VALUE_CORRUPTED => {
                AuthResponseCode::VALUE_CORRUPTED
            }
            crate::android::system::keystore2::ResponseCode::ResponseCode::INVALID_ARGUMENT => {
                AuthResponseCode::INVALID_ARGUMENT
            }
            _ => AuthResponseCode::SYSTEM_ERROR,
        },
        _ => AuthResponseCode::SYSTEM_ERROR,
    }
}
