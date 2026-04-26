use log::{debug, info, warn};
use rsbinder::{thread_state::CallingContext, Interface, Strong};

use crate::android::hardware::security::keymint::KeyParameter::KeyParameter;
use crate::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::android::hardware::security::keymint::Tag::Tag;
use crate::android::system::keystore2::AuthenticatorSpec::AuthenticatorSpec;
use crate::android::system::keystore2::CreateOperationResponse::CreateOperationResponse;
use crate::android::system::keystore2::Domain::Domain;
use crate::android::system::keystore2::EphemeralStorageKeyResponse::EphemeralStorageKeyResponse;
use crate::android::system::keystore2::IKeystoreOperation::{
    BnKeystoreOperation, IKeystoreOperation as AospKeystoreOperation,
};
use crate::android::system::keystore2::IKeystoreSecurityLevel::{
    BnKeystoreSecurityLevel, IKeystoreSecurityLevel as AospKeystoreSecurityLevel,
};
use crate::android::system::keystore2::IKeystoreService::{
    BnKeystoreService, IKeystoreService as AospKeystoreService,
};
use crate::android::system::keystore2::KeyDescriptor::KeyDescriptor;
use crate::android::system::keystore2::KeyEntryResponse::KeyEntryResponse;
use crate::android::system::keystore2::KeyMetadata::KeyMetadata;
use crate::config::InterceptConfig;
use crate::forward::BypassGuard;
use crate::identify::{self, ServiceMethod};
use crate::top::qwq2333::ohmykeymint::CallerInfo::CallerInfo;
use crate::top::qwq2333::ohmykeymint::IOhMyKsService::IOhMyKsService;
use crate::top::qwq2333::ohmykeymint::IOhMySecurityLevel::IOhMySecurityLevel;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTarget {
    System,
    Omk,
}

#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub uid: u32,
    pub pid: i32,
    pub sid: String,
}

impl CallerIdentity {
    pub fn new(uid: u32, pid: i32) -> Self {
        Self {
            uid,
            pid,
            sid: String::new(),
        }
    }

    pub fn with_sid(mut self, sid: impl Into<String>) -> Self {
        self.sid = sid.into();
        self
    }

    pub fn to_caller_info(&self) -> CallerInfo {
        CallerInfo {
            callingUid: self.uid as i64,
            callingSid: self.sid.clone(),
            callingPid: self.pid as i64,
        }
    }

    pub fn from_calling_context(context: &CallingContext) -> Self {
        Self {
            uid: context.uid as u32,
            pid: context.pid as i32,
            sid: context
                .sid
                .as_ref()
                .map(|sid| sid.to_string_lossy().into_owned())
                .unwrap_or_default(),
        }
    }
}

pub(crate) fn current_calling_identity() -> CallerIdentity {
    CallerIdentity::from_calling_context(&CallingContext::default())
}

pub type AospServiceBinder = Strong<dyn AospKeystoreService>;
pub type AospSecurityLevelBinder = Strong<dyn AospKeystoreSecurityLevel>;
pub type AospOperationBinder = Strong<dyn AospKeystoreOperation>;
pub type OmkServiceBinder = Strong<dyn IOhMyKsService>;
pub type OmkSecurityLevelBinder = Strong<dyn IOhMySecurityLevel>;

pub fn new_service_binder(
    caller: CallerIdentity,
    intercept: InterceptConfig,
    allow_omk: bool,
    system_backend: AospServiceBinder,
    omk_backend: Option<OmkServiceBinder>,
) -> AospServiceBinder {
    BnKeystoreService::new_binder(KeystoreServiceBinder {
        caller,
        intercept,
        allow_omk,
        system_backend,
        omk_backend,
    })
}

pub fn new_security_level_binder(
    security_level: SecurityLevel,
    preferred_route: RouteTarget,
    system_backend: Option<AospSecurityLevelBinder>,
    omk_backend: Option<OmkSecurityLevelBinder>,
) -> AospSecurityLevelBinder {
    BnKeystoreSecurityLevel::new_binder(KeystoreSecurityLevelBinder {
        security_level,
        preferred_route,
        system_backend,
        omk_backend,
    })
}

pub fn new_operation_binder(
    backend: AospOperationBinder,
    route: RouteTarget,
) -> AospOperationBinder {
    BnKeystoreOperation::new_binder(KeystoreOperationBinder { backend, route })
}

pub struct KeystoreServiceBinder {
    caller: CallerIdentity,
    intercept: InterceptConfig,
    allow_omk: bool,
    system_backend: AospServiceBinder,
    omk_backend: Option<OmkServiceBinder>,
}

impl Interface for KeystoreServiceBinder {}

impl KeystoreServiceBinder {
    fn caller_info(&self) -> CallerInfo {
        self.caller.to_caller_info()
    }

    fn missing_backend<T>() -> rsbinder::status::Result<T> {
        Err(rsbinder::StatusCode::BadValue.into())
    }

    fn prefer_omk(&self, method: ServiceMethod) -> bool {
        self.allow_omk
            && self.omk_backend.is_some()
            && identify::is_omk_service_route_enabled(method, &self.intercept)
    }

    fn call_system<T>(
        &self,
        call: impl FnOnce(&dyn AospKeystoreService) -> rsbinder::status::Result<T>,
    ) -> rsbinder::status::Result<T> {
        let _guard = BypassGuard::enter();
        call(self.system_backend.as_ref())
    }

    fn call_omk<T>(
        &self,
        call: impl FnOnce(&dyn IOhMyKsService, Option<&CallerInfo>) -> rsbinder::status::Result<T>,
    ) -> rsbinder::status::Result<T> {
        let Some(backend) = self.omk_backend.as_ref() else {
            return Self::missing_backend();
        };
        let caller = self.caller_info();
        let _guard = BypassGuard::enter();
        call(backend.as_ref(), Some(&caller))
    }

    fn optional_system_security_level(
        &self,
        security_level: SecurityLevel,
    ) -> Option<AospSecurityLevelBinder> {
        self.call_system(|backend| backend.r#getSecurityLevel(security_level))
            .ok()
    }

    fn fallback_to_system<T>(
        &self,
        method: ServiceMethod,
        error: rsbinder::Status,
        system_call: impl FnOnce() -> rsbinder::status::Result<T>,
    ) -> rsbinder::status::Result<T> {
        warn!(
            "[Injector][Route] OMK service backend for {:?} failed for uid={} pid={}: {}; falling back to system",
            method,
            self.caller.uid,
            self.caller.pid,
            error
        );
        system_call()
    }

    fn wrap_system_key_entry(&self, response: KeyEntryResponse) -> KeyEntryResponse {
        let KeyEntryResponse {
            r#iSecurityLevel,
            r#metadata,
        } = response;
        let security_level = r#metadata.r#keySecurityLevel;
        let system_backend =
            r#iSecurityLevel.or_else(|| self.optional_system_security_level(security_level));
        let wrapped = system_backend.map(|backend| {
            new_security_level_binder(security_level, RouteTarget::System, Some(backend), None)
        });

        KeyEntryResponse {
            r#iSecurityLevel: wrapped,
            r#metadata,
        }
    }

    fn wrap_omk_key_entry(
        &self,
        response: KeyEntryResponse,
        omk_backend: OmkSecurityLevelBinder,
    ) -> KeyEntryResponse {
        let security_level = response.r#metadata.r#keySecurityLevel;
        let system_backend = self.optional_system_security_level(security_level);
        KeyEntryResponse {
            r#iSecurityLevel: Some(new_security_level_binder(
                security_level,
                RouteTarget::Omk,
                system_backend,
                Some(omk_backend),
            )),
            r#metadata: response.r#metadata,
        }
    }
}

impl AospKeystoreService for KeystoreServiceBinder {
    fn r#getSecurityLevel(
        &self,
        security_level: SecurityLevel,
    ) -> rsbinder::status::Result<AospSecurityLevelBinder> {
        info!(
            "[Injector][Spike] request-side KeystoreServiceBinder::getSecurityLevel hit uid={} pid={} sid='{}' requested={:?} allow_omk={} omk_available={}",
            self.caller.uid,
            self.caller.pid,
            self.caller.sid,
            security_level,
            self.allow_omk,
            self.omk_backend.is_some(),
        );

        if self.prefer_omk(ServiceMethod::GetSecurityLevel) {
            match self.call_omk(|backend, _caller| backend.r#getOhMySecurityLevel(security_level)) {
                Ok(omk_backend) => {
                    let Some(system_backend) = self.optional_system_security_level(security_level)
                    else {
                        warn!(
                            "[Injector][Route] OMK getSecurityLevel({:?}) succeeded for uid={} pid={} but system fallback backend was unavailable; returning system wrapper instead",
                            security_level,
                            self.caller.uid,
                            self.caller.pid,
                        );
                        return self
                            .call_system(|backend| backend.r#getSecurityLevel(security_level))
                            .map(|system_backend| {
                                new_security_level_binder(
                                    security_level,
                                    RouteTarget::System,
                                    Some(system_backend),
                                    None,
                                )
                            });
                    };

                    return Ok(new_security_level_binder(
                        security_level,
                        RouteTarget::Omk,
                        Some(system_backend),
                        Some(omk_backend),
                    ));
                }
                Err(error) => {
                    return self.fallback_to_system(ServiceMethod::GetSecurityLevel, error, || {
                        self.call_system(|backend| backend.r#getSecurityLevel(security_level))
                            .map(|system_backend| {
                                new_security_level_binder(
                                    security_level,
                                    RouteTarget::System,
                                    Some(system_backend),
                                    None,
                                )
                            })
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#getSecurityLevel(security_level))
            .map(|system_backend| {
                new_security_level_binder(
                    security_level,
                    RouteTarget::System,
                    Some(system_backend),
                    None,
                )
            })
    }

    fn r#getKeyEntry(&self, key: &KeyDescriptor) -> rsbinder::status::Result<KeyEntryResponse> {
        if self.prefer_omk(ServiceMethod::GetKeyEntry) {
            match self.call_omk(|backend, caller| backend.r#getKeyEntry(caller, key)) {
                Ok(entry) => {
                    let security_level = entry.r#metadata.r#keySecurityLevel;
                    match self
                        .call_omk(|backend, _caller| backend.r#getOhMySecurityLevel(security_level))
                    {
                        Ok(omk_backend) => return Ok(self.wrap_omk_key_entry(entry, omk_backend)),
                        Err(error) => {
                            return self.fallback_to_system(
                                ServiceMethod::GetKeyEntry,
                                error,
                                || {
                                    self.call_system(|backend| backend.r#getKeyEntry(key))
                                        .map(|entry| self.wrap_system_key_entry(entry))
                                },
                            );
                        }
                    }
                }
                Err(error) => {
                    return self.fallback_to_system(ServiceMethod::GetKeyEntry, error, || {
                        self.call_system(|backend| backend.r#getKeyEntry(key))
                            .map(|entry| self.wrap_system_key_entry(entry))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#getKeyEntry(key))
            .map(|entry| self.wrap_system_key_entry(entry))
    }

    fn r#updateSubcomponent(
        &self,
        key: &KeyDescriptor,
        public_cert: Option<&[u8]>,
        certificate_chain: Option<&[u8]>,
    ) -> rsbinder::status::Result<()> {
        if self.prefer_omk(ServiceMethod::UpdateSubcomponent) {
            match self.call_omk(|backend, caller| {
                backend.r#updateSubcomponent(caller, key, public_cert, certificate_chain)
            }) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    return self.fallback_to_system(
                        ServiceMethod::UpdateSubcomponent,
                        error,
                        || {
                            self.call_system(|backend| {
                                backend.r#updateSubcomponent(key, public_cert, certificate_chain)
                            })
                        },
                    );
                }
            }
        }

        self.call_system(|backend| {
            backend.r#updateSubcomponent(key, public_cert, certificate_chain)
        })
    }

    fn r#listEntries(
        &self,
        domain: Domain,
        nspace: i64,
    ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
        if self.prefer_omk(ServiceMethod::ListEntries) {
            match self.call_omk(|backend, caller| backend.r#listEntries(caller, domain, nspace)) {
                Ok(entries) => return Ok(entries),
                Err(error) => {
                    return self.fallback_to_system(ServiceMethod::ListEntries, error, || {
                        self.call_system(|backend| backend.r#listEntries(domain, nspace))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#listEntries(domain, nspace))
    }

    fn r#deleteKey(&self, key: &KeyDescriptor) -> rsbinder::status::Result<()> {
        if self.prefer_omk(ServiceMethod::DeleteKey) {
            match self.call_omk(|backend, caller| backend.r#deleteKey(caller, key)) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    return self.fallback_to_system(ServiceMethod::DeleteKey, error, || {
                        self.call_system(|backend| backend.r#deleteKey(key))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#deleteKey(key))
    }

    fn r#grant(
        &self,
        key: &KeyDescriptor,
        grantee_uid: i32,
        access_vector: i32,
    ) -> rsbinder::status::Result<KeyDescriptor> {
        if self.prefer_omk(ServiceMethod::Grant) {
            match self.call_omk(|backend, caller| {
                backend.r#grant(caller, key, grantee_uid, access_vector)
            }) {
                Ok(granted) => return Ok(granted),
                Err(error) => {
                    return self.fallback_to_system(ServiceMethod::Grant, error, || {
                        self.call_system(|backend| backend.r#grant(key, grantee_uid, access_vector))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#grant(key, grantee_uid, access_vector))
    }

    fn r#ungrant(&self, key: &KeyDescriptor, grantee_uid: i32) -> rsbinder::status::Result<()> {
        if self.prefer_omk(ServiceMethod::Ungrant) {
            match self.call_omk(|backend, caller| backend.r#ungrant(caller, key, grantee_uid)) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    return self.fallback_to_system(ServiceMethod::Ungrant, error, || {
                        self.call_system(|backend| backend.r#ungrant(key, grantee_uid))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#ungrant(key, grantee_uid))
    }

    fn r#getNumberOfEntries(&self, domain: Domain, nspace: i64) -> rsbinder::status::Result<i32> {
        if self.prefer_omk(ServiceMethod::GetNumberOfEntries) {
            match self
                .call_omk(|backend, caller| backend.r#getNumberOfEntries(caller, domain, nspace))
            {
                Ok(count) => return Ok(count),
                Err(error) => {
                    return self.fallback_to_system(
                        ServiceMethod::GetNumberOfEntries,
                        error,
                        || self.call_system(|backend| backend.r#getNumberOfEntries(domain, nspace)),
                    );
                }
            }
        }

        self.call_system(|backend| backend.r#getNumberOfEntries(domain, nspace))
    }

    fn r#listEntriesBatched(
        &self,
        domain: Domain,
        nspace: i64,
        starting_past_alias: Option<&str>,
    ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
        if self.prefer_omk(ServiceMethod::ListEntriesBatched) {
            match self.call_omk(|backend, caller| {
                backend.r#listEntriesBatched(caller, domain, nspace, starting_past_alias)
            }) {
                Ok(entries) => return Ok(entries),
                Err(error) => {
                    return self.fallback_to_system(
                        ServiceMethod::ListEntriesBatched,
                        error,
                        || {
                            self.call_system(|backend| {
                                backend.r#listEntriesBatched(domain, nspace, starting_past_alias)
                            })
                        },
                    );
                }
            }
        }

        self.call_system(|backend| {
            backend.r#listEntriesBatched(domain, nspace, starting_past_alias)
        })
    }

    fn r#getSupplementaryAttestationInfo(&self, tag: Tag) -> rsbinder::status::Result<Vec<u8>> {
        if self.prefer_omk(ServiceMethod::GetSupplementaryAttestationInfo) {
            match self.call_omk(|backend, _caller| backend.r#getSupplementaryAttestationInfo(tag)) {
                Ok(info) => return Ok(info),
                Err(error) => {
                    return self.fallback_to_system(
                        ServiceMethod::GetSupplementaryAttestationInfo,
                        error,
                        || {
                            self.call_system(|backend| {
                                backend.r#getSupplementaryAttestationInfo(tag)
                            })
                        },
                    );
                }
            }
        }

        self.call_system(|backend| backend.r#getSupplementaryAttestationInfo(tag))
    }
}

pub struct KeystoreSecurityLevelBinder {
    security_level: SecurityLevel,
    preferred_route: RouteTarget,
    system_backend: Option<AospSecurityLevelBinder>,
    omk_backend: Option<OmkSecurityLevelBinder>,
}

impl Interface for KeystoreSecurityLevelBinder {}

impl KeystoreSecurityLevelBinder {
    fn caller_info(&self) -> CallerInfo {
        current_calling_identity().to_caller_info()
    }

    fn missing_backend<T>() -> rsbinder::status::Result<T> {
        Err(rsbinder::StatusCode::BadValue.into())
    }

    fn call_system<T>(
        &self,
        call: impl FnOnce(&dyn AospKeystoreSecurityLevel) -> rsbinder::status::Result<T>,
    ) -> rsbinder::status::Result<T> {
        let Some(backend) = self.system_backend.as_ref() else {
            return Self::missing_backend();
        };
        let _guard = BypassGuard::enter();
        call(backend.as_ref())
    }

    fn call_omk<T>(
        &self,
        call: impl FnOnce(&dyn IOhMySecurityLevel, Option<&CallerInfo>) -> rsbinder::status::Result<T>,
    ) -> rsbinder::status::Result<T> {
        let Some(backend) = self.omk_backend.as_ref() else {
            return Self::missing_backend();
        };
        let caller = self.caller_info();
        let _guard = BypassGuard::enter();
        call(backend.as_ref(), Some(&caller))
    }

    fn prefer_omk(&self) -> bool {
        self.preferred_route == RouteTarget::Omk && self.omk_backend.is_some()
    }

    fn wrap_operation_response(
        &self,
        mut response: CreateOperationResponse,
        route: RouteTarget,
    ) -> CreateOperationResponse {
        response.r#iOperation = response
            .r#iOperation
            .map(|backend| new_operation_binder(backend, route));
        response
    }

    fn fallback_to_system<T>(
        &self,
        error: rsbinder::Status,
        system_call: impl FnOnce() -> rsbinder::status::Result<T>,
    ) -> rsbinder::status::Result<T> {
        let caller = current_calling_identity();
        warn!(
            "[Injector][Route] OMK backend for {:?} failed for uid={} pid={}: {}; falling back to system",
            self.security_level,
            caller.uid,
            caller.pid,
            error
        );
        system_call()
    }
}

impl AospKeystoreSecurityLevel for KeystoreSecurityLevelBinder {
    fn r#createOperation(
        &self,
        key: &KeyDescriptor,
        operation_parameters: &[KeyParameter],
        forced: bool,
    ) -> rsbinder::status::Result<CreateOperationResponse> {
        if self.prefer_omk() {
            match self.call_omk(|backend, caller| {
                backend.r#createOperation(caller, key, operation_parameters, forced)
            }) {
                Ok(response) => return Ok(self.wrap_operation_response(response, RouteTarget::Omk)),
                Err(error) => {
                    return self.fallback_to_system(error, || {
                        self.call_system(|backend| {
                            backend.r#createOperation(key, operation_parameters, forced)
                        })
                        .map(|response| self.wrap_operation_response(response, RouteTarget::System))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#createOperation(key, operation_parameters, forced))
            .map(|response| self.wrap_operation_response(response, RouteTarget::System))
    }

    fn r#generateKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        entropy: &[u8],
    ) -> rsbinder::status::Result<KeyMetadata> {
        if self.prefer_omk() {
            match self.call_omk(|backend, caller| {
                backend.r#generateKey(caller, key, attestation_key, params, flags, entropy)
            }) {
                Ok(metadata) => return Ok(metadata),
                Err(error) => {
                    return self.fallback_to_system(error, || {
                        self.call_system(|backend| {
                            backend.r#generateKey(key, attestation_key, params, flags, entropy)
                        })
                    });
                }
            }
        }

        self.call_system(|backend| {
            backend.r#generateKey(key, attestation_key, params, flags, entropy)
        })
    }

    fn r#importKey(
        &self,
        key: &KeyDescriptor,
        attestation_key: Option<&KeyDescriptor>,
        params: &[KeyParameter],
        flags: i32,
        key_data: &[u8],
    ) -> rsbinder::status::Result<KeyMetadata> {
        if self.prefer_omk() {
            match self.call_omk(|backend, caller| {
                backend.r#importKey(caller, key, attestation_key, params, flags, key_data)
            }) {
                Ok(metadata) => return Ok(metadata),
                Err(error) => {
                    return self.fallback_to_system(error, || {
                        self.call_system(|backend| {
                            backend.r#importKey(key, attestation_key, params, flags, key_data)
                        })
                    });
                }
            }
        }

        self.call_system(|backend| {
            backend.r#importKey(key, attestation_key, params, flags, key_data)
        })
    }

    fn r#importWrappedKey(
        &self,
        key: &KeyDescriptor,
        wrapping_key: &KeyDescriptor,
        masking_key: Option<&[u8]>,
        params: &[KeyParameter],
        authenticators: &[AuthenticatorSpec],
    ) -> rsbinder::status::Result<KeyMetadata> {
        if self.prefer_omk() {
            match self.call_omk(|backend, caller| {
                backend.r#importWrappedKey(
                    caller,
                    key,
                    wrapping_key,
                    masking_key,
                    params,
                    authenticators,
                )
            }) {
                Ok(metadata) => return Ok(metadata),
                Err(error) => {
                    return self.fallback_to_system(error, || {
                        self.call_system(|backend| {
                            backend.r#importWrappedKey(
                                key,
                                wrapping_key,
                                masking_key,
                                params,
                                authenticators,
                            )
                        })
                    });
                }
            }
        }

        self.call_system(|backend| {
            backend.r#importWrappedKey(key, wrapping_key, masking_key, params, authenticators)
        })
    }

    fn r#convertStorageKeyToEphemeral(
        &self,
        storage_key: &KeyDescriptor,
    ) -> rsbinder::status::Result<EphemeralStorageKeyResponse> {
        if self.prefer_omk() {
            match self
                .call_omk(|backend, _caller| backend.r#convertStorageKeyToEphemeral(storage_key))
            {
                Ok(response) => return Ok(response),
                Err(error) => {
                    return self.fallback_to_system(error, || {
                        self.call_system(|backend| {
                            backend.r#convertStorageKeyToEphemeral(storage_key)
                        })
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#convertStorageKeyToEphemeral(storage_key))
    }

    fn r#deleteKey(&self, key: &KeyDescriptor) -> rsbinder::status::Result<()> {
        if self.prefer_omk() {
            match self.call_omk(|backend, _caller| backend.r#deleteKey(key)) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    return self.fallback_to_system(error, || {
                        self.call_system(|backend| backend.r#deleteKey(key))
                    });
                }
            }
        }

        self.call_system(|backend| backend.r#deleteKey(key))
    }
}

pub struct KeystoreOperationBinder {
    backend: AospOperationBinder,
    route: RouteTarget,
}

impl Interface for KeystoreOperationBinder {}

impl AospKeystoreOperation for KeystoreOperationBinder {
    fn r#updateAad(&self, aad_input: &[u8]) -> rsbinder::status::Result<()> {
        // OMK operations go to another process where the hook isn't installed,
        // so bypass guard is only needed for local system operations.
        let _guard = if self.route == RouteTarget::System {
            Some(BypassGuard::enter())
        } else {
            None
        };
        let result = self.backend.r#updateAad(aad_input);
        if let Err(ref e) = result {
            debug!(
                "[Injector][Route] KeystoreOperationBinder::updateAad failed: {}",
                e
            );
        }
        result
    }

    fn r#update(&self, input: &[u8]) -> rsbinder::status::Result<Option<Vec<u8>>> {
        let _guard = if self.route == RouteTarget::System {
            Some(BypassGuard::enter())
        } else {
            None
        };
        let result = self.backend.r#update(input);
        if let Err(ref e) = result {
            debug!(
                "[Injector][Route] KeystoreOperationBinder::update failed: {}",
                e
            );
        }
        result
    }

    fn r#finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> rsbinder::status::Result<Option<Vec<u8>>> {
        let _guard = if self.route == RouteTarget::System {
            Some(BypassGuard::enter())
        } else {
            None
        };
        let result = self.backend.r#finish(input, signature);
        if let Err(ref e) = result {
            debug!(
                "[Injector][Route] KeystoreOperationBinder::finish failed: {}",
                e
            );
        }
        result
    }

    fn r#abort(&self) -> rsbinder::status::Result<()> {
        let _guard = if self.route == RouteTarget::System {
            Some(BypassGuard::enter())
        } else {
            None
        };
        let result = self.backend.r#abort();
        if let Err(ref e) = result {
            debug!(
                "[Injector][Route] KeystoreOperationBinder::abort failed: {}",
                e
            );
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use rsbinder::{Interface, StatusCode};

    #[derive(Clone)]
    struct OperationCounters {
        system_abort: Arc<AtomicUsize>,
        omk_abort: Arc<AtomicUsize>,
    }

    struct CountingOperation {
        aborts: Arc<AtomicUsize>,
    }

    impl Interface for CountingOperation {}

    impl AospKeystoreOperation for CountingOperation {
        fn r#updateAad(&self, _aad_input: &[u8]) -> rsbinder::status::Result<()> {
            Ok(())
        }

        fn r#update(&self, _input: &[u8]) -> rsbinder::status::Result<Option<Vec<u8>>> {
            Ok(Some(vec![1, 2, 3]))
        }

        fn r#finish(
            &self,
            _input: Option<&[u8]>,
            _signature: Option<&[u8]>,
        ) -> rsbinder::status::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        fn r#abort(&self) -> rsbinder::status::Result<()> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct CountingSystemSecurityLevel {
        delete_calls: Arc<AtomicUsize>,
        operation_aborts: Arc<AtomicUsize>,
    }

    impl Interface for CountingSystemSecurityLevel {}

    impl AospKeystoreSecurityLevel for CountingSystemSecurityLevel {
        fn r#createOperation(
            &self,
            _key: &KeyDescriptor,
            _operation_parameters: &[KeyParameter],
            _forced: bool,
        ) -> rsbinder::status::Result<CreateOperationResponse> {
            Ok(CreateOperationResponse {
                r#iOperation: Some(BnKeystoreOperation::new_binder(CountingOperation {
                    aborts: self.operation_aborts.clone(),
                })),
                r#operationChallenge: None,
                r#parameters: None,
                r#upgradedBlob: None,
            })
        }

        fn r#generateKey(
            &self,
            _key: &KeyDescriptor,
            _attestation_key: Option<&KeyDescriptor>,
            _params: &[KeyParameter],
            _flags: i32,
            _entropy: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importKey(
            &self,
            _key: &KeyDescriptor,
            _attestation_key: Option<&KeyDescriptor>,
            _params: &[KeyParameter],
            _flags: i32,
            _key_data: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importWrappedKey(
            &self,
            _key: &KeyDescriptor,
            _wrapping_key: &KeyDescriptor,
            _masking_key: Option<&[u8]>,
            _params: &[KeyParameter],
            _authenticators: &[AuthenticatorSpec],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#convertStorageKeyToEphemeral(
            &self,
            _storage_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<EphemeralStorageKeyResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(&self, _key: &KeyDescriptor) -> rsbinder::status::Result<()> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct CountingOmkSecurityLevel {
        operation_aborts: Arc<AtomicUsize>,
        should_fail_create: bool,
    }

    impl Interface for CountingOmkSecurityLevel {}

    impl IOhMySecurityLevel for CountingOmkSecurityLevel {
        fn r#createOperation(
            &self,
            _ctx: Option<&CallerInfo>,
            _key: &KeyDescriptor,
            _operation_parameters: &[KeyParameter],
            _forced: bool,
        ) -> rsbinder::status::Result<CreateOperationResponse> {
            if self.should_fail_create {
                return Err(StatusCode::UnknownTransaction.into());
            }

            Ok(CreateOperationResponse {
                r#iOperation: Some(BnKeystoreOperation::new_binder(CountingOperation {
                    aborts: self.operation_aborts.clone(),
                })),
                r#operationChallenge: None,
                r#parameters: None,
                r#upgradedBlob: None,
            })
        }

        fn r#generateKey(
            &self,
            _ctx: Option<&CallerInfo>,
            _key: &KeyDescriptor,
            _attestation_key: Option<&KeyDescriptor>,
            _params: &[KeyParameter],
            _flags: i32,
            _entropy: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importKey(
            &self,
            _ctx: Option<&CallerInfo>,
            _key: &KeyDescriptor,
            _attestation_key: Option<&KeyDescriptor>,
            _params: &[KeyParameter],
            _flags: i32,
            _key_data: &[u8],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#importWrappedKey(
            &self,
            _ctx: Option<&CallerInfo>,
            _key: &KeyDescriptor,
            _wrapping_key: &KeyDescriptor,
            _masking_key: Option<&[u8]>,
            _params: &[KeyParameter],
            _authenticators: &[AuthenticatorSpec],
        ) -> rsbinder::status::Result<KeyMetadata> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#convertStorageKeyToEphemeral(
            &self,
            _storage_key: &KeyDescriptor,
        ) -> rsbinder::status::Result<EphemeralStorageKeyResponse> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(&self, _key: &KeyDescriptor) -> rsbinder::status::Result<()> {
            Ok(())
        }
    }

    struct CountingSystemService {
        security_level_backend: AospSecurityLevelBinder,
        key_entry_level: SecurityLevel,
    }

    impl Interface for CountingSystemService {}

    impl AospKeystoreService for CountingSystemService {
        fn r#getSecurityLevel(
            &self,
            _security_level: SecurityLevel,
        ) -> rsbinder::status::Result<AospSecurityLevelBinder> {
            Ok(self.security_level_backend.clone())
        }

        fn r#getKeyEntry(&self, key: &KeyDescriptor) -> rsbinder::status::Result<KeyEntryResponse> {
            Ok(KeyEntryResponse {
                r#iSecurityLevel: None,
                r#metadata: sample_key_metadata(key.clone(), self.key_entry_level),
            })
        }

        fn r#updateSubcomponent(
            &self,
            _key: &KeyDescriptor,
            _public_cert: Option<&[u8]>,
            _certificate_chain: Option<&[u8]>,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#listEntries(
            &self,
            _domain: Domain,
            _nspace: i64,
        ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#deleteKey(&self, _key: &KeyDescriptor) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#grant(
            &self,
            _key: &KeyDescriptor,
            _grantee_uid: i32,
            _access_vector: i32,
        ) -> rsbinder::status::Result<KeyDescriptor> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#ungrant(
            &self,
            _key: &KeyDescriptor,
            _grantee_uid: i32,
        ) -> rsbinder::status::Result<()> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#getNumberOfEntries(
            &self,
            _domain: Domain,
            _nspace: i64,
        ) -> rsbinder::status::Result<i32> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#listEntriesBatched(
            &self,
            _domain: Domain,
            _nspace: i64,
            _starting_past_alias: Option<&str>,
        ) -> rsbinder::status::Result<Vec<KeyDescriptor>> {
            Err(StatusCode::UnknownTransaction.into())
        }

        fn r#getSupplementaryAttestationInfo(
            &self,
            _tag: Tag,
        ) -> rsbinder::status::Result<Vec<u8>> {
            Err(StatusCode::UnknownTransaction.into())
        }
    }

    fn sample_key_descriptor() -> KeyDescriptor {
        KeyDescriptor {
            domain: Domain::APP,
            nspace: 42,
            alias: Some("alias".to_string()),
            blob: None,
        }
    }

    fn sample_key_metadata(key: KeyDescriptor, level: SecurityLevel) -> KeyMetadata {
        KeyMetadata {
            r#key: key,
            r#keySecurityLevel: level,
            r#authorizations: Vec::new(),
            r#certificate: None,
            r#certificateChain: None,
            r#modificationTimeMs: 0,
        }
    }

    fn build_system_service(
        delete_calls: Arc<AtomicUsize>,
        operation_aborts: Arc<AtomicUsize>,
        key_entry_level: SecurityLevel,
    ) -> AospServiceBinder {
        let security_level_backend =
            BnKeystoreSecurityLevel::new_binder(CountingSystemSecurityLevel {
                delete_calls,
                operation_aborts,
            });
        BnKeystoreService::new_binder(CountingSystemService {
            security_level_backend,
            key_entry_level,
        })
    }

    #[test]
    fn get_security_level_system_route_returns_functional_wrapper() {
        let delete_calls = Arc::new(AtomicUsize::new(0));
        let system_service = build_system_service(
            delete_calls.clone(),
            Arc::new(AtomicUsize::new(0)),
            SecurityLevel::SOFTWARE,
        );
        let wrapper = new_service_binder(
            CallerIdentity::new(1000, 2000),
            InterceptConfig::default(),
            false,
            system_service,
            None,
        );

        let returned = wrapper
            .r#getSecurityLevel(SecurityLevel::SOFTWARE)
            .expect("system route should return a wrapper binder");
        returned
            .r#deleteKey(&sample_key_descriptor())
            .expect("system security-level wrapper should stay functional");

        assert_eq!(delete_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_key_entry_system_route_wraps_returned_security_level() {
        let delete_calls = Arc::new(AtomicUsize::new(0));
        let system_service = build_system_service(
            delete_calls.clone(),
            Arc::new(AtomicUsize::new(0)),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        );
        let wrapper = new_service_binder(
            CallerIdentity::new(1000, 2000),
            InterceptConfig::default(),
            false,
            system_service,
            None,
        );

        let response = wrapper
            .r#getKeyEntry(&sample_key_descriptor())
            .expect("system route should return key entry metadata");
        let security_level = response
            .r#iSecurityLevel
            .expect("getKeyEntry should wrap the system security-level binder");
        security_level
            .r#deleteKey(&sample_key_descriptor())
            .expect("wrapped security level should still forward to system");

        assert_eq!(delete_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn create_operation_sticks_to_the_backend_that_created_it() {
        let counters = OperationCounters {
            system_abort: Arc::new(AtomicUsize::new(0)),
            omk_abort: Arc::new(AtomicUsize::new(0)),
        };
        let system_backend = BnKeystoreSecurityLevel::new_binder(CountingSystemSecurityLevel {
            delete_calls: Arc::new(AtomicUsize::new(0)),
            operation_aborts: counters.system_abort.clone(),
        });
        let omk_backend = rsbinder::Strong::new(Box::new(CountingOmkSecurityLevel {
            operation_aborts: counters.omk_abort.clone(),
            should_fail_create: false,
        }) as Box<dyn IOhMySecurityLevel>);

        let system_wrapper = new_security_level_binder(
            SecurityLevel::SOFTWARE,
            RouteTarget::System,
            Some(system_backend.clone()),
            Some(omk_backend.clone()),
        );
        let system_operation = system_wrapper
            .r#createOperation(&sample_key_descriptor(), &[], false)
            .expect("system backend should create the operation")
            .r#iOperation
            .expect("createOperation should return an operation binder");
        system_operation
            .r#abort()
            .expect("system operation should remain usable");

        let omk_wrapper = new_security_level_binder(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            RouteTarget::Omk,
            Some(system_backend),
            Some(omk_backend),
        );
        let omk_operation = omk_wrapper
            .r#createOperation(&sample_key_descriptor(), &[], false)
            .expect("OMK backend should create the operation")
            .r#iOperation
            .expect("createOperation should return an operation binder");
        omk_operation
            .r#abort()
            .expect("OMK operation should remain usable");

        assert_eq!(counters.system_abort.load(Ordering::SeqCst), 1);
        assert_eq!(counters.omk_abort.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_omk_create_operation_falls_back_to_system_and_keeps_system_route() {
        let counters = OperationCounters {
            system_abort: Arc::new(AtomicUsize::new(0)),
            omk_abort: Arc::new(AtomicUsize::new(0)),
        };
        let system_backend = BnKeystoreSecurityLevel::new_binder(CountingSystemSecurityLevel {
            delete_calls: Arc::new(AtomicUsize::new(0)),
            operation_aborts: counters.system_abort.clone(),
        });
        let omk_backend = rsbinder::Strong::new(Box::new(CountingOmkSecurityLevel {
            operation_aborts: counters.omk_abort.clone(),
            should_fail_create: true,
        }) as Box<dyn IOhMySecurityLevel>);

        let wrapper = new_security_level_binder(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            RouteTarget::Omk,
            Some(system_backend),
            Some(omk_backend),
        );

        let operation = wrapper
            .r#createOperation(&sample_key_descriptor(), &[], false)
            .expect("system fallback should satisfy createOperation")
            .r#iOperation
            .expect("fallback result should still return an operation binder");
        operation
            .r#abort()
            .expect("fallback operation should stay pinned to system");

        assert_eq!(counters.system_abort.load(Ordering::SeqCst), 1);
        assert_eq!(counters.omk_abort.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn current_calling_identity_matches_calling_context_default() {
        let context = CallingContext::default();
        let caller = current_calling_identity();

        assert_eq!(caller.uid, context.uid as u32);
        assert_eq!(caller.pid, context.pid as i32);
        assert_eq!(
            caller.sid,
            context
                .sid
                .as_ref()
                .map(|sid| sid.to_string_lossy().into_owned())
                .unwrap_or_default()
        );
    }
}
