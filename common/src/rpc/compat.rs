use crate::aidl::android::security::{
    authorization::IKeystoreAuthorization::transactions as auth,
    maintenance::IKeystoreMaintenance::{
        transactions as maintenance, transport as maintenance_codec,
    },
};
use crate::aidl::top::qwq2333::ohmykeymint::{
    CallerInfo::CallerInfo, IOhMyAuthorizationService::transactions as private_auth,
    IOhMyMaintenanceService::transactions as private_maintenance,
};
use binder::binder_impl::{BorrowedParcel, Parcel};
use binder::StatusCode;

pub(super) fn authorization_legacy(
    api: i32,
    code: u32,
    caller: &CallerInfo,
    input: &BorrowedParcel<'_>,
) -> Result<Option<(u32, Parcel)>, StatusCode> {
    if api > 34 || code != 2 {
        return Ok(None);
    }
    binder::ext::with_parcel_position(input, input.get_data_position(), || {
        let event: i32 = input.read()?;
        let user: i32 = input.read()?;
        let password: Option<Vec<u8>> = input.read()?;
        let sids: Option<Vec<i64>> = input.read()?;
        let mut request = Parcel::new();
        request.borrowed().mark_sensitive();
        request.write(&Some(caller))?;
        request.write(&user)?;
        // The original System dispatcher has already accepted this legacy event.
        let code = if event == 0 {
            request.write(&password)?;
            private_auth::onDeviceUnlocked
        } else {
            request.write(&sids.unwrap_or_default())?;
            request.write(&false)?;
            private_auth::onDeviceLocked
        };
        // SAFETY: This complete SDK compatibility request is owned by this call.
        unsafe { request.set_data_position(0)? };
        Ok(Some((code, request)))
    })?
}

pub fn authorization_code(api: i32, code: u32) -> Option<u32> {
    if api <= 34 {
        match code {
            1 => Some(auth::addAuthToken),
            3 => Some(auth::getAuthTokensForCredStore),
            _ => None,
        }
    } else if api <= 36 {
        let methods = [
            auth::addAuthToken,
            auth::onDeviceUnlocked,
            auth::onDeviceLocked,
            auth::onWeakUnlockMethodsExpired,
            auth::onNonLskfUnlockMethodsExpired,
            auth::getAuthTokensForCredStore,
            auth::getLastAuthTime,
        ];
        code.checked_sub(1).and_then(|index| methods.get(index as usize)).copied()
    } else {
        Some(code)
    }
}

pub(super) fn maintenance_public_code(api: i32, code: u32) -> Option<u32> {
    if api <= 34 {
        match code {
            1 => Some(maintenance::onUserAdded),
            2 => Some(maintenance::onUserRemoved),
            4 => Some(maintenance::clearNamespace),
            6 => Some(maintenance::earlyBootEnded),
            8 => Some(maintenance::migrateKeyNamespace),
            9 => Some(maintenance::deleteAllKeys),
            _ => None,
        }
    } else if api == 35 && code >= 6 {
        Some(code - 1)
    } else {
        Some(code)
    }
}

pub fn maintenance_code(api: i32, code: u32) -> Option<(u32, bool)> {
    if (api <= 34 && code == 3) || (api == 35 && code == 5) {
        Some((private_maintenance::onUserPasswordChanged, true))
    } else {
        Some((maintenance_codec::rpc_transaction(maintenance_public_code(api, code)?)?.0, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_decode_failures_restore_the_original_cursor() {
        let caller = CallerInfo { uid: 1000, ..Default::default() };
        for api in [33, 34] {
            for fields in 0..4 {
                let mut input = Parcel::new();
                input.write(&37_i32).unwrap();
                let start = input.get_data_position();
                for word in &[0_i32, 12, -1, -1][..fields] {
                    input.write(&word).unwrap();
                }
                // SAFETY: start precedes the complete test request body.
                unsafe { input.set_data_position(start).unwrap() };
                assert_eq!(
                    authorization_legacy(api, 2, &caller, input.borrowed_ref()).err(),
                    Some(StatusCode::NOT_ENOUGH_DATA)
                );
                assert_eq!(input.get_data_position(), start);
            }
        }
    }

    #[test]
    fn legacy_lock_event_keeps_nullable_password_and_sid_order() {
        let caller = CallerInfo { uid: 1000, pid: 42, sid: "u:r:system_server:s0".into() };
        for (event, password, sids) in [
            (0, None, None),
            (0, Some(vec![1_u8]), Some(vec![9_i64, 2])),
            (1, None, None),
            (1, None, Some(vec![9_i64, 2])),
        ] {
            let mut input = Parcel::new();
            input.write(&event).unwrap();
            input.write(&12_i32).unwrap();
            input.write(&password).unwrap();
            input.write(&sids).unwrap();
            for api in [33, 34] {
                // SAFETY: The complete test input is self-owned.
                unsafe { input.set_data_position(0).unwrap() };
                let (code, request) =
                    authorization_legacy(api, 2, &caller, input.borrowed_ref()).unwrap().unwrap();
                assert_eq!(input.get_data_position(), 0);
                let forwarded: Option<CallerInfo> = request.read().unwrap();
                let forwarded = forwarded.unwrap();
                assert_eq!(
                    (forwarded.uid, forwarded.pid, forwarded.sid.as_str()),
                    (caller.uid, caller.pid, caller.sid.as_str())
                );
                assert_eq!(request.read::<i32>().unwrap(), 12);
                if event == 0 {
                    assert_eq!(code, private_auth::onDeviceUnlocked);
                    assert_eq!(request.read::<Option<Vec<u8>>>().unwrap(), password);
                } else {
                    assert_eq!(code, private_auth::onDeviceLocked);
                    assert_eq!(
                        request.read::<Vec<i64>>().unwrap(),
                        sids.clone().unwrap_or_default()
                    );
                    assert!(!request.read::<bool>().unwrap());
                }
                assert_eq!(request.get_data_position(), request.get_data_size());
            }
        }
    }
}
