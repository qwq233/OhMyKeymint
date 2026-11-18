use super::{client, compat, Backend};
use crate::aidl::android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use crate::aidl::android::security::{
    authorization::IKeystoreAuthorization::transport as auth_codec,
    maintenance::IKeystoreMaintenance::transport as maintenance_codec,
};
use crate::aidl::android::system::keystore2::{
    IKeystoreOperation::{
        transport as operation_codec, BnKeystoreOperation, BpKeystoreOperation, IKeystoreOperation,
    },
    IKeystoreSecurityLevel::{
        transactions as level_codes, transport as level_codec, ParsedLevelRequest,
    },
    IKeystoreService::{
        transactions as service_codes, transport as service_codec, ParsedServiceRequest,
    },
};
use crate::aidl::top::qwq2333::ohmykeymint::{
    CallerInfo::CallerInfo, IOhMyMaintenanceService::transport as private_maintenance_codec,
};
use binder::binder_impl::{BorrowedParcel, Parcel, Proxy, Remotable, FLAG_ONEWAY};
use binder::{FromIBinder, SpIBinder, Status, StatusCode};
use std::sync::Arc;

type Validator = fn(u32, &BorrowedParcel<'_>) -> Result<(), StatusCode>;

pub fn operation_proxy(
    remote: &binder::Strong<dyn IKeystoreOperation>,
) -> Result<Arc<BnKeystoreOperation>, StatusCode> {
    Ok(Arc::new(BnKeystoreOperation(Box::new(BpKeystoreOperation::from_binder(
        remote.as_binder(),
    )?))))
}

fn private_input(
    input: &BorrowedParcel<'_>,
    caller: Option<&CallerInfo>,
) -> Result<Parcel, StatusCode> {
    let arguments = input.get_data_position();
    let size = input.get_data_size();
    let mut prefix = Parcel::new();
    prefix.mark_sensitive();
    if let Some(caller) = caller {
        prefix.write(&Some(caller))?;
    }
    let start = (arguments - prefix.get_data_size()).max(0);
    let mut parcel = Parcel::new();
    parcel.mark_sensitive();
    parcel.append_from(input, 0, start)?;
    parcel.append_all_from(&prefix)?;
    parcel.append_from(input, arguments, size - arguments)?;
    // SAFETY: start precedes the complete SDK caller prefix and original body.
    unsafe { parcel.set_data_position(start)? };
    Ok(parcel)
}

fn validate(input: &BorrowedParcel<'_>, code: u32, validate: Validator) -> Result<(), StatusCode> {
    binder::ext::with_parcel_position(input, input.get_data_position(), || validate(code, input))?
}

fn native_call(
    epoch: u64,
    binder: &impl Remotable,
    code: (u32, u32),
    input: (&BorrowedParcel<'_>, &BorrowedParcel<'_>),
    output: &mut BorrowedParcel<'_>,
    validator: Validator,
) -> binder::Result<()> {
    let result = binder::ext::with_parcel_position(input.1, input.1.get_data_position(), || {
        binder.on_transact(code.1, input.1, output)
    })?;
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            // A caller prefix can shift sized-read overflow checks. Keep the consumer SDK error.
            match validate(input.0, code.0, validator) {
                Err(original) if original != StatusCode::UNEXPECTED_NULL => Err(original.into()),
                Err(_) => Err(error.into()),
                Ok(()) => client::remote_result(epoch, Err(error.into())),
            }
        }
    }
}
/// The original native callback has already enforced the public interface header.
pub fn dispatch(
    backend: Backend<'_>,
    caller: &CallerInfo,
    transaction: (u32, u32),
    input: &BorrowedParcel<'_>,
    output: &mut BorrowedParcel<'_>,
    level: impl FnOnce(SecurityLevel) -> Result<SpIBinder, StatusCode>,
    operation: impl FnOnce(u64, Arc<BnKeystoreOperation>) -> Result<SpIBinder, StatusCode>,
) -> binder::Result<Option<()>> {
    let (code, flags) = transaction;
    let oneway = flags & FLAG_ONEWAY != 0;
    match backend {
        Backend::Keystore => {
            if matches!(code, service_codes::getSecurityLevel | service_codes::getKeyEntry) {
                let parsed =
                    binder::ext::with_parcel_position(input, input.get_data_position(), || {
                        service_codec::read_request(code, input)
                    })?;
                let parsed = match parsed {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        binder::ext::write_decode_error(error, output)?;
                        return Ok(Some(()));
                    }
                };
                client::with_keystore(|client| {
                    match parsed {
                        ParsedServiceRequest::GetSecurityLevel { security_level } => {
                            client::level(client, security_level)?;
                            if !oneway {
                                let binder = level(security_level)?;
                                output.write(&Status::ok())?;
                                output.write(&binder)?;
                            }
                        }
                        ParsedServiceRequest::GetKeyEntry { key } => {
                            let mut entry = match client::remote_result(
                                client.epoch,
                                client.service.service.0.getKeyEntry(Some(caller), &key),
                            ) {
                                Ok(entry) => entry,
                                Err(status) => {
                                    output.write(&status)?;
                                    return Ok(());
                                }
                            };
                            if let Some(remote) = &entry.iSecurityLevel {
                                // Native RPC can race a final Bp release against weak promotion.
                                client
                                    .service
                                    .public_levels
                                    .lock()
                                    .expect("public level cache poisoned")
                                    .entry(entry.metadata.keySecurityLevel)
                                    .or_insert_with(|| remote.clone());
                            }
                            if !oneway {
                                if entry.iSecurityLevel.is_some() {
                                    client::level(client, entry.metadata.keySecurityLevel)?;
                                    entry.iSecurityLevel = Some(FromIBinder::try_from(level(
                                        entry.metadata.keySecurityLevel,
                                    )?)?);
                                }
                                output.write(&Status::ok())?;
                                output.write(&entry)?;
                            }
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                })
            } else {
                let (rpc_code, prefix) =
                    service_codec::rpc_transaction(code).expect("routed service mapping");
                let private = private_input(input, prefix.then_some(caller))?;
                client::with_keystore(|client| {
                    native_call(
                        client.epoch,
                        &client.service.service,
                        (code, rpc_code),
                        (input, private.borrowed_ref()),
                        output,
                        service_codec::validate_request,
                    )
                })
            }
        }
        Backend::SecurityLevel(security_level) => {
            if code == level_codes::createOperation {
                let parsed =
                    binder::ext::with_parcel_position(input, input.get_data_position(), || {
                        level_codec::read_request(code, input)
                    })?;
                let parsed = match parsed {
                    Ok(parsed) => parsed,
                    Err(error) => {
                        binder::ext::write_decode_error(error, output)?;
                        return Ok(Some(()));
                    }
                };
                let ParsedLevelRequest::CreateOperation { key, operation_parameters, forced } =
                    parsed
                else {
                    unreachable!()
                };
                client::with_keystore(|client| {
                    let target = client::level(client, security_level)?;
                    let mut response = match client::remote_result(
                        client.epoch,
                        target.0.createOperation(Some(caller), &key, &operation_parameters, forced),
                    ) {
                        Ok(response) => response,
                        Err(status) => {
                            output.write(&status)?;
                            return Ok(());
                        }
                    };
                    if !oneway {
                        if let Some(remote) = response.iOperation.take() {
                            let proxy = operation_proxy(&remote)?;
                            response.iOperation =
                                Some(FromIBinder::try_from(operation(client.epoch, proxy)?)?);
                        }
                        let result =
                            output.write(&Status::ok()).and_then(|()| output.write(&response));
                        if let Err(error) = result {
                            binder::ext::write_decode_error(error, output)?;
                        }
                    }
                    Ok(())
                })
            } else {
                let (rpc_code, prefix) =
                    level_codec::rpc_transaction(code).expect("routed level mapping");
                let private = private_input(input, prefix.then_some(caller))?;
                client::with_keystore(|client| {
                    let target = match client::cached_level(client, security_level) {
                        Some(target) => target,
                        None => {
                            if let Err(error) = validate(input, code, level_codec::validate_request)
                            {
                                return Ok(binder::ext::write_decode_error(error, output)?);
                            }
                            client::level(client, security_level)?
                        }
                    };
                    native_call(
                        client.epoch,
                        target.as_ref(),
                        (code, rpc_code),
                        (input, private.borrowed_ref()),
                        output,
                        level_codec::validate_request,
                    )
                })
            }
        }
        Backend::Authorization => {
            if let Some((rpc_code, private)) =
                compat::authorization_legacy(binder::ext::api_level(), code, caller, input)?
            {
                return client::with_authorization(false, |epoch, binder| {
                    client::remote_result(
                        epoch,
                        binder
                            .on_transact(rpc_code, private.borrowed_ref(), output)
                            .map_err(Into::into),
                    )
                });
            }
            let public_code = compat::authorization_code(binder::ext::api_level(), code)
                .expect("routed authorization mapping");
            let (rpc_code, prefix) =
                auth_codec::rpc_transaction(public_code).expect("routed authorization SDK mapping");
            let private = private_input(input, prefix.then_some(caller))?;
            client::with_authorization(code == 1, |epoch, binder| {
                native_call(
                    epoch,
                    binder,
                    (public_code, rpc_code),
                    (input, private.borrowed_ref()),
                    output,
                    auth_codec::validate_request,
                )
            })
        }
        Backend::Maintenance => {
            let (rpc_code, legacy) = compat::maintenance_code(binder::ext::api_level(), code)
                .expect("routed maintenance mapping");
            let private = private_input(input, Some(caller))?;
            if legacy {
                client::with_maintenance(|epoch, binder| {
                    native_call(
                        epoch,
                        binder,
                        (rpc_code, rpc_code),
                        (private.borrowed_ref(), private.borrowed_ref()),
                        output,
                        private_maintenance_codec::validate_request,
                    )
                })
            } else {
                let public_code = compat::maintenance_public_code(binder::ext::api_level(), code)
                    .expect("routed maintenance SDK mapping");
                client::with_maintenance(|epoch, binder| {
                    native_call(
                        epoch,
                        binder,
                        (public_code, rpc_code),
                        (input, private.borrowed_ref()),
                        output,
                        maintenance_codec::validate_request,
                    )
                })
            }
        }
        Backend::Operation { epoch, binder } => {
            native_call(
                epoch,
                binder,
                (code, code),
                (input, input),
                output,
                operation_codec::validate_request,
            )?;
            Ok(Some(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aidl::android::system::keystore2::KeyDescriptor::KeyDescriptor;
    use crate::aidl::top::qwq2333::ohmykeymint::IOhMyKsService::{
        transactions, BnOhMyKsService, BpOhMyKsService, IOhMyKsService,
    };
    use binder::binder_impl::Binder;
    use binder::{binder_fn_get_class, ExceptionCode, Interface};
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Peer {
        calls: Arc<AtomicUsize>,
        fail: Arc<AtomicBool>,
    }
    impl Remotable for Peer {
        fn get_descriptor() -> &'static str {
            "top.qwq2333.ohmykeymint.IOhMyKsService"
        }
        fn on_transact(
            &self,
            code: u32,
            input: &BorrowedParcel<'_>,
            output: &mut BorrowedParcel<'_>,
        ) -> Result<(), StatusCode> {
            assert_eq!(code, transactions::deleteKey);
            let caller: Option<CallerInfo> = input.read()?;
            assert_eq!(caller.unwrap().uid, 10001);
            let key: KeyDescriptor = input.read()?;
            assert_eq!(key.alias.as_deref(), Some("unchanged"));
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(StatusCode::BAD_VALUE);
            }
            output.write(&Status::new_service_specific_error(17, None))
        }
        fn on_dump(&self, _: &mut dyn std::io::Write, _: &[&CStr]) -> Result<(), StatusCode> {
            Ok(())
        }
        fn on_shell_command(
            &self,
            _: &mut dyn std::io::Read,
            _: &mut dyn std::io::Write,
            _: &mut dyn std::io::Write,
            _: &[&CStr],
        ) -> Result<(), StatusCode> {
            Ok(())
        }
        binder_fn_get_class!(Binder<Self>);
    }

    #[test]
    fn typed_rpc_gateway_preserves_decode_errors_and_caller_without_an_adapter() {
        let path = std::env::temp_dir().join(format!("omk-typed-rpc-{}.sock", std::process::id()));
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicBool::new(false));
        let server = binder::ext::rpc::RpcServer::setup_unix_server(&path).unwrap();
        server
            .add_service(
                super::super::SERVICE,
                Binder::new(Peer { calls: Arc::clone(&calls), fail: Arc::clone(&fail) })
                    .as_binder(),
            )
            .unwrap();
        server.start().unwrap();
        let session = binder::ext::rpc::RpcSession::connect(
            &path,
            1,
            usize::from(binder::ext::api_level() >= 34),
        )
        .unwrap();
        let remote = session.get_interface::<dyn IOhMyKsService>(super::super::SERVICE).unwrap();
        let native =
            BnOhMyKsService(Box::new(BpOhMyKsService::from_binder(remote.as_binder()).unwrap()));
        let marker = Binder::new(()).as_binder();
        for sid_len in [1, 160] {
            let caller = CallerInfo { uid: 10001, pid: 42, sid: "s".repeat(sid_len) };
            calls.store(0, Ordering::SeqCst);
            for shape in 0..6 {
                let mut input = Parcel::new();
                // Model the already consumed native header, retaining the original absolute positions.
                for _ in 0..32 {
                    input.write(&0_i32).unwrap();
                }
                let arguments = input.get_data_position();
                match shape {
                    0 => {}
                    1 => input.write(&0_i32).unwrap(),
                    2 => {
                        input.write(&1_i32).unwrap();
                        input.write(&(i32::MAX - arguments - 4)).unwrap();
                    }
                    3 => {
                        input.write(&marker).unwrap();
                    }
                    4 => input
                        .write(&binder::ParcelFileDescriptor::new(
                            std::fs::File::open("/dev/null").unwrap(),
                        ))
                        .unwrap(),
                    _ => input
                        .write(&KeyDescriptor {
                            alias: Some("unchanged".into()),
                            ..Default::default()
                        })
                        .unwrap(),
                }
                // SAFETY: arguments precedes the complete input body in this owned Parcel.
                unsafe { input.set_data_position(arguments).unwrap() };
                let original = binder::ext::parcel_bytes(&input).unwrap();
                let expected = validate(
                    input.borrowed_ref(),
                    service_codes::deleteKey,
                    service_codec::validate_request,
                );
                let private = private_input(input.borrowed_ref(), Some(&caller)).unwrap();
                let mut output = Parcel::new();
                let result = native_call(
                    0,
                    &native,
                    (service_codes::deleteKey, transactions::deleteKey),
                    (input.borrowed_ref(), private.borrowed_ref()),
                    &mut output.borrowed(),
                    service_codec::validate_request,
                );
                drop(private);
                assert_eq!(input.get_data_position(), arguments);
                assert_eq!(binder::ext::parcel_bytes(&input).unwrap(), original);
                if shape == 4 {
                    let received =
                        binder::ext::with_parcel_position(input.borrowed_ref(), arguments, || {
                            input.read::<binder::ParcelFileDescriptor>()
                        })
                        .unwrap()
                        .unwrap();
                    assert!(unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } >= 0);
                }
                if let Err(expected) = expected {
                    assert_eq!(calls.load(Ordering::SeqCst), 0);
                    if expected == StatusCode::UNEXPECTED_NULL {
                        result.unwrap();
                        // SAFETY: The SDK error reply is complete and self-owned.
                        unsafe { output.set_data_position(0).unwrap() };
                        assert_eq!(
                            output.read::<Status>().unwrap().exception_code(),
                            ExceptionCode::NULL_POINTER
                        );
                    } else {
                        assert_eq!(result.unwrap_err().transaction_error(), expected);
                    }
                } else {
                    result.unwrap();
                    // SAFETY: The SDK reply is complete and self-owned.
                    unsafe { output.set_data_position(0).unwrap() };
                    assert_eq!(output.read::<Status>().unwrap().service_specific_error(), 17);
                }
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
        fn validate_alias(code: u32, input: &BorrowedParcel<'_>) -> Result<(), StatusCode> {
            assert_eq!(input.get_data_position(), 0);
            crate::aidl::top::qwq2333::ohmykeymint::IOhMyKsService::transport::validate_request(
                code, input,
            )
        }
        fail.store(true, Ordering::SeqCst);
        let mut input = Parcel::new();
        input.write(&Some(CallerInfo { uid: 10001, ..Default::default() })).unwrap();
        input
            .write(&KeyDescriptor { alias: Some("unchanged".into()), ..Default::default() })
            .unwrap();
        // SAFETY: The complete private request is self-owned.
        unsafe { input.set_data_position(0).unwrap() };
        let mut output = Parcel::new();
        let error = native_call(
            0,
            &native,
            (transactions::deleteKey, transactions::deleteKey),
            (input.borrowed_ref(), input.borrowed_ref()),
            &mut output.borrowed(),
            validate_alias,
        )
        .unwrap_err();
        assert_eq!(error.transaction_error(), StatusCode::BAD_VALUE);
        assert_eq!(input.get_data_position(), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(native);
        drop(remote);
        session.shutdown().unwrap();
        server.shutdown().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
