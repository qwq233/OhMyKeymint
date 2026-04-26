use anyhow::{Context, Result};
use rsbinder::{hub, Interface, SIBinder, Status, Strong};

include!(concat!(env!("OUT_DIR"), "/aidl.rs"));

use android::hardware::security::keymint::SecurityLevel::SecurityLevel;
use android::system::keystore2::IKeystoreService::{transactions as service_tx, IKeystoreService};
use top::qwq2333::ohmykeymint::IOhMyKsService::{transactions as omk_service_tx, IOhMyKsService};

const KEYSTORE_SERVICE: &str = "android.system.keystore2.IKeystoreService/default";
const OMK_SERVICE: &str = "omk";

fn main() {
    if let Err(error) = run() {
        eprintln!("get_security_level_diag failed: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    rsbinder::ProcessState::init_default();

    let service: Strong<dyn IKeystoreService> = hub::get_interface(KEYSTORE_SERVICE)
        .context("failed to connect to android.system.keystore2.IKeystoreService/default")?;

    match service.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT) {
        Ok(level) => {
            let binder = level.as_binder();
            println!(
                "typed_getSecurityLevel=ok descriptor={} remote={}",
                binder.descriptor(),
                binder.as_proxy().is_some()
            );
        }
        Err(error) => {
            println!("typed_getSecurityLevel=err {error:#}");
        }
    }

    println!("{}", raw_get_security_level_diagnostic(&service)?);

    if let Some(raw_omk_service) = hub::get_service(OMK_SERVICE) {
        println!(
            "omk_raw_service={{descriptor={}, remote={}, interface_transaction={}}}",
            raw_omk_service.descriptor(),
            raw_omk_service.as_proxy().is_some(),
            interface_transaction_result(&raw_omk_service)
        );
    } else {
        println!("omk_raw_service=missing");
    }

    if let Ok(omk) = hub::get_interface::<dyn IOhMyKsService>(OMK_SERVICE) {
        println!("omk_service=connected");
        match omk.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT) {
            Ok(level) => {
                let binder = level.as_binder();
                println!(
                    "omk_typed_getSecurityLevel=ok descriptor={} remote={}",
                    binder.descriptor(),
                    binder.as_proxy().is_some()
                );
            }
            Err(error) => {
                println!("omk_typed_getSecurityLevel=err {error:#}");
            }
        }
        println!(
            "{}",
            raw_omk_get_security_level_diagnostic(&omk, omk_service_tx::r#getSecurityLevel)?
        );

        match omk.getOhMySecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT) {
            Ok(level) => {
                let binder = level.as_binder();
                println!(
                    "omk_typed_getOhMySecurityLevel=ok descriptor={} remote={}",
                    binder.descriptor(),
                    binder.as_proxy().is_some()
                );
            }
            Err(error) => {
                println!("omk_typed_getOhMySecurityLevel=err {error:#}");
            }
        }
        println!(
            "{}",
            raw_omk_get_security_level_diagnostic(&omk, omk_service_tx::r#getOhMySecurityLevel)?
        );
    } else {
        println!("omk_service=unavailable");
    }

    Ok(())
}

fn raw_get_security_level_diagnostic(service: &Strong<dyn IKeystoreService>) -> Result<String> {
    let binder = service.as_binder();
    let proxy = binder
        .as_proxy()
        .context("IKeystoreService binder was unexpectedly local in diagnostic client")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare raw getSecurityLevel transaction")?;
    data.write(&SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("failed to encode raw getSecurityLevel argument")?;
    let mut reply = proxy
        .submit_transact(service_tx::r#getSecurityLevel, &data, 0)
        .context("raw getSecurityLevel transact failed")?
        .context("raw getSecurityLevel transact returned no reply")?;

    let mut lines = Vec::new();
    lines.push(format!("reply_debug={reply:?}"));

    reply.set_data_position(0);
    match reply.read::<Status>() {
        Ok(status) => {
            lines.push(format!(
                "status={{display={status}, exception={:?}, transaction_error={:?}, service_specific_error={}}}",
                status.exception_code(),
                status.transaction_error(),
                status.service_specific_error()
            ));
            if status.is_ok() {
                match reply.read::<SIBinder>() {
                    Ok(raw_binder) => {
                        lines.push(format!(
                            "sibinder={{descriptor={}, remote={}}}",
                            raw_binder.descriptor(),
                            raw_binder.as_proxy().is_some()
                        ));
                        lines.push(format!(
                            "interface_transaction={}",
                            interface_transaction_result(&raw_binder)
                        ));
                    }
                    Err(read_error) => {
                        lines.push(format!("sibinder_read_error={read_error:#}"));
                    }
                }
            }
        }
        Err(status_error) => {
            lines.push(format!("status_read_error={status_error:#}"));
        }
    }

    Ok(lines.join("\n"))
}

fn raw_omk_get_security_level_diagnostic(
    service: &Strong<dyn IOhMyKsService>,
    transaction_code: u32,
) -> Result<String> {
    let binder = service.as_binder();
    let proxy = binder
        .as_proxy()
        .context("IOhMyKsService binder was unexpectedly local in diagnostic client")?;
    let mut data = proxy
        .prepare_transact(true)
        .context("failed to prepare raw OMK security-level transaction")?;
    data.write(&SecurityLevel::TRUSTED_ENVIRONMENT)
        .context("failed to encode raw OMK security-level argument")?;
    let mut reply = proxy
        .submit_transact(transaction_code, &data, 0)
        .context("raw OMK security-level transact failed")?
        .context("raw OMK security-level transact returned no reply")?;

    let mut lines = Vec::new();
    lines.push(format!("omk_reply_debug={reply:?}"));

    reply.set_data_position(0);
    match reply.read::<Status>() {
        Ok(status) => {
            lines.push(format!(
                "omk_status={{display={status}, exception={:?}, transaction_error={:?}, service_specific_error={}}}",
                status.exception_code(),
                status.transaction_error(),
                status.service_specific_error()
            ));
            if status.is_ok() {
                match reply.read::<SIBinder>() {
                    Ok(raw_binder) => {
                        lines.push(format!(
                            "omk_sibinder={{descriptor={}, remote={}}}",
                            raw_binder.descriptor(),
                            raw_binder.as_proxy().is_some()
                        ));
                        lines.push(format!(
                            "omk_interface_transaction={}",
                            interface_transaction_result(&raw_binder)
                        ));
                    }
                    Err(read_error) => {
                        lines.push(format!("omk_sibinder_read_error={read_error:#}"));
                    }
                }
            }
        }
        Err(status_error) => {
            lines.push(format!("omk_status_read_error={status_error:#}"));
        }
    }

    Ok(lines.join("\n"))
}

fn interface_transaction_result(binder: &SIBinder) -> String {
    let Some(proxy) = binder.as_proxy() else {
        return "local".to_string();
    };

    match proxy.submit_transact(rsbinder::INTERFACE_TRANSACTION, &rsbinder::Parcel::new(), 0) {
        Ok(Some(mut reply)) => match reply.read::<String>() {
            Ok(value) => format!("ok:{value}"),
            Err(error) => format!("read_error:{error:#}"),
        },
        Ok(None) => "missing_reply".to_string(),
        Err(error) => format!("transact_error:{error:#}"),
    }
}
