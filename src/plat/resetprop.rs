use binder::binder_impl::IBinderInternal;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use binder::{Status, StatusCode};
use nix::fcntl::OFlag;
use nix::unistd::pipe2;
use prost::Message;

const ANDROID_PACKAGE: &str = "android";
const ACTIVITY_SERVICE: &str = "activity";
const ACTIVITY_DESCRIPTOR: &str = "android.app.IActivityManager";
const PACKAGE_MANAGER_NATIVE_DESCRIPTOR: &str = "android.content.pm.IPackageManagerNative";
const PACKAGE_MANAGER_NATIVE_SERVICE: &str = "package_native";
const PHONE_DESCRIPTOR: &str = "com.android.internal.telephony.ITelephony";
const PHONE_SERVICE: &str = "phone";
const PHONE_SUB_INFO_DESCRIPTOR: &str = "com.android.internal.telephony.IPhoneSubInfo";
const PHONE_SUB_INFO_SERVICE: &str = "iphonesubinfo";
const TELEPHONY_FEATURE: &str = "android.hardware.telephony";
const TELEPHONY_GSM_FEATURE: &str = "android.hardware.telephony.gsm";
const TELEPHONY_CDMA_FEATURE: &str = "android.hardware.telephony.cdma";
const GET_DEVICE_ID_FOR_PHONE_TRANSACTION: binder::binder_impl::TransactionCode =
    binder::binder_impl::FIRST_CALL_TRANSACTION + 3;

// Preserve the Android 13-17 field numbers; other process state is not needed here.
#[derive(Clone, PartialEq, Message)]
struct ActivityManagerServiceDumpProcessesProto {
    #[prost(message, repeated, tag = "2")]
    isolated_procs: Vec<ProcessRecordProto>,
}

#[derive(Clone, PartialEq, Message)]
struct ProcessRecordProto {
    #[prost(int32, tag = "1")]
    pid: i32,
    #[prost(int32, tag = "3")]
    uid: i32,
    #[prost(int32, tag = "4")]
    user_id: i32,
    #[prost(int32, tag = "6")]
    isolated_app_id: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TelephonyTransactions {
    get_imei_for_slot: binder::binder_impl::TransactionCode,
    get_meid_for_slot: Option<binder::binder_impl::TransactionCode>,
}

#[derive(Clone, Copy)]
enum PhoneIdentifierKind {
    DeviceId,
    Imei,
    Meid,
}

impl PhoneIdentifierKind {
    fn command(self) -> &'static str {
        match self {
            Self::DeviceId => "GET_DEVICE_ID",
            Self::Imei => "GET_IMEI",
            Self::Meid => "GET_MEID",
        }
    }

    fn from_command(command: &str) -> Option<Self> {
        match command {
            "GET_DEVICE_ID" => Some(Self::DeviceId),
            "GET_IMEI" => Some(Self::Imei),
            "GET_MEID" => Some(Self::Meid),
            _ => None,
        }
    }
}

const RESETPROP_FALLBACKS: &[(&str, Option<&str>)] = &[
    ("/system_ext/bin/resetprop", None),
    ("/system/bin/resetprop", None),
    ("/data/adb/ksu/bin/resetprop", None),
    ("/data/adb/ksud", Some("resetprop")),
];

#[derive(Clone)]
pub struct ResetpropCommand {
    program: String,
    prepend_arg: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelephonyFeatures {
    pub any: bool,
    pub gsm: bool,
    pub cdma: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("service {0} unavailable")]
pub(crate) struct BinderServiceUnavailable(pub(crate) String);

fn require_binder_service<T>(
    name: &str,
    lookup: Result<Option<T>, binder::StatusCode>,
) -> Result<T> {
    match lookup {
        Ok(Some(service)) => Ok(service),
        Ok(None) | Err(StatusCode::DEAD_OBJECT) | Err(StatusCode::NOT_ENOUGH_DATA) => {
            Err(BinderServiceUnavailable(name.to_string()).into())
        }
        // FailedTransaction is deliberately excluded: rsbinder also uses it for AIDL exceptions.
        Err(error) => {
            Err(error).with_context(|| format!("failed to look up Binder service {name}"))
        }
    }
}

static HELPER: OnceLock<Mutex<ResetpropHelperClient>> = OnceLock::new();

pub fn bootstrap_privileged_helper() -> Result<()> {
    if HELPER.get().is_some() {
        return Ok(());
    }

    let command = match find_resetprop_command() {
        Ok(command) => Some(command),
        Err(error) => {
            log::warn!("resetprop unavailable to privileged helper: {error:#}");
            None
        }
    };

    let (parent, child) = UnixStream::pair().context("failed to create resetprop socketpair")?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to fork resetprop helper");
    }
    if pid == 0 {
        drop(parent);
        let exit_code = match helper_loop(child, command) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("resetprop helper exiting after fatal error: {error:#}");
                1
            }
        };
        unsafe { libc::_exit(exit_code) };
    }

    drop(child);
    let client = ResetpropHelperClient { stream: parent };
    if HELPER.set(Mutex::new(client)).is_err() {
        log::debug!("resetprop helper was already installed");
    } else {
        log::info!("started privileged resetprop helper process pid={pid}");
    }

    Ok(())
}

pub fn runtime_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    with_helper(|helper| helper.write_and_verify_property(property, value))
}

pub fn runtime_get_isolated_owner_uid(uid: u32, pid: i32) -> Result<Option<u32>> {
    if pid <= 0 || !(90_000..=99_999).contains(&(uid % kmr_common::consts::AID_USER_OFFSET)) {
        return Ok(None);
    }
    with_helper(|helper| helper.get_isolated_owner_uid(uid, pid))
}

pub fn runtime_get_device_id_for_phone(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::DeviceId, slot)
}

pub fn runtime_get_imei_for_slot(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::Imei, slot)
}

pub fn runtime_get_meid_for_slot(slot: i32) -> Result<Option<String>> {
    runtime_get_phone_identifier(PhoneIdentifierKind::Meid, slot)
}

fn runtime_get_phone_identifier(kind: PhoneIdentifierKind, slot: i32) -> Result<Option<String>> {
    if !matches!(slot, 0 | 1) {
        bail!("unsupported phone slot {slot}");
    }
    with_helper(|helper| helper.get_phone_identifier(kind, slot))
}

pub fn runtime_telephony_features() -> Result<TelephonyFeatures> {
    with_helper(|helper| {
        Ok(TelephonyFeatures {
            any: helper.has_system_feature(TELEPHONY_FEATURE)?,
            gsm: helper.has_system_feature(TELEPHONY_GSM_FEATURE)?,
            cdma: helper.has_system_feature(TELEPHONY_CDMA_FEATURE)?,
        })
    })
}

pub(crate) fn is_binder_service_unavailable(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<BinderServiceUnavailable>().is_some())
}

fn with_helper<T>(call: impl FnOnce(&mut ResetpropHelperClient) -> Result<T>) -> Result<T> {
    let helper =
        HELPER.get().ok_or_else(|| anyhow!("privileged resetprop helper is unavailable"))?;
    let mut helper =
        helper.lock().map_err(|_| anyhow!("privileged resetprop helper lock poisoned"))?;
    call(&mut helper)
}

pub fn direct_write_and_verify_property(property: &str, value: &str) -> Result<()> {
    let command = find_resetprop_command()?;
    execute_write_and_verify(&command, property, value)
}

pub fn read_string_property(name: &str) -> Option<String> {
    rsproperties::get::<String>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn find_resetprop_command() -> Result<ResetpropCommand> {
    if let Some(program) = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join("resetprop"))
            .find(|candidate| candidate.exists())
            .map(|candidate| candidate.to_string_lossy().into_owned())
    }) {
        return Ok(ResetpropCommand { program, prepend_arg: None });
    }

    for (program, prepend_arg) in RESETPROP_FALLBACKS {
        if Path::new(program).exists() {
            return Ok(ResetpropCommand {
                program: program.to_string(),
                prepend_arg: prepend_arg.map(str::to_string),
            });
        }
    }

    Err(anyhow!("no usable resetprop binary found"))
}

fn execute_write_and_verify(command: &ResetpropCommand, property: &str, value: &str) -> Result<()> {
    let mut process = Command::new(&command.program);
    process.uid(kmr_common::consts::AID_ROOT);
    if let Some(prepend_arg) = &command.prepend_arg {
        process.arg(prepend_arg);
    }
    let status = process
        .arg(property)
        .arg(value)
        .status()
        .with_context(|| format!("failed to execute resetprop for {property}"))?;
    if !status.success() {
        bail!("resetprop failed for {property} with status {status}");
    }

    let actual = read_string_property(property)
        .ok_or_else(|| anyhow!("property {property} missing after resetprop write"))?;
    if actual.eq_ignore_ascii_case(value) {
        Ok(())
    } else {
        bail!("property verification failed for {property}: expected {value}, got {}", actual)
    }
}

struct ResetpropHelperClient {
    stream: UnixStream,
}

impl ResetpropHelperClient {
    fn get_isolated_owner_uid(&mut self, uid: u32, pid: i32) -> Result<Option<u32>> {
        let response = self.request(&format!("GET_ISOLATED_OWNER_UID\t{uid}\t{pid}\n"))?;
        if response == "NONE" {
            return Ok(None);
        }
        if let Some(value) = response.strip_prefix("OK\t") {
            return value.parse().context("invalid isolated owner UID from helper").map(Some);
        }
        bail!("unexpected isolated owner helper response")
    }

    fn write_and_verify_property(&mut self, property: &str, value: &str) -> Result<()> {
        let response = self.request(&format!("SET\t{property}\t{value}\n"))?;
        if response == "OK" {
            Ok(())
        } else {
            bail!("unexpected resetprop helper response")
        }
    }

    fn get_phone_identifier(
        &mut self,
        kind: PhoneIdentifierKind,
        slot: i32,
    ) -> Result<Option<String>> {
        let response = self.request(&format!("{}\t{slot}\n", kind.command()))?;
        if response == "NONE" {
            return Ok(None);
        }
        if let Some(value) = response.strip_prefix("OK\t") {
            if value.is_empty() {
                bail!("phone identifier helper returned an empty value");
            }
            return Ok(Some(value.to_string()));
        }
        bail!("unexpected phone identifier helper response")
    }

    fn has_system_feature(&mut self, feature: &str) -> Result<bool> {
        match self.request(&format!("HAS_FEATURE\t{feature}\n"))?.as_str() {
            "TRUE" => Ok(true),
            "FALSE" => Ok(false),
            _ => bail!("unexpected telephony feature helper response"),
        }
    }

    fn request(&mut self, request: &str) -> Result<String> {
        self.stream
            .write_all(request.as_bytes())
            .context("failed to send privileged helper request")?;
        self.stream.flush().context("failed to flush privileged helper request")?;

        let mut response = String::new();
        let mut reader = BufReader::new(
            self.stream.try_clone().context("failed to clone privileged helper stream")?,
        );
        let read =
            reader.read_line(&mut response).context("failed to read privileged helper response")?;
        if read == 0 {
            bail!("privileged helper closed unexpectedly");
        }
        let response = response.trim_end_matches(['\r', '\n']);
        if let Some(service) = response.strip_prefix("UNAVAILABLE\t") {
            return Err(BinderServiceUnavailable(service.to_string()).into());
        }
        if let Some(error) = response.strip_prefix("ERR\t") {
            bail!("{error}");
        }
        Ok(response.to_string())
    }
}

fn execute_isolated_owner_uid(uid: u32, pid: i32) -> Result<Option<u32>> {
    if pid <= 0 || !(90_000..=99_999).contains(&(uid % kmr_common::consts::AID_USER_OFFSET)) {
        bail!("invalid isolated caller");
    }
    let mut binder =
        require_binder_service(ACTIVITY_SERVICE, binder::ext::get_service_once(ACTIVITY_SERVICE))?;
    binder::ext::associate_descriptor(&binder, ACTIVITY_DESCRIPTOR)
        .context("ActivityManager descriptor mismatch")?;
    let data = capture_binder_dump(|fd| {
        binder.dump(&fd, &["--proto", "processes"]).context("ActivityManager process dump failed")
    })?;
    isolated_owner_from_proto(&data, uid, pid)
}

fn capture_binder_dump(dump: impl FnOnce(File) -> Result<()>) -> Result<Vec<u8>> {
    // AOSP dumpsys passes a pipe; system_server cannot access a generic tmpfs memfd.
    let (reader_fd, writer_fd) = pipe2(OFlag::O_CLOEXEC)?;
    std::thread::scope(|scope| {
        let reader = std::thread::Builder::new().spawn_scoped(scope, move || {
            let mut data = Vec::new();
            File::from(reader_fd).read_to_end(&mut data).context("failed to read Binder dump")?;
            Ok(data)
        })?;
        let result = dump(File::from(writer_fd));
        let data = reader.join().map_err(|_| anyhow!("Binder dump reader panicked"))?;
        result?;
        data
    })
}

fn isolated_owner_from_proto(data: &[u8], uid: u32, pid: i32) -> Result<Option<u32>> {
    let processes = ActivityManagerServiceDumpProcessesProto::decode(data)
        .context("failed to decode ActivityManager process dump")?;
    Ok(processes.isolated_procs.into_iter().find_map(|process| {
        if pid <= 0 || process.pid != pid {
            return None;
        }
        let owner = u32::try_from(process.uid).ok()?;
        let user = u32::try_from(process.user_id).ok()?;
        let app_id = u32::try_from(process.isolated_app_id).ok()?;
        if !(90_000..=99_999).contains(&app_id) {
            return None;
        }
        let actual_uid =
            user.checked_mul(kmr_common::consts::AID_USER_OFFSET)?.checked_add(app_id)?;
        (actual_uid == uid).then_some(owner)
    }))
}

fn execute_phone_identifier(kind: PhoneIdentifierKind, slot: i32) -> Result<Option<String>> {
    let transactions = telephony_transactions();
    let (service, expected_descriptor, transaction, label) = match kind {
        PhoneIdentifierKind::DeviceId => (
            PHONE_SUB_INFO_SERVICE,
            PHONE_SUB_INFO_DESCRIPTOR,
            Some(GET_DEVICE_ID_FOR_PHONE_TRANSACTION),
            "device ID",
        ),
        PhoneIdentifierKind::Imei => {
            (PHONE_SERVICE, PHONE_DESCRIPTOR, Some(transactions.get_imei_for_slot), "IMEI")
        }
        PhoneIdentifierKind::Meid => {
            (PHONE_SERVICE, PHONE_DESCRIPTOR, transactions.get_meid_for_slot, "MEID")
        }
    };
    let Some(transaction) = transaction else {
        return Ok(None);
    };

    let binder = require_binder_service(service, binder::ext::get_service_once(service))?;
    binder::ext::associate_descriptor(&binder, expected_descriptor)
        .with_context(|| format!("{label} descriptor mismatch"))?;
    let mut data = binder
        .prepare_transact()
        .with_context(|| format!("failed to prepare {label} transaction"))?;
    data.write(&slot).with_context(|| format!("failed to write {label} slot"))?;
    data.write(ANDROID_PACKAGE)
        .with_context(|| format!("failed to write {label} calling package"))?;
    data.write(&None::<String>)
        .with_context(|| format!("failed to write {label} calling feature"))?;

    let reply = binder
        .submit_transact(transaction, data, binder::binder_impl::FLAG_CLEAR_BUF)
        .with_context(|| format!("{label} transact failed"))?;
    // SAFETY: Zero is within every valid Parcel.
    unsafe { reply.set_data_position(0)? };

    let status: Status =
        reply.read().with_context(|| format!("failed to decode {label} reply status"))?;
    if !status.is_ok() {
        bail!("{label} returned non-ok status: {status}");
    }

    let Some(value): Option<String> =
        reply.read().with_context(|| format!("failed to decode {label} value"))?
    else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        bail!("{label} returned an invalid identifier");
    }
    Ok(Some(value.to_string()))
}

fn execute_has_system_feature(feature: &str) -> Result<bool> {
    let binder = require_binder_service(
        PACKAGE_MANAGER_NATIVE_SERVICE,
        binder::ext::get_service_once(PACKAGE_MANAGER_NATIVE_SERVICE),
    )?;
    binder::ext::associate_descriptor(&binder, PACKAGE_MANAGER_NATIVE_DESCRIPTOR)
        .context("PackageManager descriptor mismatch")?;
    let mut data =
        binder.prepare_transact().context("failed to prepare PackageManager transaction")?;
    data.write(feature).context("failed to write PackageManager feature name")?;
    data.write(&0_i32).context("failed to write PackageManager feature version")?;

    let reply = binder
        .submit_transact(
            has_system_feature_transaction(kmr_common::android_version::android_major_version()),
            data,
            binder::binder_impl::FLAG_CLEAR_BUF,
        )
        .context("PackageManager hasSystemFeature transact failed")?;
    // SAFETY: Zero is within every valid Parcel.
    unsafe { reply.set_data_position(0)? };

    let status: Status =
        reply.read().context("failed to decode PackageManager hasSystemFeature status")?;
    if !status.is_ok() {
        bail!("PackageManager hasSystemFeature returned non-ok status: {status}");
    }
    reply.read().context("failed to decode PackageManager hasSystemFeature result")
}

fn has_system_feature_transaction(
    android_major: Option<i32>,
) -> binder::binder_impl::TransactionCode {
    let offset = match android_major {
        Some(..=13) => 12,
        Some(14) => 9,
        Some(15 | 16) | None => 10,
        Some(17..) => 13,
    };
    binder::binder_impl::FIRST_CALL_TRANSACTION + offset
}

fn telephony_transactions() -> TelephonyTransactions {
    telephony_transactions_for(kmr_common::android_version::android_major_version())
}

fn telephony_transactions_for(android_major: Option<i32>) -> TelephonyTransactions {
    let (imei_offset, meid_offset) = match android_major {
        Some(version) if version <= 12 => (149, Some(151)),
        Some(13) => (145, Some(147)),
        Some(14) => (148, Some(151)),
        Some(version) if version >= 17 => (132, None),
        _ => (147, Some(150)),
    };

    TelephonyTransactions {
        get_imei_for_slot: binder::binder_impl::FIRST_CALL_TRANSACTION + imei_offset,
        get_meid_for_slot: meid_offset
            .map(|offset| binder::binder_impl::FIRST_CALL_TRANSACTION + offset),
    }
}

fn parse_phone_identifier_request(line: &str) -> Option<(PhoneIdentifierKind, &str)> {
    let (command, slot) = line.split_once('\t')?;
    PhoneIdentifierKind::from_command(command).map(|kind| (kind, slot))
}

fn parse_feature_request(line: &str) -> Option<&str> {
    let feature = line.strip_prefix("HAS_FEATURE\t")?;
    matches!(feature, TELEPHONY_FEATURE | TELEPHONY_GSM_FEATURE | TELEPHONY_CDMA_FEATURE)
        .then_some(feature)
}

fn helper_error_response(error: &anyhow::Error) -> String {
    if let Some(error) =
        error.chain().find_map(|cause| cause.downcast_ref::<BinderServiceUnavailable>())
    {
        format!("UNAVAILABLE\t{}\n", error.0)
    } else {
        format!("ERR\t{error:#}\n")
    }
}

fn helper_loop(stream: UnixStream, command: Option<ResetpropCommand>) -> Result<()> {
    // Keep real/saved root UID so resetprop children can regain root.
    if unsafe { libc::seteuid(kmr_common::consts::AID_SYSTEM) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to enter system Binder UID");
    }
    let reader_stream = stream.try_clone().context("failed to clone resetprop helper socket")?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();

    loop {
        line.clear();
        let read =
            reader.read_line(&mut line).context("failed to read resetprop helper request")?;
        if read == 0 {
            return Ok(());
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        let response = if let Some(feature) = parse_feature_request(trimmed) {
            match execute_has_system_feature(feature) {
                Ok(true) => "TRUE\n".to_string(),
                Ok(false) => "FALSE\n".to_string(),
                Err(error) => helper_error_response(&error),
            }
        } else if let Some((kind, slot)) = parse_phone_identifier_request(trimmed) {
            match slot.parse::<i32>() {
                Ok(slot) if matches!(slot, 0 | 1) => match execute_phone_identifier(kind, slot) {
                    Ok(Some(value)) => format!("OK\t{value}\n"),
                    Ok(None) => "NONE\n".to_string(),
                    Err(error) => helper_error_response(&error),
                },
                _ => "ERR\tinvalid phone identifier helper request\n".to_string(),
            }
        } else if let Some(arguments) = trimmed.strip_prefix("GET_ISOLATED_OWNER_UID\t") {
            match arguments
                .split_once('\t')
                .and_then(|(uid, pid)| Some((uid.parse::<u32>().ok()?, pid.parse::<i32>().ok()?)))
            {
                Some((uid, pid)) => match execute_isolated_owner_uid(uid, pid) {
                    Ok(Some(owner)) => format!("OK\t{owner}\n"),
                    Ok(None) => "NONE\n".to_string(),
                    Err(error) => helper_error_response(&error),
                },
                None => "ERR\tinvalid isolated owner helper request\n".to_string(),
            }
        } else {
            match parse_request(&line) {
                Ok((property, value)) => match command.as_ref() {
                    Some(command) => match execute_write_and_verify(command, &property, &value) {
                        Ok(()) => "OK\n".to_string(),
                        Err(error) => helper_error_response(&error),
                    },
                    None => "ERR\tresetprop is unavailable\n".to_string(),
                },
                Err(error) => format!("ERR\t{error:#}\n"),
            }
        };
        writer
            .write_all(response.as_bytes())
            .context("failed to write resetprop helper response")?;
        writer.flush().context("failed to flush resetprop helper response")?;
    }
}

fn parse_request(line: &str) -> Result<(String, String)> {
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.splitn(3, '\t');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("SET"), Some(property), Some(value))
            if !property.trim().is_empty() && !value.trim().is_empty() =>
        {
            Ok((property.to_string(), value.to_string()))
        }
        _ => Err(anyhow!("invalid resetprop helper request: {trimmed:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binder_dump_pipe_drains_large_output_and_preserves_errors() {
        let payload = vec![0x5a; 256 * 1024];
        let data = capture_binder_dump(|mut writer| {
            writer.write_all(&payload).context("failed to write test dump")
        })
        .unwrap();
        assert_eq!(data, payload);
        let error = capture_binder_dump(|_| bail!("dump rejected")).unwrap_err();
        assert_eq!(error.to_string(), "dump rejected");
    }

    #[test]
    fn isolated_owner_proto_matches_aosp_wire_and_caller_identity() {
        // AOSP: isolated_procs { pid: 42 uid: 10123 isolated_app_id: 99001 }.
        let mut wire = vec![0x12, 0x09, 0x08, 0x2a, 0x18, 0x8b, 0x4f, 0x30, 0xb9, 0x85, 0x06];
        assert_eq!(isolated_owner_from_proto(&wire, 99_001, 42).unwrap(), Some(10_123));
        assert_eq!(isolated_owner_from_proto(&wire, 99_002, 42).unwrap(), None);
        assert_eq!(isolated_owner_from_proto(&wire, 99_001, 43).unwrap(), None);
        assert_eq!(isolated_owner_from_proto(&wire, 99_001, 0).unwrap(), None);
        wire.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert_eq!(isolated_owner_from_proto(&wire, 99_001, 42).unwrap(), Some(10_123));
        assert!(isolated_owner_from_proto(&wire[..5], 99_001, 42).is_err());
        assert!(isolated_owner_from_proto(b"Permission Denial", 99_001, 42).is_err());
        assert_eq!(isolated_owner_from_proto(&[], 99_001, 42).unwrap(), None);
    }

    #[test]
    fn isolated_owner_proto_checks_users_ranges_and_overflow() {
        let record =
            ProcessRecordProto { pid: 42, uid: 110_123, user_id: 1, isolated_app_id: 99_001 };
        for (candidate, caller_uid, expected) in [
            (record.clone(), 199_001, Some(110_123)),
            (record.clone(), 99_001, None),
            (ProcessRecordProto { uid: -1, ..record.clone() }, 199_001, None),
            (ProcessRecordProto { user_id: -1, ..record.clone() }, 199_001, None),
            (ProcessRecordProto { user_id: i32::MAX, ..record.clone() }, 199_001, None),
            (ProcessRecordProto { isolated_app_id: -1, ..record.clone() }, 199_001, None),
            (ProcessRecordProto { isolated_app_id: 89_999, ..record.clone() }, 189_999, None),
            (ProcessRecordProto { isolated_app_id: 100_000, ..record.clone() }, 200_000, None),
            (
                ProcessRecordProto { isolated_app_id: 90_000, ..record.clone() },
                190_000,
                Some(110_123),
            ),
            (
                ProcessRecordProto { isolated_app_id: 99_999, ..record.clone() },
                199_999,
                Some(110_123),
            ),
        ] {
            let data = ActivityManagerServiceDumpProcessesProto {
                isolated_procs: vec![ProcessRecordProto { pid: 43, ..record.clone() }, candidate],
            }
            .encode_to_vec();
            assert_eq!(isolated_owner_from_proto(&data, caller_uid, 42).unwrap(), expected);
        }
        for (uid, pid) in [(10_123, 42), (99_001, 0), (99_001, -1)] {
            assert_eq!(runtime_get_isolated_owner_uid(uid, pid).unwrap(), None);
        }
    }

    #[test]
    fn isolated_owner_helper_response_preserves_request_identity() {
        for (response, expected) in [(b"OK\t10123\n".as_slice(), Some(10_123)), (b"NONE\n", None)] {
            let (client_stream, mut helper_stream) = UnixStream::pair().unwrap();
            helper_stream.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
            helper_stream.write_all(response).unwrap();
            let mut client = ResetpropHelperClient { stream: client_stream };
            assert_eq!(client.get_isolated_owner_uid(99_001, 42).unwrap(), expected);
            let mut request = String::new();
            BufReader::new(helper_stream).read_line(&mut request).unwrap();
            assert_eq!(request, "GET_ISOLATED_OWNER_UID\t99001\t42\n");
        }
    }

    #[test]
    fn telephony_transactions_match_android_12_through_17() {
        use binder::binder_impl::FIRST_CALL_TRANSACTION;

        assert_eq!(GET_DEVICE_ID_FOR_PHONE_TRANSACTION, FIRST_CALL_TRANSACTION + 3);
        for (version, offset) in [(12, 12), (13, 12), (14, 9), (15, 10), (16, 10), (17, 13)] {
            assert_eq!(
                has_system_feature_transaction(Some(version)),
                FIRST_CALL_TRANSACTION + offset
            );
        }
        for (version, imei, meid) in [
            (12, 149, Some(151)),
            (13, 145, Some(147)),
            (14, 148, Some(151)),
            (15, 147, Some(150)),
            (16, 147, Some(150)),
            (17, 132, None),
        ] {
            let transactions = telephony_transactions_for(Some(version));
            assert_eq!(transactions.get_imei_for_slot, FIRST_CALL_TRANSACTION + imei);
            assert_eq!(
                transactions.get_meid_for_slot,
                meid.map(|offset| FIRST_CALL_TRANSACTION + offset)
            );
        }
    }

    #[test]
    fn feature_helper_accepts_only_telephony_features() {
        for feature in [TELEPHONY_FEATURE, TELEPHONY_GSM_FEATURE, TELEPHONY_CDMA_FEATURE] {
            assert_eq!(parse_feature_request(&format!("HAS_FEATURE\t{feature}")), Some(feature));
        }
        assert_eq!(parse_feature_request("HAS_FEATURE\tandroid.hardware.camera"), None);
        assert_eq!(parse_feature_request("HAS_FEATURE"), None);
    }

    #[test]
    fn service_unavailable_response_round_trips() {
        let (client_stream, mut helper_stream) = UnixStream::pair().unwrap();
        let unavailable: anyhow::Error = BinderServiceUnavailable(PHONE_SERVICE.to_string()).into();
        helper_stream.write_all(helper_error_response(&unavailable).as_bytes()).unwrap();

        let mut client = ResetpropHelperClient { stream: client_stream };
        let error = client.get_phone_identifier(PhoneIdentifierKind::Imei, 0).unwrap_err();

        assert!(is_binder_service_unavailable(&error));
        assert_eq!(error.to_string(), "service phone unavailable");
    }

    #[test]
    fn service_lookup_only_retries_missing_or_transport_failures() {
        assert_eq!(require_binder_service(PHONE_SERVICE, Ok(Some(7_u8))).unwrap(), 7);

        let unavailable: [Result<Option<()>, binder::StatusCode>; 3] =
            [Ok(None), Err(StatusCode::DEAD_OBJECT), Err(StatusCode::NOT_ENOUGH_DATA)];
        for lookup in unavailable {
            let error = require_binder_service(PHONE_SERVICE, lookup).unwrap_err();
            assert!(is_binder_service_unavailable(&error));
            assert_eq!(helper_error_response(&error), "UNAVAILABLE\tphone\n");
        }

        for status in [
            StatusCode::NAME_NOT_FOUND,
            StatusCode::PERMISSION_DENIED,
            StatusCode::FAILED_TRANSACTION,
            StatusCode::WOULD_BLOCK,
            StatusCode::TIMED_OUT,
            StatusCode::UNKNOWN_ERROR,
        ] {
            let error = require_binder_service::<()>(PHONE_SERVICE, Err(status)).unwrap_err();
            assert!(!is_binder_service_unavailable(&error));
            assert!(error.chain().any(|cause| cause.downcast_ref::<StatusCode>() == Some(&status)));
            assert!(helper_error_response(&error).starts_with("ERR\t"));
        }
    }
}
