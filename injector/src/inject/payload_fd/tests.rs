use super::*;
use kmr_common::consts::AID_SYSTEM;

#[test]
fn remote_c_int_result_interprets_low_32_bits_as_signed() {
    assert_eq!(remote_c_int_result(0), 0);
    assert_eq!(remote_c_int_result(42), 42);
    assert_eq!(remote_c_int_result(0xffff_ffff), -1);
    assert_eq!(remote_c_int_result(0xffff_ffff_ffff_ffff), -1);
}

fn remote_msg_with_control(msg_flags: i32, msg_controllen: usize) -> libc::msghdr {
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_flags = msg_flags;
    msg.msg_controllen = msg_controllen;
    msg
}

fn cmsg(level: i32, type_: i32, payload: &[u8]) -> Vec<u8> {
    let cmsg_space = unsafe { libc::CMSG_SPACE(payload.len() as u32) as usize };
    let cmsg_len = unsafe { libc::CMSG_LEN(payload.len() as u32) as usize };
    let mut data = vec![0u8; cmsg_space];
    let header = libc::cmsghdr { cmsg_len, cmsg_level: level, cmsg_type: type_ };

    unsafe {
        std::ptr::write_unaligned(data.as_mut_ptr() as *mut libc::cmsghdr, header);
    }
    let data_offset = unsafe { libc::CMSG_LEN(0) as usize };
    data[data_offset..data_offset + payload.len()].copy_from_slice(payload);
    data
}

fn scm_rights_cmsg(fd: i32) -> Vec<u8> {
    cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, &fd.to_ne_bytes())
}

fn scm_rights_multi_cmsg(fds: &[i32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(std::mem::size_of_val(fds));
    for fd in fds {
        payload.extend_from_slice(&fd.to_ne_bytes());
    }
    cmsg(libc::SOL_SOCKET, libc::SCM_RIGHTS, &payload)
}

fn scm_credentials_cmsg(cred: libc::ucred) -> Vec<u8> {
    let payload = unsafe {
        std::slice::from_raw_parts(
            &cred as *const libc::ucred as *const u8,
            size_of::<libc::ucred>(),
        )
    };
    cmsg(libc::SOL_SOCKET, libc::SCM_CREDENTIALS, payload)
}

fn valid_test_cred() -> libc::ucred {
    libc::ucred { pid: 1234, uid: AID_SYSTEM, gid: AID_SYSTEM }
}

fn valid_control_message(fd: i32) -> (Vec<u8>, libc::ucred) {
    let cred = valid_test_cred();
    let mut data = scm_rights_cmsg(fd);
    data.extend_from_slice(&scm_credentials_cmsg(cred));
    (data, cred)
}

#[test]
fn scm_rights_validation_accepts_complete_payload() {
    let (data, cred) = valid_control_message(42);
    let msg = remote_msg_with_control(0, data.len());

    let fd = validate_received_remote_fd(&msg, 1, &data, 7, cred)
        .expect("complete SCM_RIGHTS message should validate");

    assert_eq!(fd, 42);
}

#[test]
fn scm_rights_validation_rejects_unexpected_payload_length() {
    let (data, cred) = valid_control_message(42);
    let msg = remote_msg_with_control(0, data.len());

    let error = validate_received_remote_fd(&msg, 0, &data, 7, cred)
        .expect_err("recvmsg payload length must be exactly one byte");

    assert!(format!("{error:#}").contains("expected 1 payload byte"));
}

#[test]
fn scm_rights_validation_rejects_truncation_flags() {
    let (data, cred) = valid_control_message(42);
    let msg = remote_msg_with_control(libc::MSG_CTRUNC | libc::MSG_TRUNC, data.len());

    let error = validate_received_remote_fd(&msg, 1, &data, 7, cred)
        .expect_err("truncated SCM_RIGHTS message must be rejected");

    assert!(format!("{error:#}").contains("truncated"));
}

#[test]
fn scm_rights_validation_rejects_short_control_length() {
    let (data, cred) = valid_control_message(42);
    let msg = remote_msg_with_control(0, unsafe { libc::CMSG_LEN(0) as usize - 1 });

    let error = validate_received_remote_fd(&msg, 1, &data, 7, cred)
        .expect_err("short control length must be rejected");

    assert!(format!("{error:#}").contains("msg_controllen too small"));
}

#[test]
fn scm_rights_validation_rejects_missing_credentials() {
    let data = scm_rights_cmsg(42);
    let msg = remote_msg_with_control(0, data.len());

    let error = validate_received_remote_fd(&msg, 1, &data, 7, valid_test_cred())
        .expect_err("sender credentials must be present");

    assert!(format!("{error:#}").contains("missing SCM_CREDENTIALS"));
}

#[test]
fn scm_rights_validation_rejects_wrong_credentials() {
    let (data, mut cred) = valid_control_message(42);
    cred.uid += 1;
    let msg = remote_msg_with_control(0, data.len());

    let error = validate_received_remote_fd(&msg, 1, &data, 7, cred)
        .expect_err("sender credentials must match");

    assert!(format!("{error:#}").contains("unexpected SCM_CREDENTIALS sender"));
}

#[test]
fn rejected_handoff_cleanup_finds_received_rights_fds() {
    let mut data = scm_rights_multi_cmsg(&[42, 43]);
    data.extend_from_slice(&scm_credentials_cmsg(valid_test_cred()));
    let msg = remote_msg_with_control(0, data.len());

    assert_eq!(received_remote_fds_from_control_data(&msg, &data), vec![42, 43]);
}
