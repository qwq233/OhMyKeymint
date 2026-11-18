use crate::sys;
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};
use nix::unistd::Pid;
use rand::TryRng;
use std::ffi::{c_void, CString};
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixDatagram;
use std::path::Path;

#[derive(Clone, Copy)]
pub(super) struct RemoteFdHandoffAddrs {
    pub(super) socket: usize,
    pub(super) bind: usize,
    pub(super) recvmsg: usize,
    pub(super) setsockopt: usize,
    pub(super) libc_return: usize,
}

pub(super) fn log_loader_abi() {
    debug!(
        "abi build_target={} runtime_arch={} sockaddr_un(size={}, sun_path_offset={}, c_char_size={}) msghdr(size={}, msg_control_offset={}, msg_controllen_offset={}) cmsghdr(size={}, cmsg_len_offset={}, cmsg_level_offset={}, cmsg_type_offset={}) cmsg_space_int={} cmsg_len_int={}",
        crate::utils::build_target(),
        std::env::consts::ARCH,
        size_of::<libc::sockaddr_un>(),
        offset_of!(libc::sockaddr_un, sun_path),
        size_of::<libc::c_char>(),
        size_of::<libc::msghdr>(),
        offset_of!(libc::msghdr, msg_control),
        offset_of!(libc::msghdr, msg_controllen),
        size_of::<libc::cmsghdr>(),
        offset_of!(libc::cmsghdr, cmsg_len),
        offset_of!(libc::cmsghdr, cmsg_level),
        offset_of!(libc::cmsghdr, cmsg_type),
        unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize },
        unsafe { libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize },
    );
}

fn build_abstract_sockaddr(magic_bytes: &[u8]) -> Result<(libc::sockaddr_un, usize)> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if magic_bytes.len() > addr.sun_path.len().saturating_sub(1) {
        bail!("abstract socket name is too long for sockaddr_un: {} bytes", magic_bytes.len());
    }

    addr.sun_family = libc::AF_UNIX as u16;
    for (i, byte) in magic_bytes.iter().enumerate() {
        addr.sun_path[1 + i] = *byte as libc::c_char;
    }
    Ok((addr, offset_of!(libc::sockaddr_un, sun_path) + 1 + magic_bytes.len()))
}

fn generate_fd_handoff_name() -> Result<[u8; 16]> {
    let mut random = [0u8; 16];
    let mut rng = rand::rngs::SysRng;
    rng.try_fill_bytes(&mut random).context("failed to fill fd handoff socket name from SysRng")?;
    Ok(random)
}

fn control_words(size: usize) -> usize {
    size.div_ceil(size_of::<usize>())
}

fn cmsg_align(size: usize) -> usize {
    let align = size_of::<usize>();
    (size + align - 1) & !(align - 1)
}

fn remote_c_int_result(value: usize) -> i32 {
    value as u32 as i32
}

pub(super) fn open_remote_payload_fd_from_path<F, G>(
    pid: Pid,
    open_addr: usize,
    libc_return_addr: usize,
    path: &Path,
    push_to_remote_stack: &mut F,
    get_remote_errno: &G,
) -> Result<i32>
where
    F: FnMut(&[u8]) -> Result<usize>,
    G: Fn() -> sys::RemoteCallPostStatus<i32>,
{
    let path_c = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("Invalid remote payload path {}", path.display()))?;
    let remote_path_ptr = push_to_remote_stack(path_c.as_bytes_with_nul())?;
    let remote_lib_fd = remote_c_int_result(
        sys::remote_call(
            pid,
            open_addr,
            libc_return_addr,
            &[remote_path_ptr, (libc::O_RDONLY | libc::O_CLOEXEC) as usize, 0],
        )
        .result?,
    );
    if remote_lib_fd == -1 {
        let err = get_remote_errno().result?;
        bail!("Failed to open remote payload path {}. Remote errno: {}", path.display(), err);
    }
    info!("remote payload path opened: path={} fd={}", path.display(), remote_lib_fd);
    Ok(remote_lib_fd)
}

fn validate_received_remote_fd(
    remote_msg: &libc::msghdr,
    recv_res: isize,
    remote_cmsg_data: &[u8],
    remote_socket_fd: i32,
    expected_cred: libc::ucred,
) -> Result<i32> {
    if recv_res != 1 {
        bail!("remote recvmsg returned {recv_res} bytes, expected 1 payload byte");
    }

    let trunc_flags = libc::MSG_CTRUNC | libc::MSG_TRUNC;
    if remote_msg.msg_flags & trunc_flags != 0 {
        bail!(
            "remote recvmsg reported truncated data/control: msg_flags=0x{:x}",
            remote_msg.msg_flags
        );
    }

    let min_len = unsafe { libc::CMSG_LEN(0) as usize };
    if remote_msg.msg_controllen < min_len {
        bail!(
            "remote msg_controllen too small: got {}, expected at least {}",
            remote_msg.msg_controllen,
            min_len
        );
    }

    let control_len = remote_msg.msg_controllen.min(remote_cmsg_data.len());
    let mut offset = 0usize;
    let mut received_fd = None;
    let mut received_cred = None;
    while offset + size_of::<libc::cmsghdr>() <= control_len {
        let header = unsafe {
            std::ptr::read_unaligned(remote_cmsg_data.as_ptr().add(offset) as *const libc::cmsghdr)
        };
        if header.cmsg_len < min_len || offset + header.cmsg_len > control_len {
            bail!(
                "invalid remote cmsghdr length at offset {}: len={} control_len={}",
                offset,
                header.cmsg_len,
                control_len
            );
        }

        let data_offset = offset + min_len;
        let data_len = header.cmsg_len - min_len;
        let data = &remote_cmsg_data[data_offset..data_offset + data_len];
        if header.cmsg_level != libc::SOL_SOCKET {
            bail!(
                "invalid remote cmsghdr level: got {}, expected {}",
                header.cmsg_level,
                libc::SOL_SOCKET
            );
        }

        match header.cmsg_type {
            libc::SCM_RIGHTS => {
                if received_fd.is_some() {
                    bail!("duplicate SCM_RIGHTS control message");
                }
                if data_len != size_of::<libc::c_int>() {
                    bail!(
                        "invalid SCM_RIGHTS payload length: got {}, expected {}",
                        data_len,
                        size_of::<libc::c_int>()
                    );
                }
                received_fd = Some(i32::from_ne_bytes(data.try_into().unwrap()));
            }
            libc::SCM_CREDENTIALS => {
                if received_cred.is_some() {
                    bail!("duplicate SCM_CREDENTIALS control message");
                }
                if data_len != size_of::<libc::ucred>() {
                    bail!(
                        "invalid SCM_CREDENTIALS payload length: got {}, expected {}",
                        data_len,
                        size_of::<libc::ucred>()
                    );
                }
                let cred = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const libc::ucred) };
                received_cred = Some(cred);
            }
            other => bail!("unexpected remote cmsghdr type: {}", other),
        }

        offset = cmsg_align(offset + header.cmsg_len);
    }

    let fd = received_fd.ok_or_else(|| anyhow!("missing SCM_RIGHTS fd"))?;
    if fd < 0 {
        bail!("remote payload fd is negative: {}", fd);
    }
    if fd == remote_socket_fd {
        bail!(
            "remote payload fd {} unexpectedly matches the remote socket fd; SCM_RIGHTS parsing is corrupted",
            fd
        );
    }

    let cred =
        received_cred.ok_or_else(|| anyhow!("missing SCM_CREDENTIALS sender credentials"))?;
    if cred.pid != expected_cred.pid
        || cred.uid != expected_cred.uid
        || cred.gid != expected_cred.gid
    {
        bail!(
            "unexpected SCM_CREDENTIALS sender: pid={} uid={} gid={} expected pid={} uid={} gid={}",
            cred.pid,
            cred.uid,
            cred.gid,
            expected_cred.pid,
            expected_cred.uid,
            expected_cred.gid
        );
    }

    Ok(fd)
}

fn received_remote_fds_from_control_data(
    remote_msg: &libc::msghdr,
    remote_cmsg_data: &[u8],
) -> Vec<i32> {
    let min_len = unsafe { libc::CMSG_LEN(0) as usize };
    if remote_msg.msg_controllen < min_len {
        return Vec::new();
    }

    let control_len = remote_msg.msg_controllen.min(remote_cmsg_data.len());
    let mut offset = 0usize;
    let mut fds = Vec::new();
    while offset + size_of::<libc::cmsghdr>() <= control_len {
        let header = unsafe {
            std::ptr::read_unaligned(remote_cmsg_data.as_ptr().add(offset) as *const libc::cmsghdr)
        };
        if header.cmsg_len < min_len || offset + header.cmsg_len > control_len {
            break;
        }

        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let data_offset = offset + min_len;
            let data_len = header.cmsg_len - min_len;
            let data = &remote_cmsg_data[data_offset..data_offset + data_len];
            for fd in data.as_chunks::<{ size_of::<libc::c_int>() }>().0 {
                fds.push(i32::from_ne_bytes(*fd));
            }
        }

        offset = cmsg_align(offset + header.cmsg_len);
    }
    fds
}

fn close_rejected_remote_fd_handoff<H>(
    remote_msg: &libc::msghdr,
    remote_cmsg_data: &[u8],
    remote_socket_fd: i32,
    close_remote: &H,
) -> sys::RemoteCallPostStatus<()>
where
    H: Fn(i32) -> sys::RemoteCallPostStatus<()>,
{
    let mut close_errors = Vec::new();
    let mut restored = true;
    for fd in received_remote_fds_from_control_data(remote_msg, remote_cmsg_data)
        .into_iter()
        .filter(|fd| *fd >= 0 && *fd != remote_socket_fd)
        .chain(std::iter::once(remote_socket_fd))
    {
        let closed = close_remote(fd);
        restored = closed.restored;
        if let Err(error) = closed.result {
            close_errors.push(format!("fd {fd}: {error:#}"));
        }
        if !restored {
            break;
        }
    }
    let result = if close_errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "failed to close rejected remote fd handoff descriptors: {}",
            close_errors.join("; ")
        ))
    };
    sys::RemoteCallPostStatus { result, restored }
}

fn finish_remote_fd_handoff(
    mut status: sys::RemoteCallPostStatus<i32>,
    socket: Option<i32>,
    control: Option<(&libc::msghdr, &[u8])>,
    close_remote: &impl Fn(i32) -> sys::RemoteCallPostStatus<()>,
) -> sys::RemoteCallPostStatus<i32> {
    if !status.restored {
        return status;
    }
    let Some(socket) = socket else { return status };
    let mut cleanup = match (&status.result, control) {
        (Err(_), Some((msg, data))) => {
            close_rejected_remote_fd_handoff(msg, data, socket, close_remote)
        }
        _ => close_remote(socket),
    };
    if cleanup.result.is_err() && cleanup.restored {
        if let Ok(fd) = &status.result {
            let rejected = close_remote(*fd);
            cleanup.restored = rejected.restored;
            if let Err(error) = rejected.result {
                cleanup.result =
                    cleanup.result.context(format!("received fd close also failed: {error:#}"));
            }
        }
    }
    status.restored = cleanup.restored;
    status.result = match (status.result, cleanup.result) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("remote fd handoff cleanup also failed: {cleanup:#}")))
        }
        (Ok(_), Err(error)) => Err(error),
        (result, Ok(())) => result,
    };
    status
}

fn expected_sender_credentials() -> libc::ucred {
    libc::ucred {
        pid: unsafe { libc::getpid() },
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    }
}

pub(super) fn send_fd_to_remote<F, G, H>(
    pid: Pid,
    local_fd: RawFd,
    label: &str,
    addrs: RemoteFdHandoffAddrs,
    push_to_remote_stack: &mut F,
    get_remote_errno: &G,
    close_remote: &H,
) -> sys::RemoteCallPostStatus<i32>
where
    F: FnMut(&[u8]) -> Result<usize>,
    G: Fn() -> sys::RemoteCallPostStatus<i32>,
    H: Fn(i32) -> sys::RemoteCallPostStatus<()>,
{
    let mut restored = true;
    let mut socket_to_close = None;
    let mut control_to_close = None;
    let result = (|| {
        let local_socket = UnixDatagram::unbound()
            .with_context(|| format!("Failed to create local {label} handoff socket"))?;

        let call = sys::remote_call(
            pid,
            addrs.socket,
            addrs.libc_return,
            &[libc::AF_UNIX as usize, (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as usize, 0],
        );
        restored = call.restored;
        let remote_socket = remote_c_int_result(call.result?);
        if remote_socket == -1 {
            let errno = get_remote_errno();
            restored = errno.restored;
            let err = errno.result?;
            bail!("Failed to create remote {label} handoff socket. Remote errno: {err}");
        }
        socket_to_close = Some(remote_socket);
        let enable: libc::c_int = 1;
        let remote_enable_ptr = push_to_remote_stack(&enable.to_ne_bytes())?;
        let call = sys::remote_call(
            pid,
            addrs.setsockopt,
            addrs.libc_return,
            &[
                remote_socket as usize,
                libc::SOL_SOCKET as usize,
                libc::SO_PASSCRED as usize,
                remote_enable_ptr,
                size_of::<libc::c_int>(),
            ],
        );
        restored = call.restored;
        let result = remote_c_int_result(call.result?);
        if result == -1 {
            let errno = get_remote_errno();
            restored = errno.restored;
            let err = errno.result?;
            bail!("Failed to enable SO_PASSCRED on remote {label} handoff socket. Remote errno: {err}");
        }

        let magic_bytes = generate_fd_handoff_name()?;

        let (mut local_dest_addr, addr_len) = build_abstract_sockaddr(&magic_bytes)?;
        debug!(
            "Generated {label} handoff socket with {} random abstract-name bytes",
            magic_bytes.len()
        );

        let addr_bytes = unsafe {
            std::slice::from_raw_parts(
                &local_dest_addr as *const _ as *const u8,
                size_of::<libc::sockaddr_un>(),
            )
        };
        let remote_addr_ptr = push_to_remote_stack(addr_bytes)?;
        let call = sys::remote_call(
            pid,
            addrs.bind,
            addrs.libc_return,
            &[remote_socket as usize, remote_addr_ptr, addr_len],
        );
        restored = call.restored;
        let bind_res = remote_c_int_result(call.result?);
        if bind_res == -1 {
            let errno = get_remote_errno();
            restored = errno.restored;
            let err = errno.result?;
            bail!("Failed to bind remote {label} handoff socket. Remote errno: {err}");
        }

        let send_cmsg_space = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) as usize };
        let recv_cmsg_space =
            send_cmsg_space + unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) as usize };
        let remote_cmsg_storage = vec![0usize; control_words(recv_cmsg_space)];
        let remote_cmsg_bytes = unsafe {
            std::slice::from_raw_parts(remote_cmsg_storage.as_ptr() as *const u8, recv_cmsg_space)
        };
        let remote_cmsg_ptr = push_to_remote_stack(remote_cmsg_bytes)?;
        let remote_payload_storage = push_to_remote_stack(&[0u8])?;
        let remote_iov =
            libc::iovec { iov_base: remote_payload_storage as *mut c_void, iov_len: 1 };
        let remote_iov_bytes = unsafe {
            std::slice::from_raw_parts(
                &remote_iov as *const _ as *const u8,
                size_of::<libc::iovec>(),
            )
        };
        let remote_iov_ptr = push_to_remote_stack(remote_iov_bytes)?;

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = remote_iov_ptr as *mut libc::iovec;
        msg.msg_iovlen = 1;
        msg.msg_control = remote_cmsg_ptr as *mut c_void;
        msg.msg_controllen = recv_cmsg_space;

        let msg_bytes = unsafe {
            std::slice::from_raw_parts(&msg as *const _ as *const u8, size_of::<libc::msghdr>())
        };
        let remote_msg_ptr = push_to_remote_stack(msg_bytes)?;

        let mut local_cmsg_storage = vec![0usize; control_words(send_cmsg_space)];
        let mut payload_byte = [0x42u8];
        let mut local_iov = libc::iovec {
            iov_base: payload_byte.as_mut_ptr() as *mut c_void,
            iov_len: payload_byte.len(),
        };

        let mut local_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        local_hdr.msg_name = &mut local_dest_addr as *mut _ as *mut c_void;
        local_hdr.msg_namelen = addr_len as u32;
        local_hdr.msg_iov = &mut local_iov;
        local_hdr.msg_iovlen = 1;
        local_hdr.msg_control = local_cmsg_storage.as_mut_ptr() as *mut c_void;
        local_hdr.msg_controllen = send_cmsg_space;

        debug!(
            "{label} cmsg buffer ptr=0x{:x} align={} remote cmsg ptr=0x{:x} align={}",
            local_hdr.msg_control as usize,
            (local_hdr.msg_control as usize) % size_of::<usize>(),
            remote_cmsg_ptr,
            remote_cmsg_ptr % size_of::<usize>()
        );

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&local_hdr);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
            *(libc::CMSG_DATA(cmsg) as *mut libc::c_int) = local_fd;
        }

        let send_res =
            unsafe { libc::sendmsg(local_socket.as_raw_fd(), &local_hdr, libc::MSG_DONTWAIT) };
        if send_res == -1 {
            let send_error = std::io::Error::last_os_error();
            bail!("Failed to send {label} fd locally: {send_error}");
        }
        debug!("sent {label} fd={local_fd} to remote abstract socket");

        let recv_status = sys::remote_call(
            pid,
            addrs.recvmsg,
            addrs.libc_return,
            &[remote_socket as usize, remote_msg_ptr, libc::MSG_DONTWAIT as usize],
        );
        restored = recv_status.restored;
        let recv_res =
            recv_status.result.with_context(|| format!("remote recvmsg for {label} failed"))?
                as isize;

        if recv_res == -1 {
            let errno = get_remote_errno();
            restored = errno.restored;
            let err = errno.result?;
            bail!("remote recvmsg for {label} failed with errno {err}");
        }

        debug!("remote recvmsg for {label} completed: payload_bytes={recv_res}");

        let mut remote_msg_data = vec![0u8; size_of::<libc::msghdr>()];
        sys::read_stack(pid, remote_msg_ptr, &mut remote_msg_data)
            .with_context(|| format!("failed to read remote {label} msghdr"))?;
        let remote_msg =
            unsafe { std::ptr::read_unaligned(remote_msg_data.as_ptr() as *const libc::msghdr) };
        debug!(
            "{label} remote msghdr after recvmsg: msg_controllen={} msg_flags=0x{:x}",
            remote_msg.msg_controllen, remote_msg.msg_flags
        );

        let mut remote_cmsg_data = vec![0u8; recv_cmsg_space];
        sys::read_stack(pid, remote_cmsg_ptr, &mut remote_cmsg_data)
            .with_context(|| format!("failed to read remote {label} control data"))?;
        control_to_close = Some((remote_msg, remote_cmsg_data));
        let (remote_msg, remote_cmsg_data) =
            control_to_close.as_ref().expect("complete control data");
        let fd = validate_received_remote_fd(
            remote_msg,
            recv_res,
            remote_cmsg_data,
            remote_socket,
            expected_sender_credentials(),
        )
        .with_context(|| format!("failed to validate remote {label} fd from SCM_RIGHTS"))?;
        debug!("remote received {label} fd={fd}");
        Ok(fd)
    })();
    finish_remote_fd_handoff(
        sys::RemoteCallPostStatus { result, restored },
        socket_to_close,
        control_to_close.as_ref().map(|(msg, data)| (msg, data.as_slice())),
        close_remote,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use kmr_common::consts::AID_SYSTEM;

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

    #[test]
    fn handoff_finish_preserves_payload_and_only_closes_known_descriptors() {
        use std::cell::RefCell;
        for result in [Ok(42), Err(anyhow!("control read failed"))] {
            let closes = RefCell::new(Vec::new());
            let successful = result.is_ok();
            let status = finish_remote_fd_handoff(
                sys::RemoteCallPostStatus { result, restored: true },
                Some(7),
                None,
                &|fd| {
                    closes.borrow_mut().push(fd);
                    sys::RemoteCallPostStatus { result: Ok(()), restored: true }
                },
            );
            assert_eq!(*closes.borrow(), [7]);
            assert!(status.restored);
            if successful {
                assert_eq!(status.result.unwrap(), 42);
            } else {
                assert_eq!(
                    status.result.unwrap_err().root_cause().to_string(),
                    "control read failed"
                );
            }
        }
    }

    #[test]
    fn fd_and_credentials_queue_before_the_receiver_starts() {
        use std::io::{Read, Write};
        use std::os::fd::{FromRawFd, OwnedFd};
        use std::os::unix::net::UnixStream;

        let receiver = UnixDatagram::unbound().unwrap();
        let sender = UnixDatagram::unbound().unwrap();
        let (mut address, address_len) =
            build_abstract_sockaddr(&generate_fd_handoff_name().unwrap()).unwrap();
        let enable: libc::c_int = 1;
        // SAFETY: The option and address point to initialized, live values of the declared lengths.
        unsafe {
            assert_eq!(
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PASSCRED,
                    (&enable as *const libc::c_int).cast(),
                    size_of::<libc::c_int>() as _
                ),
                0
            );
            assert_eq!(
                libc::bind(
                    receiver.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    address_len as _
                ),
                0
            );
        }
        let (source, mut peer) = UnixStream::pair().unwrap();
        let mut rights = scm_rights_cmsg(source.as_raw_fd());
        let mut byte = [0x42u8];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
        // SAFETY: All-zero msghdr fields are valid before assigning the live buffers below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = (&mut address as *mut libc::sockaddr_un).cast();
        msg.msg_namelen = address_len as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = rights.as_mut_ptr().cast();
        msg.msg_controllen = rights.len();
        // SAFETY: msg and all its buffers remain live for this nonblocking send.
        assert_eq!(unsafe { libc::sendmsg(sender.as_raw_fd(), &msg, libc::MSG_DONTWAIT) }, 1);
        drop(source);

        // SAFETY: These fixed ancillary payload sizes fit the CMSG_SPACE calculation.
        let control_len = unsafe {
            libc::CMSG_SPACE(size_of::<libc::c_int>() as _)
                + libc::CMSG_SPACE(size_of::<libc::ucred>() as _)
        } as usize;
        let mut control = vec![0usize; control_words(control_len)];
        msg.msg_name = std::ptr::null_mut();
        msg.msg_namelen = 0;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control_len;
        byte[0] = 0;
        // SAFETY: msg still owns live, correctly aligned receive buffers.
        let received = unsafe { libc::recvmsg(receiver.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
        // SAFETY: The initialized word storage covers control_len bytes.
        let control =
            unsafe { std::slice::from_raw_parts(control.as_ptr().cast::<u8>(), control_len) };
        let fd = validate_received_remote_fd(
            &msg,
            received,
            control,
            receiver.as_raw_fd(),
            expected_sender_credentials(),
        )
        .unwrap();
        // SAFETY: recvmsg returned this new SCM_RIGHTS descriptor, which has no other owner.
        let mut stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(fd) });
        stream.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
        assert_eq!(byte, [0x42]);
        peer.write_all(b"x").unwrap();
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }
}
