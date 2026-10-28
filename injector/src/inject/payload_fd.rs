use crate::sys;
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, info};
use nix::unistd::Pid;
use rand::TryRng;
use std::ffi::{c_void, CString};
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

#[cfg(test)]
mod tests;

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
        bail!(
            "abstract socket name is too long for sockaddr_un: {} bytes",
            magic_bytes.len()
        );
    }

    addr.sun_family = libc::AF_UNIX as u16;
    for (i, byte) in magic_bytes.iter().enumerate() {
        addr.sun_path[1 + i] = *byte as libc::c_char;
    }
    Ok((
        addr,
        offset_of!(libc::sockaddr_un, sun_path) + 1 + magic_bytes.len(),
    ))
}

fn generate_fd_handoff_name() -> Result<[u8; 16]> {
    let mut random = [0u8; 16];
    let mut rng = rand::rngs::SysRng;
    rng.try_fill_bytes(&mut random)
        .context("failed to fill fd handoff socket name from SysRng")?;
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
    G: Fn() -> Result<i32>,
{
    let path_c = CString::new(path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("Invalid remote payload path {}", path.display()))?;
    let remote_path_ptr = push_to_remote_stack(path_c.as_bytes_with_nul())?;
    let remote_lib_fd = remote_c_int_result(sys::remote_call(
        pid,
        open_addr,
        libc_return_addr,
        &[
            remote_path_ptr,
            (libc::O_RDONLY | libc::O_CLOEXEC) as usize,
            0,
        ],
    )?);
    if remote_lib_fd == -1 {
        let err = get_remote_errno()?;
        bail!(
            "Failed to open remote payload path {}. Remote errno: {}",
            path.display(),
            err
        );
    }
    info!(
        "remote payload path opened: path={} fd={}",
        path.display(),
        remote_lib_fd
    );
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
) -> Result<()>
where
    H: Fn(i32) -> Result<()>,
{
    let mut close_errors = Vec::new();
    for fd in received_remote_fds_from_control_data(remote_msg, remote_cmsg_data) {
        if fd < 0 || fd == remote_socket_fd {
            continue;
        }
        if let Err(error) = close_remote(fd) {
            close_errors.push(format!("fd {fd}: {error:#}"));
        }
    }
    if let Err(error) = close_remote(remote_socket_fd) {
        close_errors.push(format!("socket {remote_socket_fd}: {error:#}"));
    }

    if close_errors.is_empty() {
        Ok(())
    } else {
        bail!(
            "failed to close rejected remote fd handoff descriptors: {}",
            close_errors.join("; ")
        );
    }
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
) -> Result<i32>
where
    F: FnMut(&[u8]) -> Result<usize>,
    G: Fn() -> Result<i32>,
    H: Fn(i32) -> Result<()>,
{
    let local_socket =
        unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if local_socket == -1 {
        bail!(
            "Failed to create local {label} handoff socket: {}",
            std::io::Error::last_os_error()
        );
    }
    let local_socket = unsafe { OwnedFd::from_raw_fd(local_socket) };

    let remote_socket = remote_c_int_result(sys::remote_call(
        pid,
        addrs.socket,
        addrs.libc_return,
        &[
            libc::AF_UNIX as usize,
            (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as usize,
            0,
        ],
    )?);
    if remote_socket == -1 {
        let err = get_remote_errno()?;
        bail!("Failed to create remote {label} handoff socket. Remote errno: {err}");
    }
    let enable: libc::c_int = 1;
    let remote_enable_ptr = push_to_remote_stack(&enable.to_ne_bytes())?;
    let result = remote_c_int_result(sys::remote_call(
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
    )?);
    if result == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_socket)?;
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
    let bind_res = remote_c_int_result(sys::remote_call(
        pid,
        addrs.bind,
        addrs.libc_return,
        &[remote_socket as usize, remote_addr_ptr, addr_len],
    )?);
    if bind_res == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_socket)?;
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
    let remote_iov = libc::iovec {
        iov_base: remote_payload_storage as *mut c_void,
        iov_len: 1,
    };
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

    let recvmsg_call = sys::remote_pre_call(
        pid,
        addrs.recvmsg,
        addrs.libc_return,
        &[
            remote_socket as usize,
            remote_msg_ptr,
            libc::MSG_WAITALL as usize,
        ],
    )?;

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

    let send_res = unsafe { libc::sendmsg(local_socket.as_raw_fd(), &local_hdr, 0) };
    if send_res == -1 {
        let send_error = std::io::Error::last_os_error();
        if let Err(cancel_error) = sys::remote_cancel_call(pid, recvmsg_call) {
            return Err(
                anyhow!("Failed to send {label} fd locally: {send_error}").context(format!(
                    "failed to cancel remote recvmsg after local sendmsg failure: {cancel_error:#}"
                )),
            );
        }
        if let Err(close_error) = close_remote(remote_socket) {
            return Err(
                anyhow!("Failed to send {label} fd locally: {send_error}").context(format!(
                    "failed to close remote socket after canceling recvmsg: {close_error:#}"
                )),
            );
        }
        bail!("Failed to send {label} fd locally: {send_error}");
    }
    debug!("sent {label} fd={local_fd} to remote abstract socket");

    let recv_status = sys::remote_post_call_with_status(pid, recvmsg_call);
    let recv_res = match recv_status.result {
        Ok(recv_res) => recv_res as isize,
        Err(error) => {
            if recv_status.restored {
                if let Err(close_error) = close_remote(remote_socket) {
                    return Err(error.context(format!(
                        "remote recvmsg for {label} failed after register restore; remote socket close also failed: {close_error:#}"
                    )));
                }
                return Err(error.context(format!(
                    "remote recvmsg for {label} failed after register restore"
                )));
            }
            return Err(error.context(format!(
                "remote recvmsg for {label} failed and register restore failed; remote socket not closed because tracee state is uncertain"
            )));
        }
    };

    if recv_res == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_socket)?;
        bail!("remote recvmsg for {label} failed with errno {err}");
    }

    debug!("remote recvmsg for {label} completed: payload_bytes={recv_res}");

    let mut remote_msg_data = vec![0u8; size_of::<libc::msghdr>()];
    if let Err(error) = sys::read_stack(pid, remote_msg_ptr, &mut remote_msg_data) {
        if let Err(close_error) = close_remote(remote_socket) {
            return Err(error.context(format!(
                "failed to read remote {label} msghdr; remote socket close also failed: {close_error:#}"
            )));
        }
        return Err(error.context(format!("failed to read remote {label} msghdr")));
    }
    let remote_msg =
        unsafe { std::ptr::read_unaligned(remote_msg_data.as_ptr() as *const libc::msghdr) };
    debug!(
        "{label} remote msghdr after recvmsg: msg_controllen={} msg_flags=0x{:x}",
        remote_msg.msg_controllen, remote_msg.msg_flags
    );

    let mut remote_cmsg_data = vec![0u8; recv_cmsg_space];
    if let Err(error) = sys::read_stack(pid, remote_cmsg_ptr, &mut remote_cmsg_data) {
        if let Err(close_error) = close_remote(remote_socket) {
            return Err(error.context(format!(
                "failed to read remote {label} control data; remote socket close also failed: {close_error:#}"
            )));
        }
        return Err(error.context(format!("failed to read remote {label} control data")));
    }

    let fd = match validate_received_remote_fd(
        &remote_msg,
        recv_res,
        &remote_cmsg_data,
        remote_socket,
        expected_sender_credentials(),
    ) {
        Ok(fd) => fd,
        Err(error) => {
            if let Err(close_error) = close_rejected_remote_fd_handoff(
                &remote_msg,
                &remote_cmsg_data,
                remote_socket,
                close_remote,
            ) {
                return Err(error.context(format!(
                    "failed to validate remote {label} fd from SCM_RIGHTS; cleanup also failed: {close_error:#}"
                )));
            }
            return Err(error)
                .with_context(|| format!("failed to validate remote {label} fd from SCM_RIGHTS"));
        }
    };
    debug!("remote received {label} fd={fd}");
    if let Err(error) = close_remote(remote_socket) {
        if let Err(close_error) = close_remote(fd) {
            return Err(error.context(format!(
                "failed to close remote {label} socket; received fd close also failed: {close_error:#}"
            )));
        }
        return Err(error.context(format!(
            "failed to close remote {label} socket after receiving fd"
        )));
    }
    Ok(fd)
}
