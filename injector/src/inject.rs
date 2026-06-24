use std::ffi::{c_void, CString};
use std::mem::{offset_of, size_of};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use kmr_common::rpc;
use log::{debug, error, info, warn};
use nix::{sys::signal::Signal, unistd::Pid};
use rand::TryRng;
use rsbinder::rpc::RpcSession;

use crate::sys::wait_pid;
use crate::{sys, utils};

const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;
const REMOTE_PAYLOAD_STATE_PATH: &str = "/data/adb/omk/injector.payload";
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_RETRY_DELAY: Duration = Duration::from_millis(200);

#[repr(C)]
struct android_dlextinfo {
    flags: u64,
    reserved_addr: *mut c_void,
    reserved_size: usize,
    relro_fd: i32,
    library_fd: i32,
    library_fd_offset: i64,
    library_namespace: *mut c_void,
}

struct RawFdGuard(RawFd);

impl Drop for RawFdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[derive(Clone, Copy)]
struct RemoteFdHandoffAddrs {
    socket: usize,
    bind: usize,
    recvmsg: usize,
    setsockopt: usize,
    libc_return: usize,
}

fn log_loader_abi() {
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

fn build_remote_abstract_sockaddr_bytes(magic_bytes: &[u8]) -> Result<(Vec<u8>, usize)> {
    let sun_path_offset = offset_of!(libc::sockaddr_un, sun_path);
    let mut addr_bytes = vec![0u8; size_of::<libc::sockaddr_un>()];
    let family = (libc::AF_UNIX as u16).to_ne_bytes();
    addr_bytes[0] = family[0];
    addr_bytes[1] = family[1];

    let needed = sun_path_offset + 1 + magic_bytes.len();
    if needed > addr_bytes.len() {
        bail!(
            "abstract socket name is too long for sockaddr_un: {} bytes",
            magic_bytes.len()
        );
    }

    addr_bytes[sun_path_offset] = 0;
    let start = sun_path_offset + 1;
    addr_bytes[start..start + magic_bytes.len()].copy_from_slice(magic_bytes);
    Ok((addr_bytes, needed))
}

fn build_local_abstract_sockaddr(magic_bytes: &[u8]) -> Result<libc::sockaddr_un> {
    let mut local_dest_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let max_len = local_dest_addr.sun_path.len().saturating_sub(1);
    if magic_bytes.len() > max_len {
        bail!(
            "abstract socket name is too long for local sockaddr_un: {} bytes",
            magic_bytes.len()
        );
    }

    local_dest_addr.sun_family = libc::AF_UNIX as u16;
    local_dest_addr.sun_path[0] = 0 as libc::c_char;
    for (i, byte) in magic_bytes.iter().enumerate() {
        local_dest_addr.sun_path[1 + i] = *byte as libc::c_char;
    }

    Ok(local_dest_addr)
}

fn align_down(value: usize, alignment: usize) -> Result<usize> {
    if alignment == 0 || !alignment.is_power_of_two() {
        bail!("invalid alignment: {}", alignment);
    }
    Ok(value & !(alignment - 1))
}

fn format_remote_payload_identifier(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut identifier = String::with_capacity(3 + (bytes.len() * 2) + 3);
    identifier.push_str("lib");
    for byte in bytes {
        identifier.push(HEX[(byte >> 4) as usize] as char);
        identifier.push(HEX[(byte & 0x0f) as usize] as char);
    }
    identifier.push_str(".so");
    identifier
}

fn generate_remote_payload_identifier() -> Result<String> {
    let mut random = [0u8; 16];
    let mut rng = rand::rngs::SysRng;
    rng.try_fill_bytes(&mut random)
        .context("failed to fill payload identifier bytes from SysRng")?;
    Ok(format_remote_payload_identifier(&random))
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

fn cleanup_error_message(errors: &[anyhow::Error]) -> String {
    errors
        .iter()
        .map(|error| format!("{error:#}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn finish_injection_result(result: Result<()>, cleanup_errors: Vec<anyhow::Error>) -> Result<()> {
    if cleanup_errors.is_empty() {
        return result;
    }

    for cleanup_error in &cleanup_errors {
        error!("injection cleanup failed: {cleanup_error:#}");
    }

    let cleanup_message = cleanup_error_message(&cleanup_errors);
    match result {
        Ok(()) => Err(anyhow!("injection cleanup failed: {cleanup_message}")),
        Err(error) => Err(error.context(format!(
            "injection failed and cleanup also failed: {cleanup_message}"
        ))),
    }
}

fn persist_remote_payload_state(pid: Pid, payload_identifier: &str) -> Result<()> {
    let path = Path::new(REMOTE_PAYLOAD_STATE_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create injector payload state directory {}",
                parent.display()
            )
        })?;
    }
    std::fs::write(path, format!("{} {}\n", pid, payload_identifier))
        .with_context(|| format!("failed to write injector payload state {}", path.display()))?;
    Ok(())
}

fn open_remote_payload_fd_from_path<F, G>(
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
    let args = vec![
        remote_path_ptr,
        (libc::O_RDONLY | libc::O_CLOEXEC) as usize,
        0,
    ];
    let remote_lib_fd =
        remote_c_int_result(sys::remote_call(pid, open_addr, libc_return_addr, &args)?);
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
            for fd in data.chunks_exact(size_of::<libc::c_int>()) {
                fds.push(i32::from_ne_bytes(fd.try_into().unwrap()));
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

fn enable_remote_passcred<F, G, H>(
    pid: Pid,
    remote_socket: i32,
    label: &str,
    addrs: RemoteFdHandoffAddrs,
    push_to_remote_stack: &mut F,
    get_remote_errno: &G,
    close_remote: &H,
) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<usize>,
    G: Fn() -> Result<i32>,
    H: Fn(i32) -> Result<()>,
{
    let enable: libc::c_int = 1;
    let remote_enable_ptr = push_to_remote_stack(&enable.to_ne_bytes())?;
    let args = vec![
        remote_socket as usize,
        libc::SOL_SOCKET as usize,
        libc::SO_PASSCRED as usize,
        remote_enable_ptr,
        size_of::<libc::c_int>(),
    ];
    let result = remote_c_int_result(sys::remote_call(
        pid,
        addrs.setsockopt,
        addrs.libc_return,
        &args,
    )?);
    if result == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_socket)?;
        bail!("Failed to enable SO_PASSCRED on remote {label} handoff socket. Remote errno: {err}");
    }
    Ok(())
}

fn send_fd_to_remote<F, G, H>(
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
    let _local_sock_guard = RawFdGuard(local_socket);

    let args = vec![
        libc::AF_UNIX as usize,
        (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as usize,
        0,
    ];
    let remote_socket = remote_c_int_result(sys::remote_call(
        pid,
        addrs.socket,
        addrs.libc_return,
        &args,
    )?);
    if remote_socket == -1 {
        let err = get_remote_errno()?;
        bail!("Failed to create remote {label} handoff socket. Remote errno: {err}");
    }
    enable_remote_passcred(
        pid,
        remote_socket,
        label,
        addrs,
        push_to_remote_stack,
        get_remote_errno,
        close_remote,
    )?;

    let magic_bytes = generate_fd_handoff_name()?;

    let (addr_bytes, addr_len) = build_remote_abstract_sockaddr_bytes(&magic_bytes)?;
    debug!(
        "Generated {label} handoff socket with {} random abstract-name bytes",
        magic_bytes.len()
    );

    let remote_addr_ptr = push_to_remote_stack(&addr_bytes)?;
    let args = vec![remote_socket as usize, remote_addr_ptr, addr_len];
    let bind_res =
        remote_c_int_result(sys::remote_call(pid, addrs.bind, addrs.libc_return, &args)?);
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

    let mut local_dest_addr = build_local_abstract_sockaddr(&magic_bytes)?;
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

    let send_res = unsafe { libc::sendmsg(local_socket, &local_hdr, 0) };
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

fn check_rpc_ready_once() -> Result<()> {
    let session = RpcSession::setup_unix_client_android13plus(rpc::SOCKET, rpc::WIRE_MAX_VERSION)
        .context("failed to connect to OMK RPC socket")?;
    session
        .get_service(rpc::SERVICE)
        .context("failed to resolve OMK RPC service")?;
    Ok(())
}

fn wait_for_rpc_ready() -> Result<()> {
    let start = Instant::now();
    let mut last_error: Option<anyhow::Error> = None;

    while start.elapsed() < READY_TIMEOUT {
        match check_rpc_ready_once() {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                thread::sleep(READY_RETRY_DELAY);
            }
        }
    }

    match last_error {
        Some(error) => Err(error).context("OMK RPC server did not become ready in time"),
        None => bail!("OMK RPC server did not become ready in time"),
    }
}

fn open_payload_rpc_stream() -> Result<UnixStream> {
    UnixStream::connect(rpc::SOCKET).context("failed to connect OMK RPC socket for payload")
}

pub fn inject_library(pid: Pid) -> Result<()> {
    wait_for_rpc_ready()?;

    let self_path =
        std::fs::read_link("/proc/self/exe").context("Failed to read link /proc/self/exe")?;

    nix::sys::ptrace::attach(pid).with_context(|| format!("Failed to attach to process {pid}"))?;
    debug!("attached to process {}", pid);

    if let Err(e) = wait_pid(pid, Signal::SIGSTOP) {
        warn!("wait for process stop failed; detaching: {}", e);
        if let Err(detach_error) = nix::sys::ptrace::detach(pid, None)
            .with_context(|| format!("Failed to detach from process {pid} after wait failure"))
        {
            return Err(e.context(format!(
                "Failed to wait for process {pid} to stop; cleanup also failed: {detach_error:#}"
            )));
        }
        return Err(e.context(format!("Failed to wait for process {pid} to stop")));
    }

    let backup_regs = match sys::get_regs(pid).context("Failed to backup registers.") {
        Ok(regs) => regs,
        Err(error) => {
            if let Err(detach_error) = nix::sys::ptrace::detach(pid, None).with_context(|| {
                format!("Failed to detach from process {pid} after get_regs failure")
            }) {
                return Err(error.context(format!(
                    "cleanup after get_regs failure also failed: {detach_error:#}"
                )));
            }
            return Err(error);
        }
    };

    // Run actual injection; regardless of success/failure we MUST restore regs and detach
    let result = do_inject(pid, &self_path);

    // === CLEANUP: Always restore registers and detach ===
    debug!("restoring registers and detaching");
    let mut cleanup_errors = Vec::new();
    if let Err(e) = sys::set_regs(pid, &backup_regs) {
        cleanup_errors.push(e.context("Failed to restore registers"));
    }
    if let Err(e) = nix::sys::ptrace::detach(pid, None)
        .with_context(|| format!("Failed to detach from process {pid}"))
    {
        cleanup_errors.push(e);
    }

    finish_injection_result(result, cleanup_errors)
}

fn do_inject(pid: Pid, self_path: &std::path::Path) -> Result<()> {
    let payload_identifier =
        generate_remote_payload_identifier().context("failed to generate payload identifier")?;
    log_loader_abi();
    info!(
        "starting injection build_id={} pid={} payload={} self_path={}",
        crate::utils::build_id(),
        pid,
        payload_identifier,
        self_path.display(),
    );
    let mut regs = sys::get_regs(pid)?;

    let local_maps = lsplt_rs::MapInfo::scan("self");
    let remote_maps = lsplt_rs::MapInfo::scan(pid.as_raw().to_string().as_str());

    // Helper closure to resolve function address
    let resolve = |lib: &str, name: &str| -> Result<usize> {
        utils::resolve_func_addr(&local_maps, &remote_maps, lib, name)
            .or_else(|_| utils::resolve_func_addr(&local_maps, &remote_maps, "libc.so", name))
        // Fallback to libc for newer android
    };

    // Helper to push data to remote stack and update regs SP
    let mut push_to_remote_stack = |data: &[u8]| -> Result<usize> {
        let sp = {
            #[cfg(target_arch = "x86_64")]
            {
                regs.rsp as usize
            }
            #[cfg(target_arch = "x86")]
            {
                regs.esp as usize
            }
            #[cfg(target_arch = "aarch64")]
            {
                regs.sp as usize
            }
            #[cfg(target_arch = "arm")]
            {
                regs.uregs[13] as usize
            }
        };
        let tentative_sp = sp
            .checked_sub(data.len())
            .context("stack underflow while reserving remote storage")?;
        let new_sp = align_down(tentative_sp, 16)?;
        let write_base = new_sp
            .checked_add(data.len())
            .context("aligned remote stack write overflow")?;
        // Keep the remote scratch allocations 16-byte aligned like the reference
        // injector. Ancillary socket control buffers are sensitive to layout.
        let new_sp = sys::push_stack(pid, write_base, data, false)?;

        // Update local regs copy
        #[cfg(target_arch = "x86_64")]
        {
            regs.rsp = new_sp as u64;
        }
        #[cfg(target_arch = "x86")]
        {
            regs.esp = new_sp as u32;
        }
        #[cfg(target_arch = "aarch64")]
        {
            regs.sp = new_sp as u64;
        }
        #[cfg(target_arch = "arm")]
        {
            regs.uregs[13] = new_sp as u32;
        }

        // Commit SP change to remote process so subsequent remote_call works correctly
        sys::set_regs(pid, &regs)?;
        debug!(
            "remote scratch push: size={} old_sp=0x{:x} new_sp=0x{:x} align={}",
            data.len(),
            sp,
            new_sp,
            new_sp % 16
        );
        Ok(new_sp)
    };

    let libc_return_addr = utils::resolve_return_addr(&remote_maps, "libc.so")?;
    debug!("resolved libc return address=0x{:x}", libc_return_addr);

    let close_addr = resolve("libc.so", "close")?;
    let open_addr = resolve("libc.so", "open").or_else(|_| resolve("libc.so", "open64"))?;
    let socket_addr = resolve("libc.so", "socket")?;
    let setsockopt_addr = resolve("libc.so", "setsockopt")?;
    let bind_addr = resolve("libc.so", "bind")?;
    let recvmsg_addr = resolve("libc.so", "recvmsg")?;
    let errno_addr = resolve("libc.so", "__errno").ok();
    let strlen_addr = resolve("libc.so", "strlen").ok();
    let dlopen_addr = resolve("libdl.so", "android_dlopen_ext")?;
    let dlsym_addr = resolve("libdl.so", "dlsym")?;
    let dlerror_addr = resolve("libdl.so", "dlerror").ok();

    let read_remote_dlerror = || -> Result<Option<String>> {
        if let (Some(err_fn), Some(str_fn)) = (dlerror_addr, strlen_addr) {
            let err_ptr = sys::remote_call(pid, err_fn, libc_return_addr, &[])?;
            if err_ptr == 0 {
                return Ok(None);
            }

            let len = sys::remote_call(pid, str_fn, libc_return_addr, &[err_ptr])?;
            if len == 0 || len > 1024 {
                return Ok(Some(format!(
                    "remote dlerror pointer=0x{err_ptr:x} returned invalid length {len}"
                )));
            }

            let mut err_buf = vec![0u8; len];
            sys::read_stack(pid, err_ptr, &mut err_buf)?;
            return Ok(Some(String::from_utf8_lossy(&err_buf).into_owned()));
        }

        Ok(None)
    };

    let get_remote_errno = || -> Result<i32> {
        if let Some(addr) = errno_addr {
            let ptr = sys::remote_call(pid, addr, libc_return_addr, &[])?;
            let mut buf = [0u8; 4];
            sys::read_stack(pid, ptr, &mut buf)?;
            Ok(i32::from_ne_bytes(buf))
        } else {
            Ok(0)
        }
    };

    let close_remote = |fd: i32| -> Result<()> {
        let args = vec![fd as usize];
        let close_res = sys::remote_call(pid, close_addr, libc_return_addr, &args)?;
        if close_res != 0 {
            let err = get_remote_errno().unwrap_or(0);
            bail!(
                "Remote close failed for fd {}: result={} errno={}",
                fd,
                close_res,
                err
            );
        }
        Ok(())
    };

    let local_lib_file = std::fs::File::open(self_path).with_context(|| {
        format!(
            "Failed to open deployed payload image {}",
            self_path.display()
        )
    })?;
    let local_lib_fd = local_lib_file.as_raw_fd();
    info!(
        "local payload file ready: fd={} path={} identifier={} sha256={}",
        local_lib_fd,
        self_path.display(),
        payload_identifier,
        utils::sha256_file(self_path).unwrap_or_else(|_| "<unavailable>".to_string())
    );
    let rpc_stream = open_payload_rpc_stream()?;

    // Keep the old sockcreate tweak as best-effort only; the main path uses
    // the already deployed injector image and no longer stages an extra copy.
    if let Err(error) = utils::set_sockcreate_con("u:object_r:system_file:s0") {
        warn!("sockcreate context setup failed: {error:#}");
    }

    let fd_handoff_addrs = RemoteFdHandoffAddrs {
        socket: socket_addr,
        bind: bind_addr,
        recvmsg: recvmsg_addr,
        setsockopt: setsockopt_addr,
        libc_return: libc_return_addr,
    };

    let remote_lib_fd = match send_fd_to_remote(
        pid,
        local_lib_fd,
        "payload image",
        fd_handoff_addrs,
        &mut push_to_remote_stack,
        &get_remote_errno,
        &close_remote,
    ) {
        Ok(fd) => fd,
        Err(error) => {
            warn!(
                "payload fd handoff failed: {error:#}. Trying direct fallback via {}.",
                self_path.display()
            );
            open_remote_payload_fd_from_path(
                pid,
                open_addr,
                libc_return_addr,
                self_path,
                &mut push_to_remote_stack,
                &get_remote_errno,
            )
            .with_context(|| {
                format!(
                    "failed to hand off payload fd and could not reopen {} directly",
                    self_path.display()
                )
            })?
        }
    };

    let dlext_info = android_dlextinfo {
        flags: ANDROID_DLEXT_USE_LIBRARY_FD,
        reserved_addr: std::ptr::null_mut(),
        reserved_size: 0,
        relro_fd: -1,
        library_fd: remote_lib_fd,
        library_fd_offset: 0,
        library_namespace: std::ptr::null_mut(),
    };
    let info_bytes = unsafe {
        std::slice::from_raw_parts(
            &dlext_info as *const _ as *const u8,
            std::mem::size_of::<android_dlextinfo>(),
        )
    };
    let remote_info_ptr = push_to_remote_stack(info_bytes)?;

    let remote_loader_path_c = CString::new(payload_identifier.as_str())?;
    let remote_path_ptr = push_to_remote_stack(remote_loader_path_c.as_bytes_with_nul())?;

    // Call dlopen
    // args: filename, flags (RTLD_NOW=2), extinfo
    let args = vec![remote_path_ptr, libc::RTLD_NOW as usize, remote_info_ptr];
    let handle = sys::remote_call(pid, dlopen_addr, libc_return_addr, &args)?;

    debug!(
        "Remote dlopen handle: 0x{:x} using identifier={} fd={}",
        handle, payload_identifier, remote_lib_fd
    );

    if handle == 0 {
        if let Some(error_message) = read_remote_dlerror()? {
            error!("android_dlopen_ext failed: {}", error_message);
        }
        close_remote(remote_lib_fd)?;
        bail!("Remote dlopen failed");
    }

    close_remote(remote_lib_fd)?;

    if let Some(err_fn) = dlerror_addr {
        let _ = sys::remote_call(pid, err_fn, libc_return_addr, &[]);
    }
    let entry_symbol = std::ffi::CString::new("entry")?;
    let remote_entry_symbol_ptr = push_to_remote_stack(entry_symbol.as_bytes_with_nul())?;
    let injector_entry = sys::remote_call(
        pid,
        dlsym_addr,
        libc_return_addr,
        &[handle, remote_entry_symbol_ptr],
    )?;
    if injector_entry == 0 {
        if let Some(error_message) = read_remote_dlerror()? {
            error!("dlsym(entry) failed: {}", error_message);
        }
        bail!("Failed to find 'entry' symbol in injected image");
    }
    debug!(
        "resolved remote entry via dlsym address=0x{:x}",
        injector_entry
    );

    let remote_rpc_fd = send_fd_to_remote(
        pid,
        rpc_stream.as_raw_fd(),
        "OMK RPC connection",
        fd_handoff_addrs,
        &mut push_to_remote_stack,
        &get_remote_errno,
        &close_remote,
    )
    .context("failed to hand off OMK RPC fd to payload")?;
    drop(rpc_stream);

    let args = vec![handle, remote_rpc_fd as usize];
    let entry_result = sys::remote_call(pid, injector_entry, libc_return_addr, &args)?;
    if entry_result == 0 {
        bail!("Remote entry returned false");
    }

    if let Err(error) = persist_remote_payload_state(pid, &payload_identifier) {
        warn!(
            "failed to persist payload identifier state for pid {}: {:#}",
            pid, error
        );
    }

    info!("remote entry returned successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatted_payload_identifier_looks_like_shared_library_name() {
        let identifier =
            format_remote_payload_identifier(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);

        assert_eq!(identifier, "lib0123456789abcdef.so");
    }

    #[test]
    fn generated_payload_identifier_has_expected_shape() {
        let identifier = generate_remote_payload_identifier().expect("identifier should generate");
        assert!(identifier.starts_with("lib"));
        assert!(identifier.ends_with(".so"));
        assert_eq!(identifier.len(), 38);
        assert!(identifier[3..identifier.len() - 3]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }

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
        let header = libc::cmsghdr {
            cmsg_len,
            cmsg_level: level,
            cmsg_type: type_,
        };

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
        libc::ucred {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        }
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

        assert_eq!(
            received_remote_fds_from_control_data(&msg, &data),
            vec![42, 43]
        );
    }
}
