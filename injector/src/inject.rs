use std::ffi::{c_void, CString};
use std::mem::{offset_of, size_of};
use std::os::fd::AsRawFd;
use std::path::Path;

use anyhow::{bail, Context, Result};
use log::{debug, error, info, warn};
use nix::{sys::signal::Signal, unistd::Pid};
use rand::TryRngCore;

use crate::sys::wait_pid;
use crate::{sys, utils};

const ANDROID_DLEXT_USE_LIBRARY_FD: u64 = 0x10;
const CMSG_STORAGE_WORDS: usize = 4;
const REMOTE_PAYLOAD_STATE_PATH: &str = "/data/adb/omk/injector.payload";

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

fn log_loader_abi() {
    debug!(
        "[Injector][Loader] build_target={} runtime_arch={} sockaddr_un(size={}, sun_path_offset={}, c_char_size={}) msghdr(size={}, msg_control_offset={}, msg_controllen_offset={}) cmsghdr(size={}, cmsg_len_offset={}, cmsg_level_offset={}, cmsg_type_offset={}) cmsg_space_int={} cmsg_len_int={}",
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
    let mut rng = rand::rngs::OsRng;
    rng.try_fill_bytes(&mut random)
        .context("failed to fill payload identifier bytes from OsRng")?;
    Ok(format_remote_payload_identifier(&random))
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
    let remote_lib_fd = sys::remote_call(pid, open_addr, libc_return_addr, &args)? as i32;
    if remote_lib_fd == -1 {
        let err = get_remote_errno()?;
        bail!(
            "Failed to open remote payload path {}. Remote errno: {}",
            path.display(),
            err
        );
    }
    info!(
        "[Injector][Loader] remote payload path opened: path={} fd={}",
        path.display(),
        remote_lib_fd
    );
    Ok(remote_lib_fd)
}

fn validate_received_remote_fd(remote_cmsg_data: &[u8], remote_socket_fd: i32) -> Result<i32> {
    if remote_cmsg_data.len() < size_of::<libc::cmsghdr>() {
        bail!(
            "remote control buffer too small: {} < {}",
            remote_cmsg_data.len(),
            size_of::<libc::cmsghdr>()
        );
    }

    let header =
        unsafe { std::ptr::read_unaligned(remote_cmsg_data.as_ptr() as *const libc::cmsghdr) };
    let expected_len = unsafe { libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize };
    if header.cmsg_len != expected_len {
        bail!(
            "invalid remote cmsghdr length: got {}, expected {}",
            header.cmsg_len,
            expected_len
        );
    }
    if header.cmsg_level != libc::SOL_SOCKET {
        bail!(
            "invalid remote cmsghdr level: got {}, expected {}",
            header.cmsg_level,
            libc::SOL_SOCKET
        );
    }
    if header.cmsg_type != libc::SCM_RIGHTS {
        bail!(
            "invalid remote cmsghdr type: got {}, expected {}",
            header.cmsg_type,
            libc::SCM_RIGHTS
        );
    }

    let data_offset = unsafe { libc::CMSG_LEN(0) as usize };
    let data_end = data_offset + size_of::<libc::c_int>();
    if data_end > remote_cmsg_data.len() {
        bail!(
            "remote cmsghdr payload truncated: need {} bytes, have {}",
            data_end,
            remote_cmsg_data.len()
        );
    }

    let fd = i32::from_ne_bytes(remote_cmsg_data[data_offset..data_end].try_into().unwrap());
    if fd < 0 {
        bail!("remote payload fd is negative: {}", fd);
    }
    if fd == remote_socket_fd {
        bail!(
            "remote payload fd {} unexpectedly matches the remote socket fd; SCM_RIGHTS parsing is corrupted",
            fd
        );
    }

    Ok(fd)
}

pub fn inject_library(pid: Pid) -> Result<()> {
    let self_path =
        std::fs::read_link("/proc/self/exe").context("Failed to read link /proc/self/exe")?;

    nix::sys::ptrace::attach(pid)?;
    debug!("Attached to process {}", pid);

    if let Err(e) = wait_pid(pid, Signal::SIGSTOP) {
        warn!("Wait failed, detaching: {}", e);
        let _ = nix::sys::ptrace::detach(pid, None);
        bail!("Failed to wait for process {} to stop: {}", pid, e);
    }

    let backup_regs = sys::get_regs(pid)?;

    // Run actual injection; regardless of success/failure we MUST restore regs and detach
    let result = do_inject(pid, &self_path);

    // === CLEANUP: Always restore registers and detach ===
    debug!("Restoring registers and detaching");
    if let Err(e) = sys::set_regs(pid, &backup_regs) {
        error!("Failed to restore registers: {}", e);
    }
    if let Err(e) = nix::sys::ptrace::detach(pid, None) {
        error!("Failed to detach from process {}: {}", pid, e);
    }

    result
}

fn do_inject(pid: Pid, self_path: &std::path::Path) -> Result<()> {
    let payload_identifier =
        generate_remote_payload_identifier().context("failed to generate payload identifier")?;
    log_loader_abi();
    info!(
        "[Injector][Loader] starting build_id={} pid={} payload={} self_path={}",
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
            "[Injector][Loader] remote scratch push: size={} old_sp=0x{:x} new_sp=0x{:x} align={}",
            data.len(),
            sp,
            new_sp,
            new_sp % 16
        );
        Ok(new_sp)
    };

    let libc_return_addr = utils::resolve_return_addr(&remote_maps, "libc.so")?;
    debug!("Resolved libc return address: 0x{:x}", libc_return_addr);

    let close_addr = resolve("libc.so", "close")?;
    let open_addr = resolve("libc.so", "open").or_else(|_| resolve("libc.so", "open64"))?;
    let socket_addr = resolve("libc.so", "socket")?;
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
        if sys::remote_call(pid, close_addr, libc_return_addr, &args)? != 0 {
            error!("Remote close failed for fd {}", fd);
        }
        Ok(())
    };

    // Keep the old sockcreate tweak as best-effort only; the main path uses
    // the already deployed injector image and no longer stages an extra copy.
    if let Err(error) = utils::set_sockcreate_con("u:object_r:system_file:s0") {
        warn!("[Injector][Loader] sockcreate context setup failed: {error:#}");
    }

    // Create local socket
    let local_socket =
        unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if local_socket == -1 {
        bail!(
            "Failed to create local socket: {}",
            std::io::Error::last_os_error()
        );
    }
    // Ensure local socket is closed when we drop/exit
    let _local_sock_guard = {
        // Simple scope guard to close fd
        struct FdGuard(i32);
        impl Drop for FdGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::close(self.0);
                }
            }
        }
        FdGuard(local_socket)
    };
    let local_lib_file = std::fs::File::open(self_path).with_context(|| {
        format!(
            "Failed to open deployed payload image {}",
            self_path.display()
        )
    })?;
    let local_lib_fd = local_lib_file.as_raw_fd();
    info!(
        "[Injector][Loader] local payload file ready: fd={} path={} identifier={} sha256={}",
        local_lib_fd,
        self_path.display(),
        payload_identifier,
        utils::sha256_file(self_path).unwrap_or_else(|_| "<unavailable>".to_string())
    );

    let args = vec![
        libc::AF_UNIX as usize,
        (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as usize,
        0,
    ];
    let remote_fd = sys::remote_call(pid, socket_addr, libc_return_addr, &args)? as i32;
    if remote_fd == -1 {
        let err = get_remote_errno()?;
        bail!("Failed to create remote socket. Remote errno: {}", err);
    }

    // generate magic socket name
    let mut magic_bytes = Vec::with_capacity(16);
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .subsec_nanos();
    for i in 0..16 {
        magic_bytes.push(b'a' + ((time.wrapping_add(i) % 26) as u8)); // a-z
    }

    let (addr_bytes, addr_len) = build_remote_abstract_sockaddr_bytes(&magic_bytes)?;

    debug!(
        "Generated magic socket: @{}",
        String::from_utf8_lossy(&magic_bytes)
    );

    let remote_addr_ptr = push_to_remote_stack(&addr_bytes)?;

    let args = vec![remote_fd as usize, remote_addr_ptr, addr_len];
    let bind_res = sys::remote_call(pid, bind_addr, libc_return_addr, &args)?;
    if (bind_res as isize) == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_fd)?;
        bail!("Failed to bind remote socket. Remote errno: {}", err);
    }

    // CMSG buffer
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) as usize };
    let remote_cmsg_storage = [0usize; CMSG_STORAGE_WORDS];
    let remote_cmsg_bytes = unsafe {
        std::slice::from_raw_parts(remote_cmsg_storage.as_ptr() as *const u8, cmsg_space)
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
    msg.msg_controllen = cmsg_space;

    let msg_bytes = unsafe {
        std::slice::from_raw_parts(
            &msg as *const _ as *const u8,
            std::mem::size_of::<libc::msghdr>(),
        )
    };
    let remote_msg_ptr = push_to_remote_stack(msg_bytes)?;

    let recvmsg_call = sys::remote_pre_call(
        pid,
        recvmsg_addr,
        libc_return_addr,
        &[
            remote_fd as usize,
            remote_msg_ptr,
            libc::MSG_WAITALL as usize,
        ],
    )?;

    // 6b. Sendmsg (Local) -> Send the FD
    // Construct local address to send TO
    let mut local_dest_addr = build_local_abstract_sockaddr(&magic_bytes)?;

    // Construct Control Message
    // Requires explicit CMSG construction
    let mut local_cmsg_storage = [0usize; CMSG_STORAGE_WORDS];
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
    local_hdr.msg_controllen = cmsg_space;

    debug!(
        "[Injector][Loader] local cmsg buffer ptr=0x{:x} align={} remote cmsg ptr=0x{:x} align={}",
        local_hdr.msg_control as usize,
        (local_hdr.msg_control as usize) % size_of::<usize>(),
        remote_cmsg_ptr,
        remote_cmsg_ptr % size_of::<usize>()
    );

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&local_hdr);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        *(libc::CMSG_DATA(cmsg) as *mut libc::c_int) = local_lib_fd;
        // NOTE: Keep msg_controllen as cmsg_space (CMSG_SPACE), not cmsg_len.
        // The kernel expects the full CMSG_SPACE which includes alignment padding.
    }

    let send_res = unsafe { libc::sendmsg(local_socket, &local_hdr, 0) };
    if send_res == -1 {
        close_remote(remote_fd)?;
        bail!(
            "Failed to send FD locally: {}",
            std::io::Error::last_os_error()
        );
    }
    debug!("Sent FD {} to remote abstract socket", local_lib_fd);

    let recv_res = sys::remote_post_call(pid, recvmsg_call)? as isize;

    let remote_lib_fd = if recv_res == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_fd)?;
        warn!(
            "[Injector][Loader] remote recvmsg failed with errno {}; trying direct fallback via {}",
            err,
            self_path.display()
        );
        open_remote_payload_fd_from_path(
            pid,
            open_addr,
            libc_return_addr,
            self_path,
            &mut push_to_remote_stack,
            &get_remote_errno,
        )?
    } else {
        debug!(
            "[Injector][Loader] remote recvmsg completed: payload_bytes={}",
            recv_res
        );

        let mut remote_msg_data = vec![0u8; size_of::<libc::msghdr>()];
        sys::read_stack(pid, remote_msg_ptr, &mut remote_msg_data)?;
        let remote_msg =
            unsafe { std::ptr::read_unaligned(remote_msg_data.as_ptr() as *const libc::msghdr) };
        debug!(
            "[Injector][Loader] remote msghdr after recvmsg: msg_controllen={} msg_flags=0x{:x}",
            remote_msg.msg_controllen, remote_msg.msg_flags
        );

        let mut remote_cmsg_data = vec![0u8; cmsg_space];
        sys::read_stack(pid, remote_cmsg_ptr, &mut remote_cmsg_data)?;
        match validate_received_remote_fd(&remote_cmsg_data, remote_fd) {
            Ok(fd) => {
                debug!("Remote received FD: {}", fd);
                close_remote(remote_fd)?;
                fd
            }
            Err(error) => {
                close_remote(remote_fd)?;
                warn!(
                    "[Injector][Loader] SCM_RIGHTS payload handoff failed: {error:#}. Trying direct fallback via {}.",
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
                        "failed to validate SCM_RIGHTS payload fd from remote recvmsg and could not reopen {} directly",
                        self_path.display()
                    )
                })?
            }
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
    debug!("Resolved remote entry via dlsym at 0x{:x}", injector_entry);

    let args = vec![handle];
    let entry_result = sys::remote_call(pid, injector_entry, libc_return_addr, &args)?;
    if entry_result == 0 {
        bail!("Remote entry returned false");
    }

    if let Err(error) = persist_remote_payload_state(pid, &payload_identifier) {
        warn!(
            "[Injector][Loader] failed to persist payload identifier state for pid {}: {:#}",
            pid, error
        );
    }

    info!("Remote entry called successfully");
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
}
