use std::ffi::c_void;

use anyhow::{bail, Context, Result};
use log::{debug, error};
use nix::{sys::signal::Signal, unistd::Pid};

use crate::sys::wait_pid;

pub mod logging;
pub mod sys;
pub mod utils;

fn main() {
    logging::init_logger();
    let (pid, _) = utils::find_process_by_name("keystore2").unwrap();
    let pid = Pid::from_raw(pid);
    inject_library(pid, entry).unwrap();
}

fn inject_library(pid: Pid, entry: extern "C" fn(*const c_void) -> bool) -> Result<()> {
    let self_path =
        std::fs::read_link("/proc/self/exe").context("Failed to read link /proc/self/exe")?;

    nix::sys::ptrace::attach(pid)?;
    debug!("Attached to process {}", pid);

    if let Err(e) = wait_pid(pid, Signal::SIGSTOP) {
        bail!("Failed to wait for process {} to stop: {}", pid, e);
    }

    let mut regs = sys::get_regs(pid)?;
    let backup_regs = regs;

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
        // sys::push_stack returns the NEW stack pointer address
        let new_sp = sys::push_stack(pid, sp, data, false)?;

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
        Ok(new_sp)
    };

    let libc_return_addr = utils::resolve_return_addr(&remote_maps, "libc.so")?;
    debug!("Resolved libc return address: 0x{:x}", libc_return_addr);

    let close_addr = resolve("libc.so", "close")?;
    let socket_addr = resolve("libc.so", "socket")?;
    let bind_addr = resolve("libc.so", "bind")?;
    let recvmsg_addr = resolve("libc.so", "recvmsg")?;
    let errno_addr = resolve("libc.so", "__errno").ok();
    let strlen_addr = resolve("libc.so", "strlen").ok();

    let dlopen_addr = resolve("libdl.so", "dlopen")?;
    let dlerror_addr = resolve("libdl.so", "dlerror").ok();

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

    // Prepare FD Passing
    utils::set_sockcreate_con("u:object_r:system_file:s0")?;

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
    // Set SELinux context for the file
    utils::set_file_con(&self_path, "u:object_r:system_file:s0")?;

    let local_lib_file = std::fs::OpenOptions::new()
        .read(true)
        .open(&self_path)
        .context("Failed to open self executable")?;
    use std::os::unix::io::AsRawFd;
    let local_lib_fd = local_lib_file.as_raw_fd();

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

    // Construct sockaddr_un
    // Layout: family (u16) + path (108 bytes)
    // Using explicit bytes to ensure layout matches C struct exactly without imports
    let mut addr_bytes = vec![0u8; std::mem::size_of::<libc::sockaddr_un>()];
    // Set family AF_UNIX
    let family = (libc::AF_UNIX as u16).to_ne_bytes();
    addr_bytes[0] = family[0];
    addr_bytes[1] = family[1];
    // Set abstract path (starts with \0, then magic)
    // sun_path offset is 2
    addr_bytes[2] = 0;
    for (i, b) in magic_bytes.iter().enumerate() {
        if 3 + i < addr_bytes.len() {
            addr_bytes[3 + i] = *b;
        }
    }
    let addr_len = 2 + 1 + magic_bytes.len(); // family + null + magic

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
    let cmsg_buf = vec![0u8; cmsg_space];
    let remote_cmsg_ptr = push_to_remote_stack(&cmsg_buf)?;

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = remote_cmsg_ptr as *mut c_void;
    msg.msg_controllen = cmsg_space;

    let msg_bytes = unsafe {
        std::slice::from_raw_parts(
            &msg as *const _ as *const u8,
            std::mem::size_of::<libc::msghdr>(),
        )
    };
    let remote_msg_ptr = push_to_remote_stack(msg_bytes)?;

    // 6b. Sendmsg (Local) -> Send the FD
    // Construct local address to send TO
    let mut local_dest_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    local_dest_addr.sun_family = libc::AF_UNIX as u16;
    local_dest_addr.sun_path[0] = 0; // Abstract
    for (i, b) in magic_bytes.iter().enumerate() {
        local_dest_addr.sun_path[1 + i] = *b;
    }

    // Construct Control Message
    // Requires explicit CMSG construction
    let mut local_cmsg_buf = vec![0u8; cmsg_space];
    let mut local_iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    }; // Send 0 bytes of real data

    let mut local_hdr: libc::msghdr = unsafe { std::mem::zeroed() };
    local_hdr.msg_name = &mut local_dest_addr as *mut _ as *mut c_void;
    local_hdr.msg_namelen = addr_len as u32;
    local_hdr.msg_iov = &mut local_iov;
    local_hdr.msg_iovlen = 1;
    local_hdr.msg_control = local_cmsg_buf.as_mut_ptr() as *mut c_void;
    local_hdr.msg_controllen = cmsg_space;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&local_hdr);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize;
        *(libc::CMSG_DATA(cmsg) as *mut libc::c_int) = local_lib_fd;
        // Update controllen to actual length used
        local_hdr.msg_controllen = (*cmsg).cmsg_len;
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

    let args = vec![
        remote_fd as usize,
        remote_msg_ptr,
        libc::MSG_WAITALL as usize,
    ];
    let recv_res = sys::remote_call(pid, recvmsg_addr, libc_return_addr, &args)? as isize;

    if recv_res == -1 {
        let err = get_remote_errno()?;
        close_remote(remote_fd)?;
        bail!("Remote recvmsg failed. Errno: {}", err);
    }

    // Retrieve Received FD from Remote Memory
    let mut remote_cmsg_data = vec![0u8; cmsg_space];
    sys::read_stack(pid, remote_cmsg_ptr, &mut remote_cmsg_data)?;

    let cmsg_hdr_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let remote_lib_fd_bytes = &remote_cmsg_data[cmsg_hdr_len..cmsg_hdr_len + 4];
    let remote_lib_fd = i32::from_ne_bytes(remote_lib_fd_bytes.try_into().unwrap());

    debug!("Remote received FD: {}", remote_lib_fd);

    close_remote(remote_fd)?;

    let info_size = 64; // Safe upper bound
    let mut info_bytes = vec![0u8; info_size];

    let flags: u64 = 0x10;
    info_bytes[0..8].copy_from_slice(&flags.to_ne_bytes());

    // library_fd offset
    // 64-bit: 0(u64), 8(ptr), 16(u64), 24(int), 28(int library_fd)
    // 32-bit: 0(u64), 8(ptr), 12(u32), 16(int), 20(int library_fd)
    let fd_offset = if std::mem::size_of::<usize>() == 8 {
        28
    } else {
        20
    };
    info_bytes[fd_offset..fd_offset + 4].copy_from_slice(&remote_lib_fd.to_ne_bytes());

    let remote_info_ptr = push_to_remote_stack(&info_bytes)?;

    // Push library path string
    let lib_path_str = self_path.to_string_lossy();
    let lib_path_c = std::ffi::CString::new(lib_path_str.as_bytes())?;
    let remote_path_ptr = push_to_remote_stack(lib_path_c.as_bytes_with_nul())?;

    // Call dlopen
    // args: filename, flags (RTLD_NOW=2), extinfo
    let args = vec![remote_path_ptr, libc::RTLD_NOW as usize, remote_info_ptr];
    let handle = sys::remote_call(pid, dlopen_addr, libc_return_addr, &args)?;

    debug!("Remote dlopen handle: 0x{:x}", handle);

    if handle == 0 {
        // Read dlerror
        if let (Some(err_fn), Some(str_fn)) = (dlerror_addr, strlen_addr) {
            let err_ptr = sys::remote_call(pid, err_fn, libc_return_addr, &[])?;
            if err_ptr != 0 {
                let len = sys::remote_call(pid, str_fn, libc_return_addr, &[err_ptr])?;
                if len > 0 && len < 1024 {
                    let mut err_buf = vec![0u8; len];
                    sys::read_stack(pid, err_ptr, &mut err_buf)?;
                    error!("dlopen failed: {}", String::from_utf8_lossy(&err_buf));
                }
            }
        }
        // Close the leaked lib_fd in remote
        close_remote(remote_lib_fd)?;
        bail!("Remote dlopen failed");
    }

    close_remote(remote_lib_fd)?;

    // a
    let local_entry_addr = entry as usize;
    let local_base = utils::resolve_base_addr(
        &local_maps,
        &self_path.file_name().unwrap().to_string_lossy(),
    )?;
    let offset = local_entry_addr - local_base;
    debug!(
        "Local Entry: 0x{:x}, Local Base: 0x{:x}, Offset: 0x{:x}",
        local_entry_addr, local_base, offset
    );

    let remote_maps = lsplt_rs::MapInfo::scan(pid.as_raw().to_string().as_str()); // Refresh remote maps
    let remote_base = utils::resolve_base_addr(
        &remote_maps,
        &self_path.file_name().unwrap().to_string_lossy(),
    )?;

    let injector_entry = remote_base + offset;
    debug!("Found 'entry' at: 0x{:x}", injector_entry);

    if injector_entry == 0 {
        bail!("Failed to find 'entry' symbol in injected library");
    }

    let args = vec![handle];
    sys::remote_call(pid, injector_entry, libc_return_addr, &args)?;

    // Cleanup
    debug!("Restore context and detach");
    sys::set_regs(pid, &backup_regs)?;
    nix::sys::ptrace::detach(pid, None)?;

    Ok(())
}

#[no_mangle]
#[allow(unused)]
pub extern "C" fn entry(handle: *const c_void) -> bool {
    true
}
