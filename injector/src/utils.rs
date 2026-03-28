use std::os::unix::ffi::OsStrExt;
use std::{ffi::CString, path::PathBuf};

use std::ffi::{c_void, CStr};

use anyhow::{anyhow, Context, Result};
use log::{debug, error};
use lsplt_rs::MapInfo;
use nix::{
    dir::{Dir, Type},
    fcntl::OFlag,
    sys::stat::Mode,
};

// SELinux stuff
pub fn set_sockcreate_con(context: &str) -> Result<()> {
    let context = CString::new(context).context("Invalid context string")?;
    let context = context.as_bytes_with_nul();
    if let Err(e) = std::fs::write("/proc/thread-self/attr/sockcreate", context) {
        error!("Failed to set sockcreate context: {}", e);

        let tid = unsafe { libc::gettid() as usize };
        std::fs::write(format!("/proc/{}/attr/sockcreate", tid), context)
            .context("Failed to set sockcreate context via /proc/[tid]/attr/sockcreate")?;
    }

    Ok(())
}

pub fn set_file_con(path: &PathBuf, context: &str) -> Result<()> {
    const XATTR_NAME_SELINUX: &CStr = c"security.selinux";

    let path =
        CString::new(path.as_os_str().as_bytes()).context("Invalid file path for setxattr")?;
    let context = CString::new(context).context("Invalid context string")?;
    let size = context.as_bytes_with_nul().len();

    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            XATTR_NAME_SELINUX.as_ptr(),
            context.as_ptr() as *const c_void,
            size,
            0,
        )
    };

    if result != 0 {
        Err(anyhow!(
            "Failed to set file context: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

// Hook stuff
pub fn resolve_base_addr(info: &[MapInfo], lib_name: &str) -> Result<usize> {
    for map in info {
        if let Some(path) = &map.pathname {
            if map.offset == 0 && path.as_str().ends_with(lib_name) {
                debug!(
                    "Found library '{}' at base address: 0x{:x}",
                    lib_name, map.start
                );
                return Ok(map.start);
            }
        }
    }
    Err(anyhow!("Library '{}' not found in process maps", lib_name))
}

pub fn resolve_return_addr(info: &[MapInfo], lib_name: &str) -> Result<usize> {
    for map in info {
        if let Some(path) = &map.pathname {
            if (map.perms & libc::PROT_EXEC as u8) == 0 && path.as_str().ends_with(lib_name) {
                // Use map.start directly (not + offset). This is a non-executable
                // region that will cause SIGSEGV when the remote function "returns"
                // here, allowing us to catch the return value.
                debug!(
                    "Found return addr in library '{}' at address: 0x{:x}",
                    lib_name, map.start
                );
                return Ok(map.start);
            }
        }
    }
    Err(anyhow!("Not found in library '{}'", lib_name))
}

pub fn resolve_func_addr(
    local: &[MapInfo],
    remote: &[MapInfo],
    lib_name: &str,
    name: &str,
) -> Result<usize> {
    let lib = unsafe {
        let lib = CString::new(lib_name).map_err(|_| anyhow!("Invalid library name"))?;
        libc::dlopen(lib.as_ptr(), libc::RTLD_NOW)
    };
    if lib.is_null() {
        return Err(anyhow!(
            "Failed to open library '{}': {}",
            lib_name,
            std::io::Error::last_os_error()
        ));
    }

    let symbol = unsafe {
        let name = CString::new(name).map_err(|_| anyhow!("Invalid function name"))?;
        libc::dlsym(lib, name.as_ptr())
    };
    if symbol.is_null() {
        return Err(anyhow!(
            "Failed to find symbol '{}' in library '{}': {}",
            name,
            lib_name,
            std::io::Error::last_os_error()
        ));
    }

    unsafe {
        libc::dlclose(lib);
    }

    let local_addr = resolve_base_addr(local, lib_name)
        .context(format!("failed to find local base for module {}", lib_name))?;
    let remote_addr = resolve_base_addr(remote, lib_name).context(format!(
        "failed to find remote base for module {}",
        lib_name
    ))?;

    let offset = (symbol as usize)
        .checked_sub(local_addr)
        .ok_or_else(|| anyhow!("Invalid symbol address"))?;
    let remote_func_addr = remote_addr
        .checked_add(offset)
        .ok_or_else(|| anyhow!("Address overflow"))?;

    debug!(
        "Resolved function '{}' address: 0x{:x}",
        name, remote_func_addr
    );
    Ok(remote_func_addr)
}

pub fn find_process_by_name(target_name: &str) -> Result<(i32, PathBuf)> {
    let mut proc_dir = Dir::open("/proc", OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty())?;

    for entry_result in proc_dir.iter() {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        if entry.file_type() != Some(Type::Directory) {
            continue;
        }

        let file_name = entry.file_name();

        let pid_str = file_name.to_str().unwrap();
        if !pid_str.chars().all(char::is_numeric) {
            continue;
        }

        let path = PathBuf::from("/proc").join(pid_str);

        let comm_path = path.join("exe");
        let target = match std::fs::read_link(comm_path) {
            Ok(name) => name,
            Err(_) => continue,
        };
        let file_name = match target.file_name().and_then(std::ffi::OsStr::to_str) {
            Some(name) => name,
            None => continue,
        };
        if file_name.trim() != target_name {
            continue;
        }

        let pid = pid_str.parse::<i32>().unwrap();
        debug!("Found target executable: {:?} (PID {})", target, pid);

        return Ok((pid, target));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Process '{}' not found", target_name),
    ))
    .context("")
}
