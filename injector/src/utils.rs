use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::{
    ffi::CString,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use log::{debug, error};
use lsplt_rs::MapInfo;
use nix::{
    dir::{Dir, Type},
    fcntl::OFlag,
    sys::stat::Mode,
};
use sha2::{Digest, Sha256};

const ELF_CLASS_32: u8 = 1;
const ELF_CLASS_64: u8 = 2;
const EM_386: u16 = 3;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

#[derive(Debug, Clone)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub elf: String,
}

pub fn build_id() -> &'static str {
    env!("INJECTOR_BUILD_ID")
}

pub fn build_target() -> &'static str {
    env!("INJECTOR_BUILD_TARGET")
}

pub fn build_git_sha() -> &'static str {
    env!("INJECTOR_BUILD_GIT_SHA")
}

pub fn current_exe_path() -> Result<PathBuf> {
    std::fs::read_link("/proc/self/exe").context("Failed to read link /proc/self/exe")
}

pub fn current_exe_identity() -> Result<ExecutableIdentity> {
    let path = current_exe_path()?;
    executable_identity(&path)
}

pub fn executable_identity(path: &Path) -> Result<ExecutableIdentity> {
    Ok(ExecutableIdentity {
        path: path.to_path_buf(),
        sha256: sha256_file(path)?,
        elf: describe_elf(path)?,
    })
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("Failed to open {} for hashing", path.display()))?;
    let mut sha256 = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to read {} for hashing", path.display()))?;
        if read == 0 {
            break;
        }
        sha256.update(&buffer[..read]);
    }

    Ok(format!("{:x}", sha256.finalize()))
}

pub fn describe_elf(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open ELF {}", path.display()))?;
    let mut header = [0u8; 20];
    file.read_exact(&mut header)
        .with_context(|| format!("Failed to read ELF header from {}", path.display()))?;

    if header[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(anyhow!("{} is not an ELF file", path.display()));
    }

    let class = match header[4] {
        ELF_CLASS_32 => "ELF32",
        ELF_CLASS_64 => "ELF64",
        other => return Err(anyhow!("unsupported ELF class {}", other)),
    };

    let machine = u16::from_le_bytes([header[18], header[19]]);
    let arch = match machine {
        EM_386 => "x86",
        EM_ARM => "arm",
        EM_X86_64 => "x86_64",
        EM_AARCH64 => "aarch64",
        _ => "unknown",
    };

    Ok(format!("{class} {arch} (e_machine={machine})"))
}

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

pub fn create_memfd_from_path(path: &Path, name: &str) -> Result<File> {
    let memfd_name = CString::new(name).context("Invalid memfd name")?;
    let raw_fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create as libc::c_long,
            memfd_name.as_ptr(),
            libc::MFD_CLOEXEC as libc::c_uint,
        )
    } as libc::c_int;
    if raw_fd < 0 {
        return Err(anyhow!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut input = File::open(path)
        .with_context(|| format!("Failed to open payload image {}", path.display()))?;
    let mut memfd = unsafe { File::from_raw_fd(raw_fd) };
    std::io::copy(&mut input, &mut memfd)
        .with_context(|| format!("Failed to copy payload image {}", path.display()))?;
    memfd.flush().context("Failed to flush memfd payload")?;
    memfd
        .seek(SeekFrom::Start(0))
        .context("Failed to rewind memfd payload")?;
    Ok(memfd)
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

        let process_name = match std::fs::read(path.join("cmdline")) {
            Ok(cmdline) => {
                let first = cmdline
                    .split(|byte| *byte == 0)
                    .find(|part| !part.is_empty())
                    .unwrap_or(&[]);
                Path::new(std::ffi::OsStr::from_bytes(first))
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .map(str::to_owned)
            }
            Err(_) => None,
        }
        .or_else(|| {
            std::fs::read_to_string(path.join("comm"))
                .ok()
                .map(|name| name.trim().to_owned())
        });

        if process_name.as_deref() != Some(target_name) {
            continue;
        }

        let pid = pid_str.parse::<i32>().unwrap();
        let target = std::fs::read_link(path.join("exe"))
            .unwrap_or_else(|_| PathBuf::from(format!("/proc/{pid}/exe")));
        debug!("Found target executable: {:?} (PID {})", target, pid);

        return Ok((pid, target));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("Process '{}' not found", target_name),
    ))
    .context("")
}
