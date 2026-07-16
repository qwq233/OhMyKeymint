use std::ffi::c_void;

use anyhow::{anyhow, bail, Context, Result};
use libc::iovec;
use log::{debug, error, trace, warn};
use nix::sys::signal::Signal;
use nix::{
    sys::wait::{WaitPidFlag, WaitStatus},
    unistd::Pid,
};

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86_64",
    target_arch = "x86"
))]
pub type Regs = libc::user_regs_struct;

pub const NT_PRSTATUS: std::ffi::c_int = 1;

pub fn align_stack(regs: &mut Regs) {
    #[cfg(target_arch = "x86_64")]
    {
        regs.rsp &= !0xf;
    }
    #[cfg(target_arch = "x86")]
    {
        regs.esp &= !0xf;
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.sp &= !0xf;
    }
    #[cfg(target_arch = "arm")]
    {
        regs.uregs[13] &= !0xf;
    }
}

pub fn wait_pid(pid: Pid, target: Signal) -> Result<()> {
    loop {
        match nix::sys::wait::waitpid(pid, Some(WaitPidFlag::__WALL))? {
            WaitStatus::Stopped(_, sig) => {
                if sig == target {
                    return Ok(());
                }
                // Got an unexpected signal — re-deliver it via PTRACE_CONT and keep waiting
                warn!(
                    "Process {} stopped with unexpected signal {}, re-delivering",
                    pid,
                    sig.as_str()
                );
                let deliver_sig = if sig == Signal::SIGTRAP || sig == Signal::SIGSTOP {
                    0
                } else {
                    sig as i32
                };
                unsafe {
                    libc::ptrace(libc::PTRACE_CONT, pid.as_raw(), 0, deliver_sig);
                }
                continue;
            }
            WaitStatus::Signaled(_, sig, _) => {
                bail!("Process {} terminated with signal {}", pid, sig.as_str());
            }
            WaitStatus::Exited(_, code) => {
                bail!("Process {} exited with code {}", pid, code);
            }
            _ => continue,
        }
    }
}

pub fn get_regs(pid: Pid) -> Result<Regs> {
    let mut regs: Regs = unsafe { std::mem::zeroed() };

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                pid.as_raw(),
                0,
                &mut regs as *mut _ as *mut c_void,
            )
        };

        if result == -1 {
            bail!(
                "ptrace(PTRACE_GETREGS) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        let mut iov = libc::iovec {
            iov_base: &mut regs as *mut _ as *mut c_void,
            iov_len: std::mem::size_of::<Regs>(),
        };

        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid.as_raw(),
                NT_PRSTATUS as *mut c_void,
                &mut iov as *mut _ as *mut c_void,
            )
        };

        if result == -1 {
            bail!(
                "ptrace(PTRACE_GETREGS) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(regs)
}

pub fn set_regs(pid: Pid, regs: &Regs) -> Result<()> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGS,
                pid.as_raw(),
                0,
                regs as *const _ as *mut c_void,
            )
        };

        if result == -1 {
            bail!(
                "ptrace(PTRACE_SETREGS) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    {
        let mut iov = libc::iovec {
            iov_base: regs as *const _ as *mut c_void,
            iov_len: std::mem::size_of::<Regs>(),
        };

        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                pid.as_raw(),
                NT_PRSTATUS as *mut c_void,
                &mut iov as *mut _ as *mut c_void,
            )
        };

        if result == -1 {
            bail!(
                "ptrace(PTRACE_SETREGS) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}

pub fn read_stack(pid: Pid, remote_addr: usize, buf: &mut [u8]) -> Result<usize> {
    let local = iovec {
        iov_base: buf.as_mut_ptr() as *mut c_void,
        iov_len: buf.len(),
    };

    let remote = iovec {
        iov_base: remote_addr as *mut c_void,
        iov_len: buf.len(),
    };

    let result = unsafe {
        libc::process_vm_readv(
            pid.as_raw(),
            &local as *const iovec,
            1,
            &remote as *const iovec,
            1,
            0,
        )
    };

    if result == -1 {
        bail!(
            "process_vm_readv failed: {}",
            std::io::Error::last_os_error()
        );
    } else if result != buf.len() as isize {
        bail!(
            "process_vm_readv read incomplete data: {}/{} bytes",
            result,
            buf.len()
        )
    } else {
        Ok(result as usize)
    }
}

pub fn push_stack(pid: Pid, remote_addr: usize, data: &[u8]) -> Result<usize> {
    let new_addr = remote_addr
        .checked_sub(data.len())
        .ok_or_else(|| anyhow!("Stack overflow when pushing data"))?;

    let local = iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    let remote = iovec {
        iov_base: new_addr as *mut c_void,
        iov_len: data.len(),
    };

    let result = unsafe {
        libc::process_vm_writev(
            pid.as_raw(),
            &local as *const iovec,
            1,
            &remote as *const iovec,
            1,
            0,
        )
    };

    if result == -1 {
        let error = std::io::Error::last_os_error();
        error!("process_vm_writev failed: {}", error);
        bail!("process_vm_writev failed: {}", error);
    }
    if result != data.len() as isize {
        bail!(
            "process_vm_writev wrote incomplete data: {}/{} bytes",
            result,
            data.len()
        );
    }
    Ok(new_addr)
}

pub fn setup_remote_call(
    pid: Pid,
    regs: &mut Regs,
    func_addr: usize,
    return_addr: usize,
    args: &[usize],
) -> Result<()> {
    align_stack(regs);
    trace!(
        "Setting up remote call: func_addr=0x{:x}, return_addr=0x{:x}, regs=0{:?}, args={:?}",
        func_addr,
        return_addr,
        regs,
        args
    );

    #[cfg(target_arch = "x86_64")]
    {
        let mut sp = regs.rsp as usize;

        // set up arguments in registers
        if args.len() > 0 {
            regs.rdi = args[0] as u64;
        }
        if args.len() > 1 {
            regs.rsi = args[1] as u64;
        }
        if args.len() > 2 {
            regs.rdx = args[2] as u64;
        }
        if args.len() > 3 {
            regs.rcx = args[3] as u64;
        }
        if args.len() > 4 {
            regs.r8 = args[4] as u64;
        }
        if args.len() > 5 {
            regs.r9 = args[5] as u64;
        }

        if args.len() > 6 {
            let padding = if (args.len() - 6) % 2 == 1 {
                std::mem::size_of::<usize>()
            } else {
                0
            };
            sp = sp
                .checked_sub(padding)
                .ok_or_else(|| anyhow!("Stack overflow when reserving x86_64 call padding"))?;
            for i in (6..args.len()).rev() {
                let arg_bytes = args[i].to_ne_bytes();
                sp = push_stack(pid, sp, &arg_bytes)?;
            }
        }

        let ret_bytes = return_addr.to_ne_bytes();
        sp = push_stack(pid, sp, &ret_bytes)?;
        regs.rsp = sp as u64;
        regs.rip = func_addr as u64;
    }

    #[cfg(target_arch = "x86")]
    {
        let mut sp = regs.esp as usize;

        for i in (0..args.len()).rev() {
            let arg_bytes = (args[i] as u32).to_ne_bytes();
            sp = push_stack(pid, sp, &arg_bytes)?;
        }

        let ret_bytes = (return_addr as u32).to_ne_bytes();
        sp = push_stack(pid, sp, &ret_bytes)?;

        regs.esp = sp as u32;
        regs.eip = func_addr as u32;
    }

    #[cfg(target_arch = "aarch64")]
    {
        const ARG_REG_COUNT: usize = 8;
        let mut sp = regs.sp as usize;

        // set up arguments in registers
        for (i, arg) in args.iter().enumerate().take(ARG_REG_COUNT) {
            regs.regs[i] = *arg as u64;
        }
        // jump to stack for additional arguments
        if args.len() > ARG_REG_COUNT {
            // ensure 16-byte alignment
            let size = (args.len() - ARG_REG_COUNT) * std::mem::size_of::<usize>();
            let target_sp = sp.wrapping_sub(size) & !0xf;
            sp = target_sp + size;

            for i in (ARG_REG_COUNT..args.len()).rev() {
                sp = push_stack(pid, sp, &args[i].to_ne_bytes())?;
            }
        }
        // set link register to dummy return address
        regs.regs[30] = return_addr as u64;
        // set program counter to function address
        regs.pc = func_addr as u64;
        // ensure proper instruction set state
        regs.sp = sp as u64;
    }

    #[cfg(target_arch = "arm")]
    {
        const REG_ARGS_COUNT: usize = 4;
        let mut sp = regs.uregs[13] as usize; // SP

        if args.len() > REG_ARGS_COUNT {
            let stack_args_len = (args.len() - REG_ARGS_COUNT) * 4;
            let target_sp = (sp - stack_args_len) & !0x7;
            sp = target_sp + stack_args_len;

            for i in (REG_ARGS_COUNT..args.len()).rev() {
                let arg_bytes = (args[i] as u32).to_ne_bytes();
                sp = push_stack(pid, sp, &arg_bytes)?;
            }
        }

        for i in 0..std::cmp::min(args.len(), REG_ARGS_COUNT) {
            regs.uregs[i] = args[i] as u32;
        }

        regs.uregs[14] = return_addr as u32; // LR
        regs.uregs[13] = sp as u32; // SP

        if (func_addr & 1) != 0 {
            regs.uregs[15] = (func_addr & !1) as u32; // PC
            regs.uregs[16] |= 0x20; // Set CPSR T bit (bit 5)
        } else {
            regs.uregs[15] = func_addr as u32; // PC
            regs.uregs[16] &= !0x20; // Clear T bit
        }
    }

    set_regs(pid, regs)?;
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid.as_raw(), 0, 0) } != 0 {
        bail!(
            "ptrace(PTRACE_CONT) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    Ok(())
}

fn wait_remote_call(pid: Pid, return_addr: usize) -> Result<usize> {
    wait_pid(pid, Signal::SIGSEGV)?;
    let regs = get_regs(pid)?;

    #[cfg(target_arch = "x86_64")]
    {
        if regs.rip != (return_addr as u64) {
            error!(
                "unexpected RIP after remote call: expected 0x{:x}, got 0x{:x}",
                return_addr, regs.rip
            );
            match nix::sys::ptrace::getsiginfo(pid) {
                Ok(info) => error!("remote call stopped with signal info {:?}", info),
                Err(e) => error!("failed to get remote call signal info: {}", e),
            }
            bail!("Remote call did not reach expected function address");
        }

        Ok(regs.rax as usize)
    }
    #[cfg(target_arch = "x86")]
    {
        if regs.eip != (return_addr as u32) {
            error!(
                "unexpected EIP after remote call: expected 0x{:x}, got 0x{:x}",
                return_addr, regs.eip
            );
            match nix::sys::ptrace::getsiginfo(pid) {
                Ok(info) => error!("remote call stopped with signal info {:?}", info),
                Err(e) => error!("failed to get remote call signal info: {}", e),
            }
            bail!("Remote call did not reach expected function address");
        }

        Ok(regs.eax as usize)
    }

    #[cfg(target_arch = "aarch64")]
    {
        if regs.pc != (return_addr as u64) {
            error!(
                "unexpected PC after remote call: expected 0x{:x}, got 0x{:x}",
                return_addr, regs.pc
            );
            match nix::sys::ptrace::getsiginfo(pid) {
                Ok(info) => error!("remote call stopped with signal info {:?}", info),
                Err(e) => error!("failed to get remote call signal info: {}", e),
            }
            bail!("Remote call did not reach expected function address");
        }

        Ok(regs.regs[0] as usize)
    }
    #[cfg(target_arch = "arm")]
    {
        if regs.uregs[15] != (return_addr as u32) {
            error!(
                "unexpected PC after remote call: expected 0x{:x}, got 0x{:x}",
                return_addr, regs.uregs[15]
            );
            match nix::sys::ptrace::getsiginfo(pid) {
                Ok(info) => error!("remote call stopped with signal info {:?}", info),
                Err(e) => error!("failed to get remote call signal info: {}", e),
            }
            bail!("Remote call did not reach expected function address");
        }

        Ok(regs.uregs[0] as usize)
    }
}

#[derive(Debug)]
pub struct RemoteCallSession {
    original_regs: Regs,
    return_addr: usize,
}

pub struct RemoteCallPostStatus {
    pub result: Result<usize>,
    pub restored: bool,
}

pub fn remote_pre_call(
    pid: Pid,
    func_addr: usize,
    return_addr: usize,
    args: &[usize],
) -> Result<RemoteCallSession> {
    debug!(
        "Preparing remote call to 0x{:x} with return address 0x{:x} and args {:?}",
        func_addr, return_addr, args
    );
    let original_regs = get_regs(pid).context("Failed to backup registers.")?;
    let mut regs = original_regs;
    if let Err(error) = setup_remote_call(pid, &mut regs, func_addr, return_addr, args) {
        if let Err(restore_error) = set_regs(pid, &original_regs)
            .context("Failed to restore registers after remote call setup failure")
        {
            return Err(error.context(format!(
                "remote call setup failed and register restore also failed: {restore_error:#}"
            )));
        }
        return Err(error);
    }

    Ok(RemoteCallSession {
        original_regs,
        return_addr,
    })
}

pub fn remote_post_call(pid: Pid, session: RemoteCallSession) -> Result<usize> {
    remote_post_call_with_status(pid, session).result
}

pub fn remote_post_call_with_status(pid: Pid, session: RemoteCallSession) -> RemoteCallPostStatus {
    let wait_result = wait_remote_call(pid, session.return_addr);
    let restore_result =
        set_regs(pid, &session.original_regs).context("Failed to restore registers.");
    let restored = restore_result.is_ok();

    let result = match (wait_result, restore_result) {
        (Ok(ret), Ok(())) => Ok(ret),
        (Err(wait_error), Ok(())) => Err(wait_error),
        (Ok(_), Err(restore_error)) => Err(restore_error),
        (Err(wait_error), Err(restore_error)) => Err(wait_error).with_context(|| {
            format!("Failed to restore registers after remote call failure: {restore_error:#}")
        }),
    };

    RemoteCallPostStatus { result, restored }
}

pub fn remote_cancel_call(pid: Pid, session: RemoteCallSession) -> Result<()> {
    nix::sys::signal::kill(pid, Signal::SIGSTOP)
        .context("Failed to stop remote process for remote call cancellation")?;
    wait_pid(pid, Signal::SIGSTOP)
        .context("Failed to wait for remote process to stop during remote call cancellation")?;
    set_regs(pid, &session.original_regs)
        .context("Failed to restore registers after remote call cancellation")
}

pub fn remote_call(
    pid: Pid,
    func_addr: usize,
    return_addr: usize,
    args: &[usize],
) -> Result<usize> {
    let session = remote_pre_call(pid, func_addr, return_addr, args)?;
    remote_post_call(pid, session)
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_stack_padding_preserves_abi_entry_alignment() {
        const START_SP_MOD_16: usize = 0;
        for stack_arg_count in 0..8 {
            let padding = if stack_arg_count % 2 == 1 {
                std::mem::size_of::<usize>()
            } else {
                0
            };
            let pushed_bytes = (stack_arg_count + 1) * std::mem::size_of::<usize>();
            let final_mod = (START_SP_MOD_16 + 16 - (padding + pushed_bytes) % 16) % 16;
            assert_eq!(
                final_mod, 8,
                "stack_arg_count={stack_arg_count} padding={padding}"
            );
        }
    }
}
