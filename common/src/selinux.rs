use anyhow::{Context, Result};
use std::ffi::CString;

pub fn set_sockcreate_con(context: &str) -> Result<()> {
    let context = CString::new(context).context("Invalid context string")?;
    write_sockcreate_con(context.as_bytes_with_nul())
}

pub fn clear_sockcreate_con() -> Result<()> {
    write_sockcreate_con(&[0])
}

fn write_sockcreate_con(bytes: &[u8]) -> Result<()> {
    if std::fs::write("/proc/thread-self/attr/sockcreate", bytes).is_err() {
        let tid = unsafe { libc::gettid() };
        std::fs::write(format!("/proc/{tid}/attr/sockcreate"), bytes)
            .context("Failed to write sockcreate context via /proc/[tid]/attr/sockcreate")?;
    }
    Ok(())
}
