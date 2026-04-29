use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCheckResult {
    pub got_mismatch: Option<bool>,
    pub text_mismatch: Option<bool>,
    pub honeypot_anomaly: Option<bool>,
    pub detail: String,
}

pub fn inspect(quick: bool) -> NativeCheckResult {
    let got_mismatch = None;
    let text_mismatch = inspect_ioctl_text_mismatch().ok();
    let honeypot_anomaly = if quick { None } else { None };

    NativeCheckResult {
        got_mismatch,
        text_mismatch,
        honeypot_anomaly,
        detail: format!(
            "got={}, text={}, honeypot={}",
            optional_flag(got_mismatch),
            optional_flag(text_mismatch),
            optional_flag(honeypot_anomaly)
        ),
    }
}

fn inspect_ioctl_text_mismatch() -> Result<bool, String> {
    let symbol = resolve_symbol_address(["ioctl", "__ioctl"])
        .ok_or_else(|| "unable to resolve ioctl/__ioctl from the current process".to_string())?;
    let runtime_entry = find_loaded_library("libc.so")
        .ok_or_else(|| "unable to resolve libc.so from /proc/self/maps".to_string())?;
    let relative = symbol
        .checked_sub(runtime_entry.base_addr)
        .ok_or_else(|| "ioctl address did not belong to the resolved libc mapping".to_string())?;
    let disk = fs::read(&runtime_entry.path)
        .map_err(|error| format!("failed to read {}: {error}", runtime_entry.path.display()))?;
    let end = relative
        .checked_add(PROLOGUE_COMPARE_BYTES)
        .ok_or_else(|| "ioctl relative offset overflowed".to_string())?;
    if end > disk.len() {
        return Err("ioctl relative offset exceeded the libc image".to_string());
    }

    let disk_bytes = &disk[relative..end];
    let runtime_bytes =
        unsafe { std::slice::from_raw_parts(symbol as *const u8, PROLOGUE_COMPARE_BYTES) };
    Ok(runtime_bytes != disk_bytes)
}

fn resolve_symbol_address<const N: usize>(names: [&str; N]) -> Option<usize> {
    for name in names {
        let c_name = CString::new(name).ok()?;
        let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c_name.as_ptr()) };
        if !address.is_null() {
            return Some(address as usize);
        }
    }
    None
}

fn optional_flag(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "fail",
        Some(false) => "pass",
        None => "unavailable",
    }
}

#[derive(Debug, Clone)]
struct LoadedLibrary {
    base_addr: usize,
    path: PathBuf,
}

fn find_loaded_library(needle: &str) -> Option<LoadedLibrary> {
    let contents = fs::read_to_string("/proc/self/maps").ok()?;
    contents
        .lines()
        .filter_map(parse_maps_line)
        .find(|entry| {
            entry.offset == 0
                && entry
                    .path
                    .as_ref()
                    .map(|path| path.ends_with(needle))
                    .unwrap_or(false)
        })
        .map(|entry| LoadedLibrary {
            base_addr: entry.start,
            path: PathBuf::from(entry.path.unwrap()),
        })
}

#[derive(Debug, Clone)]
struct MapEntry {
    start: usize,
    offset: usize,
    path: Option<String>,
}

fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let _perms = parts.next()?;
    let offset = usize::from_str_radix(parts.next()?, 16).ok()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let path = parts.next().map(|path| path.to_string());

    let (start, _end) = range.split_once('-')?;
    Some(MapEntry {
        start: usize::from_str_radix(start, 16).ok()?,
        offset,
        path,
    })
}

const PROLOGUE_COMPARE_BYTES: usize = 16;
