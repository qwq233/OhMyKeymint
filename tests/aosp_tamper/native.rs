use std::ffi::{c_int, c_void, CStr, CString};
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Instant;

use crate::aosp_tamper::model::{ProbeRow, SignalLevel};

const PROLOGUE_COMPARE_BYTES: usize = 16;
const BINDER_VERSION_IOCTL: libc::c_int = 0xc0046209u32 as libc::c_int;
const BINDER_DEVICE_PATH: &str = "/dev/binder";
const BINDER_TIMING_WARMUP_COUNT: usize = 8;
const BINDER_TIMING_SAMPLE_COUNT: usize = 64;
const BINDER_TIMING_WARN_RATIO: u128 = 8;
const BINDER_TIMING_WARN_NS: u128 = 250_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCheckResult {
    pub got_mismatch: Option<bool>,
    pub text_mismatch: Option<bool>,
    pub honeypot_anomaly: Option<bool>,
    pub detail: String,
    pub advisory_rows: Vec<ProbeRow>,
}

#[derive(Debug, Clone)]
struct ResolvedSymbol {
    address: usize,
    map_entry: MapEntry,
    library_base: MapEntry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TextInspection {
    mismatch: bool,
    branch_like: bool,
    suspicious_jump: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MapSignals {
    deleted_exec: Vec<String>,
    writable_exec: Vec<String>,
    anonymous_exec: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FdSignals {
    deleted_targets: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SmapsSignals {
    shared_dirty_exec: Vec<String>,
    anonymous_exec_kb: Vec<String>,
    swapped_exec: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LinkerSignals {
    maps_only_modules: Vec<String>,
    hidden_modules: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ResidueSignals {
    maps: Vec<String>,
    fds: Vec<String>,
    linker: Vec<String>,
    smaps: Vec<String>,
}

pub fn inspect(quick: bool) -> NativeCheckResult {
    let maps = read_self_maps();
    let resolved_ioctl = maps
        .as_ref()
        .ok()
        .and_then(|entries| resolve_ioctl_symbol(entries));
    let got_mismatch = resolved_ioctl.as_ref().map(|symbol| {
        !path_matches(
            symbol.map_entry.path.as_deref().unwrap_or_default(),
            symbol.library_base.path.as_deref().unwrap_or_default(),
        )
    });
    let text_inspection = resolved_ioctl
        .as_ref()
        .and_then(|symbol| inspect_ioctl_text_mismatch(symbol).ok());
    let text_mismatch = text_inspection.map(|inspection| inspection.mismatch);
    let honeypot_anomaly = None;

    let target_detail = match resolved_ioctl.as_ref() {
        Some(symbol) => format!(
            "{}@0x{:x}",
            symbol.map_entry.path.as_deref().unwrap_or("[anonymous]"),
            symbol.address
        ),
        None => "unavailable".to_string(),
    };
    let prologue_detail = match text_inspection {
        Some(inspection) => format!(
            "mismatch={}, branch={}, trampoline={}",
            inspection.mismatch, inspection.branch_like, inspection.suspicious_jump
        ),
        None => "unavailable".to_string(),
    };

    let advisory_rows = vec![
        binder_version_parity_row(),
        binder_timing_honeypot_row(quick),
        runtime_maps_row(maps.as_ref().ok()),
        runtime_fd_row(),
        runtime_linker_row(maps.as_ref().ok()),
        runtime_smaps_row(quick),
        runtime_residue_row(maps.as_ref().ok(), quick),
    ];

    NativeCheckResult {
        got_mismatch,
        text_mismatch,
        honeypot_anomaly,
        detail: format!(
            "got={}, text={}, honeypot={}, target={}, prologue={}",
            optional_flag(got_mismatch),
            optional_flag(text_mismatch),
            optional_flag(honeypot_anomaly),
            target_detail,
            prologue_detail
        ),
        advisory_rows,
    }
}

fn binder_version_parity_row() -> ProbeRow {
    let file = match File::open(BINDER_DEVICE_PATH) {
        Ok(file) => file,
        Err(error) => {
            return advisory_row(
                "Native binder parity",
                format!("unavailable: failed to open {BINDER_DEVICE_PATH}: {error}"),
                SignalLevel::Unavailable,
            );
        }
    };

    let fd = file.as_raw_fd();
    let libc_result = ioctl_binder_version_via_libc(fd);
    let syscall_result = ioctl_binder_version_via_syscall(fd);
    let raw_svc_result = ioctl_binder_version_via_raw_svc(fd);
    let suspicious = binder_results_disagree([&libc_result, &syscall_result, &raw_svc_result]);

    advisory_row(
        "Native binder parity",
        format!(
            "libc={}, syscall={}, rawSvc={}",
            describe_binder_result(&libc_result),
            describe_binder_result(&syscall_result),
            describe_binder_result(&raw_svc_result)
        ),
        match (&libc_result, &syscall_result, &raw_svc_result) {
            (Err(_), Err(_), Err(_)) => SignalLevel::Unavailable,
            _ if suspicious => SignalLevel::Warn,
            _ => SignalLevel::Info,
        },
    )
}

fn ioctl_binder_version_via_libc(fd: c_int) -> Result<i32, String> {
    let mut version = BinderVersion {
        protocol_version: 0,
    };
    let rc = unsafe { libc::ioctl(fd, BINDER_VERSION_IOCTL, &mut version) };
    if rc != 0 {
        return Err(last_errno_string("libc::ioctl"));
    }
    Ok(version.protocol_version)
}

fn ioctl_binder_version_via_syscall(fd: c_int) -> Result<i32, String> {
    let mut version = BinderVersion {
        protocol_version: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ioctl as libc::c_long,
            fd,
            BINDER_VERSION_IOCTL,
            &mut version as *mut _,
        ) as c_int
    };
    if rc != 0 {
        return Err(last_errno_string("syscall(ioctl)"));
    }
    Ok(version.protocol_version)
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "android", target_os = "linux")
))]
fn ioctl_binder_version_via_raw_svc(fd: c_int) -> Result<i32, String> {
    let mut version = BinderVersion {
        protocol_version: 0,
    };
    let mut x0 = fd as usize;
    let request = BINDER_VERSION_IOCTL as usize;
    let version_ptr = &mut version as *mut BinderVersion as usize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            inlateout("x0") x0,
            in("x1") request,
            in("x2") version_ptr,
            in("x8") libc::SYS_ioctl as usize,
            options(nostack)
        );
    }
    let rc = x0 as isize;
    if rc < 0 {
        return Err(format!("raw_svc(ioctl): errno={}", -rc));
    }
    if rc != 0 {
        return Err(format!("raw_svc(ioctl): rc={rc}"));
    }
    Ok(version.protocol_version)
}

#[cfg(not(all(
    target_arch = "aarch64",
    any(target_os = "android", target_os = "linux")
)))]
fn ioctl_binder_version_via_raw_svc(_fd: c_int) -> Result<i32, String> {
    Err("raw_svc(ioctl): unavailable on this target".to_string())
}

fn binder_results_disagree(results: [&Result<i32, String>; 3]) -> bool {
    let oks = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .copied()
        .collect::<Vec<_>>();
    if oks.len() >= 2 && oks.windows(2).any(|pair| pair[0] != pair[1]) {
        return true;
    }

    let hard_errors = results
        .iter()
        .filter(|result| {
            result
                .as_ref()
                .err()
                .map(|error| !error.contains("unavailable on this target"))
                .unwrap_or(false)
        })
        .count();
    !oks.is_empty() && hard_errors > 0
}

fn describe_binder_result(result: &Result<i32, String>) -> String {
    match result {
        Ok(version) => format!("ok({version})"),
        Err(error) => format!("err({error})"),
    }
}

fn binder_timing_honeypot_row(quick: bool) -> ProbeRow {
    if quick {
        return advisory_row(
            "Native binder timing",
            "skipped by --quick".to_string(),
            SignalLevel::Unavailable,
        );
    }

    let file = match File::open(BINDER_DEVICE_PATH) {
        Ok(file) => file,
        Err(error) => {
            return advisory_row(
                "Native binder timing",
                format!("unavailable: failed to open {BINDER_DEVICE_PATH}: {error}"),
                SignalLevel::Unavailable,
            );
        }
    };

    let fd = file.as_raw_fd();
    for _ in 0..BINDER_TIMING_WARMUP_COUNT {
        let _ = ioctl_binder_version_via_libc(fd);
        let _ = ioctl_binder_version_via_syscall(fd);
    }

    let mut gaps = Vec::with_capacity(BINDER_TIMING_SAMPLE_COUNT);
    let mut noise = Vec::with_capacity(BINDER_TIMING_SAMPLE_COUNT);
    for _ in 0..BINDER_TIMING_SAMPLE_COUNT {
        let noise_start = Instant::now();
        let noise_mid = Instant::now();
        noise.push(noise_mid.duration_since(noise_start).as_nanos());

        let left_start = Instant::now();
        let left = ioctl_binder_version_via_libc(fd);
        let left_ns = left_start.elapsed().as_nanos();

        let right_start = Instant::now();
        let right = ioctl_binder_version_via_syscall(fd);
        let right_ns = right_start.elapsed().as_nanos();

        if left.is_ok() && right.is_ok() {
            gaps.push(left_ns.abs_diff(right_ns));
        }
    }

    if gaps.len() < BINDER_TIMING_SAMPLE_COUNT / 2 {
        return advisory_row(
            "Native binder timing",
            format!("unavailable: only {} paired samples succeeded", gaps.len()),
            SignalLevel::Unavailable,
        );
    }

    let median_gap = median_u128(&mut gaps);
    let gap_mad = mad_u128(&gaps, median_gap);
    let noise_floor = median_u128(&mut noise);
    let suspicious =
        median_gap > BINDER_TIMING_WARN_NS && median_gap > noise_floor * BINDER_TIMING_WARN_RATIO;
    advisory_row(
        "Native binder timing",
        format!(
            "samples={}, medianGapNs={}, gapMadNs={}, medianNoiseNs={}",
            gaps.len(),
            median_gap,
            gap_mad,
            noise_floor
        ),
        if suspicious {
            SignalLevel::Warn
        } else {
            SignalLevel::Info
        },
    )
}

fn runtime_maps_row(maps: Option<&Vec<MapEntry>>) -> ProbeRow {
    let Some(maps) = maps else {
        return advisory_row(
            "Native maps",
            "unavailable: /proc/self/maps was not readable".to_string(),
            SignalLevel::Unavailable,
        );
    };

    let signals = inspect_maps_anomalies(maps);
    let suspicious_count =
        signals.deleted_exec.len() + signals.writable_exec.len() + signals.anonymous_exec.len();
    advisory_row(
        "Native maps",
        format!(
            "deletedExec={}, writableExec={}, anonymousExec={}",
            summarize_list(&signals.deleted_exec),
            summarize_list(&signals.writable_exec),
            summarize_list(&signals.anonymous_exec)
        ),
        if suspicious_count > 0 {
            SignalLevel::Warn
        } else {
            SignalLevel::Info
        },
    )
}

fn runtime_fd_row() -> ProbeRow {
    let targets = match read_self_fd_targets() {
        Ok(targets) => targets,
        Err(error) => {
            return advisory_row(
                "Native fd",
                format!("unavailable: {error}"),
                SignalLevel::Unavailable,
            );
        }
    };
    let signals = inspect_fd_targets(&targets);
    advisory_row(
        "Native fd",
        format!("deletedExec={}", summarize_list(&signals.deleted_targets)),
        if signals.deleted_targets.is_empty() {
            SignalLevel::Info
        } else {
            SignalLevel::Warn
        },
    )
}

fn runtime_linker_row(maps: Option<&Vec<MapEntry>>) -> ProbeRow {
    let Some(maps) = maps else {
        return advisory_row(
            "Native linker",
            "unavailable: /proc/self/maps was not readable".to_string(),
            SignalLevel::Unavailable,
        );
    };

    let linker_objects = match collect_linker_objects() {
        Ok(objects) => objects,
        Err(error) => {
            return advisory_row(
                "Native linker",
                format!("unavailable: {error}"),
                SignalLevel::Unavailable,
            );
        }
    };

    let signals = inspect_linker_visibility(maps, &linker_objects);
    advisory_row(
        "Native linker",
        format!(
            "mapsOnly={}, hiddenModules={}",
            summarize_list(&signals.maps_only_modules),
            summarize_list(&signals.hidden_modules)
        ),
        if signals.maps_only_modules.is_empty() && signals.hidden_modules.is_empty() {
            SignalLevel::Info
        } else {
            SignalLevel::Warn
        },
    )
}

fn runtime_smaps_row(quick: bool) -> ProbeRow {
    if quick {
        return advisory_row(
            "Native smaps",
            "skipped by --quick".to_string(),
            SignalLevel::Unavailable,
        );
    }

    let smaps = match read_self_smaps() {
        Ok(smaps) => smaps,
        Err(error) => {
            return advisory_row(
                "Native smaps",
                format!("unavailable: {error}"),
                SignalLevel::Unavailable,
            );
        }
    };

    let signals = inspect_smaps_anomalies(&smaps);
    advisory_row(
        "Native smaps",
        format!(
            "sharedDirtyExec={}, anonymousExecKb={}, swappedExec={}",
            summarize_list(&signals.shared_dirty_exec),
            summarize_list(&signals.anonymous_exec_kb),
            summarize_list(&signals.swapped_exec)
        ),
        if signals.shared_dirty_exec.is_empty()
            && signals.anonymous_exec_kb.is_empty()
            && signals.swapped_exec.is_empty()
        {
            SignalLevel::Info
        } else {
            SignalLevel::Warn
        },
    )
}

fn runtime_residue_row(maps: Option<&Vec<MapEntry>>, quick: bool) -> ProbeRow {
    let Some(maps) = maps else {
        return advisory_row(
            "Native targeted residue",
            "unavailable: /proc/self/maps was not readable".to_string(),
            SignalLevel::Unavailable,
        );
    };

    let fd_targets = read_self_fd_targets().unwrap_or_default();
    let linker_objects = collect_linker_objects().unwrap_or_default();
    let smaps = if quick { None } else { read_self_smaps().ok() };
    let signals = inspect_targeted_residue(
        maps,
        &fd_targets,
        &linker_objects,
        smaps.as_deref().unwrap_or(&[]),
    );
    let count = signals.maps.len() + signals.fds.len() + signals.linker.len() + signals.smaps.len();
    advisory_row(
        "Native targeted residue",
        format!(
            "maps={}, fds={}, linker={}, smaps={}",
            summarize_list(&signals.maps),
            summarize_list(&signals.fds),
            summarize_list(&signals.linker),
            if quick {
                "skipped by --quick".to_string()
            } else {
                summarize_list(&signals.smaps)
            }
        ),
        if count > 0 {
            SignalLevel::Warn
        } else {
            SignalLevel::Info
        },
    )
}

fn inspect_ioctl_text_mismatch(symbol: &ResolvedSymbol) -> Result<TextInspection, String> {
    let relative = symbol
        .address
        .checked_sub(symbol.library_base.start)
        .ok_or_else(|| "ioctl address did not belong to the resolved libc mapping".to_string())?;
    let library_path = symbol
        .library_base
        .path
        .as_ref()
        .ok_or_else(|| "resolved libc mapping did not expose a filesystem path".to_string())?;
    let disk = fs::read(strip_deleted_suffix(library_path))
        .map_err(|error| format!("failed to read {}: {error}", library_path))?;
    let end = relative
        .checked_add(PROLOGUE_COMPARE_BYTES)
        .ok_or_else(|| "ioctl relative offset overflowed".to_string())?;
    if end > disk.len() {
        return Err("ioctl relative offset exceeded the libc image".to_string());
    }

    let disk_bytes = &disk[relative..end];
    let runtime_bytes =
        unsafe { std::slice::from_raw_parts(symbol.address as *const u8, PROLOGUE_COMPARE_BYTES) };
    let branch_like = looks_like_branch_instruction(runtime_bytes);
    let suspicious_jump = looks_like_trampoline(runtime_bytes);
    Ok(TextInspection {
        mismatch: runtime_bytes != disk_bytes,
        branch_like,
        suspicious_jump,
    })
}

fn resolve_ioctl_symbol(maps: &[MapEntry]) -> Option<ResolvedSymbol> {
    let address = resolve_symbol_address(["ioctl", "__ioctl"])?;
    let map_entry = find_entry_for_address(maps, address)?;
    let library_base = find_loaded_library(maps, "libc.so")?;
    Some(ResolvedSymbol {
        address,
        map_entry,
        library_base,
    })
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

fn read_self_maps() -> Result<Vec<MapEntry>, String> {
    let contents = fs::read_to_string("/proc/self/maps")
        .map_err(|error| format!("failed to read /proc/self/maps: {error}"))?;
    Ok(contents.lines().filter_map(parse_maps_line).collect())
}

fn read_self_smaps() -> Result<Vec<SmapsEntry>, String> {
    let contents = fs::read_to_string("/proc/self/smaps")
        .map_err(|error| format!("failed to read /proc/self/smaps: {error}"))?;
    let mut entries = Vec::new();
    let mut current: Option<SmapsEntry> = None;

    for line in contents.lines() {
        if let Some(header) = parse_maps_line(line) {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(SmapsEntry {
                map: header,
                ..Default::default()
            });
            continue;
        }

        let Some(entry) = current.as_mut() else {
            continue;
        };
        if let Some(value) = parse_kb_field(line, "Anonymous:") {
            entry.anonymous_kb = value;
        } else if let Some(value) = parse_kb_field(line, "Swap:") {
            entry.swap_kb = value;
        } else if let Some(value) = parse_kb_field(line, "Shared_Dirty:") {
            entry.shared_dirty_kb = value;
        }
    }

    if let Some(entry) = current {
        entries.push(entry);
    }
    Ok(entries)
}

fn read_self_fd_targets() -> Result<Vec<String>, String> {
    let entries = fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("failed to enumerate /proc/self/fd: {error}"))?;
    let mut targets = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("fd enumeration failed: {error}"))?;
        let link = fs::read_link(entry.path()).map_err(|error| {
            format!(
                "failed to read fd target {}: {error}",
                entry.path().display()
            )
        })?;
        targets.push(link.display().to_string());
    }
    Ok(targets)
}

fn collect_linker_objects() -> Result<Vec<String>, String> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let mut objects = Vec::new();
        let rc = unsafe {
            libc::dl_iterate_phdr(
                Some(collect_linker_object_callback),
                &mut objects as *mut Vec<String> as *mut c_void,
            )
        };
        if rc < 0 {
            return Err("dl_iterate_phdr returned a negative status".to_string());
        }
        Ok(objects)
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        Err("dl_iterate_phdr is not available on this target".to_string())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
unsafe extern "C" fn collect_linker_object_callback(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    data: *mut c_void,
) -> c_int {
    let objects = &mut *(data as *mut Vec<String>);
    let Some(info) = info.as_ref() else {
        return 0;
    };
    if info.dlpi_name.is_null() {
        return 0;
    }
    let Ok(name) = CStr::from_ptr(info.dlpi_name).to_str() else {
        return 0;
    };
    if !name.is_empty() {
        objects.push(name.to_string());
    }
    0
}

fn inspect_maps_anomalies(maps: &[MapEntry]) -> MapSignals {
    let mut signals = MapSignals::default();
    for entry in maps {
        if !entry.executable || is_probably_jit_path(entry.path.as_deref().unwrap_or_default()) {
            continue;
        }
        let path = entry.path.as_deref().unwrap_or("[anonymous]");
        if path.ends_with(" (deleted)")
            && !is_benign_loader_artifact_path(path)
            && should_report_targeted_residue(path)
        {
            push_unique(&mut signals.deleted_exec, path.to_string());
        }
        if entry.writable && should_report_targeted_residue(path) {
            push_unique(
                &mut signals.writable_exec,
                format!("0x{:x}-0x{:x} {path}", entry.start, entry.end),
            );
        }
        if is_anonymous_path(path) && should_report_targeted_residue(path) {
            push_unique(
                &mut signals.anonymous_exec,
                format!("0x{:x}-0x{:x} {path}", entry.start, entry.end),
            );
        }
    }
    signals
}

fn inspect_fd_targets(targets: &[String]) -> FdSignals {
    let mut signals = FdSignals::default();
    for target in targets {
        let lowered = to_lower_ascii(target);
        if lowered.contains("(deleted)")
            && !is_benign_loader_artifact_path(&lowered)
            && should_report_targeted_residue(&lowered)
            && (lowered.contains(".so")
                || lowered.starts_with("/memfd:")
                || lowered.starts_with("memfd:"))
        {
            push_unique(&mut signals.deleted_targets, target.clone());
        }
    }
    signals
}

fn inspect_smaps_anomalies(entries: &[SmapsEntry]) -> SmapsSignals {
    let mut signals = SmapsSignals::default();
    for entry in entries {
        let path = entry.map.path.as_deref().unwrap_or_default();
        if !entry.map.executable || is_probably_jit_path(path) {
            continue;
        }
        if entry.swap_kb > 0 && should_report_targeted_residue(path) {
            push_unique(
                &mut signals.swapped_exec,
                format!("{path}:{}kB", entry.swap_kb),
            );
        }
        if entry.shared_dirty_kb > 0 && should_report_targeted_residue(path) {
            push_unique(
                &mut signals.shared_dirty_exec,
                format!("{path}:{}kB", entry.shared_dirty_kb),
            );
        }
        if entry.anonymous_kb > 0 && should_report_targeted_residue(path) {
            push_unique(
                &mut signals.anonymous_exec_kb,
                format!("{path}:{}kB", entry.anonymous_kb),
            );
        }
    }
    signals
}

fn inspect_linker_visibility(maps: &[MapEntry], linker_objects: &[String]) -> LinkerSignals {
    let map_candidates = maps
        .iter()
        .filter_map(|entry| {
            let path = entry.path.as_ref()?;
            let lowered = to_lower_ascii(path);
            (entry.executable
                && !is_benign_loader_artifact_path(&lowered)
                && lowered.contains(".so")
                && should_report_targeted_residue(&lowered))
            .then_some(path.clone())
        })
        .collect::<Vec<_>>();

    let mut signals = LinkerSignals::default();
    for candidate in &map_candidates {
        if !linker_objects
            .iter()
            .any(|name| path_matches(name, candidate))
        {
            push_unique(&mut signals.maps_only_modules, candidate.clone());
        }
    }

    for object in linker_objects {
        let lowered = to_lower_ascii(object);
        if lowered.is_empty()
            || is_benign_loader_artifact_path(&lowered)
            || !lowered.contains(".so")
            || !should_report_targeted_residue(&lowered)
        {
            continue;
        }
        if !map_candidates
            .iter()
            .any(|candidate| path_matches(candidate, object))
        {
            push_unique(&mut signals.hidden_modules, object.clone());
        }
    }

    signals
}

fn inspect_targeted_residue(
    maps: &[MapEntry],
    fd_targets: &[String],
    linker_objects: &[String],
    smaps: &[SmapsEntry],
) -> ResidueSignals {
    let mut signals = ResidueSignals::default();
    for entry in maps {
        let path = entry.path.as_deref().unwrap_or_default();
        if should_report_targeted_residue(path)
            && (entry.executable || entry.writable || path.contains("(deleted)"))
        {
            push_unique(&mut signals.maps, describe_map_entry(entry));
        }
    }

    for target in fd_targets {
        if should_report_targeted_residue(target) {
            push_unique(&mut signals.fds, target.clone());
        }
    }

    for object in linker_objects {
        if should_report_targeted_residue(object) {
            push_unique(&mut signals.linker, object.clone());
        }
    }

    for entry in smaps {
        let path = entry.map.path.as_deref().unwrap_or_default();
        if should_report_targeted_residue(path)
            && entry.map.executable
            && (entry.shared_dirty_kb > 0 || entry.anonymous_kb > 0 || entry.swap_kb > 0)
        {
            push_unique(
                &mut signals.smaps,
                format!(
                    "{}:dirty={}kB anon={}kB swap={}kB",
                    path, entry.shared_dirty_kb, entry.anonymous_kb, entry.swap_kb
                ),
            );
        }
    }

    signals
}

fn parse_kb_field(line: &str, prefix: &str) -> Option<usize> {
    let value = line.strip_prefix(prefix)?.trim();
    let value = value.strip_suffix("kB").unwrap_or(value).trim();
    value.parse().ok()
}

fn optional_flag(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "fail",
        Some(false) => "pass",
        None => "unavailable",
    }
}

fn advisory_row(
    label: impl Into<String>,
    value: impl Into<String>,
    level: SignalLevel,
) -> ProbeRow {
    ProbeRow::new(label, value, level, None)
}

fn summarize_list(values: &[String]) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    let preview = values
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    if values.len() > 2 {
        format!("{preview} (+{} more)", values.len() - 2)
    } else {
        preview
    }
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn describe_map_entry(entry: &MapEntry) -> String {
    format!(
        "0x{:x}-0x{:x} {}{}{}{}",
        entry.start,
        entry.end,
        if entry.readable { "r" } else { "-" },
        if entry.writable { "w" } else { "-" },
        if entry.executable { "x" } else { "-" },
        entry
            .path
            .as_deref()
            .map(|path| format!(" {path}"))
            .unwrap_or_default()
    )
}

fn find_loaded_library(maps: &[MapEntry], needle: &str) -> Option<MapEntry> {
    maps.iter()
        .find(|entry| {
            entry.offset == 0
                && entry
                    .path
                    .as_ref()
                    .map(|path| path.ends_with(needle))
                    .unwrap_or(false)
        })
        .cloned()
}

fn find_entry_for_address(maps: &[MapEntry], address: usize) -> Option<MapEntry> {
    maps.iter()
        .find(|entry| address >= entry.start && address < entry.end)
        .cloned()
}

fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let perms = parts.next()?;
    let offset = usize::from_str_radix(parts.next()?, 16).ok()?;
    let _dev = parts.next()?;
    let inode = parts.next()?.parse::<u64>().ok()?;
    let path = {
        let remainder = parts.collect::<Vec<_>>();
        (!remainder.is_empty()).then(|| remainder.join(" "))
    };
    let (start, end) = range.split_once('-')?;
    Some(MapEntry {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        readable: perms.as_bytes().first().copied() == Some(b'r'),
        writable: perms.as_bytes().get(1).copied() == Some(b'w'),
        executable: perms.as_bytes().get(2).copied() == Some(b'x'),
        private_mapping: perms.as_bytes().get(3).copied() == Some(b'p'),
        offset,
        inode,
        path,
    })
}

fn strip_deleted_suffix(path: &str) -> PathBuf {
    let normalized = path.strip_suffix(" (deleted)").unwrap_or(path);
    PathBuf::from(normalized)
}

fn path_matches(lhs: &str, rhs: &str) -> bool {
    normalize_library_name(lhs) == normalize_library_name(rhs)
        || basename_of(lhs) == basename_of(rhs)
}

fn normalize_library_name(value: &str) -> String {
    value.trim_end_matches(" (deleted)").to_string()
}

fn basename_of(path: &str) -> String {
    normalize_library_name(path)
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .to_string()
}

fn is_system_path(path: &str) -> bool {
    let lowered = to_lower_ascii(path);
    lowered.starts_with("/system/")
        || lowered.starts_with("/system_ext/")
        || lowered.starts_with("/vendor/")
        || lowered.starts_with("/product/")
        || lowered.starts_with("/odm/")
        || lowered.starts_with("/apex/")
}

fn is_anonymous_path(path: &str) -> bool {
    path.is_empty()
        || path == "[anon]"
        || path.starts_with("[anon:")
        || path.starts_with("/dev/zero")
}

fn is_probably_jit_path(path: &str) -> bool {
    let lowered = to_lower_ascii(path);
    if lowered.is_empty() {
        return false;
    }
    [
        "jit-cache",
        "jit-zygote-cache",
        "dalvik-jit-code-cache",
        "dalvik-data-code-cache",
        "dalvik-zygote-jit-code-cache",
        "dalvik-zygote-data-code-cache",
        "zygote-jit-code-cache",
        "zygote-data-code-cache",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn is_benign_loader_artifact_path(path: &str) -> bool {
    let lowered = to_lower_ascii(path);
    if is_probably_jit_path(&lowered) {
        return true;
    }
    if lowered.starts_with("/dev/ashmem") {
        return true;
    }
    if lowered.contains("fontmap") || lowered.contains("gfxstats") {
        return true;
    }
    if lowered.starts_with("/memfd:") || lowered.starts_with("memfd:") {
        return [
            "jit-cache",
            "jit-zygote-cache",
            "gralloc",
            "hwui",
            "fresco",
            "fontmap",
            "gfxstats",
            "skia",
        ]
        .iter()
        .any(|needle| lowered.contains(needle));
    }
    false
}

fn should_report_targeted_residue(path: &str) -> bool {
    let lowered = to_lower_ascii(path);
    if lowered.is_empty() || is_benign_loader_artifact_path(&lowered) {
        return false;
    }
    if !contains_project_residue_needle(&lowered) {
        return false;
    }
    if is_normal_platform_security_path(&lowered) {
        return false;
    }
    true
}

fn contains_project_residue_needle(lowered: &str) -> bool {
    [
        "android.hardware.security.keymint",
        "android.system.keystore2",
        "ikeystoresecuritylevel",
        "ikeystoreservice",
        "keystore2",
        "keymint",
        "keyattest",
        "attestation",
        "binder_intercept",
        "binder-hook",
        "binder_hook",
        "trickystore",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn is_normal_platform_security_path(lowered: &str) -> bool {
    is_system_path(lowered)
        && !lowered.contains("(deleted)")
        && !lowered.contains("hook")
        && !lowered.contains("intercept")
        && !lowered.contains("trickystore")
        && !lowered.starts_with("/memfd:")
        && !lowered.starts_with("memfd:")
}

fn to_lower_ascii(value: &str) -> String {
    value.chars().map(|ch| ch.to_ascii_lowercase()).collect()
}

fn median_u128(values: &mut [u128]) -> u128 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}

fn mad_u128(values: &[u128], median: u128) -> u128 {
    let mut deviations = values
        .iter()
        .map(|value| value.abs_diff(median))
        .collect::<Vec<_>>();
    median_u128(&mut deviations)
}

fn last_errno_string(prefix: &str) -> String {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(errno) => format!("{prefix}: errno={errno}"),
        None => format!("{prefix}: errno=unknown"),
    }
}

fn looks_like_branch_instruction(bytes: &[u8]) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() < 4 {
            return false;
        }
        let instruction = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        (instruction >> 26) == 0x05
            || (instruction >> 26) == 0x25
            || (instruction & 0xFFFF_FC1F) == 0xD61F_0000
            || (instruction & 0xFFFF_FC1F) == 0xD63F_0000
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

fn looks_like_trampoline(bytes: &[u8]) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        if bytes.len() < 8 {
            return false;
        }
        let first = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        let second = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let ldr_literal = (first & 0xFF00_0000) == 0x5800_0000;
        let branch_register = (second & 0xFFFF_FC00) == 0xD61F_0000;
        (ldr_literal && branch_register) || (first >> 26) == 0x05 || (first >> 26) == 0x25
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    start: usize,
    end: usize,
    readable: bool,
    writable: bool,
    executable: bool,
    private_mapping: bool,
    offset: usize,
    inode: u64,
    path: Option<String>,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinderVersion {
    protocol_version: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SmapsEntry {
    map: MapEntry,
    anonymous_kb: usize,
    swap_kb: usize,
    shared_dirty_kb: usize,
}

impl Default for MapEntry {
    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            readable: false,
            writable: false,
            executable: false,
            private_mapping: false,
            offset: 0,
            inode: 0,
            path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_line_keeps_deleted_suffix_and_permissions() {
        let entry = parse_maps_line(
            "7f6d1000-7f6d2000 r-xp 00000000 00:00 0 /apex/com.android.runtime/lib64/libc.so (deleted)",
        )
        .unwrap();
        assert_eq!(
            entry.path.as_deref(),
            Some("/apex/com.android.runtime/lib64/libc.so (deleted)")
        );
        assert!(entry.readable);
        assert!(!entry.writable);
        assert!(entry.executable);
    }

    #[test]
    fn benign_loader_artifacts_do_not_flag_jit_cache() {
        assert!(is_probably_jit_path("/memfd:jit-cache"));
        assert!(is_benign_loader_artifact_path("/memfd:jit-cache"));
    }

    #[test]
    fn maps_and_fd_detectors_flag_deleted_exec_and_writable_exec_paths() {
        let maps = vec![
            MapEntry {
                start: 0x1000,
                end: 0x2000,
                readable: true,
                writable: false,
                executable: true,
                private_mapping: true,
                offset: 0,
                inode: 1,
                path: Some("/data/app/~~demo/lib/arm64/libkeymint_hook.so (deleted)".to_string()),
            },
            MapEntry {
                start: 0x2000,
                end: 0x3000,
                readable: true,
                writable: true,
                executable: true,
                private_mapping: true,
                offset: 0,
                inode: 1,
                path: Some("/data/app/~~demo/lib/arm64/libkeystore2_intercept.so".to_string()),
            },
            MapEntry {
                start: 0x3000,
                end: 0x4000,
                readable: true,
                writable: true,
                executable: true,
                private_mapping: true,
                offset: 0,
                inode: 1,
                path: Some("/data/app/~~demo/lib/arm64/libordinary.so (deleted)".to_string()),
            },
        ];
        let map_signals = inspect_maps_anomalies(&maps);
        assert_eq!(map_signals.deleted_exec.len(), 1);
        assert_eq!(map_signals.writable_exec.len(), 1);

        let fd_signals = inspect_fd_targets(&[
            "/data/app/libkeymint_hook.so (deleted)".to_string(),
            "/data/app/libordinary.so (deleted)".to_string(),
        ]);
        assert_eq!(fd_signals.deleted_targets.len(), 1);
    }

    #[test]
    fn linker_visibility_reports_maps_only_and_hidden_candidates() {
        let maps = vec![MapEntry {
            start: 0x1000,
            end: 0x2000,
            readable: true,
            writable: false,
            executable: true,
            private_mapping: true,
            offset: 0,
            inode: 1,
            path: Some("/data/app/~~demo/lib/arm64/libkeymint_hook.so".to_string()),
        }];
        let linker = inspect_linker_visibility(
            &maps,
            &["/data/app/~~demo/lib/arm64/libkeystore2_intercept.so".to_string()],
        );
        assert_eq!(linker.maps_only_modules.len(), 1);
        assert_eq!(linker.hidden_modules.len(), 1);
    }

    #[test]
    fn smaps_detector_tracks_system_exec_drift() {
        let signals = inspect_smaps_anomalies(&[SmapsEntry {
            map: MapEntry {
                start: 0x1000,
                end: 0x2000,
                readable: true,
                writable: false,
                executable: true,
                private_mapping: true,
                offset: 0,
                inode: 1,
                path: Some("/data/app/~~demo/lib/arm64/libkeymint_hook.so".to_string()),
            },
            anonymous_kb: 4,
            swap_kb: 1,
            shared_dirty_kb: 2,
        }]);
        assert_eq!(signals.shared_dirty_exec.len(), 1);
        assert_eq!(signals.anonymous_exec_kb.len(), 1);
        assert_eq!(signals.swapped_exec.len(), 1);
    }

    #[test]
    fn targeted_residue_suppresses_normal_platform_security_libraries() {
        assert!(!should_report_targeted_residue(
            "/apex/com.android.hardware.keymint/lib64/libkeymint.so"
        ));
        assert!(!should_report_targeted_residue(
            "/system/lib64/libbinder.so"
        ));
        assert!(!should_report_targeted_residue(
            "/data/app/~~demo/lib/arm64/libordinary.so (deleted)"
        ));
        assert!(should_report_targeted_residue(
            "/data/app/~~demo/lib/arm64/libkeymint_hook.so (deleted)"
        ));
    }

    #[test]
    fn binder_timing_quick_mode_is_schema_stable_skip() {
        let row = binder_timing_honeypot_row(true);
        assert_eq!(row.label, "Native binder timing");
        assert_eq!(row.level, SignalLevel::Unavailable);
        assert!(row.value.contains("skipped"));
    }

    #[test]
    fn binder_parity_advisory_preserves_contract_shape() {
        let row = advisory_row(
            "Native binder parity",
            "libc=ok(8), syscall=ok(8)",
            SignalLevel::Info,
        );
        assert_eq!(row.label, "Native binder parity");
        assert_eq!(row.scored_category, None);
    }

    #[test]
    fn branch_and_trampoline_helpers_recognize_arm64_patterns() {
        #[cfg(target_arch = "aarch64")]
        {
            let branch = 0x1400_0000u32.to_le_bytes();
            assert!(looks_like_branch_instruction(&branch));
            let trampoline = [0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x1f, 0xd6, 0, 0, 0, 0];
            assert!(looks_like_trampoline(&trampoline));
        }
    }
}
