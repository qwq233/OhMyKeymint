use kmr_common::consts::{KEYSTORE_GID, KEYSTORE_UID};
use kmr_common::runtime::{
    file_watch::{self, WatchTrigger},
    fs::atomic_replace_preserving_metadata,
    retry::{retry_read_race, ReadRaceErrorKind, RetryOutcome},
};
use log::LevelFilter;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/keystore/omk/injector.toml";
const CURRENT_CONFIG_VERSION: u32 = 1;
const REPLACE_SAVE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const REPLACE_SAVE_RETRY_LIMIT: usize = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InjectorConfig {
    pub version: u32,
    pub scoop: Vec<String>,
    pub scoop_details: BTreeMap<String, toml::Table>,
    pub main: MainConfig,
    pub filter: FilterConfig,
    pub intercept: InterceptConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct MainConfig {
    pub enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    pub enabled: bool,
    pub deny_packages: Vec<String>,
    pub block_android_package: bool,
    pub allow_unknown_package: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct InterceptConfig {
    pub get_security_level: bool,
    pub get_key_entry: bool,
    pub update_subcomponent: bool,
    pub list_entries: bool,
    pub delete_key: bool,
    pub grant: bool,
    pub ungrant: bool,
    pub get_number_of_entries: bool,
    pub list_entries_batched: bool,
    pub get_supplementary_attestation_info: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            scoop: default_scoop(),
            scoop_details: BTreeMap::new(),
            main: MainConfig::default(),
            filter: FilterConfig::default(),
            intercept: InterceptConfig::default(),
        }
    }
}

fn default_scoop() -> Vec<String> {
    [
        "io.github.vvb2060.keyattestation",
        "com.google.android.gsf",
        "com.google.android.gms",
        "com.android.vending",
        "com.eltavine.duckdetector",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Default for MainConfig {
    fn default() -> Self {
        Self { enabled: true, log_level: "debug".to_string() }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_packages: Vec::new(),
            block_android_package: true,
            allow_unknown_package: false,
        }
    }
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            get_security_level: true,
            get_key_entry: true,
            update_subcomponent: true,
            list_entries: true,
            delete_key: true,
            grant: true,
            ungrant: true,
            get_number_of_entries: true,
            list_entries_batched: true,
            get_supplementary_attestation_info: true,
        }
    }
}

#[derive(Debug)]
enum LoadError {
    Missing(io::Error),
    Io(io::Error),
    Parse(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(error) | Self::Io(error) => write!(f, "{error}"),
            Self::Parse(error) => write!(f, "{error}"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LoadContext {
    Startup,
    Reload(WatchTrigger),
}

#[derive(Deserialize)]
struct ScoopHeaderValue {
    package: String,
}

#[derive(Deserialize)]
struct ConfigVersion {
    version: Option<toml::Spanned<i64>>,
}

static CONFIG: OnceLock<RwLock<Arc<InjectorConfig>>> = OnceLock::new();
static WATCHER_STARTED: OnceLock<()> = OnceLock::new();
static CONFIG_FILE_WRITE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
thread_local! {
    static TEST_CONFIG: std::cell::RefCell<Option<Arc<InjectorConfig>>> = std::cell::RefCell::default();
}

#[cfg(test)]
pub(crate) fn with_test_config<T>(config: InjectorConfig, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<InjectorConfig>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_CONFIG.replace(self.0.take());
        }
    }
    let _restore = Restore(TEST_CONFIG.replace(Some(Arc::new(config))));
    run()
}

impl LoadContext {
    fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Reload(trigger) => trigger.label(),
        }
    }
}

pub fn get() -> Arc<InjectorConfig> {
    #[cfg(test)]
    if let Some(config) = TEST_CONFIG.with_borrow(Clone::clone) {
        return config;
    }
    if CONFIG.get().is_none() || WATCHER_STARTED.get().is_none() {
        ensure_initialized();
    }
    Arc::clone(
        &CONFIG
            .get()
            .expect("injector config should be initialized")
            .read()
            .expect("injector config lock poisoned"),
    )
}

fn ensure_initialized() {
    let path = config_path();
    CONFIG.get_or_init(|| {
        RwLock::new(Arc::new(
            load_or_seed(&path, LoadContext::Startup)
                .expect("startup config loading always returns a fallback"),
        ))
    });
    WATCHER_STARTED.get_or_init(|| start_watcher(path));
}

fn config_path() -> PathBuf {
    std::env::var_os("OMK_INJECTOR_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn load_from_path(path: &Path, allow_migration: bool) -> Result<InjectorConfig, LoadError> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| LoadError::Io(io::Error::other("config file write lock poisoned")))?;
    let contents = fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            LoadError::Missing(error)
        } else {
            LoadError::Io(error)
        }
    })?;
    let (config, migrated_contents) =
        parse_versioned_config(&contents, allow_migration).map_err(LoadError::Parse)?;
    if let Some(migrated_contents) = migrated_contents {
        let (default_uid, default_gid) = default_owner(path);
        atomic_replace_preserving_metadata(
            path,
            migrated_contents.as_bytes(),
            0o600,
            default_uid,
            default_gid,
        )
        .map_err(LoadError::Io)?;
        log::info!("migrated injector.toml to version {CURRENT_CONFIG_VERSION}");
    }
    Ok(config)
}

fn load_with_context(
    path: &Path,
    context: LoadContext,
) -> Result<RetryOutcome<InjectorConfig>, LoadError> {
    match context {
        LoadContext::Reload(trigger) if trigger.should_retry_reads() => load_with_read_race_retry(
            path,
            context,
            |path| load_from_path(path, false),
            std::thread::sleep,
        ),
        LoadContext::Startup => {
            load_from_path(path, true).map(|value| RetryOutcome { value, retries: 0 })
        }
        LoadContext::Reload(_) => {
            load_from_path(path, false).map(|value| RetryOutcome { value, retries: 0 })
        }
    }
}

fn load_or_seed(path: &Path, context: LoadContext) -> Option<InjectorConfig> {
    match load_with_context(path, context) {
        Ok(loaded) => {
            if loaded.retries > 0 {
                log::info!(
                    "{} config load from {} succeeded after {} retr{}",
                    context.label(),
                    path.display(),
                    loaded.retries,
                    if loaded.retries == 1 { "y" } else { "ies" }
                );
            }
            if matches!(context, LoadContext::Startup) {
                log::info!("loaded config from {} via {}", path.display(), context.label());
            }
            Some(loaded.value)
        }
        Err(LoadError::Missing(error)) if matches!(context, LoadContext::Startup) => {
            log::warn!(
                "config missing at {} during startup: {}; seeding defaults",
                path.display(),
                error
            );
            let mut config = InjectorConfig::default();
            if let Err(write_error) = write_default_config(path) {
                log::error!(
                    "failed to seed config at {}: {}; disabling injector",
                    path.display(),
                    write_error
                );
                config.main.enabled = false;
            }
            Some(config)
        }
        Err(error) => {
            log::warn!(
                "load from {} via {} failed: {}; {}",
                path.display(),
                context.label(),
                error,
                if matches!(context, LoadContext::Startup) {
                    "using disabled defaults"
                } else {
                    "keeping current config"
                }
            );
            if matches!(context, LoadContext::Startup) {
                let mut config = InjectorConfig::default();
                config.main.enabled = false;
                Some(config)
            } else {
                None
            }
        }
    }
}

fn write_default_config(path: &Path) -> io::Result<()> {
    let _write_guard = CONFIG_FILE_WRITE_LOCK
        .lock()
        .map_err(|_| io::Error::other("config file write lock poisoned"))?;
    let contents = include_str!("../../template/injector.toml");
    let (default_uid, default_gid) = default_owner(path);
    atomic_replace_preserving_metadata(path, contents.as_bytes(), 0o600, default_uid, default_gid)?;
    log::info!("wrote config to {}", path.display());
    Ok(())
}

fn default_owner(path: &Path) -> (u32, u32) {
    if path == Path::new(DEFAULT_CONFIG_PATH) {
        (KEYSTORE_UID, KEYSTORE_GID)
    } else {
        (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }
}

fn parse_versioned_config(
    contents: &str,
    allow_migration: bool,
) -> Result<(InjectorConfig, Option<String>), String> {
    let without_bom = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let bom_len = contents.len() - without_bom.len();
    let preprocessed = preprocess_config(without_bom)?;
    let version: ConfigVersion =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    if version.version.as_ref().is_none_or(|version| *version.get_ref() == 0) && !allow_migration {
        return Err("injector config version 0 requires an injector restart to migrate".into());
    }
    let migrated = match version.version {
        None => Some(insert_config_version(contents, bom_len)),
        Some(version) => match *version.get_ref() {
            0 => {
                let span = version.span();
                let mut migrated = contents.to_string();
                migrated.replace_range(span.start + bom_len..span.end + bom_len, "1");
                Some(migrated)
            }
            version if version == i64::from(CURRENT_CONFIG_VERSION) => None,
            version if version < 0 => {
                return Err(format!("config version must not be negative: {version}"))
            }
            version => {
                return Err(format!(
                "config version {version} is newer than supported version {CURRENT_CONFIG_VERSION}"
            ))
            }
        },
    };
    let candidate = migrated.as_deref().unwrap_or(contents);
    let candidate = candidate.strip_prefix('\u{feff}').unwrap_or(candidate);
    let preprocessed = preprocess_config(candidate)?;
    let parsed: InjectorConfig =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    Ok((parsed.normalized(), migrated))
}

fn insert_config_version(contents: &str, bom_len: usize) -> String {
    let newline = if contents.contains("\r\n") { "\r\n" } else { "\n" };
    format!("{}version = 1{newline}{}", &contents[..bom_len], &contents[bom_len..])
}

fn preprocess_config(contents: &str) -> Result<String, String> {
    let mut rewritten = String::with_capacity(contents.len());
    for (line_no, line) in contents.split_inclusive('\n').enumerate() {
        rewritten.push_str(&rewrite_scoop_header(line, line_no + 1)?);
    }
    Ok(rewritten)
}

fn rewrite_scoop_header(line: &str, line_no: usize) -> Result<String, String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("[[") || !trimmed.starts_with("[scoop.") {
        return Ok(line.to_string());
    }

    let leading = &line[..line.len() - trimmed.len()];
    let Some(close_idx) = trimmed.find(']') else {
        return Err(format!("line {line_no}: unterminated [scoop.<package>] header"));
    };
    let header = &trimmed[..=close_idx];
    let trailer = &trimmed[close_idx + 1..];
    let header_body = &header[1..header.len() - 1];
    let package_fragment = header_body
        .strip_prefix("scoop.")
        .ok_or_else(|| format!("line {line_no}: invalid scoop header"))?;
    let package = decode_scoop_package_header(package_fragment.trim(), line_no)?;

    Ok(format!("{leading}[scoop_details.{package:?}]{trailer}"))
}

fn decode_scoop_package_header(fragment: &str, line_no: usize) -> Result<String, String> {
    if fragment.is_empty() {
        return Err(format!("line {line_no}: empty scoop package name"));
    }

    if (fragment.starts_with('"') && fragment.ends_with('"'))
        || (fragment.starts_with('\'') && fragment.ends_with('\''))
    {
        let wrapped = format!("package = {fragment}");
        let decoded: ScoopHeaderValue =
            toml::from_str(&wrapped).map_err(|error| format!("line {line_no}: {error}"))?;
        let package = decoded.package.trim();
        if package.is_empty() {
            return Err(format!("line {line_no}: empty scoop package name"));
        }
        return Ok(package.to_string());
    }

    Ok(fragment.to_string())
}

fn normalize_packages(packages: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();
    for package in packages {
        let package = package.trim();
        if !package.is_empty() && seen.insert(package.to_string()) {
            normalized.push(package.to_string());
        }
    }
    normalized
}

fn normalize_scoop_details(
    details: BTreeMap<String, toml::Table>,
) -> BTreeMap<String, toml::Table> {
    let mut normalized = BTreeMap::new();
    for (package, table) in details {
        let package = package.trim();
        if !package.is_empty() {
            normalized.insert(package.to_string(), table);
        }
    }
    normalized
}

fn start_watcher(path: PathBuf) {
    let reload_path = path.clone();
    if let Err(error) =
        file_watch::spawn_path_watcher("injector-config-watch", path, move |trigger| {
            reload_runtime_config(&reload_path, trigger);
        })
    {
        log::error!("failed to start config watcher thread: {}", error);
    }
}

fn reload_runtime_config(path: &Path, trigger: WatchTrigger) {
    let Some(config) = load_or_seed(path, LoadContext::Reload(trigger)) else {
        return;
    };
    if let Some(lock) = CONFIG.get() {
        let level = config.main.log_level_filter();
        let next = Arc::new(config);
        match lock.write() {
            Ok(mut guard) => {
                let previous = std::mem::replace(&mut *guard, next);
                log::set_max_level(level);
                drop(guard);
                drop(previous);
                log::info!("reloaded config from {} via {}", path.display(), trigger.label());
            }
            Err(error) => {
                log::error!("failed to apply config reload from {}: {}", path.display(), error);
            }
        }
    }
}

fn load_with_read_race_retry<F, S>(
    path: &Path,
    context: LoadContext,
    mut loader: F,
    sleeper: S,
) -> Result<RetryOutcome<InjectorConfig>, LoadError>
where
    F: FnMut(&Path) -> Result<InjectorConfig, LoadError>,
    S: FnMut(Duration),
{
    retry_read_race(
        || loader(path),
        |error| match error {
            LoadError::Missing(_) | LoadError::Io(_) => ReadRaceErrorKind::Retryable,
            LoadError::Parse(_) => ReadRaceErrorKind::Fatal,
        },
        REPLACE_SAVE_RETRY_LIMIT,
        REPLACE_SAVE_RETRY_INTERVAL,
        sleeper,
        |retries, error, interval| {
            log::warn!(
                "{} config load from {} hit read-side race on retry {}/{}: {}; waiting {} ms",
                context.label(),
                path.display(),
                retries,
                REPLACE_SAVE_RETRY_LIMIT,
                error,
                interval.as_millis()
            );
        },
    )
}

pub fn parse_level_filter(value: &str) -> Option<LevelFilter> {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "warn" | "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        _ => None,
    }
}

impl MainConfig {
    pub fn log_level_filter(&self) -> LevelFilter {
        parse_level_filter(&self.log_level).unwrap_or(LevelFilter::Debug)
    }
}

impl InjectorConfig {
    fn normalized(mut self) -> Self {
        self.scoop = normalize_packages(self.scoop);
        self.scoop_details = normalize_scoop_details(self.scoop_details);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Deref;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempConfigPath(PathBuf);

    impl Deref for TempConfigPath {
        type Target = Path;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for TempConfigPath {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            if let (Some(parent), Some(file_name)) = (self.0.parent(), self.0.file_name()) {
                let temp = parent.join(format!(
                    ".{}.tmp-{}",
                    file_name.to_string_lossy(),
                    std::process::id()
                ));
                let _ = fs::remove_file(temp);
            }
        }
    }

    fn temp_config_path(name: &str) -> TempConfigPath {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        TempConfigPath(std::env::temp_dir().join(format!("omk-injector-{name}-{unique}.toml")))
    }

    #[test]
    fn missing_config_is_seeded_but_invalid_startup_config_is_untouched() {
        let path = temp_config_path("missing");

        let loaded = load_or_seed(&path, LoadContext::Startup).unwrap();
        assert!(path.exists(), "missing config should be written to disk");
        assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);

        let on_disk = fs::read_to_string(&*path).expect("written config should be readable");
        assert_eq!(on_disk, include_str!("../../template/injector.toml"));
        let reparsed = parse_config(&on_disk).expect("written config should parse");
        assert_eq!(reparsed.scoop, loaded.scoop);

        let path = temp_config_path("invalid");
        let invalid = "[main\nbroken";
        fs::write(&*path, invalid).expect("invalid config should be written");

        let loaded = load_or_seed(&path, LoadContext::Startup).unwrap();
        assert!(!loaded.main.enabled, "invalid startup config must disable injection");
        assert_eq!(fs::read_to_string(&*path).unwrap(), invalid);
        assert!(!PathBuf::from(format!("{}.bak", path.display())).exists());
    }

    #[test]
    fn v0_config_migrates_through_public_scoop_syntax_and_preserves_mode() {
        let path = temp_config_path("v0-migration");
        let v0 = "\u{feff}scoop = [\"com.example.app\"]\r\n\r\n\
                  [scoop.com.example.app]\r\nmode = \"strict\"\r\n";
        fs::write(&*path, v0).unwrap();
        fs::set_permissions(&*path, fs::Permissions::from_mode(0o640)).unwrap();

        let loaded = load_from_path(&path, true).expect("v0 config should migrate");
        assert_eq!(loaded.version, CURRENT_CONFIG_VERSION);
        assert_eq!(
            loaded
                .scoop_details
                .get("com.example.app")
                .and_then(|table| table.get("mode"))
                .and_then(toml::Value::as_str),
            Some("strict")
        );

        let migrated = fs::read_to_string(&*path).unwrap();
        assert!(parse_versioned_config(&migrated, false).is_ok());
        assert_eq!(fs::metadata(&*path).unwrap().mode() & 0o777, 0o640);
    }

    #[test]
    fn reload_rejects_v0_without_rewriting() {
        let path = temp_config_path("reload-v0");
        for v0 in
            ["scoop = [\"com.example.app\"]\n", "version = 0\nscoop = [\"com.example.app\"]\n"]
        {
            fs::write(&*path, v0).unwrap();
            assert!(load_or_seed(&path, LoadContext::Reload(WatchTrigger::CloseWrite)).is_none());
            assert_eq!(fs::read_to_string(&*path).unwrap(), v0);
        }
    }

    #[test]
    fn unsupported_versions_are_rejected_without_rewriting() {
        let path = temp_config_path("future-version");
        let future = "version = 2\n";
        fs::write(&*path, future).unwrap();
        let loaded = load_or_seed(&path, LoadContext::Startup).unwrap();
        assert!(!loaded.main.enabled);
        assert_eq!(fs::read_to_string(&*path).unwrap(), future);
    }

    fn parse_config(contents: &str) -> Result<InjectorConfig, String> {
        parse_versioned_config(contents, true).map(|(config, _)| config)
    }
}
