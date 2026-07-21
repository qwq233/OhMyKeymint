use kmr_common::runtime::{
    file_watch::{self, WatchTrigger},
    fs::backup_file_with_reason,
    retry::{retry_read_race, ReadRaceErrorKind, RetryOutcome},
};
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

pub const DEFAULT_CONFIG_PATH: &str = "/data/misc/keystore/omk/injector.toml";
const REPLACE_SAVE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const REPLACE_SAVE_RETRY_LIMIT: usize = 10;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InjectorConfig {
    pub scoop: Vec<String>,
    pub scoop_details: BTreeMap<String, toml::Table>,
    pub main: MainConfig,
    pub filter: FilterConfig,
    pub intercept: InterceptConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct MainConfig {
    pub enabled: bool,
    pub log_level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    pub enabled: bool,
    pub deny_packages: Vec<String>,
    pub block_android_package: bool,
    pub allow_unknown_package: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
        Self {
            enabled: true,
            log_level: "debug".to_string(),
        }
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
    Io(io::Error),
    Parse(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
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

#[derive(Serialize)]
struct WritableConfig<'a> {
    scoop: &'a [String],
    main: &'a MainConfig,
    filter: &'a FilterConfig,
    intercept: &'a InterceptConfig,
}

static CONFIG: OnceLock<RwLock<Arc<InjectorConfig>>> = OnceLock::new();
static WATCHER_STARTED: OnceLock<()> = OnceLock::new();

impl LoadContext {
    fn label(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Reload(trigger) => trigger.label(),
        }
    }
}

pub fn get() -> Arc<InjectorConfig> {
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
    CONFIG.get_or_init(|| RwLock::new(Arc::new(load_or_seed(&path, LoadContext::Startup))));
    WATCHER_STARTED.get_or_init(|| start_watcher(path));
}

fn config_path() -> PathBuf {
    std::env::var_os("OMK_INJECTOR_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
}

fn load_from_path(path: &Path) -> Result<InjectorConfig, LoadError> {
    let contents = fs::read_to_string(path).map_err(LoadError::Io)?;
    parse_config(&contents).map_err(LoadError::Parse)
}

fn load_with_context(
    path: &Path,
    context: LoadContext,
) -> Result<RetryOutcome<InjectorConfig>, LoadError> {
    match context {
        LoadContext::Reload(trigger) if trigger.should_retry_reads() => {
            load_with_read_race_retry(path, context, load_from_path, std::thread::sleep)
        }
        _ => load_from_path(path).map(|value| RetryOutcome { value, retries: 0 }),
    }
}

fn load_or_seed(path: &Path, context: LoadContext) -> InjectorConfig {
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
                log::info!(
                    "loaded config from {} via {}",
                    path.display(),
                    context.label()
                );
            }
            loaded.value
        }
        Err(LoadError::Io(error)) => {
            let reason = format!("failed to read config: {error}");
            log::warn!(
                "load from {} via {} {}; restoring current config",
                path.display(),
                context.label(),
                reason
            );
            recover_broken_config(path, &reason)
        }
        Err(LoadError::Parse(error)) => {
            let reason = format!("failed to parse config: {error}");
            log::warn!(
                "load from {} via {} {}; restoring current config",
                path.display(),
                context.label(),
                reason
            );
            recover_broken_config(path, &reason)
        }
    }
}

fn recover_broken_config(path: &Path, reason: &str) -> InjectorConfig {
    if path.exists() {
        let backup_path = PathBuf::from(format!("{}.bak", path.display()));
        match backup_file_with_reason(
            path,
            &backup_path,
            "injector config recovery reason",
            reason,
            false,
        ) {
            Ok(()) => log::info!("moved invalid config to {}", backup_path.display()),
            Err(backup_error) => log::error!(
                "failed to preserve broken config {}: {}",
                path.display(),
                backup_error
            ),
        }
    }

    let replacement = current_config_snapshot();
    if let Err(write_error) = write_config(path, &replacement) {
        log::error!(
            "failed to write replacement config to {}: {}",
            path.display(),
            write_error
        );
    }
    replacement
}

fn current_config_snapshot() -> InjectorConfig {
    match CONFIG.get() {
        Some(lock) => match lock.read() {
            Ok(config) => config.as_ref().clone(),
            Err(error) => {
                log::error!("current config lock poisoned while snapshotting: {}", error);
                InjectorConfig::default()
            }
        },
        None => InjectorConfig::default(),
    }
}

fn write_config(path: &Path, config: &InjectorConfig) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let contents = render_config(config)?;
    fs::write(path, contents)?;
    log::info!("wrote config to {}", path.display());
    Ok(())
}

fn render_config(config: &InjectorConfig) -> io::Result<String> {
    let mut contents = String::from(
        "# With `[filter].enabled = true`, a UID is intercepted when any package\n\
         # sharing that UID is listed in `scoop`.\n\
         # Filter deny settings still apply to every package resolved for the UID.\n\
         # Optional per-package settings can be added under [scoop.<package>].\n\
         # Example:\n\
         # [scoop.io.github.vvb2060.keyattestation]\n\
         # mode = \"strict\"\n\n",
    );
    let base = toml::to_string_pretty(&WritableConfig {
        scoop: &config.scoop,
        main: &config.main,
        filter: &config.filter,
        intercept: &config.intercept,
    })
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    contents.push_str(&base);

    for (package, table) in &config.scoop_details {
        contents.push('\n');
        contents.push_str("[scoop.");
        contents.push_str(package);
        contents.push_str("]\n");
        if !table.is_empty() {
            let table_body = toml::to_string_pretty(table)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            contents.push_str(&table_body);
        }
    }

    Ok(contents)
}

fn parse_config(contents: &str) -> Result<InjectorConfig, String> {
    let preprocessed = preprocess_config(contents)?;
    let parsed: InjectorConfig =
        toml::from_str(&preprocessed).map_err(|error| error.to_string())?;
    Ok(parsed.normalized())
}

fn preprocess_config(contents: &str) -> Result<String, String> {
    let mut rewritten = String::with_capacity(contents.len());
    for (line_no, line) in contents.split_inclusive('\n').enumerate() {
        let (body, ending) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        rewritten.push_str(&rewrite_scoop_header(body, line_no + 1)?);
        rewritten.push_str(ending);
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
        return Err(format!(
            "line {line_no}: unterminated [scoop.<package>] header"
        ));
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
    let config = load_or_seed(path, LoadContext::Reload(trigger));
    if let Some(lock) = CONFIG.get() {
        match lock.write() {
            Ok(mut guard) => {
                let level = config.main.log_level_filter();
                *guard = Arc::new(config);
                crate::logging::update_runtime_level(level);
                log::info!(
                    "reloaded config from {} via {}",
                    path.display(),
                    trigger.label()
                );
            }
            Err(error) => {
                log::error!(
                    "failed to apply config reload from {}: {}",
                    path.display(),
                    error
                );
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
            LoadError::Io(_) => ReadRaceErrorKind::Retryable,
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("omk-injector-{name}-{unique}.toml"))
    }

    #[test]
    fn config_defaults_and_log_levels_match_contract() {
        let config = InjectorConfig::default();
        assert!(config.main.enabled);
        assert_eq!(config.scoop, default_scoop());
        assert!(config.scoop_details.is_empty());
        assert_eq!(config.main.log_level_filter(), LevelFilter::Debug);
        assert!(config.filter.block_android_package);
        assert!(!config.filter.allow_unknown_package);
        assert!(config.intercept.get_security_level);
        assert!(config.intercept.get_key_entry);
        assert!(config.intercept.update_subcomponent);
        assert!(config.intercept.list_entries);
        assert!(config.intercept.delete_key);
        assert!(config.intercept.grant);
        assert!(config.intercept.ungrant);
        assert!(config.intercept.get_number_of_entries);
        assert!(config.intercept.list_entries_batched);
        assert!(config.intercept.get_supplementary_attestation_info);

        assert_eq!(parse_level_filter("warn"), Some(LevelFilter::Warn));
        assert_eq!(parse_level_filter("WARNING"), Some(LevelFilter::Warn));
        assert_eq!(parse_level_filter("trace"), Some(LevelFilter::Trace));
        assert_eq!(parse_level_filter("unknown"), None);
    }

    #[test]
    fn parses_new_scoop_format_and_preserves_package_details() {
        let parsed = parse_config(
            r#"
scoop = ["com.example.app", "com.other.app", "com.example.app"]

[scoop."com.example.app"]
mode = "strict"

[main]
enabled = false
log_level = "trace"

[filter]
enabled = true
deny_packages = ["com.blocked"]
block_android_package = false
allow_unknown_package = true

[intercept]
get_security_level = false
get_key_entry = true
update_subcomponent = false
list_entries = false
delete_key = false
grant = false
ungrant = false
get_number_of_entries = false
list_entries_batched = false
get_supplementary_attestation_info = true
"#,
        )
        .expect("config should parse");

        assert_eq!(
            parsed.scoop,
            vec!["com.example.app".to_string(), "com.other.app".to_string()]
        );
        assert_eq!(parsed.main.log_level_filter(), LevelFilter::Trace);
        assert!(!parsed.main.enabled);
        assert_eq!(
            parsed
                .scoop_details
                .get("com.example.app")
                .and_then(|table| table.get("mode"))
                .and_then(toml::Value::as_str),
            Some("strict")
        );
        assert!(!parsed.intercept.get_security_level);
        assert!(parsed.intercept.get_key_entry);
        assert!(!parsed.intercept.update_subcomponent);
        assert!(!parsed.intercept.list_entries);
        assert!(!parsed.intercept.delete_key);
        assert!(!parsed.intercept.grant);
        assert!(!parsed.intercept.ungrant);
        assert!(!parsed.intercept.get_number_of_entries);
        assert!(!parsed.intercept.list_entries_batched);
        assert!(parsed.intercept.get_supplementary_attestation_info);
    }

    #[test]
    fn legacy_config_syntax_is_rejected() {
        let error = parse_config(
            r#"
[[scope]]
package = "com.legacy.app"
"#,
        )
        .expect_err("legacy scope syntax should be rejected");
        assert!(error.contains("unknown field"));

        let error = parse_config(
            r#"
scoop = ["com.example.app"]

[filter]
allow_packages = ["com.legacy.app"]
"#,
        )
        .expect_err("legacy allow_packages should be rejected");
        assert!(error.contains("unknown field"));
    }

    #[test]
    fn rendered_config_uses_new_scoop_format() {
        let mut config = InjectorConfig {
            scoop: vec!["com.example.app".to_string()],
            ..Default::default()
        };
        let mut table = toml::Table::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        config
            .scoop_details
            .insert("com.example.app".to_string(), table);

        let rendered = render_config(&config).expect("config should render");
        assert!(rendered.contains("scoop = ["));
        assert!(rendered.contains("[scoop.com.example.app]"));
        assert!(!rendered.contains("[[scope]]"));
        let reparsed = parse_config(&rendered).expect("rendered config should parse");
        assert_eq!(reparsed.scoop_details, config.scoop_details);
    }

    #[test]
    fn missing_and_invalid_config_recover_safely() {
        let path = temp_config_path("missing");
        if path.exists() {
            fs::remove_file(&path).expect("stale test config should be removable");
        }

        let loaded = load_or_seed(&path, LoadContext::Startup);
        assert!(path.exists(), "missing config should be written to disk");
        assert_eq!(loaded.scoop, default_scoop());

        let on_disk = fs::read_to_string(&path).expect("written config should be readable");
        let reparsed = parse_config(&on_disk).expect("written config should parse");
        assert_eq!(reparsed.scoop, default_scoop());

        fs::remove_file(&path).expect("test config should be cleaned up");

        let path = temp_config_path("invalid");
        let backup = PathBuf::from(format!("{}.bak", path.display()));
        fs::write(&path, "[main\nbroken").expect("invalid config should be written");

        let loaded = load_or_seed(&path, LoadContext::Startup);
        assert!(backup.exists(), "invalid config should be backed up");
        assert_eq!(
            loaded.scoop,
            default_scoop(),
            "defaults should be loaded after parse failure"
        );

        let rewritten = fs::read_to_string(&path).expect("rewritten config should be readable");
        let reparsed = parse_config(&rewritten).expect("rewritten config should parse");
        assert_eq!(reparsed.scoop, default_scoop());

        let backup_contents =
            fs::read_to_string(&backup).expect("backup config should be readable");
        assert!(
            backup_contents.contains("# injector config recovery reason:"),
            "backup should contain the appended error reason"
        );

        fs::remove_file(&path).expect("test config should be cleaned up");
        fs::remove_file(&backup).expect("backup config should be cleaned up");
    }

    #[test]
    fn template_scope_matches_default_scope() {
        let template = include_str!("../../template/injector.toml");
        let parsed = parse_config(template).expect("template injector config should parse");
        assert_eq!(parsed.scoop, default_scoop());
    }

    #[test]
    fn replace_save_retry_only_retries_read_failures() {
        let path = temp_config_path("replace-save-retry");
        let mut attempts = 0usize;
        let mut sleeps = Vec::new();

        let loaded = load_with_read_race_retry(
            &path,
            LoadContext::Reload(WatchTrigger::ReplaceSave),
            |_path| {
                attempts += 1;
                match attempts {
                    1 => Err(LoadError::Io(io::Error::from(io::ErrorKind::NotFound))),
                    2 => Err(LoadError::Io(io::Error::from(
                        io::ErrorKind::PermissionDenied,
                    ))),
                    _ => Ok(InjectorConfig::default()),
                }
            },
            |duration| sleeps.push(duration),
        )
        .expect("replace-save retry should eventually succeed");

        assert_eq!(loaded.retries, 2);
        assert_eq!(attempts, 3);
        assert_eq!(sleeps.len(), 2);
        assert!(sleeps
            .iter()
            .all(|duration| *duration == REPLACE_SAVE_RETRY_INTERVAL));

        let path = temp_config_path("replace-save-parse");
        let mut sleeps = Vec::new();

        let error = load_with_read_race_retry(
            &path,
            LoadContext::Reload(WatchTrigger::ReplaceSave),
            |_path| Err(LoadError::Parse("broken".to_string())),
            |duration| sleeps.push(duration),
        )
        .expect_err("parse failures should bypass replace-save retries");

        assert!(matches!(error, LoadError::Parse(_)));
        assert!(sleeps.is_empty());
    }
}
