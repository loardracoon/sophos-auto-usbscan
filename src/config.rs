//! `key = value` configuration file (no serde/toml to keep the binary small).

use crate::log::Level;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Sophos on-demand CLI if found, otherwise touch.
    Auto,
    /// Only the on-demand CLI scanner.
    Cli,
    /// Open/read every file so the on-access engine inspects it.
    Touch,
    /// CLI scan followed by a touch pass.
    Both,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::Cli => "cli",
            Mode::Touch => "touch",
            Mode::Both => "both",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub path: PathBuf,
    pub mode: Mode,
    /// Explicit scanner path; None = auto-detect from the built-in list.
    pub scanner: Option<PathBuf>,
    /// Scanner arguments; `{path}` is replaced by the mount point.
    pub scanner_args: Option<String>,
    /// Scanner exit codes that mean "threat found" (others != 0 = error).
    pub threat_exit_codes: Vec<i32>,
    pub scan_timeout: u64,
    /// Seconds to wait after mount before scanning (let automounters settle).
    pub settle: u64,
    pub scan_on_start: bool,
    /// Skip a device scanned clean within this many seconds (0 = no cache).
    pub cache_ttl: u64,
    pub cache_max: usize,
    pub cache_file: PathBuf,
    pub log_file: PathBuf,
    pub log_level: Level,
    /// JSON lines instead of plain text (SIEM ingestion).
    pub log_json: bool,
    /// Rotate the log when it exceeds this size (0 = never rotate).
    pub log_max_bytes: u64,
    /// Total log files kept, including the active one (usbscan.log + .1 .. .N-1).
    pub log_max_files: usize,
    pub touch_bytes: usize,
    pub touch_max_files: u64,
    pub touch_max_depth: usize,
    /// Linux: mount (read-only) USB partitions nobody mounted (headless boxes).
    pub auto_mount: bool,
    /// Windows: drive polling interval in milliseconds.
    pub poll_ms: u64,
    /// Problems found while parsing the file.
    pub warnings: Vec<String>,
}

pub fn data_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("usbscan")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/usbscan")
    } else {
        PathBuf::from("/var/lib/usbscan")
    }
}

pub fn status_file() -> PathBuf {
    data_dir().join("status.json")
}

pub fn default_path() -> PathBuf {
    if cfg!(windows) {
        data_dir().join("usbscan.conf")
    } else {
        PathBuf::from("/etc/usbscan.conf")
    }
}

impl Default for Config {
    fn default() -> Self {
        let log_file = if cfg!(windows) { data_dir().join("usbscan.log") } else { PathBuf::from("/var/log/usbscan.log") };
        Config {
            path: default_path(),
            mode: Mode::Auto,
            scanner: None,
            scanner_args: None,
            threat_exit_codes: vec![3, 24],
            scan_timeout: 3600,
            settle: 3,
            scan_on_start: true,
            cache_ttl: 86_400,
            cache_max: 10,
            cache_file: data_dir().join("cache.tsv"),
            log_file,
            log_level: Level::Info,
            log_json: false,
            log_max_bytes: 10 * 1024 * 1024,
            log_max_files: 7,
            touch_bytes: 4096,
            touch_max_files: 500_000,
            touch_max_depth: 64,
            auto_mount: false,
            poll_ms: 2000,
            warnings: Vec::new(),
        }
    }
}

/// Accepts plain bytes or a K/M/G suffix: `10485760`, `10M`, `512K`, `1G`.
fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim().to_ascii_uppercase();
    let v = v.strip_suffix('B').unwrap_or(&v);
    let (num, mul) = match v.chars().last()? {
        'K' => (&v[..v.len() - 1], 1024),
        'M' => (&v[..v.len() - 1], 1024 * 1024),
        'G' => (&v[..v.len() - 1], 1024 * 1024 * 1024),
        _ => (v, 1),
    };
    num.trim().parse::<u64>().ok()?.checked_mul(mul)
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

impl Config {
    pub fn load(path: &Path) -> Config {
        let mut c = Config { path: path.to_path_buf(), ..Config::default() };
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                c.warnings.push(format!("{}: {e} (using built-in defaults)", path.display()));
                return c;
            }
        };
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                c.warnings.push(format!("{}:{}: ignored, missing '='", path.display(), n + 1));
                continue;
            };
            let (k, v) = (k.trim(), v.trim().trim_matches('"'));
            let ok = match k {
                "mode" => match v {
                    "auto" => Some(Mode::Auto),
                    "cli" => Some(Mode::Cli),
                    "touch" => Some(Mode::Touch),
                    "both" => Some(Mode::Both),
                    _ => None,
                }
                .map(|m| c.mode = m)
                .is_some(),
                "scanner" => {
                    c.scanner = (!v.is_empty()).then(|| PathBuf::from(v));
                    true
                }
                "scanner_args" => {
                    c.scanner_args = (!v.is_empty()).then(|| v.to_string());
                    true
                }
                "threat_exit_codes" => {
                    let codes: Result<Vec<i32>, _> =
                        v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::parse).collect();
                    codes.map(|x| c.threat_exit_codes = x).is_ok()
                }
                "scan_timeout" => v.parse().map(|x| c.scan_timeout = x).is_ok(),
                "settle" => v.parse().map(|x| c.settle = x).is_ok(),
                "scan_on_start" => parse_bool(v).map(|x| c.scan_on_start = x).is_some(),
                "cache_ttl" => v.parse().map(|x| c.cache_ttl = x).is_ok(),
                "cache_max" => v.parse().map(|x| c.cache_max = x).is_ok(),
                "cache_file" => {
                    c.cache_file = PathBuf::from(v);
                    true
                }
                "log_file" => {
                    c.log_file = PathBuf::from(v);
                    true
                }
                "log_level" => Level::parse(v).map(|l| c.log_level = l).is_some(),
                "log_format" => match v {
                    "text" => Some(false),
                    "json" => Some(true),
                    _ => None,
                }
                .map(|j| c.log_json = j)
                .is_some(),
                // Backwards compatible alias.
                "debug" => parse_bool(v)
                    .map(|x| {
                        if x && c.log_level < Level::Debug {
                            c.log_level = Level::Debug
                        }
                    })
                    .is_some(),
                "log_max_bytes" => parse_size(v).map(|x| c.log_max_bytes = x).is_some(),
                "log_max_files" => v.parse().map(|x: usize| c.log_max_files = x.clamp(1, 100)).is_ok(),
                "touch_bytes" => v.parse().map(|x| c.touch_bytes = x).is_ok(),
                "touch_max_files" => v.parse().map(|x| c.touch_max_files = x).is_ok(),
                "touch_max_depth" => v.parse().map(|x| c.touch_max_depth = x).is_ok(),
                "auto_mount" => parse_bool(v).map(|x| c.auto_mount = x).is_some(),
                "poll_ms" => v.parse().map(|x: u64| c.poll_ms = x.max(250)).is_ok(),
                _ => false,
            };
            if !ok {
                c.warnings.push(format!("{}:{}: invalid setting '{line}'", path.display(), n + 1));
            }
        }
        c
    }

    pub fn dump(&self) -> String {
        let mut s = String::new();
        let o = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        let codes: Vec<String> = self.threat_exit_codes.iter().map(i32::to_string).collect();
        let _ = writeln!(s, "# effective configuration (source: {})", self.path.display());
        let _ = writeln!(s, "mode = {}", self.mode.as_str());
        let _ = writeln!(s, "scanner = {}", o(&self.scanner));
        let _ = writeln!(s, "scanner_args = {}", self.scanner_args.clone().unwrap_or_default());
        let _ = writeln!(s, "threat_exit_codes = {}", codes.join(","));
        let _ = writeln!(s, "scan_timeout = {}", self.scan_timeout);
        let _ = writeln!(s, "settle = {}", self.settle);
        let _ = writeln!(s, "scan_on_start = {}", self.scan_on_start);
        let _ = writeln!(s, "cache_ttl = {}", self.cache_ttl);
        let _ = writeln!(s, "cache_max = {}", self.cache_max);
        let _ = writeln!(s, "cache_file = {}", self.cache_file.display());
        let _ = writeln!(s, "log_file = {}", self.log_file.display());
        let _ = writeln!(s, "log_level = {}", self.log_level.as_str());
        let _ = writeln!(s, "log_format = {}", if self.log_json { "json" } else { "text" });
        let _ = writeln!(s, "log_max_bytes = {}", self.log_max_bytes);
        let _ = writeln!(s, "log_max_files = {}", self.log_max_files);
        let _ = writeln!(s, "touch_bytes = {}", self.touch_bytes);
        let _ = writeln!(s, "touch_max_files = {}", self.touch_max_files);
        let _ = writeln!(s, "touch_max_depth = {}", self.touch_max_depth);
        let _ = writeln!(s, "auto_mount = {}", self.auto_mount);
        let _ = writeln!(s, "poll_ms = {}", self.poll_ms);
        s
    }
}

/// Writes the commented template if no config exists yet (never overwrites).
pub fn write_default(path: &Path) -> Result<(), String> {
    if path.exists() {
        return Ok(());
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("create {}: {e}", d.display()))?;
    }
    std::fs::write(path, TEMPLATE).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Commented default config written by `usbscan install`.
pub const TEMPLATE: &str = "\
# usbscan configuration
# Restart the service after editing. `usbscan config` shows the effective values.

# ---------------------------------------------------------------- scanning
# mode: how a new USB volume is scanned
#   auto  - Sophos on-demand CLI if installed, otherwise 'touch'   (default)
#   cli   - only the on-demand scanner (avscanner / SophosInterceptXCLI / sweep)
#   touch - open and read every file so the on-access engine inspects it
#           (Sophos only alerts on files that are opened/read)
#   both  - cli scan followed by a touch pass
mode = auto

# Scanner binary and arguments. Empty = auto-detect. {path} = mount point.
# Linux   : /opt/sophos-spl/plugins/av/bin/avscanner   args: {path} --scan-archives
# Windows : C:\\Program Files\\Sophos\\Endpoint Defense\\SophosInterceptXCLI.exe
#           args: scan --noui --expand_archives {path}
# macOS   : /usr/local/bin/sweep                       args: -archive {path}
scanner =
scanner_args =
# Exit codes reported as a threat (event=scan_alert). Any other non-zero code
# is reported as a scan error (event=scan_failed). Exit code 0 = clean.
threat_exit_codes = 3,24
scan_timeout = 3600

# Seconds to wait after mount before scanning.
settle = 3
# Scan USB volumes that are already mounted when the service starts.
scan_on_start = true

# Skip a device (vendor/product/serial/partition) scanned clean within
# cache_ttl seconds. 0 disables the cache (scan on every insertion).
cache_ttl = 86400
cache_max = 10

# touch strategy limits
touch_bytes = 4096
touch_max_files = 500000
touch_max_depth = 64

# ---------------------------------------------------------------- platform
# Linux only: mount unmounted USB partitions read-only under /run/usbscan
# (servers / kiosks without a desktop automounter).
auto_mount = false
# Windows only: drive polling interval (ms).
poll_ms = 2000

# ---------------------------------------------------------------- logging
# log_level: error | warn | info | debug | trace
#   debug - detection decisions, cache decisions, scanner command lines
#   trace - every mount evaluated and every file touched (very verbose)
# Can be raised at runtime without restart: `usbscan debug on|trace|off`
log_level = info
# log_format: text | json (one JSON object per line, for SIEM ingestion)
log_format = text
# Size-based rotation: when usbscan.log exceeds log_max_bytes it becomes
# usbscan.log.1 (.1 newest ... .N-1 oldest) and the oldest file is deleted.
# Disk usage is capped at about log_max_bytes x log_max_files (default 70 MB).
# Sizes accept K/M/G suffixes. log_max_bytes = 0 disables rotation.
log_max_bytes = 10M
log_max_files = 7
";

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizes() {
        assert_eq!(parse_size("10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size("512k"), Some(512 * 1024));
        assert_eq!(parse_size("1GB"), Some(1 << 30));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("abc"), None);
    }
}
