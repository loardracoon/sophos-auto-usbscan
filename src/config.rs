//! `key = value` configuration file (no serde/toml to keep the binary small).

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
    pub mode: Mode,
    /// Explicit scanner path; empty = auto-detect from the built-in list.
    pub scanner: Option<PathBuf>,
    /// Scanner arguments; `{path}` is replaced by the mount point.
    pub scanner_args: Option<String>,
    pub scan_timeout: u64,
    /// Seconds to wait after mount before scanning (let automounters settle).
    pub settle: u64,
    pub scan_on_start: bool,
    /// Skip a device scanned clean within this many seconds (0 = no cache).
    pub cache_ttl: u64,
    pub cache_max: usize,
    pub cache_file: PathBuf,
    pub log_file: PathBuf,
    pub log_max_bytes: u64,
    pub touch_bytes: usize,
    pub touch_max_files: u64,
    pub touch_max_depth: usize,
    /// Linux: mount (read-only) USB partitions nobody mounted (headless boxes).
    pub auto_mount: bool,
    /// Windows: drive polling interval in milliseconds.
    pub poll_ms: u64,
    pub debug: bool,
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
            mode: Mode::Auto,
            scanner: None,
            scanner_args: None,
            scan_timeout: 3600,
            settle: 3,
            scan_on_start: true,
            cache_ttl: 86_400,
            cache_max: 10,
            cache_file: data_dir().join("cache.tsv"),
            log_file,
            log_max_bytes: 5 * 1024 * 1024,
            touch_bytes: 4096,
            touch_max_files: 500_000,
            touch_max_depth: 64,
            auto_mount: false,
            poll_ms: 2000,
            debug: false,
        }
    }
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
        let mut c = Config::default();
        let Ok(text) = std::fs::read_to_string(path) else { return c };
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                eprintln!("{}:{}: ignored (no '=')", path.display(), n + 1);
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
                "log_max_bytes" => v.parse().map(|x| c.log_max_bytes = x).is_ok(),
                "touch_bytes" => v.parse().map(|x| c.touch_bytes = x).is_ok(),
                "touch_max_files" => v.parse().map(|x| c.touch_max_files = x).is_ok(),
                "touch_max_depth" => v.parse().map(|x| c.touch_max_depth = x).is_ok(),
                "auto_mount" => parse_bool(v).map(|x| c.auto_mount = x).is_some(),
                "poll_ms" => v.parse().map(|x: u64| c.poll_ms = x.max(250)).is_ok(),
                "debug" => parse_bool(v).map(|x| c.debug = x).is_some(),
                _ => false,
            };
            if !ok {
                eprintln!("{}:{}: invalid setting '{line}'", path.display(), n + 1);
            }
        }
        c
    }

    pub fn dump(&self) -> String {
        let mut s = String::new();
        let o = |p: &Option<PathBuf>| p.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        let _ = writeln!(s, "mode = {}", self.mode.as_str());
        let _ = writeln!(s, "scanner = {}", o(&self.scanner));
        let _ = writeln!(s, "scanner_args = {}", self.scanner_args.clone().unwrap_or_default());
        let _ = writeln!(s, "scan_timeout = {}", self.scan_timeout);
        let _ = writeln!(s, "settle = {}", self.settle);
        let _ = writeln!(s, "scan_on_start = {}", self.scan_on_start);
        let _ = writeln!(s, "cache_ttl = {}", self.cache_ttl);
        let _ = writeln!(s, "cache_max = {}", self.cache_max);
        let _ = writeln!(s, "cache_file = {}", self.cache_file.display());
        let _ = writeln!(s, "log_file = {}", self.log_file.display());
        let _ = writeln!(s, "log_max_bytes = {}", self.log_max_bytes);
        let _ = writeln!(s, "touch_bytes = {}", self.touch_bytes);
        let _ = writeln!(s, "touch_max_files = {}", self.touch_max_files);
        let _ = writeln!(s, "touch_max_depth = {}", self.touch_max_depth);
        let _ = writeln!(s, "auto_mount = {}", self.auto_mount);
        let _ = writeln!(s, "poll_ms = {}", self.poll_ms);
        let _ = writeln!(s, "debug = {}", self.debug);
        s
    }
}

/// Commented default config written by `usbscan install`.
pub const TEMPLATE: &str = "\
# usbscan configuration
#
# mode: how a new USB volume is scanned
#   auto  - Sophos on-demand CLI if installed, otherwise 'touch'   (default)
#   cli   - only the on-demand scanner (avscanner / SophosInterceptXCLI / sweep)
#   touch - open and read every file so the on-access engine inspects it
#           (Sophos alerts only on files that are opened/read)
#   both  - cli scan followed by a touch pass
mode = auto

# Scanner binary and arguments. Empty = auto-detect. {path} = mount point.
# Linux   : /opt/sophos-spl/plugins/av/bin/avscanner   args: {path} --scan-archives
# Windows : C:\\Program Files\\Sophos\\Endpoint Defense\\SophosInterceptXCLI.exe
#           args: scan --noui --expand_archives {path}
# macOS   : /usr/local/bin/sweep                       args: -archive {path}
scanner =
scanner_args =
scan_timeout = 3600

# Seconds to wait after mount before scanning.
settle = 3
# Scan USB volumes that are already mounted when the service starts.
scan_on_start = true

# Skip a device (vendor/product/serial/partition) scanned clean within cache_ttl
# seconds. 0 disables the cache (scan on every insertion).
cache_ttl = 86400
cache_max = 10

# touch strategy limits
touch_bytes = 4096
touch_max_files = 500000
touch_max_depth = 64

# Linux only: mount unmounted USB partitions read-only under /run/usbscan
# (servers / kiosks without a desktop automounter).
auto_mount = false

# Windows only: drive polling interval (ms).
poll_ms = 2000

log_max_bytes = 5242880
debug = false
";

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
