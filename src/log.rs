//! Leveled, thread-tagged logger with optional JSON lines output and
//! size-based rotation (no dependencies).
//!
//! Every line carries the thread name. Scan workers are named `scan-<id>`,
//! so all lines of one scan (including scanner output) share a correlation
//! id that can be grepped or filtered in a SIEM.

use crate::config::Config;
use std::collections::VecDeque;
use std::fmt::{Display, Write as _};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        }
    }
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s.to_ascii_lowercase().as_str() {
            "error" => Level::Error,
            "warn" | "warning" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            "trace" => Level::Trace,
            _ => return None,
        })
    }
    fn from_u8(v: u8) -> Level {
        match v {
            0 => Level::Error,
            1 => Level::Warn,
            2 => Level::Info,
            3 => Level::Debug,
            _ => Level::Trace,
        }
    }
}

/// Current (possibly runtime-overridden) level and the configured one.
static LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static BASE_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
static JSON: AtomicBool = AtomicBool::new(false);

struct Sink {
    path: PathBuf,
    file: Option<File>,
    max: u64,
    console: bool,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);
static RECENT: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
const RECENT_MAX: usize = 50;

pub fn init(cfg: &Config, console: bool) {
    LEVEL.store(cfg.log_level as u8, Ordering::Relaxed);
    BASE_LEVEL.store(cfg.log_level as u8, Ordering::Relaxed);
    JSON.store(cfg.log_json, Ordering::Relaxed);
    if let Some(dir) = cfg.log_file.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let file = OpenOptions::new().create(true).append(true).open(&cfg.log_file).ok();
    if file.is_none() {
        eprintln!("warning: cannot open log file {}", cfg.log_file.display());
    }
    *SINK.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Sink { path: cfg.log_file.clone(), file, max: cfg.log_max_bytes, console });
}

pub fn level() -> Level {
    Level::from_u8(LEVEL.load(Ordering::Relaxed))
}

pub fn enabled(l: Level) -> bool {
    (l as u8) <= LEVEL.load(Ordering::Relaxed)
}

/// Async-signal-safe: only touches atomics.
pub fn set_level(l: Level) {
    LEVEL.store(l as u8, Ordering::Relaxed);
}

/// Back to the level from the configuration file.
pub fn restore_level() {
    LEVEL.store(BASE_LEVEL.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Plain message.
pub fn write(level: Level, msg: &str) {
    emit(level, None, msg, &[]);
}

/// Structured event: `event=<name> key=value ...` (text) or JSON fields.
pub fn event(level: Level, name: &str, fields: &[(&str, &dyn Display)]) {
    emit(level, Some(name), "", fields);
}

fn emit(level: Level, event: Option<&str>, msg: &str, fields: &[(&str, &dyn Display)]) {
    if !enabled(level) {
        return;
    }
    let ts = timestamp();
    let th = std::thread::current();
    let thread = th.name().unwrap_or("worker");
    let line = if JSON.load(Ordering::Relaxed) {
        let mut s = format!(
            "{{\"ts\":{},\"level\":\"{}\",\"thread\":{},\"pid\":{}",
            json_str(&ts),
            level.as_str(),
            json_str(thread),
            std::process::id()
        );
        if let Some(e) = event {
            let _ = write!(s, ",\"event\":{}", json_str(e));
        }
        if !msg.is_empty() {
            let _ = write!(s, ",\"msg\":{}", json_str(msg));
        }
        for (k, v) in fields {
            let _ = write!(s, ",{}:{}", json_str(k), json_str(&v.to_string()));
        }
        s.push_str("}\n");
        s
    } else {
        let mut body = String::from(msg);
        if let Some(e) = event {
            let _ = write!(body, "event={e}");
            for (k, v) in fields {
                let _ = write!(body, " {k}={}", kv_value(&v.to_string()));
            }
        }
        format!("{ts} {:<5} [{thread}] {body}\n", level.as_str().to_ascii_uppercase())
    };

    if event.is_some() && level <= Level::Info {
        let mut r = RECENT.lock().unwrap_or_else(|e| e.into_inner());
        if r.len() >= RECENT_MAX {
            r.pop_front();
        }
        r.push_back(line.trim_end().to_string());
    }

    let mut g = SINK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sink) = g.as_mut() else {
        let _ = std::io::stderr().write_all(line.as_bytes());
        return;
    };
    if sink.console {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    if let Some(f) = sink.file.as_mut() {
        let _ = f.write_all(line.as_bytes());
        if sink.max > 0 && f.metadata().map(|m| m.len() > sink.max).unwrap_or(false) {
            let _ = fs::rename(&sink.path, sink.path.with_extension("log.1"));
            sink.file = OpenOptions::new().create(true).append(true).open(&sink.path).ok();
        }
    }
}

/// Last important events (info and above), newest last.
pub fn recent() -> Vec<String> {
    RECENT.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
}

fn kv_value(v: &str) -> String {
    if !v.is_empty() && !v.contains(|c: char| c.is_whitespace() || c == '"' || c == '=') {
        v.to_string()
    } else {
        format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

pub fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// RFC 3339 UTC timestamp with milliseconds, without a time crate.
pub fn timestamp() -> String {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    format_epoch(ms / 1000, Some(ms % 1000))
}

pub fn format_epoch(t: u64, millis: Option<u64>) -> String {
    let (days, rem) = (t / 86400, t % 86400);
    // civil-from-days (Howard Hinnant)
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let base = format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
    match millis {
        Some(ms) => format!("{base}.{ms:03}Z"),
        None => format!("{base}Z"),
    }
}

#[macro_export]
macro_rules! error { ($($t:tt)*) => { if $crate::log::enabled($crate::log::Level::Error) { $crate::log::write($crate::log::Level::Error, &format!($($t)*)) } } }
#[macro_export]
macro_rules! warn { ($($t:tt)*) => { if $crate::log::enabled($crate::log::Level::Warn) { $crate::log::write($crate::log::Level::Warn, &format!($($t)*)) } } }
#[macro_export]
macro_rules! info { ($($t:tt)*) => { if $crate::log::enabled($crate::log::Level::Info) { $crate::log::write($crate::log::Level::Info, &format!($($t)*)) } } }
#[macro_export]
macro_rules! debug { ($($t:tt)*) => { if $crate::log::enabled($crate::log::Level::Debug) { $crate::log::write($crate::log::Level::Debug, &format!($($t)*)) } } }
#[macro_export]
macro_rules! trace { ($($t:tt)*) => { if $crate::log::enabled($crate::log::Level::Trace) { $crate::log::write($crate::log::Level::Trace, &format!($($t)*)) } } }

/// `ev!(Info, "scan_start", mount = path.display(), id = dev.id)`
#[macro_export]
macro_rules! ev {
    ($lvl:ident, $name:expr $(, $k:ident = $v:expr)* $(,)?) => {
        if $crate::log::enabled($crate::log::Level::$lvl) {
            $crate::log::event(
                $crate::log::Level::$lvl,
                $name,
                &[$((stringify!($k), &$v as &dyn std::fmt::Display)),*],
            )
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats() {
        assert_eq!(format_epoch(0, Some(5)), "1970-01-01T00:00:00.005Z");
        assert_eq!(format_epoch(1_793_750_400, None), "2026-11-04T00:00:00Z");
        assert_eq!(kv_value("E:\\"), "E:\\");
        assert_eq!(kv_value("a b"), "\"a b\"");
        assert_eq!(json_str("a\"b\\\n"), "\"a\\\"b\\\\\\n\"");
    }
}
