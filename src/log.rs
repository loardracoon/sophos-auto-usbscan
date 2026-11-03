//! Minimal thread-safe file logger with size based rotation (no dependencies).

use crate::config::Config;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct Logger {
    path: PathBuf,
    file: Option<File>,
    max: u64,
    console: bool,
    debug: bool,
}

static LOG: Mutex<Option<Logger>> = Mutex::new(None);

pub fn init(cfg: &Config, console: bool) {
    if let Some(dir) = cfg.log_file.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let file = OpenOptions::new().create(true).append(true).open(&cfg.log_file).ok();
    if file.is_none() {
        eprintln!("warning: cannot open log file {}", cfg.log_file.display());
    }
    *LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(Logger {
        path: cfg.log_file.clone(),
        file,
        max: cfg.log_max_bytes,
        console: console || cfg.debug,
        debug: cfg.debug,
    });
}

pub fn write(level: &str, msg: &str) {
    let mut g = LOG.lock().unwrap_or_else(|e| e.into_inner());
    let Some(l) = g.as_mut() else {
        if level != "DEBUG" {
            eprintln!("[{level}] {msg}");
        }
        return;
    };
    if level == "DEBUG" && !l.debug {
        return;
    }
    let line = format!("{} [{level}] {msg}\n", timestamp());
    if l.console {
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
    if let Some(f) = l.file.as_mut() {
        let _ = f.write_all(line.as_bytes());
        if l.max > 0 && f.metadata().map(|m| m.len() > l.max).unwrap_or(false) {
            let old = l.path.with_extension("log.1");
            let _ = fs::rename(&l.path, &old);
            l.file = OpenOptions::new().create(true).append(true).open(&l.path).ok();
        }
    }
}

/// Raw handle to the log file so child scanners can append their output.
pub fn file_handle() -> Option<File> {
    let g = LOG.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().and_then(|l| l.file.as_ref()).and_then(|f| f.try_clone().ok())
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// UTC timestamp `YYYY-MM-DD HH:MM:SSZ` without a time crate.
fn timestamp() -> String {
    let t = now_secs();
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
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[macro_export]
macro_rules! info { ($($t:tt)*) => { $crate::log::write("INFO", &format!($($t)*)) } }
#[macro_export]
macro_rules! warn { ($($t:tt)*) => { $crate::log::write("WARN", &format!($($t)*)) } }
#[macro_export]
macro_rules! error { ($($t:tt)*) => { $crate::log::write("ERROR", &format!($($t)*)) } }
#[macro_export]
macro_rules! debug { ($($t:tt)*) => { $crate::log::write("DEBUG", &format!($($t)*)) } }
