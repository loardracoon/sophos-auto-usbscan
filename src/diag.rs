//! Operator commands: status, logs, debug, doctor, devices, cache.

use crate::cache::Cache;
use crate::config::{self, Config, Mode};
use crate::log::{format_epoch, json_str, now_secs, Level};
use crate::{platform, scan, status};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// File holding the runtime log level requested by `usbscan debug`.
pub fn override_file() -> PathBuf {
    config::data_dir().join("log_level.override")
}

// ------------------------------------------------------------------ status

pub fn status(cfg: &Config, json: bool) -> Result<(), String> {
    let state = platform::service_state();
    let file = config::status_file();
    let body = fs::read_to_string(&file).ok();
    let pid = body.as_deref().and_then(status::read_pid);
    let alive = pid.and_then(platform::pid_alive);

    if json {
        println!(
            "{{\"service_state\": {}, \"process_alive\": {}, \"status_file\": {}, \"status\": {}}}",
            json_str(&state),
            alive.map(|b| b.to_string()).unwrap_or_else(|| "null".into()),
            json_str(&file.display().to_string()),
            body.as_deref().map(str::trim).unwrap_or("null")
        );
        return Ok(());
    }

    println!("service       : {state}");
    println!("config        : {}", cfg.path.display());
    println!("log file      : {}", cfg.log_file.display());
    println!("status file   : {}", file.display());
    match (&body, pid, alive) {
        (None, _, _) => println!("\nno status file yet: the service has not run on this machine (or lacks write access)."),
        (Some(_), Some(p), Some(false)) => println!("\nWARNING: status file is from pid {p}, which is not running (stale data below)."),
        _ => {}
    }
    if let Some(b) = body {
        println!("\n{}", b.trim_end());
    }
    Ok(())
}

// -------------------------------------------------------------------- logs

pub fn logs(cfg: &Config, n: usize, follow: bool, scan: Option<&str>) -> Result<(), String> {
    let path = &cfg.log_file;
    let tags = scan.map(|id| (format!("[scan-{id}]"), format!("\"thread\":\"scan-{id}\"")));
    let keep = |l: &str| tags.as_ref().map(|(a, b)| l.contains(a.as_str()) || l.contains(b.as_str())).unwrap_or(true);

    let mut f = OpenOptions::new().read(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut text = String::new();
    f.read_to_string(&mut text).map_err(|e| e.to_string())?;
    // Older lines live in the rotated files (.1 newest): read them, newest
    // first, until enough matching lines are collected.
    let mut lines: Vec<String> = text.lines().filter(|l| keep(l)).map(String::from).collect();
    for k in 1..cfg.log_max_files.max(1) {
        if lines.len() >= n {
            break;
        }
        let Ok(old) = fs::read_to_string(crate::log::rotated_path(path, k)) else { break };
        let mut older: Vec<String> = old.lines().filter(|l| keep(l)).map(String::from).collect();
        older.append(&mut lines);
        lines = older;
    }
    for l in &lines[lines.len().saturating_sub(n)..] {
        println!("{l}");
    }
    if !follow {
        return Ok(());
    }
    let mut pos = text.len() as u64;
    let mut partial = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if len < pos {
            // Rotated or truncated: start over on the new file.
            f = OpenOptions::new().read(true).open(path).map_err(|e| e.to_string())?;
            pos = 0;
        }
        if len == pos {
            continue;
        }
        f.seek(SeekFrom::Start(pos)).map_err(|e| e.to_string())?;
        let mut chunk = String::new();
        let read = f.read_to_string(&mut chunk).map_err(|e| e.to_string())?;
        pos += read as u64;
        partial.push_str(&chunk);
        while let Some(i) = partial.find('\n') {
            let line: String = partial.drain(..=i).collect();
            if keep(&line) {
                print!("{line}");
            }
        }
    }
}

// ------------------------------------------------------------------- debug

pub fn debug_cmd(arg: Option<&str>) -> Result<(), String> {
    let level = match arg {
        Some("on") | Some("debug") => Some(Level::Debug),
        Some("trace") => Some(Level::Trace),
        Some("off") | Some("normal") => None,
        _ => return Err("usage: usbscan debug on|trace|off".into()),
    };
    let f = override_file();
    match level {
        Some(l) => {
            if let Some(d) = f.parent() {
                let _ = fs::create_dir_all(d);
            }
            fs::write(&f, l.as_str()).map_err(|e| format!("write {}: {e} (run as root/Administrator)", f.display()))?;
        }
        None => {
            let _ = fs::remove_file(&f);
        }
    }
    platform::notify_reload()?;
    println!(
        "log level of the running service set to '{}'{}. Follow with: usbscan logs -f",
        level.map(Level::as_str).unwrap_or("configured value"),
        if level.is_some() { " until 'usbscan debug off' or a service restart" } else { "" }
    );
    Ok(())
}

// ------------------------------------------------------------------ doctor

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Ok,
    Info,
    Warn,
    Fail,
}

pub fn line(c: Check, name: &str, detail: impl AsRef<str>) {
    let tag = match c {
        Check::Ok => "[ OK ]",
        Check::Info => "[INFO]",
        Check::Warn => "[WARN]",
        Check::Fail => "[FAIL]",
    };
    println!("{tag} {name:<18} {}", detail.as_ref());
}

fn writable_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let probe = dir.join(".usbscan-write-test");
    fs::write(&probe, b"x").map_err(|e| e.to_string())?;
    let _ = fs::remove_file(probe);
    Ok(())
}

pub fn doctor(cfg: &Config) -> Result<(), String> {
    let mut fails = 0;
    let mut chk = |c: Check, name: &str, d: String| {
        if c == Check::Fail {
            fails += 1;
        }
        line(c, name, d);
    };

    chk(Check::Info, "version", format!("{} ({}/{})", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH));
    chk(
        if platform::is_admin() { Check::Ok } else { Check::Warn },
        "privileges",
        if platform::is_admin() { "root/Administrator".into() } else { "not elevated: some checks may be inaccurate".into() },
    );
    if cfg.path.exists() {
        chk(Check::Ok, "config", cfg.path.display().to_string());
    } else {
        chk(Check::Warn, "config", format!("{} not found, using defaults", cfg.path.display()));
    }
    for w in &cfg.warnings {
        chk(Check::Warn, "config", w.clone());
    }

    let scanner = scan::resolve_scanner(cfg);
    match &scanner {
        Some((p, a)) if p.is_file() => chk(Check::Ok, "scanner", format!("{} {a}", p.display())),
        Some((p, _)) => chk(
            if cfg.mode == Mode::Auto { Check::Warn } else { Check::Fail },
            "scanner",
            format!("{} does not exist", p.display()),
        ),
        None => chk(
            if matches!(cfg.mode, Mode::Cli | Mode::Both) { Check::Fail } else { Check::Info },
            "scanner",
            format!(
                "no on-demand scanner found (looked for: {})",
                scan::CANDIDATES.iter().map(|c| c.0).collect::<Vec<_>>().join(", ")
            ),
        ),
    }
    let (cli, touch) = scan::strategies(cfg);
    chk(Check::Info, "strategy", format!("mode={} -> cli={cli} touch={touch}", cfg.mode.as_str()));

    let log_dir = cfg.log_file.parent().unwrap_or(Path::new("."));
    match OpenOptions::new().create(true).append(true).open(&cfg.log_file) {
        Ok(_) => chk(Check::Ok, "log file", cfg.log_file.display().to_string()),
        Err(e) => chk(Check::Fail, "log file", format!("{}: {e} ({})", cfg.log_file.display(), log_dir.display())),
    }
    match writable_dir(&config::data_dir()) {
        Ok(()) => chk(Check::Ok, "data dir", config::data_dir().display().to_string()),
        Err(e) => chk(Check::Fail, "data dir", format!("{}: {e}", config::data_dir().display())),
    }
    chk(
        Check::Info,
        "log level",
        format!("{} ({})", cfg.log_level.as_str(), if cfg.log_json { "json" } else { "text" }),
    );
    let used: u64 = std::iter::once(cfg.log_file.clone())
        .chain((1..cfg.log_max_files.max(1)).map(|k| crate::log::rotated_path(&cfg.log_file, k)))
        .filter_map(|p| fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    let hs = |b: u64| {
        if b >= 1 << 20 { format!("{:.1} MB", b as f64 / 1_048_576.0) } else { format!("{:.0} KB", b as f64 / 1024.0) }
    };
    chk(
        Check::Info,
        "log rotation",
        if cfg.log_max_bytes == 0 {
            format!("disabled (log grows without limit), {} used", hs(used))
        } else {
            format!(
                "{} x {} files (max ~{}), {} used",
                hs(cfg.log_max_bytes),
                cfg.log_max_files,
                hs(cfg.log_max_bytes * cfg.log_max_files as u64),
                hs(used)
            )
        },
    );
    if override_file().exists() {
        chk(Check::Info, "debug override", format!("active: {}", fs::read_to_string(override_file()).unwrap_or_default().trim()));
    }

    let state = platform::service_state();
    chk(if state.starts_with("running") { Check::Ok } else { Check::Warn }, "service", state);
    if let Ok(body) = fs::read_to_string(config::status_file()) {
        let pid = status::read_pid(&body);
        match pid.and_then(platform::pid_alive) {
            Some(true) => chk(Check::Ok, "process", format!("pid {}", pid.unwrap_or(0))),
            Some(false) => chk(Check::Warn, "process", format!("status.json pid {} is not running", pid.unwrap_or(0))),
            None => {}
        }
    }

    for (c, name, d) in platform::doctor(cfg) {
        chk(c, &name, d);
    }

    let mut w = platform::Watcher::new(cfg);
    let probes = w.probe();
    let usb: Vec<_> = probes.iter().filter(|p| p.usb).collect();
    chk(Check::Info, "volumes", format!("{} evaluated, {} USB (details: usbscan devices --all)", probes.len(), usb.len()));
    for p in usb {
        chk(Check::Info, "usb volume", format!("{} id={}", p.mount.display(), p.id));
    }

    let cache = Cache::load(cfg.cache_file.clone(), cfg.cache_ttl, cfg.cache_max);
    chk(
        Check::Info,
        "cache",
        if cache.enabled() {
            format!("{} entr(y/ies), ttl {}s, {}", cache.entries().len(), cfg.cache_ttl, cfg.cache_file.display())
        } else {
            "disabled (every insertion is scanned)".into()
        },
    );

    println!();
    if fails == 0 {
        println!("no blocking problems found");
        Ok(())
    } else {
        Err(format!("{fails} check(s) failed"))
    }
}

// ----------------------------------------------------------------- devices

pub fn devices(cfg: &Config, all: bool) {
    let mut w = platform::Watcher::new(cfg);
    let probes = w.probe();
    let shown: Vec<_> = probes.iter().filter(|p| all || p.usb).collect();
    if shown.is_empty() {
        println!("no USB storage volume mounted{}", if all { "" } else { " (use --all to see why other volumes were ignored)" });
        return;
    }
    for p in shown {
        println!("{} {}", if p.usb { "USB " } else { "skip" }, p.mount.display());
        println!("     source : {}", p.source);
        if !p.id.is_empty() {
            println!("     id     : {}", p.id);
        }
        if !p.desc.is_empty() {
            println!("     desc   : {}", p.desc);
        }
        println!("     reason : {}", p.reason);
    }
}

// ------------------------------------------------------------------- cache

pub fn cache_cmd(cfg: &Config, sub: &str) -> Result<(), String> {
    let mut c = Cache::load(cfg.cache_file.clone(), cfg.cache_ttl, cfg.cache_max);
    match sub {
        "list" => {
            println!("cache file: {} (ttl {}s, max {})", cfg.cache_file.display(), c.ttl(), cfg.cache_max);
            if c.entries().is_empty() {
                println!("empty");
            }
            let now = now_secs();
            for (id, t) in c.entries() {
                let age = now.saturating_sub(*t);
                let state = if age < c.ttl() { format!("valid {}s more", c.ttl() - age) } else { "expired".into() };
                println!("{}  {id}  ({state})", format_epoch(*t, None));
            }
            Ok(())
        }
        "clear" => {
            c.clear().map_err(|e| format!("{}: {e}", cfg.cache_file.display()))?;
            println!("cache cleared: every device will be scanned on its next insertion");
            Ok(())
        }
        _ => Err("usage: usbscan cache [list|clear]".into()),
    }
}
