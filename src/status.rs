//! Runtime state exported to `status.json` so operators (and monitoring
//! tools) can see what the service is doing without reading the log:
//! counters, scans in progress, USB volumes present and recent events.

use crate::log::{format_epoch, json_str, now_secs};
use crate::Device;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;

#[derive(Default)]
struct State {
    started: u64,
    mode: String,
    scanner: String,
    detected: u64,
    removed: u64,
    scans: u64,
    clean: u64,
    alerts: u64,
    failed: u64,
    bypassed: u64,
    last_alert: String,
    active: BTreeMap<u64, (String, u64)>,
    devices: Vec<Device>,
}

#[derive(Clone, Copy)]
pub enum Counter {
    Detected,
    Removed,
    Clean,
    Alert,
    Failed,
    Bypassed,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with<F: FnOnce(&mut State)>(f: F) {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = g.as_mut() {
        f(s);
    }
}

pub fn init(mode: &str, scanner: &str) {
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(State { started: now_secs(), mode: mode.into(), scanner: scanner.into(), ..State::default() });
    flush();
}

pub fn inc(c: Counter) {
    with(|s| match c {
        Counter::Detected => s.detected += 1,
        Counter::Removed => s.removed += 1,
        Counter::Clean => s.clean += 1,
        Counter::Alert => s.alerts += 1,
        Counter::Failed => s.failed += 1,
        Counter::Bypassed => s.bypassed += 1,
    });
}

pub fn alert(desc: String) {
    with(|s| s.last_alert = desc);
}

pub fn scan_begin(id: u64, mount: &str) {
    with(|s| {
        s.scans += 1;
        s.active.insert(id, (mount.to_string(), now_secs()));
    });
    flush();
}

pub fn scan_end(id: u64) {
    with(|s| {
        s.active.remove(&id);
    });
    flush();
}

pub fn set_devices(d: &[Device]) {
    with(|s| s.devices = d.to_vec());
    flush();
}

/// Writes status.json atomically (tmp + rename).
pub fn flush() {
    let g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = g.as_ref() else { return };
    let now = now_secs();
    let mut j = String::from("{\n");
    let _ = writeln!(j, "  \"version\": {},", json_str(env!("CARGO_PKG_VERSION")));
    let _ = writeln!(j, "  \"pid\": {},", std::process::id());
    let _ = writeln!(j, "  \"started\": {},", json_str(&format_epoch(s.started, None)));
    let _ = writeln!(j, "  \"updated\": {},", json_str(&format_epoch(now, None)));
    let _ = writeln!(j, "  \"uptime_secs\": {},", now.saturating_sub(s.started));
    let _ = writeln!(j, "  \"mode\": {},", json_str(&s.mode));
    let _ = writeln!(j, "  \"scanner\": {},", json_str(&s.scanner));
    let _ = writeln!(j, "  \"log_level\": {},", json_str(crate::log::level().as_str()));
    let _ = writeln!(
        j,
        "  \"counters\": {{\"detected\": {}, \"removed\": {}, \"scans\": {}, \"clean\": {}, \"alerts\": {}, \"failed\": {}, \"bypassed\": {}}},",
        s.detected, s.removed, s.scans, s.clean, s.alerts, s.failed, s.bypassed
    );
    let _ = writeln!(j, "  \"last_alert\": {},", json_str(&s.last_alert));
    let active: Vec<String> = s
        .active
        .iter()
        .map(|(id, (m, t))| format!("{{\"scan\": {id}, \"mount\": {}, \"running_secs\": {}}}", json_str(m), now.saturating_sub(*t)))
        .collect();
    let _ = writeln!(j, "  \"active_scans\": [{}],", active.join(", "));
    let devs: Vec<String> = s
        .devices
        .iter()
        .map(|d| format!("{{\"mount\": {}, \"id\": {}, \"desc\": {}}}", json_str(&d.mount.to_string_lossy()), json_str(&d.id), json_str(&d.desc)))
        .collect();
    let _ = writeln!(j, "  \"usb_volumes\": [{}],", devs.join(", "));
    let recent: Vec<String> = crate::log::recent().iter().rev().take(20).map(|l| format!("    {}", json_str(l))).collect();
    let _ = writeln!(j, "  \"recent_events\": [\n{}\n  ]", recent.join(",\n"));
    j.push_str("}\n");
    drop(g);

    let path = crate::config::status_file();
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, j).and_then(|_| std::fs::rename(&tmp, &path)).is_err() {
        debug!("cannot write {}", path.display());
    }
}

/// Reads the `"pid": N` field of an existing status.json.
pub fn read_pid(text: &str) -> Option<u32> {
    let i = text.find("\"pid\":")?;
    text[i + 6..].trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}
