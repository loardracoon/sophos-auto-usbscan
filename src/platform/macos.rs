//! macOS: kqueue watch on /Volumes (fires when a volume is mounted or
//! unmounted) plus a 30 s safety re-check; getfsstat(2) lists mounts and
//! `diskutil info` (once per new volume, then cached) tells whether the
//! backing disk is on the USB bus.

use crate::config::Config;
use crate::diag::Check;
use crate::{Device, Probe};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use crate::unix::{is_admin, notify_reload, pid_alive};
use crate::unix::{copy_self, require_root};

const BIN: &str = "/usr/local/bin/usbscan";
const LABEL: &str = "com.usbscan.daemon";
const PLIST: &str = "/Library/LaunchDaemons/com.usbscan.daemon.plist";

pub struct Watcher {
    kq: i32,
    _vol: i32,
    /// (dev node, mount point) -> classification (diskutil runs once per volume).
    known: HashMap<(String, String), Probe>,
}

impl Watcher {
    pub fn new(_cfg: &Config) -> Watcher {
        unsafe {
            let kq = libc::kqueue();
            let vol = libc::open(c"/Volumes".as_ptr(), libc::O_EVTONLY);
            if kq >= 0 && vol >= 0 {
                let mut ev: libc::kevent = std::mem::zeroed();
                ev.ident = vol as usize;
                ev.filter = libc::EVFILT_VNODE;
                ev.flags = libc::EV_ADD | libc::EV_CLEAR;
                ev.fflags = libc::NOTE_WRITE;
                libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null());
            }
            Watcher { kq, _vol: vol, known: HashMap::new() }
        }
    }

    pub fn probe(&mut self) -> Vec<Probe> {
        let mounts = list_mounts();
        self.known.retain(|k, _| mounts.contains(k));
        mounts
            .into_iter()
            .map(|(from, on)| self.known.entry((from.clone(), on.clone())).or_insert_with(|| diskutil(&from, &on)).clone())
            .collect()
    }

    pub fn wait(&mut self) {
        let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
        let ts = libc::timespec { tv_sec: 30, tv_nsec: 0 };
        if self.kq < 0 {
            std::thread::sleep(std::time::Duration::from_secs(5));
            return;
        }
        unsafe { libc::kevent(self.kq, std::ptr::null(), 0, &mut ev, 1, &ts) };
        // Volume appears in /Volumes slightly before the mount completes.
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

fn cstr(buf: &[libc::c_char]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
}

fn list_mounts() -> Vec<(String, String)> {
    unsafe {
        let n = libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT);
        if n <= 0 {
            return Vec::new();
        }
        let mut buf: Vec<libc::statfs> = vec![std::mem::zeroed(); n as usize + 8];
        let size = (buf.len() * std::mem::size_of::<libc::statfs>()) as libc::c_int;
        let n = libc::getfsstat(buf.as_mut_ptr(), size, libc::MNT_NOWAIT);
        buf.truncate(n.max(0) as usize);
        buf.iter()
            .map(|s| (cstr(&s.f_mntfromname), cstr(&s.f_mntonname)))
            .filter(|(from, _)| from.starts_with("/dev/disk"))
            .collect()
    }
}

/// Classifies a volume with `diskutil info` (Protocol: USB).
fn diskutil(dev: &str, mount: &str) -> Probe {
    let mut p = Probe {
        mount: PathBuf::from(mount),
        source: dev.to_string(),
        usb: false,
        id: String::new(),
        desc: String::new(),
        reason: String::new(),
    };
    let out = match Command::new("/usr/sbin/diskutil").args(["info", dev]).output() {
        Ok(o) => o,
        Err(e) => {
            p.reason = format!("diskutil failed: {e}");
            return p;
        }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(k).and_then(|v| v.trim_start().strip_prefix(':')).map(|v| v.trim().to_string()))
            .unwrap_or_default()
    };
    let protocol = field("Protocol");
    if protocol != "USB" {
        p.reason = format!("diskutil Protocol: {}", if protocol.is_empty() { "<none>" } else { &protocol });
        return p;
    }
    let media = field("Device / Media Name");
    let mut uuid = field("Volume UUID");
    if uuid.is_empty() {
        uuid = field("Disk / Partition UUID");
    }
    p.usb = true;
    p.id = format!("{}:{}", media.replace(' ', "_"), if uuid.is_empty() { dev } else { &uuid });
    p.desc = format!("{} {}", field("Type (Bundle)"), media).trim().to_string();
    p.reason = "diskutil Protocol: USB".into();
    p
}

pub fn service_state() -> String {
    if !Path::new(PLIST).exists() {
        return "not installed (no LaunchDaemon plist)".into();
    }
    match Command::new("launchctl").args(["print", &format!("system/{LABEL}")]).output() {
        Ok(o) if o.status.success() => {
            let t = String::from_utf8_lossy(&o.stdout);
            let get = |k: &str| t.lines().find_map(|l| l.trim().strip_prefix(k)).unwrap_or("?").trim().to_string();
            format!("{}, pid {}, last exit {}", get("state ="), get("pid ="), get("last exit code ="))
        }
        Ok(_) => "installed but not loaded".into(),
        Err(e) => format!("unknown (launchctl: {e})"),
    }
}

pub fn doctor(_cfg: &Config) -> Vec<(Check, String, String)> {
    let mut v = Vec::new();
    let du = Path::new("/usr/sbin/diskutil").exists();
    v.push((if du { Check::Ok } else { Check::Fail }, "diskutil".into(), if du { "found" } else { "missing" }.into()));
    // Reading the TCC database requires Full Disk Access: a cheap FDA probe
    // for *this* process (the daemon needs its own grant for usbscan).
    let fda = fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db").is_ok();
    v.push((
        if fda { Check::Ok } else { Check::Warn },
        "full disk access".into(),
        if fda {
            "granted to this process".into()
        } else {
            format!("not granted to this process; make sure {BIN} has Full Disk Access")
        },
    ));
    v
}

pub fn release(_dev: &Device) {}

pub fn install(cfg_path: &Path) -> Result<(), String> {
    require_root()?;
    copy_self(BIN)?;
    crate::config::write_default(cfg_path)?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{BIN}</string><string>run</string><string>--config</string><string>{}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>StandardErrorPath</key><string>/dev/null</string>
  <key>StandardOutPath</key><string>/dev/null</string>
</dict>
</plist>
"#,
        cfg_path.display()
    );
    fs::write(PLIST, plist).map_err(|e| format!("write {PLIST}: {e}"))?;
    let _ = Command::new("launchctl").args(["bootout", &format!("system/{LABEL}")]).output();
    let s = Command::new("launchctl").args(["bootstrap", "system", PLIST]).status().map_err(|e| e.to_string())?;
    if !s.success() {
        return Err("launchctl bootstrap failed".into());
    }
    println!(
        "installed: {BIN}\nconfig:    {}\ndaemon:    {LABEL} (running)\nlog:       /var/log/usbscan.log\n\
         NOTE: grant Full Disk Access to {BIN} (System Settings > Privacy & Security) so it can read removable volumes.",
        cfg_path.display()
    );
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    require_root()?;
    let _ = Command::new("launchctl").args(["bootout", &format!("system/{LABEL}")]).status();
    let _ = fs::remove_file(PLIST);
    let _ = fs::remove_file(BIN);
    println!("usbscan daemon removed (config, cache and log kept)");
    Ok(())
}
