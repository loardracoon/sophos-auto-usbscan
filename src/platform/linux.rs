//! Linux: event driven via poll(2) on /proc/self/mountinfo (fires on every
//! mount/umount) and, optionally, the kernel uevent netlink socket to mount
//! USB partitions on headless machines. USB detection uses sysfs only — no
//! udev/udisks/jq dependency.

use crate::config::Config;
use crate::Device;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const OWN_MOUNTS: &str = "/run/usbscan";
const BIN: &str = "/usr/local/bin/usbscan";
const UNIT: &str = "/etc/systemd/system/usbscan.service";

pub struct Watcher {
    mountinfo: fs::File,
    uevent: Option<OwnedFd>,
    settle: u64,
}

impl Watcher {
    pub fn new(cfg: &Config) -> Watcher {
        let mountinfo = fs::File::open("/proc/self/mountinfo").expect("open /proc/self/mountinfo");
        let uevent = if cfg.auto_mount { open_uevent() } else { None };
        Watcher { mountinfo, uevent, settle: cfg.settle }
    }

    pub fn usb_mounts(&mut self) -> Vec<Device> {
        let mut text = String::new();
        let _ = self.mountinfo.seek(SeekFrom::Start(0));
        let _ = self.mountinfo.read_to_string(&mut text);
        let mut out: Vec<Device> = Vec::new();
        for line in text.lines() {
            let Some(m) = parse_mountinfo(line) else { continue };
            if !m.source.starts_with("/dev/") || out.iter().any(|d| d.mount == m.mount) {
                continue;
            }
            let Ok(sys) = fs::canonicalize(format!("/sys/dev/block/{}", m.majmin)) else { continue };
            if !sys.to_string_lossy().contains("/usb") {
                continue;
            }
            let (id, desc) = identify(&sys, &m.majmin);
            out.push(Device {
                mount: PathBuf::from(&m.mount),
                id,
                desc: format!("{} {} {}", m.source, m.fstype, desc),
            });
        }
        out
    }

    /// Blocks until the mount table changes or a stop is requested.
    pub fn wait(&mut self) {
        loop {
            let mut fds = vec![libc::pollfd { fd: self.mountinfo.as_raw_fd(), events: libc::POLLPRI, revents: 0 }];
            if let Some(u) = &self.uevent {
                fds.push(libc::pollfd { fd: u.as_raw_fd(), events: libc::POLLIN, revents: 0 });
            }
            let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if crate::stopping() {
                return;
            }
            if r < 0 {
                continue; // EINTR
            }
            if fds.len() > 1 && fds[1].revents & libc::POLLIN != 0 {
                self.handle_uevent();
            }
            if fds[0].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
                return;
            }
        }
    }

    fn handle_uevent(&mut self) {
        let Some(u) = &self.uevent else { return };
        let mut buf = [0u8; 8192];
        let n = unsafe { libc::recv(u.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n <= 0 {
            return;
        }
        let (mut action, mut subsystem, mut devname, mut devpath) = ("", "", "", "");
        for kv in buf[..n as usize].split(|b| *b == 0).filter_map(|s| std::str::from_utf8(s).ok()) {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "ACTION" => action = v,
                    "SUBSYSTEM" => subsystem = v,
                    "DEVNAME" => devname = v,
                    "DEVPATH" => devpath = v,
                    _ => {}
                }
            }
        }
        if action != "add" || subsystem != "block" || !devpath.contains("/usb") || devname.is_empty() {
            return;
        }
        let name = devname.trim_start_matches("/dev/").to_string();
        let wait = Duration::from_secs(self.settle.max(1) + 5);
        debug!("uevent: USB block device {name} added");
        let _ = std::thread::Builder::new().stack_size(128 * 1024).spawn(move || {
            std::thread::sleep(wait); // give a desktop automounter the first chance
            auto_mount(&name);
        });
    }
}

struct MountInfo {
    majmin: String,
    mount: String,
    fstype: String,
    source: String,
}

fn parse_mountinfo(line: &str) -> Option<MountInfo> {
    let (pre, post) = line.split_once(" - ")?;
    let f: Vec<&str> = pre.split(' ').collect();
    let mut p = post.split(' ');
    Some(MountInfo {
        majmin: f.get(2)?.to_string(),
        mount: unescape(f.get(4)?),
        fstype: p.next()?.to_string(),
        source: unescape(p.next()?),
    })
}

/// mountinfo escapes space, tab, newline and backslash as \ooo.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_trim(p: &Path) -> String {
    fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Builds `vendor:product:serial:partN` from the USB device node in sysfs.
fn identify(sys: &Path, majmin: &str) -> (String, String) {
    let part = read_trim(&PathBuf::from(format!("/sys/dev/block/{majmin}/partition")));
    let usb = sys.ancestors().find(|a| a.join("idVendor").is_file());
    let Some(usb) = usb else { return (format!("dev:{majmin}"), String::new()) };
    let (vid, pid, serial) = (read_trim(&usb.join("idVendor")), read_trim(&usb.join("idProduct")), read_trim(&usb.join("serial")));
    let desc = format!("{} {}", read_trim(&usb.join("manufacturer")), read_trim(&usb.join("product")));
    let serial = if serial.is_empty() { format!("noserial-{majmin}") } else { serial };
    (format!("{vid}:{pid}:{serial}:p{}", if part.is_empty() { "0" } else { &part }), desc.trim().to_string())
}

fn open_uevent() -> Option<OwnedFd> {
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::NETLINK_KOBJECT_UEVENT);
        if fd < 0 {
            warn!("auto_mount: cannot open uevent socket");
            return None;
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as _;
        sa.nl_groups = 1; // kernel events
        let r = libc::bind(fd, (&sa as *const libc::sockaddr_nl).cast(), std::mem::size_of::<libc::sockaddr_nl>() as _);
        if r < 0 {
            warn!("auto_mount: cannot bind uevent socket (needs root)");
            return None;
        }
        Some(owned)
    }
}

fn is_mounted(name: &str) -> bool {
    let majmin = read_trim(&PathBuf::from(format!("/sys/class/block/{name}/dev")));
    fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .filter_map(parse_mountinfo)
        .any(|m| m.majmin == majmin || m.source == format!("/dev/{name}"))
}

fn auto_mount(name: &str) {
    let sys = PathBuf::from(format!("/sys/class/block/{name}"));
    if !sys.exists() || is_mounted(name) {
        return;
    }
    // Whole disk with a partition table: its partitions get their own events.
    let has_parts = fs::read_dir(&sys)
        .map(|rd| rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with(name)))
        .unwrap_or(false);
    if has_parts {
        return;
    }
    let dir = PathBuf::from(OWN_MOUNTS).join(name);
    let _ = fs::create_dir_all(&dir);
    let ok = Command::new("mount")
        .args(["-o", "ro,nosuid,nodev,noexec", &format!("/dev/{name}")])
        .arg(&dir)
        .output();
    match ok {
        Ok(o) if o.status.success() => info!("auto_mount: /dev/{name} mounted read-only at {}", dir.display()),
        Ok(o) => {
            debug!("auto_mount: /dev/{name} not mountable: {}", String::from_utf8_lossy(&o.stderr).trim());
            let _ = fs::remove_dir(&dir);
        }
        Err(e) => {
            warn!("auto_mount: cannot run mount: {e}");
            let _ = fs::remove_dir(&dir);
        }
    }
}

/// Called after a device was processed: undo our own read-only mounts.
pub fn release(dev: &Device) {
    if dev.mount.starts_with(OWN_MOUNTS) {
        let _ = Command::new("umount").arg(&dev.mount).status();
        let _ = fs::remove_dir(&dev.mount);
        debug!("auto_mount: released {}", dev.mount.display());
    }
}

pub use crate::unix::install_signal_handlers;
use crate::unix::{copy_self, require_root};

fn systemctl(args: &[&str]) -> Result<(), String> {
    let s = Command::new("systemctl").args(args).status().map_err(|e| format!("systemctl: {e} (systemd required)"))?;
    if s.success() { Ok(()) } else { Err(format!("systemctl {} failed", args.join(" "))) }
}

pub fn install(cfg_path: &Path) -> Result<(), String> {
    require_root()?;
    copy_self(BIN)?;
    crate::config::write_default(cfg_path)?;
    let unit = format!(
        "[Unit]\n\
         Description=usbscan - antivirus scan of USB storage on insertion\n\
         After=local-fs.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={BIN} run --config {}\n\
         Restart=always\n\
         RestartSec=3\n\
         Nice=10\n\
         IOSchedulingClass=best-effort\n\
         IOSchedulingPriority=7\n\
         StandardOutput=null\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        cfg_path.display()
    );
    fs::write(UNIT, unit).map_err(|e| format!("write {UNIT}: {e}"))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "usbscan.service"])?;
    systemctl(&["restart", "usbscan.service"])?;
    println!("installed: {BIN}\nconfig:    {}\nservice:   usbscan.service (enabled, running)\nlog:       /var/log/usbscan.log", cfg_path.display());
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    require_root()?;
    let _ = systemctl(&["disable", "--now", "usbscan.service"]);
    let _ = fs::remove_file(UNIT);
    let _ = systemctl(&["daemon-reload"]);
    let _ = fs::remove_file(BIN);
    println!("usbscan service removed (config, cache and log kept)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mountinfo_line() {
        let l = "36 35 8:17 / /media/u/MY\\040STICK rw,nosuid shared:1 - vfat /dev/sdb1 rw,uid=1000";
        let m = parse_mountinfo(l).unwrap();
        assert_eq!(m.majmin, "8:17");
        assert_eq!(m.mount, "/media/u/MY STICK");
        assert_eq!(m.fstype, "vfat");
        assert_eq!(m.source, "/dev/sdb1");
    }
}
