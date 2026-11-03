//! usbscan — triggers an antivirus scan every time USB mass storage is mounted.
//!
//! Sophos on-access protection only raises an alert when a file is actually
//! opened/read. A freshly inserted pen drive whose files nobody touches is
//! therefore never inspected. usbscan closes that gap by actively scanning
//! every new USB volume, using one of two strategies:
//!
//! * `cli`   – calls the Sophos on-demand scanner (avscanner / SophosInterceptXCLI / sweep)
//! * `touch` – walks the volume and opens/reads every file, forcing the
//!   on-access engine to inspect (and alert on) each one
//!
//! `auto` (default) uses `cli` when a scanner binary is found, `touch` otherwise.
//! `both` runs `cli` and then `touch`.

#[macro_use]
mod log;
mod cache;
mod config;
mod engine;
mod scan;
#[cfg(unix)]
mod unix;

#[cfg_attr(target_os = "linux", path = "platform/linux.rs")]
#[cfg_attr(target_os = "macos", path = "platform/macos.rs")]
#[cfg_attr(windows, path = "platform/windows.rs")]
mod platform;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub static STOP: AtomicBool = AtomicBool::new(false);

pub fn stopping() -> bool {
    STOP.load(Ordering::Relaxed)
}

/// A mounted USB volume.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Device {
    /// Where the volume is mounted (`/media/x/STICK`, `/Volumes/STICK`, `E:\`).
    pub mount: PathBuf,
    /// Stable identity used by the cache (vendor/product/serial/partition).
    pub id: String,
    /// Human readable description for the log.
    pub desc: String,
}

const USAGE: &str = "\
usbscan - antivirus scan trigger for USB storage

USAGE:
  usbscan install   [--config FILE]   install binary + config and start as a service
  usbscan uninstall                   stop and remove the service
  usbscan run       [--debug] [--no-cache] [--config FILE]
                                      run the monitor in the foreground
  usbscan scan PATH [--debug] [--config FILE]
                                      scan a path now with the configured strategy
  usbscan devices                     list USB volumes currently mounted
  usbscan config                      print the effective configuration
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("");

    let mut debug = false;
    let mut no_cache = false;
    let mut cfg_path: Option<PathBuf> = None;
    let mut positional: Vec<String> = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--debug" | "-d" => debug = true,
            "--no-cache" => no_cache = true,
            "--config" | "-c" => cfg_path = it.next().map(PathBuf::from),
            _ => positional.push(a.clone()),
        }
    }
    let cfg_path = cfg_path.unwrap_or_else(config::default_path);

    // The Windows SCM entry point must be dispatched before anything else.
    #[cfg(windows)]
    if cmd == "service" {
        return match platform::service_dispatch() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("service dispatcher failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let load = |debug: bool, no_cache: bool| {
        let mut c = config::Config::load(&cfg_path);
        c.debug |= debug;
        if no_cache {
            c.cache_ttl = 0;
        }
        c
    };

    let res: Result<(), String> = match cmd {
        "run" => {
            let cfg = load(debug, no_cache);
            log::init(&cfg, true);
            run_monitor(cfg);
            Ok(())
        }
        "scan" => match positional.first() {
            None => Err("scan: missing PATH".into()),
            Some(p) => {
                let cfg = load(debug, no_cache);
                log::init(&cfg, true);
                let dev = Device { mount: PathBuf::from(p), id: String::new(), desc: "manual".into() };
                scan::run(&cfg, &dev).map(|r| println!("{r}"))
            }
        },
        "devices" => {
            let cfg = load(debug, no_cache);
            let mut w = platform::Watcher::new(&cfg);
            for d in w.usb_mounts() {
                println!("{}\t{}\t{}", d.mount.display(), d.id, d.desc);
            }
            Ok(())
        }
        "config" => {
            print!("{}", load(debug, no_cache).dump());
            Ok(())
        }
        "install" => platform::install(&cfg_path),
        "uninstall" => platform::uninstall(),
        "" | "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Main service loop shared by every OS: diff the set of mounted USB volumes
/// and hand new ones to the engine. `Watcher::wait` blocks on a native
/// change notification (Linux: mountinfo poll, macOS: kqueue, Windows: cheap
/// drive bitmask poll), so the loop costs ~0 CPU while idle.
pub fn run_monitor(cfg: config::Config) {
    #[cfg(unix)]
    platform::install_signal_handlers();

    let cfg = Arc::new(cfg);
    info!(
        "usbscan {} starting (mode={}, scanner={}, cache_ttl={}s)",
        env!("CARGO_PKG_VERSION"),
        cfg.mode.as_str(),
        scan::resolve_scanner(&cfg).map(|s| s.0.display().to_string()).unwrap_or_else(|| "<none>".into()),
        cfg.cache_ttl
    );

    let engine = engine::Engine::new(cfg.clone());
    let mut watcher = platform::Watcher::new(&cfg);
    let mut known: Vec<Device> = watcher.usb_mounts();

    if cfg.scan_on_start {
        for d in &known {
            engine.submit(d.clone());
        }
    } else {
        debug!("ignoring {} USB volume(s) already mounted at start", known.len());
    }
    info!("monitor active, waiting for USB storage");

    while !stopping() {
        watcher.wait();
        if stopping() {
            break;
        }
        let now = watcher.usb_mounts();
        debug!("mount change: {} USB volume(s) mounted", now.len());
        for d in &now {
            if !known.contains(d) {
                info!("USB volume detected: {} [{}] {}", d.mount.display(), d.id, d.desc);
                engine.submit(d.clone());
            }
        }
        for d in &known {
            if !now.contains(d) {
                info!("USB volume removed: {}", d.mount.display());
            }
        }
        known = now;
    }
    info!("usbscan stopping");
}
