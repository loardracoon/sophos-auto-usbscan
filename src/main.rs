//! usbscan — triggers an antivirus scan every time USB mass storage is mounted.
//!
//! Sophos on-access protection only raises an alert when a file is actually
//! opened/read. A freshly inserted USB drive whose files nobody touches is
//! therefore never inspected. usbscan closes that gap by actively scanning
//! every new USB volume, using one of two strategies:
//!
//! * `cli`   – runs the Sophos on-demand scanner (avscanner / SophosInterceptXCLI / sweep)
//! * `touch` – walks the volume and opens/reads every file, forcing the
//!   on-access engine to inspect (and alert on) each one
//!
//! `auto` (default) uses `cli` when a scanner binary is found, `touch` otherwise.
//! `both` runs `cli` and then `touch`.

#[macro_use]
mod log;
mod cache;
mod config;
mod diag;
mod engine;
mod scan;
mod status;
#[cfg(unix)]
mod unix;

#[cfg_attr(target_os = "linux", path = "platform/linux.rs")]
#[cfg_attr(target_os = "macos", path = "platform/macos.rs")]
#[cfg_attr(windows, path = "platform/windows.rs")]
mod platform;

use log::Level;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Set by SIGTERM/SIGINT or the Windows SCM stop control.
pub static STOP: AtomicBool = AtomicBool::new(false);
/// Set by SIGUSR1 or Windows user control 128: re-read the log level override.
pub static RELOAD: AtomicBool = AtomicBool::new(false);

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

/// One mounted volume as evaluated by the platform detector, with the
/// reason it was (or was not) classified as USB storage.
#[derive(Clone, Debug)]
pub struct Probe {
    pub mount: PathBuf,
    pub source: String,
    pub usb: bool,
    pub id: String,
    pub desc: String,
    pub reason: String,
}

impl Probe {
    fn device(&self) -> Device {
        Device { mount: self.mount.clone(), id: self.id.clone(), desc: format!("{} {}", self.source, self.desc).trim().to_string() }
    }
}

const USAGE: &str = "\
usbscan - antivirus scan trigger for USB storage

SERVICE
  usbscan install   [--config FILE]   install binary + config and start the service
  usbscan uninstall                   stop and remove the service

RUN / SCAN
  usbscan run  [--debug|--trace] [--json] [--no-cache] [--config FILE]
                                      run the monitor in the foreground (logs to console)
  usbscan scan PATH [--debug|--trace] scan a path now with the configured strategy

OBSERVABILITY / TROUBLESHOOTING
  usbscan status [--json]             service state, counters, active scans, recent events
  usbscan logs [-n N] [-f] [--scan ID]
                                      show the log (last N lines, follow, one scan only)
  usbscan debug on|trace|off          change the running service's log level, no restart
  usbscan doctor                      check installation, permissions and scanner
  usbscan devices [--all]             USB volumes detected (--all: every volume + reason)
  usbscan cache [list|clear]          show or clear the scanned-device cache
  usbscan config                      print the effective configuration
  usbscan version
";

#[derive(Default)]
struct Args {
    level: Option<Level>,
    json: bool,
    no_cache: bool,
    all: bool,
    follow: bool,
    lines: Option<usize>,
    scan: Option<String>,
    cfg_path: Option<PathBuf>,
    positional: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = args.iter();
    while let Some(s) = it.next() {
        match s.as_str() {
            "--debug" | "-d" => a.level = Some(Level::Debug),
            "--trace" => a.level = Some(Level::Trace),
            "--json" => a.json = true,
            "--no-cache" => a.no_cache = true,
            "--all" | "-a" => a.all = true,
            "--follow" | "-f" => a.follow = true,
            "-n" | "--lines" => {
                a.lines = Some(it.next().and_then(|v| v.parse().ok()).ok_or("-n needs a number")?);
            }
            "--scan" => a.scan = Some(it.next().ok_or("--scan needs an id")?.trim_start_matches("scan-").to_string()),
            "--config" | "-c" => a.cfg_path = Some(PathBuf::from(it.next().ok_or("--config needs a file")?)),
            x if x.starts_with('-') && x.len() > 1 => return Err(format!("unknown option '{x}'")),
            _ => a.positional.push(s.clone()),
        }
    }
    Ok(a)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().map(String::as_str).unwrap_or("");

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

    let a = match parse_args(argv.get(1..).unwrap_or(&[])) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let cfg_path = a.cfg_path.clone().unwrap_or_else(config::default_path);
    let load = || {
        let mut c = config::Config::load(&cfg_path);
        if let Some(l) = a.level {
            c.log_level = c.log_level.max(l);
        }
        c.log_json |= a.json && cmd == "run";
        if a.no_cache {
            c.cache_ttl = 0;
        }
        c
    };

    let res: Result<(), String> = match cmd {
        "run" => {
            let cfg = load();
            log::init(&cfg, true);
            for w in &cfg.warnings {
                warn!("config: {w}");
            }
            run_monitor(cfg);
            Ok(())
        }
        "scan" => match a.positional.first() {
            None => Err("scan: missing PATH".into()),
            Some(p) => {
                let cfg = load();
                log::init(&cfg, true);
                let dev = Device { mount: PathBuf::from(p), id: String::new(), desc: "manual".into() };
                match scan::run(&cfg, &dev) {
                    Ok(r) => {
                        println!("CLEAN: {r}");
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        },
        "status" => diag::status(&load(), a.json),
        "logs" => diag::logs(&load(), a.lines.unwrap_or(50), a.follow, a.scan.as_deref()),
        "debug" => diag::debug_cmd(a.positional.first().map(String::as_str)),
        "doctor" => diag::doctor(&load()),
        "devices" => {
            diag::devices(&load(), a.all);
            Ok(())
        }
        "cache" => diag::cache_cmd(&load(), a.positional.first().map(String::as_str).unwrap_or("list")),
        "config" => {
            let c = load();
            for w in &c.warnings {
                eprintln!("warning: {w}");
            }
            print!("{}", c.dump());
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("usbscan {} ({}/{})", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH);
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

/// Applies (or clears) the runtime log level override written by
/// `usbscan debug`.
fn apply_level_override() {
    let before = log::level();
    match std::fs::read_to_string(diag::override_file()).ok().and_then(|s| Level::parse(s.trim())) {
        Some(l) => log::set_level(l),
        None => log::restore_level(),
    }
    let after = log::level();
    // Logged at error level so the change is always visible.
    ev!(Error, "log_level_changed", from = before.as_str(), to = after.as_str());
    status::flush();
}

/// USB volumes from a probe; also traces why other volumes were ignored.
fn usb_devices(probes: &[Probe]) -> Vec<Device> {
    for p in probes.iter().filter(|p| !p.usb) {
        trace!("ignored {} ({}): {}", p.mount.display(), p.source, p.reason);
    }
    probes.iter().filter(|p| p.usb).map(Probe::device).collect()
}

/// Main service loop shared by every OS: diff the set of mounted USB volumes
/// and hand new ones to the engine. `Watcher::wait` blocks on a native
/// change notification (Linux: mountinfo poll, macOS: kqueue, Windows: cheap
/// drive bitmask poll), so the loop costs ~0 CPU while idle.
pub fn run_monitor(cfg: config::Config) {
    #[cfg(unix)]
    unix::install_signal_handlers();
    // A debug override from a previous run must not survive a restart.
    let _ = std::fs::remove_file(diag::override_file());

    let cfg = Arc::new(cfg);
    let scanner = scan::resolve_scanner(&cfg).map(|s| s.0.display().to_string()).unwrap_or_else(|| "<none>".into());
    let (cli, touch) = scan::strategies(&cfg);
    ev!(
        Info,
        "service_start",
        version = env!("CARGO_PKG_VERSION"),
        pid = std::process::id(),
        os = std::env::consts::OS,
        config = cfg.path.display(),
        mode = cfg.mode.as_str(),
        cli = cli,
        touch = touch,
        scanner = scanner,
        cache_ttl = cfg.cache_ttl,
        log_level = cfg.log_level.as_str(),
    );
    debug!("effective configuration:\n{}", cfg.dump().trim_end());
    status::init(cfg.mode.as_str(), &scanner);

    let engine = engine::Engine::new(cfg.clone());
    let mut watcher = platform::Watcher::new(&cfg);
    let mut known: Vec<Device> = usb_devices(&watcher.probe());
    status::set_devices(&known);

    if cfg.scan_on_start {
        for d in &known {
            ev!(Info, "device_present", mount = d.mount.display(), device = d.id, desc = d.desc);
            status::inc(status::Counter::Detected);
            engine.submit(d.clone());
        }
    } else {
        debug!("scan_on_start=false: ignoring {} USB volume(s) already mounted", known.len());
    }
    info!("monitor active, waiting for USB storage");

    while !stopping() {
        watcher.wait();
        if stopping() {
            break;
        }
        if RELOAD.swap(false, Ordering::Relaxed) {
            apply_level_override();
        }
        let probes = watcher.probe();
        let now = usb_devices(&probes);
        trace!("volume table re-read: {} volume(s), {} USB", probes.len(), now.len());
        let mut changed = false;
        for d in &now {
            if !known.contains(d) {
                ev!(Info, "device_detected", mount = d.mount.display(), device = d.id, desc = d.desc);
                status::inc(status::Counter::Detected);
                engine.submit(d.clone());
                changed = true;
            }
        }
        for d in &known {
            if !now.contains(d) {
                ev!(Info, "device_removed", mount = d.mount.display(), device = d.id);
                status::inc(status::Counter::Removed);
                changed = true;
            }
        }
        if changed {
            status::set_devices(&now);
        }
        known = now;
    }
    ev!(Info, "service_stop", pid = std::process::id());
    let _ = std::fs::remove_file(diag::override_file());
    status::flush();
}
