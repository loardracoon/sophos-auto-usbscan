//! Scan strategies: Sophos on-demand CLI and on-access "touch".

use crate::config::{Config, Mode};
use crate::Device;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Known on-demand scanners: (binary, default args). `{path}` = mount point.
#[cfg(target_os = "linux")]
pub const CANDIDATES: &[(&str, &str)] = &[
    ("/opt/sophos-spl/plugins/av/bin/avscanner", "{path} --scan-archives"),
    ("/opt/sophos-av/bin/savscan", "-archive {path}"),
];
#[cfg(target_os = "macos")]
pub const CANDIDATES: &[(&str, &str)] = &[("/usr/local/bin/sweep", "-archive {path}")];
#[cfg(windows)]
pub const CANDIDATES: &[(&str, &str)] = &[
    (r"C:\Program Files\Sophos\Endpoint Defense\SophosInterceptXCLI.exe", "scan --noui --expand_archives {path}"),
    (r"C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sav32cli.exe", "-archive {path}"),
];

/// Why a scan did not end clean.
#[derive(Debug)]
pub enum ScanError {
    /// The scanner / on-access engine reported a threat.
    Threat(String),
    /// The scan could not be completed (missing scanner, timeout, error code...).
    Failed(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Threat(s) => write!(f, "threat: {s}"),
            ScanError::Failed(s) => write!(f, "failed: {s}"),
        }
    }
}

/// Returns the scanner binary and its argument template.
pub fn resolve_scanner(cfg: &Config) -> Option<(PathBuf, String)> {
    if let Some(p) = &cfg.scanner {
        let args = cfg
            .scanner_args
            .clone()
            .or_else(|| CANDIDATES.iter().find(|(c, _)| Path::new(c) == p).map(|(_, a)| a.to_string()));
        return Some((p.clone(), args.unwrap_or_else(|| "{path}".into())));
    }
    CANDIDATES
        .iter()
        .find(|(c, _)| Path::new(c).is_file())
        .map(|(c, a)| (PathBuf::from(c), cfg.scanner_args.clone().unwrap_or_else(|| a.to_string())))
}

/// Which strategies `mode` resolves to: (cli, touch).
pub fn strategies(cfg: &Config) -> (bool, bool) {
    let found = resolve_scanner(cfg).is_some();
    match cfg.mode {
        Mode::Cli => (true, false),
        Mode::Touch => (false, true),
        Mode::Both => (true, true),
        Mode::Auto => (found, !found),
    }
}

/// Runs the configured strategy. Ok = clean summary.
pub fn run(cfg: &Config, dev: &Device) -> Result<String, ScanError> {
    let (cli, touch) = strategies(cfg);
    debug!("strategy for {}: cli={cli} touch={touch} (mode={})", dev.mount.display(), cfg.mode.as_str());
    let mut out = Vec::new();
    if cli {
        let Some((exe, args)) = resolve_scanner(cfg) else {
            return Err(ScanError::Failed("mode=cli but no scanner binary found (set 'scanner =')".into()));
        };
        out.push(run_cli(cfg, &exe, &args, &dev.mount)?);
    }
    if touch {
        out.push(run_touch(cfg, &dev.mount)?);
    }
    Ok(out.join("; "))
}

/// Forwards each line of a child stream into the log, tagged with the
/// scan's thread name so it stays correlated with the scan.
fn pump<R: Read + Send + 'static>(r: R, stream: &'static str) -> Option<std::thread::JoinHandle<()>> {
    let name = std::thread::current().name().unwrap_or("scan").to_string();
    std::thread::Builder::new()
        .name(name)
        .stack_size(64 * 1024)
        .spawn(move || {
            for line in BufReader::new(r).lines().map_while(Result::ok) {
                let line = line.trim_end();
                if !line.is_empty() {
                    ev!(Info, "scanner_output", stream = stream, line = line);
                }
            }
        })
        .ok()
}

fn run_cli(cfg: &Config, exe: &Path, tmpl: &str, mount: &Path) -> Result<String, ScanError> {
    let target = mount.to_string_lossy().into_owned();
    let args: Vec<String> = tmpl.split_whitespace().map(|a| a.replace("{path}", &target)).collect();
    ev!(Info, "cli_start", scanner = exe.display(), args = args.join(" "));

    let mut cmd = Command::new(exe);
    cmd.args(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| ScanError::Failed(format!("cannot start {}: {e}", exe.display())))?;
    debug!("scanner pid {}", child.id());
    let readers = [
        child.stdout.take().and_then(|o| pump(o, "stdout")),
        child.stderr.take().and_then(|e| pump(e, "stderr")),
    ];
    let limit = Duration::from_secs(cfg.scan_timeout.max(1));
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if started.elapsed() > limit || crate::stopping() => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ScanError::Failed(format!("scanner aborted after {}s (timeout or service stop)", started.elapsed().as_secs())));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(250)),
            Err(e) => return Err(ScanError::Failed(format!("wait failed: {e}"))),
        }
    };
    for h in readers.into_iter().flatten() {
        let _ = h.join();
    }
    let ms = started.elapsed().as_millis();
    let code = status.code();
    ev!(Info, "cli_end", exit_code = code.map(|c| c.to_string()).unwrap_or_else(|| "signal".into()), duration_ms = ms);
    match code {
        Some(0) => Ok(format!("cli clean ({ms} ms)")),
        Some(c) if cfg.threat_exit_codes.contains(&c) => Err(ScanError::Threat(format!("scanner exit code {c}"))),
        Some(c) => Err(ScanError::Failed(format!("scanner exit code {c}"))),
        None => Err(ScanError::Failed("scanner terminated by signal".into())),
    }
}

/// Opens and reads the head of every regular file so the on-access engine
/// inspects it. Files the AV blocks (access denied / virus detected) are
/// reported as threats.
fn run_touch(cfg: &Config, root: &Path) -> Result<String, ScanError> {
    ev!(Info, "touch_start", root = root.display(), max_files = cfg.touch_max_files);
    let started = Instant::now();
    let mut buf = vec![0u8; cfg.touch_bytes.max(1)];
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let (mut files, mut dirs, mut bytes, mut errors) = (0u64, 0u64, 0u64, 0u64);
    let mut blocked: Vec<String> = Vec::new();

    'walk: while let Some((dir, depth)) = stack.pop() {
        dirs += 1;
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                debug!("cannot list {}: {e}", dir.display());
                errors += 1;
                continue;
            }
        };
        for ent in rd.flatten() {
            if crate::stopping() {
                return Err(ScanError::Failed("interrupted by service stop".into()));
            }
            let Ok(ft) = ent.file_type() else { continue }; // never follows symlinks
            let p = ent.path();
            if ft.is_dir() {
                if depth < cfg.touch_max_depth {
                    stack.push((p, depth + 1));
                } else {
                    debug!("touch_max_depth reached at {}", p.display());
                }
            } else if ft.is_file() {
                files += 1;
                match File::open(&p).and_then(|mut f| f.read(&mut buf)) {
                    Ok(n) => {
                        bytes += n as u64;
                        trace!("touched {} ({n} bytes)", p.display());
                    }
                    Err(e) if is_av_block(&e) => {
                        ev!(Warn, "av_blocked", file = p.display(), error = e);
                        blocked.push(p.display().to_string());
                    }
                    Err(e) => {
                        debug!("read error {}: {e}", p.display());
                        errors += 1;
                    }
                }
                if files % 1000 == 0 {
                    debug!("touch progress: {files} files, {dirs} dirs, {} s", started.elapsed().as_secs());
                }
                if files >= cfg.touch_max_files {
                    warn!("touch_max_files ({}) reached, stopping walk", cfg.touch_max_files);
                    break 'walk;
                }
            }
        }
    }
    let ms = started.elapsed().as_millis();
    ev!(Info, "touch_end", files = files, dirs = dirs, bytes = bytes, read_errors = errors, blocked = blocked.len(), duration_ms = ms);
    if blocked.is_empty() {
        Ok(format!("touched {files} files ({errors} read errors, {ms} ms)"))
    } else {
        Err(ScanError::Threat(format!("{} file(s) blocked by AV: {}", blocked.len(), blocked.join(", "))))
    }
}

fn is_av_block(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    if matches!(e.raw_os_error(), Some(225) | Some(226)) {
        // ERROR_VIRUS_INFECTED / ERROR_VIRUS_DELETED
        return true;
    }
    e.kind() == ErrorKind::PermissionDenied
}
