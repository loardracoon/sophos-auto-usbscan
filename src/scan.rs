//! Scan strategies: Sophos on-demand CLI and on-access "touch".

use crate::config::{Config, Mode};
use crate::Device;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Known on-demand scanners: (binary, default args). `{path}` = mount point.
#[cfg(target_os = "linux")]
const CANDIDATES: &[(&str, &str)] = &[
    ("/opt/sophos-spl/plugins/av/bin/avscanner", "{path} --scan-archives"),
    ("/opt/sophos-av/bin/savscan", "-archive {path}"),
];
#[cfg(target_os = "macos")]
const CANDIDATES: &[(&str, &str)] = &[("/usr/local/bin/sweep", "-archive {path}")];
#[cfg(windows)]
const CANDIDATES: &[(&str, &str)] = &[
    (r"C:\Program Files\Sophos\Endpoint Defense\SophosInterceptXCLI.exe", "scan --noui --expand_archives {path}"),
    (r"C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sav32cli.exe", "-archive {path}"),
];

/// Returns the scanner binary and its argument template.
pub fn resolve_scanner(cfg: &Config) -> Option<(PathBuf, String)> {
    if let Some(p) = &cfg.scanner {
        let args = cfg.scanner_args.clone().or_else(|| {
            CANDIDATES.iter().find(|(c, _)| Path::new(c) == p).map(|(_, a)| a.to_string())
        });
        return Some((p.clone(), args.unwrap_or_else(|| "{path}".into())));
    }
    CANDIDATES
        .iter()
        .find(|(c, _)| Path::new(c).is_file())
        .map(|(c, a)| (PathBuf::from(c), cfg.scanner_args.clone().unwrap_or_else(|| a.to_string())))
}

/// Runs the configured strategy. Ok = clean, Err = threat found or scan failure.
pub fn run(cfg: &Config, dev: &Device) -> Result<String, String> {
    let scanner = resolve_scanner(cfg);
    let (cli, touch) = match cfg.mode {
        Mode::Cli => (true, false),
        Mode::Touch => (false, true),
        Mode::Both => (true, true),
        Mode::Auto => (scanner.is_some(), scanner.is_none()),
    };
    let mut out = Vec::new();
    if cli {
        let Some((exe, args)) = &scanner else {
            return Err("mode=cli but no scanner binary found (set 'scanner =')".into());
        };
        out.push(run_cli(cfg, exe, args, &dev.mount)?);
    }
    if touch {
        out.push(run_touch(cfg, &dev.mount)?);
    }
    Ok(out.join("; "))
}

fn run_cli(cfg: &Config, exe: &Path, tmpl: &str, mount: &Path) -> Result<String, String> {
    let target = mount.to_string_lossy().into_owned();
    let args: Vec<String> = tmpl.split_whitespace().map(|a| a.replace("{path}", &target)).collect();
    info!("scan start: {} {}", exe.display(), args.join(" "));

    let mut cmd = Command::new(exe);
    cmd.args(&args).stdin(Stdio::null());
    match (crate::log::file_handle(), crate::log::file_handle()) {
        (Some(o), Some(e)) => cmd.stdout(o).stderr(e),
        _ => cmd.stdout(Stdio::null()).stderr(Stdio::null()),
    };
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let started = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("cannot start {}: {e}", exe.display()))?;
    let limit = Duration::from_secs(cfg.scan_timeout.max(1));
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if started.elapsed() > limit || crate::stopping() => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("scanner aborted after {}s", started.elapsed().as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(500)),
            Err(e) => return Err(format!("wait failed: {e}")),
        }
    };
    let secs = started.elapsed().as_secs();
    match status.code() {
        Some(0) => Ok(format!("cli scan clean in {secs}s")),
        Some(c) => Err(format!("scanner exit code {c} after {secs}s (threat detected or scan error, see log)")),
        None => Err("scanner terminated by signal".into()),
    }
}

/// Opens and reads the head of every regular file so the on-access engine
/// inspects it. Files the AV blocks (access denied / virus detected) are
/// reported as possible threats.
fn run_touch(cfg: &Config, root: &Path) -> Result<String, String> {
    info!("touch start: {}", root.display());
    let started = Instant::now();
    let mut buf = vec![0u8; cfg.touch_bytes.max(1)];
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    let (mut files, mut blocked, mut errors) = (0u64, Vec::<String>::new(), 0u64);

    'walk: while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = fs::read_dir(&dir) else {
            errors += 1;
            continue;
        };
        for ent in rd.flatten() {
            if crate::stopping() {
                return Err("interrupted".into());
            }
            let Ok(ft) = ent.file_type() else { continue }; // never follows symlinks
            let p = ent.path();
            if ft.is_dir() {
                if depth < cfg.touch_max_depth {
                    stack.push((p, depth + 1));
                }
            } else if ft.is_file() {
                files += 1;
                match File::open(&p).and_then(|mut f| f.read(&mut buf)) {
                    Ok(_) => {}
                    Err(e) if is_av_block(&e) => {
                        warn!("blocked by AV (possible threat): {} ({e})", p.display());
                        blocked.push(p.display().to_string());
                    }
                    Err(e) => {
                        debug!("read error {}: {e}", p.display());
                        errors += 1;
                    }
                }
                if files >= cfg.touch_max_files {
                    warn!("touch_max_files ({}) reached, stopping walk", cfg.touch_max_files);
                    break 'walk;
                }
            }
        }
    }
    let secs = started.elapsed().as_secs();
    if blocked.is_empty() {
        Ok(format!("touched {files} files in {secs}s ({errors} read errors)"))
    } else {
        Err(format!("{} file(s) blocked by AV out of {files}: {}", blocked.len(), blocked.join(", ")))
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
