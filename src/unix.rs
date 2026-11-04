//! Helpers shared by the Linux and macOS back ends.

use std::path::Path;
use std::sync::atomic::Ordering;

extern "C" fn on_stop(_: libc::c_int) {
    crate::STOP.store(true, Ordering::Relaxed);
}

extern "C" fn on_reload(_: libc::c_int) {
    crate::RELOAD.store(true, Ordering::Relaxed);
}

/// SIGTERM/SIGINT stop the service, SIGUSR1 re-reads the log level override.
/// No SA_RESTART, so blocking poll()/kevent() return EINTR and the main
/// loop reacts immediately. Handlers only touch atomics.
pub fn install_signal_handlers() {
    unsafe {
        let set = |sig: libc::c_int, h: extern "C" fn(libc::c_int)| {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = h as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        };
        set(libc::SIGTERM, on_stop);
        set(libc::SIGINT, on_stop);
        set(libc::SIGUSR1, on_reload);
    }
}

pub fn is_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn require_root() -> Result<(), String> {
    if !is_admin() {
        return Err("must be run as root (sudo)".into());
    }
    Ok(())
}

pub fn pid_alive(pid: u32) -> Option<bool> {
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    Some(r == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

/// Sends SIGUSR1 to the running service (pid from status.json).
pub fn notify_reload() -> Result<(), String> {
    let body = std::fs::read_to_string(crate::config::status_file())
        .map_err(|e| format!("cannot read status file ({e}); is the service running?"))?;
    let pid = crate::status::read_pid(&body).ok_or("status file has no pid")?;
    if pid_alive(pid) != Some(true) {
        return Err(format!("service process {pid} is not running"));
    }
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGUSR1) } != 0 {
        return Err(format!("cannot signal pid {pid}: {} (run as root)", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Copies the running executable to `dst` atomically (works while the old
/// binary is still running).
pub fn copy_self(dst: &str) -> Result<(), String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if me == Path::new(dst) {
        return Ok(());
    }
    if let Some(d) = Path::new(dst).parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = format!("{dst}.new");
    std::fs::copy(&me, &tmp).and_then(|_| std::fs::rename(&tmp, dst)).map_err(|e| format!("copy to {dst}: {e}"))
}
