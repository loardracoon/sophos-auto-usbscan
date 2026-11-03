//! Helpers shared by the Linux and macOS back ends.

use std::path::Path;

extern "C" fn on_signal(_: libc::c_int) {
    crate::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// SIGTERM/SIGINT set the global stop flag; no SA_RESTART so blocking
/// poll()/kevent() return EINTR and the main loop exits cleanly.
pub fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

pub fn require_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("must be run as root (sudo)".into());
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
