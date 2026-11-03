//! Windows: native service (SCM) that polls the logical drive bitmask
//! (one GetLogicalDrives() syscall every `poll_ms`, ~0 CPU) and identifies
//! USB storage with IOCTL_STORAGE_QUERY_PROPERTY (BusTypeUsb). This also
//! catches USB HDD/SSD enclosures that Windows reports as DRIVE_FIXED.

use crate::config::Config;
use crate::Device;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::Diagnostics::Debug::{SetErrorMode, SEM_FAILCRITICALERRORS};
use windows_sys::Win32::System::IO::DeviceIoControl;

const NAME: &str = "usbscan";
const DISPLAY: &str = "USB Antivirus Scan Trigger";
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const BUS_TYPE_USB: i32 = 7;

#[repr(C)]
struct StoragePropertyQuery {
    property_id: i32, // StorageDeviceProperty = 0
    query_type: i32,  // PropertyStandardQuery = 0
    additional: [u8; 1],
}

#[repr(C)]
struct StorageDeviceDescriptor {
    version: u32,
    size: u32,
    device_type: u8,
    device_type_modifier: u8,
    removable_media: u8,
    command_queueing: u8,
    vendor_id_offset: u32,
    product_id_offset: u32,
    product_revision_offset: u32,
    serial_number_offset: u32,
    bus_type: i32,
    raw_properties_length: u32,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn from_wide(b: &[u16]) -> String {
    String::from_utf16_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())])
}

/// (is_usb, "vendor:product:serial") of the disk behind a drive letter.
fn storage_info(letter: char) -> Option<(bool, String)> {
    unsafe {
        let path = wide(&format!(r"\\.\{letter}:"));
        let h = CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            return None;
        }
        let q = StoragePropertyQuery { property_id: 0, query_type: 0, additional: [0] };
        let mut buf = [0u8; 1024];
        let mut ret = 0u32;
        let ok = DeviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&q as *const StoragePropertyQuery).cast(),
            std::mem::size_of::<StoragePropertyQuery>() as u32,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut ret,
            std::ptr::null_mut(),
        );
        CloseHandle(h);
        if ok == 0 || (ret as usize) < std::mem::size_of::<StorageDeviceDescriptor>() {
            return None;
        }
        let d: StorageDeviceDescriptor = std::ptr::read_unaligned(buf.as_ptr().cast());
        let s = |off: u32| -> String {
            let off = off as usize;
            if off == 0 || off >= ret as usize {
                return String::new();
            }
            let end = buf[off..ret as usize].iter().position(|b| *b == 0).map_or(ret as usize, |p| off + p);
            String::from_utf8_lossy(&buf[off..end]).trim().replace(' ', "_")
        };
        Some((
            d.bus_type == BUS_TYPE_USB,
            format!("{}:{}:{}", s(d.vendor_id_offset), s(d.product_id_offset), s(d.serial_number_offset)),
        ))
    }
}

/// (volume serial, label, filesystem) — fails when no media is inserted.
fn volume_info(root: &[u16]) -> Option<(u32, String, String)> {
    let mut serial = 0u32;
    let mut label = [0u16; 261];
    let mut fs = [0u16; 261];
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    };
    (ok != 0).then(|| (serial, from_wide(&label), from_wide(&fs)))
}

pub struct Watcher {
    poll: Duration,
    /// Fixed drives: letter -> is USB (fixed media never changes).
    fixed: HashMap<char, bool>,
    /// (letter, volume serial) -> (id, desc), or None if not USB.
    vols: HashMap<(char, u32), Option<(String, String)>>,
}

impl Watcher {
    pub fn new(cfg: &Config) -> Watcher {
        // Never pop up "insert a disk" dialogs for empty card readers.
        unsafe { SetErrorMode(SEM_FAILCRITICALERRORS) };
        Watcher { poll: Duration::from_millis(cfg.poll_ms), fixed: HashMap::new(), vols: HashMap::new() }
    }

    pub fn usb_mounts(&mut self) -> Vec<Device> {
        let mask = unsafe { GetLogicalDrives() };
        let present = |c: char| mask & (1 << (c as u8 - b'A')) != 0;
        self.fixed.retain(|c, _| present(*c));
        self.vols.retain(|(c, _), _| present(*c));

        let mut out = Vec::new();
        for c in 'C'..='Z' {
            if !present(c) {
                continue;
            }
            let root_s = format!(r"{c}:\");
            let root = wide(&root_s);
            let kind = unsafe { GetDriveTypeW(root.as_ptr()) };
            if kind == DRIVE_FIXED {
                let usb = *self.fixed.entry(c).or_insert_with(|| storage_info(c).map(|i| i.0).unwrap_or(false));
                if !usb {
                    continue;
                }
            } else if kind != DRIVE_REMOVABLE {
                continue;
            }
            let Some((vserial, label, fs)) = volume_info(&root) else { continue }; // no media
            let info = self
                .vols
                .entry((c, vserial))
                .or_insert_with(|| {
                    let (usb, hw) = storage_info(c).unwrap_or((kind == DRIVE_REMOVABLE, String::new()));
                    (usb || kind == DRIVE_REMOVABLE)
                        .then(|| (format!("{hw}:{vserial:08X}"), format!("{label} {fs} {}", if usb { "USB" } else { "removable" })))
                })
                .clone();
            if let Some((id, desc)) = info {
                out.push(Device { mount: PathBuf::from(root_s), id, desc });
            }
        }
        out
    }

    pub fn wait(&mut self) {
        let end = Instant::now() + self.poll;
        while Instant::now() < end && !crate::stopping() {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

pub fn release(_dev: &Device) {}

// ---------------------------------------------------------------- service

define_windows_service!(ffi_service_main, service_main);

pub fn service_dispatch() -> Result<(), String> {
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let handler = |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            crate::STOP.store(true, std::sync::atomic::Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(h) = service_control_handler::register(NAME, handler) else { return };
    let _ = h.set_service_status(status(ServiceState::Running));

    // The SCM passes our own command line ("service --config X") via argv.
    let argv: Vec<String> = std::env::args().collect();
    let cfg_path = argv
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| argv.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(crate::config::default_path);
    let cfg = Config::load(&cfg_path);
    crate::log::init(&cfg, false);
    crate::run_monitor(cfg);

    let _ = h.set_service_status(status(ServiceState::Stopped));
}

fn program_path() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
    PathBuf::from(pf).join("usbscan").join("usbscan.exe")
}

fn stop_and_wait(svc: &windows_service::service::Service) {
    let _ = svc.stop();
    let end = Instant::now() + Duration::from_secs(20);
    while Instant::now() < end {
        match svc.query_status() {
            Ok(s) if s.current_state != ServiceState::Stopped => std::thread::sleep(Duration::from_millis(300)),
            _ => break,
        }
    }
}

fn werr(e: windows_service::Error) -> String {
    format!("{e} (run from an elevated/Administrator prompt)")
}

pub fn install(cfg_path: &Path) -> Result<(), String> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(werr)?;
    let dst = program_path();

    // Upgrade path: stop the running instance before replacing the binary.
    let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::START | ServiceAccess::CHANGE_CONFIG;
    let existing = mgr.open_service(NAME, access).ok();
    if let Some(s) = &existing {
        stop_and_wait(s);
    }

    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    if me != dst {
        std::fs::create_dir_all(dst.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::copy(&me, &dst).map_err(|e| format!("copy to {}: {e}", dst.display()))?;
    }
    crate::config::write_default(cfg_path)?;

    let info = ServiceInfo {
        name: NAME.into(),
        display_name: DISPLAY.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: dst.clone(),
        launch_arguments: vec!["service".into(), "--config".into(), cfg_path.as_os_str().to_owned()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let svc = match existing {
        Some(s) => {
            s.change_config(&info).map_err(werr)?;
            s
        }
        None => mgr.create_service(&info, access).map_err(werr)?,
    };
    let _ = svc.set_description("Triggers an antivirus scan whenever USB storage is connected.");
    let restart = ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) };
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    });
    svc.start::<&str>(&[]).map_err(werr)?;
    println!(
        "installed: {}\nconfig:    {}\nservice:   {NAME} (auto start, running)\nlog:       {}",
        dst.display(),
        cfg_path.display(),
        crate::config::data_dir().join("usbscan.log").display()
    );
    Ok(())
}

pub fn uninstall() -> Result<(), String> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(werr)?;
    let svc = mgr
        .open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .map_err(werr)?;
    stop_and_wait(&svc);
    svc.delete().map_err(werr)?;
    drop(svc);
    let _ = std::fs::remove_file(program_path());
    println!("usbscan service removed (config, cache and log kept)");
    Ok(())
}
