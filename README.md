# sophos-auto-usbscan

[![build](https://github.com/loardracoon/sophos-auto-usbscan/actions/workflows/build.yml/badge.svg)](https://github.com/loardracoon/sophos-auto-usbscan/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Automatic antivirus scanning of USB flash drives and disks on Windows, Linux and macOS.**

`usbscan` is a lightweight service written in Rust that triggers an antivirus
scan **every time a USB storage device is connected**. It is a single binary
with no dependencies (no PowerShell, udisks2, jq or udev required) that installs
itself as a system service.

- [Why it exists](#why-it-exists)
- [How it works](#how-it-works)
- [Installation on Linux](#installation-on-linux)
- [Installation on Windows](#installation-on-windows)
- [Installation on macOS](#installation-on-macos)
- [Building from source](#building-from-source)
- [Configuration](#configuration)
- [Commands](#commands)
- [Observability and debugging](#observability-and-debugging)
- [Verifying it works](#verifying-it-works)
- [Mass deployment](#mass-deployment)
- [Troubleshooting](#troubleshooting)
- [Validation status and known limitations](#validation-status-and-known-limitations)
- [Releasing a version](#releasing-a-version)

---

## Why it exists

Sophos real-time (on-access) protection only inspects — and only alerts on — a
file when it is **opened or read**. A USB drive whose files nobody opens is
never scanned and never raises an alert in Sophos Central.

`usbscan` closes that gap by actively scanning every USB volume as soon as it is
mounted.

## How it works

### Scan strategies

| Mode    | What it does |
|---------|--------------|
| `auto`  | **Default** — uses the on-demand scanner if installed, otherwise `touch` |
| `cli`   | Runs the Sophos on-demand scanner against the USB mount point |
| `touch` | Walks the volume and opens/reads the beginning of every file, forcing the real-time engine to inspect each one and raise the alert |
| `both`  | `cli` followed by `touch` |

Scanners detected automatically (path and arguments can be overridden in the
configuration):

| OS | Binary | Arguments |
|----|--------|-----------|
| Linux | `/opt/sophos-spl/plugins/av/bin/avscanner` | `{path} --scan-archives` |
| Linux (legacy) | `/opt/sophos-av/bin/savscan` | `-archive {path}` |
| Windows | `C:\Program Files\Sophos\Endpoint Defense\SophosInterceptXCLI.exe` | `scan --noui --expand_archives {path}` |
| Windows (legacy) | `C:\Program Files (x86)\Sophos\Sophos Anti-Virus\sav32cli.exe` | `-archive {path}` |
| macOS | `/usr/local/bin/sweep` | `-archive {path}` |

> Verify the scanner arguments and exit codes against the Sophos version you
> run; both are configurable (`scanner_args`, `threat_exit_codes`).

### Results

| Outcome | Event | Cached? |
|---------|-------|---------|
| Scanner exit code `0` / every file read | `scan_clean` | yes |
| Exit code listed in `threat_exit_codes` (default `3,24`) or a file blocked by the AV during `touch` (access denied / `ERROR_VIRUS_INFECTED`) | `scan_alert` | no |
| Any other exit code, timeout, scanner missing | `scan_failed` | no |

A device that is not cached is scanned again on its next insertion.

### USB detection

| OS | Mechanism |
|----|-----------|
| Linux | Woken by every mount/unmount (`poll` on `/proc/self/mountinfo`); USB identified through sysfs. The `auto_mount` option mounts read-only any USB partition nobody mounted (headless servers) and unmounts it after the scan. |
| macOS | Watches `/Volumes` (`kqueue`) and confirms with `diskutil` that the disk is on the USB bus. |
| Windows | Native service; checks the drive letters every 2 s (negligible cost) and identifies the USB bus type. Also detects USB HDDs/SSDs that Windows reports as fixed disks, and removable media such as SD cards. |

Measured footprint on Linux: 0.4–0.6 MB binary, ~2 MB RAM and 0 % CPU while idle.

---

## Installation on Linux

**Requirements:** x86_64 or ARM64, systemd, root access. Sophos Protection for
Linux (SPL) recommended for `cli` mode.

### Option A — one-line installer

```bash
curl -fsSL https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
```

Without `curl` (minimal Debian/Ubuntu images), use `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
```

The script checks for root and systemd, detects the architecture, downloads
the binary from the latest Release, verifies its SHA-256 checksum and runs
`usbscan install`. To pin a version: `curl ... | sudo USBSCAN_VERSION=v0.1.0 sh`.

### Option B — manual

```bash
curl -fsSLO https://github.com/loardracoon/sophos-auto-usbscan/releases/latest/download/usbscan-linux-x86_64
```
```bash
chmod +x usbscan-linux-x86_64
```
```bash
sudo ./usbscan-linux-x86_64 install
```

(On ARM64 use `usbscan-linux-aarch64`.) The Linux binaries are statically linked
(musl) and run on any distribution.

### What `install` does

| Item | Location |
|------|----------|
| Binary | `/usr/local/bin/usbscan` |
| Configuration | `/etc/usbscan.conf` (created only if missing) |
| Service | `/etc/systemd/system/usbscan.service` (enabled and started) |
| Log | `/var/log/usbscan.log` |
| Cache and status | `/var/lib/usbscan/` |

> **RHEL, Rocky, Alma, CentOS, Fedora:** `sudo`'s `secure_path` does not
> include `/usr/local/bin`, so `sudo usbscan` answers *command not found*. Use
> the full path: `sudo /usr/local/bin/usbscan status`.

### Verify

```bash
sudo usbscan status
```
```bash
sudo usbscan logs -f
```

### Headless servers

Without an automounter (GNOME/KDE/udisks) the USB drive is never mounted, so
there is nothing to scan. Enable in `/etc/usbscan.conf`:

```ini
auto_mount = true
```
```bash
sudo systemctl restart usbscan
```

### Update / uninstall

Update: run the installer again (or `sudo ./usbscan-new install`).

```bash
sudo usbscan uninstall
```

Uninstalling keeps the configuration, cache and log. To remove everything:
`sudo rm -rf /etc/usbscan.conf /var/lib/usbscan /var/log/usbscan.log*`.

---

## Installation on Windows

**Requirements:** Windows 10/11 or Server 2016+ (x64; Windows 11 on ARM runs
the x64 binary through emulation), Administrator account, Windows PowerShell
5.1 or PowerShell 7+. Sophos Intercept X / Endpoint recommended for `cli` mode.

### Option A — one-line installer

Open **PowerShell as Administrator**:

```powershell
irm https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.ps1 | iex
```

The script checks for Administrator rights, downloads
`usbscan-windows-x86_64.exe` from the latest Release, verifies its SHA-256
checksum and runs `usbscan install`. To pin a version, run
`$env:USBSCAN_VERSION = 'v0.1.0'` first.

If your policy forbids `iex`, download the script and run it explicitly
(the execution policy applies only to this invocation):

```powershell
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.ps1 -OutFile install.ps1
```
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

### Option B — manual

1. Download `usbscan-windows-x86_64.exe` from the
   [Releases](https://github.com/loardracoon/sophos-auto-usbscan/releases) page.
2. If downloaded with a browser, right-click → Properties → tick **Unblock**
   (or run `Unblock-File .\usbscan-windows-x86_64.exe`).
3. From an **elevated (Administrator)** prompt:

```bat
usbscan-windows-x86_64.exe install
```

### What `install` does

| Item | Location |
|------|----------|
| Binary | `C:\Program Files\usbscan\usbscan.exe` |
| Configuration | `C:\ProgramData\usbscan\usbscan.conf` |
| Service | `usbscan` — "USB Antivirus Scan Trigger", automatic start, LocalSystem account, automatic restart on failure |
| Log | `C:\ProgramData\usbscan\usbscan.log` |
| Cache and status | `C:\ProgramData\usbscan\` |

The install folder is not added to `PATH`: call the binary by its full path,
`& "C:\Program Files\usbscan\usbscan.exe" <command>`, from an elevated prompt.

### Verify

```powershell
& "C:\Program Files\usbscan\usbscan.exe" status
```
```powershell
& "C:\Program Files\usbscan\usbscan.exe" logs -f
```

### Update / uninstall

Update: run the installer again — the service is stopped, the binary replaced
and the service restarted.

```bat
"C:\Program Files\usbscan\usbscan.exe" uninstall
```

To also delete configuration and logs: `rmdir /s /q C:\ProgramData\usbscan`.

---

## Installation on macOS

**Requirements:** macOS 11 or later (Intel or Apple Silicon), administrator
account.

### Option A — one-line installer

```bash
curl -fsSL https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
```

### Option B — manual

```bash
curl -fsSLO https://github.com/loardracoon/sophos-auto-usbscan/releases/latest/download/usbscan-macos-aarch64
```
```bash
chmod +x usbscan-macos-aarch64
```
```bash
xattr -d com.apple.quarantine usbscan-macos-aarch64 2>/dev/null; true
```
```bash
sudo ./usbscan-macos-aarch64 install
```

(On Intel Macs use `usbscan-macos-x86_64`.)

### Required step: Full Disk Access

macOS blocks processes without permission from reading removable volumes.
Open **System Settings → Privacy & Security → Full Disk Access**, click **+**,
press `⌘⇧G`, type `/usr/local/bin/usbscan` and enable it. Then restart the
service:

```bash
sudo launchctl kickstart -k system/com.usbscan.daemon
```

For managed fleets, grant this permission via MDM (PPPC profile, see
[Mass deployment](#mass-deployment)).

To confirm the daemon has the permission, connect a USB drive and check that
`touch_end` reports `files=` greater than 0 and `read_errors=0`. (The
`full disk access` line of `usbscan doctor` checks the terminal that runs it,
not the daemon.)

### What `install` does

| Item | Location |
|------|----------|
| Binary | `/usr/local/bin/usbscan` |
| Configuration | `/etc/usbscan.conf` |
| Service | `/Library/LaunchDaemons/com.usbscan.daemon.plist` (loaded, starts at boot) |
| Log | `/var/log/usbscan.log` |
| Cache and status | `/Library/Application Support/usbscan/` |

### Verify

```bash
sudo usbscan status
```
```bash
sudo usbscan logs -f
```

### Update / uninstall

Update: run the installer again.

```bash
sudo usbscan uninstall
```

---

## Building from source

Requires stable [Rust](https://rustup.rs).

```bash
git clone https://github.com/loardracoon/sophos-auto-usbscan
```
```bash
cd sophos-auto-usbscan && cargo build --release
```

The binary is written to `target/release/usbscan` (`usbscan.exe` on Windows).
Then run `sudo target/release/usbscan install` (or `usbscan.exe install` as
Administrator).

Static Linux binary (runs on any distribution):

```bash
rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl
```

---

## Configuration

`install` creates a commented configuration file and never overwrites it. After
editing, restart the service (`systemctl restart usbscan`,
`Restart-Service usbscan` or `launchctl kickstart -k system/com.usbscan.daemon`).
`usbscan config` prints the effective values and any invalid line.

| Key | Default | Description |
|-----|---------|-------------|
| `mode` | `auto` | `auto`, `cli`, `touch` or `both` |
| `scanner` | *(auto)* | path of the on-demand scanner |
| `scanner_args` | *(auto)* | arguments; `{path}` is replaced by the mount point |
| `threat_exit_codes` | `3,24` | scanner exit codes reported as a threat (`scan_alert`); other non-zero codes are `scan_failed` |
| `scan_timeout` | `3600` | seconds before the scanner is aborted |
| `settle` | `3` | seconds to wait after mounting before scanning |
| `scan_on_start` | `true` | scan USB drives already connected when the service starts |
| `cache_ttl` | `86400` | do not rescan a device found clean within this many seconds; `0` = always scan |
| `cache_max` | `10` | number of devices kept in the cache |
| `touch_bytes` | `4096` | bytes read from each file in `touch` mode |
| `touch_max_files` | `500000` | file limit per volume in `touch` mode |
| `touch_max_depth` | `64` | maximum directory depth in `touch` mode |
| `auto_mount` | `false` | *Linux* — mount unmounted USB partitions read-only |
| `poll_ms` | `2000` | *Windows* — drive polling interval |
| `log_level` | `info` | `error`, `warn`, `info`, `debug` or `trace` |
| `log_format` | `text` | `text` or `json` (one JSON object per line) |
| `log_file` / `cache_file` | per OS | alternative paths |
| `log_max_bytes` | `5242880` | size at which the log is rotated (`.log.1`) |

The cache identifies a device by vendor:product:serial:partition (Linux),
model:volume UUID (macOS) or vendor:product:serial:volume serial (Windows).
In high-risk environments use `cache_ttl = 0`: a clean drive can be modified on
another machine and reconnected within the cache window.

## Commands

```text
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
```

On Windows, call the installed binary as
`"C:\Program Files\usbscan\usbscan.exe" <command>` from an elevated prompt; on
Linux/macOS use `sudo usbscan <command>`.

## Observability and debugging

### Log format and traceability

Every line has a millisecond UTC timestamp, a level and the thread that wrote
it. Each scan runs in a worker named `scan-<id>`, so **every line of one scan —
including the scanner's own output — carries the same correlation id**:

```text
2026-11-04T21:40:27.088Z INFO  [main]   event=device_detected mount=/media/u/STICK device=0781:5581:4C53...:p1 desc="/dev/sdb1 vfat SanDisk Ultra"
2026-11-04T21:40:30.091Z INFO  [scan-7] event=scan_start scan=7 mount=/media/u/STICK device=0781:5581:4C53...:p1
2026-11-04T21:40:30.092Z INFO  [scan-7] event=cli_start scanner=/opt/sophos-spl/plugins/av/bin/avscanner args="/media/u/STICK --scan-archives"
2026-11-04T21:40:31.345Z INFO  [scan-7] event=scanner_output stream=stdout line="..."
2026-11-04T21:40:31.594Z INFO  [scan-7] event=cli_end exit_code=24 duration_ms=1502
2026-11-04T21:40:31.594Z ERROR [scan-7] event=scan_alert scan=7 mount=/media/u/STICK device=... duration_ms=1503 result="scanner exit code 24"
```

Important lines are structured `event=<name> key=value` records. Events:

| Event | Level | Meaning |
|-------|-------|---------|
| `service_start` / `service_stop` | info | service lifecycle, with version, pid, config, mode and scanner |
| `device_present` | info | USB volume already mounted at service start |
| `device_detected` / `device_removed` | info | USB volume mounted / unmounted |
| `scan_bypass` | info | skipped: device scanned clean within `cache_ttl` |
| `scan_start` | info | scan begins (`scan` = correlation id) |
| `cli_start` / `cli_end` | info | scanner command line, exit code and duration |
| `scanner_output` | info | each line printed by the scanner (stdout/stderr) |
| `touch_start` / `touch_end` | info | file walk with counters (files, dirs, bytes, errors, blocked) |
| `av_blocked` | warn | the AV blocked access to a file during `touch` |
| `scan_clean` | info | no threat found |
| `scan_alert` | error | threat found |
| `scan_failed` | warn | scan could not complete |
| `scan_skipped` | warn | volume disappeared before the scan |
| `log_level_changed` | error* | runtime level changed with `usbscan debug` (*always logged) |

With `log_format = json` (or `usbscan run --json`) each line is a JSON object
(`ts`, `level`, `thread`, `pid`, `event`, `msg` and the event fields), ready
for Splunk, Elastic, Sentinel or any SIEM.

### Log levels

| Level | Adds |
|-------|------|
| `info` | the events above (default) |
| `debug` | strategy selection, cache hit/miss decisions, settle wait, scanner pid, `touch` progress every 1000 files, read errors, effective configuration at start |
| `trace` | every volume evaluated and why it was ignored, every file touched (very verbose) |

### Changing the level without restarting

```bash
sudo usbscan debug on       # debug
```
```bash
sudo usbscan debug trace    # trace
```
```bash
sudo usbscan debug off      # back to log_level from the config file
```

The override lasts until `debug off` or a service restart. On Linux/macOS it
is delivered with `SIGUSR1`; on Windows with service control code `128`
(`sc control usbscan 128` also works after writing the override file).

### Live status

`usbscan status` shows the service manager state plus `status.json`, which
the service rewrites on every event:

```json
{
  "version": "0.1.0",
  "pid": 671,
  "started": "2026-11-04T21:40:35Z",
  "uptime_secs": 3600,
  "mode": "auto",
  "scanner": "/opt/sophos-spl/plugins/av/bin/avscanner",
  "log_level": "info",
  "counters": {"detected": 4, "removed": 3, "scans": 3, "clean": 2, "alerts": 1, "failed": 0, "bypassed": 1},
  "last_alert": "2026-11-04T21:40:31.594Z scan-7 /media/u/STICK ...: threat: scanner exit code 24",
  "active_scans": [],
  "usb_volumes": [{"mount": "/media/u/STICK", "id": "...", "desc": "..."}],
  "recent_events": ["..."]
}
```

`usbscan status --json` prints a single JSON document for monitoring agents
(Zabbix, Nagios, Prometheus textfile exporters, etc.).

### Other tools

| Command | Use |
|---------|-----|
| `usbscan logs --scan 7` | every line of scan 7 only |
| `usbscan logs -f` | follow the log (handles rotation) |
| `usbscan doctor` | checks privileges, config errors, scanner path, log/data directory permissions, service state, systemd/mountinfo/uevent (Linux), diskutil and Full Disk Access of the calling terminal (macOS) |
| `usbscan devices --all` | every mounted volume and the reason it is or is not treated as USB |
| `usbscan cache list` / `clear` | inspect or reset the cache (takes effect on the running service immediately) |
| `usbscan run --trace` | stop the service and run in the foreground with full output on the console |

## Verifying it works

1. Run `usbscan doctor`: there must be no `[FAIL]` lines.
2. Run `usbscan logs -f`, connect a USB drive and look for
   `device_detected` → `scan_start` → `scan_clean` (or `scan_alert`).
3. Detection test: write the
   [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) to
   the drive **with real-time protection disabled** (or on another machine),
   reconnect it and confirm the `scan_alert` event and the alert in Sophos
   Central.
4. `usbscan devices --all` shows whether the volume is recognised as USB and why.

## Mass deployment

The installer is silent and idempotent: distribute the binary and run
`install` with administrative privileges.

- **Windows (GPO / Intune / SCCM):** startup script or Win32 app running
  `usbscan-windows-x86_64.exe install`; uninstall with
  `"C:\Program Files\usbscan\usbscan.exe" uninstall`. A standard configuration
  can be copied to `C:\ProgramData\usbscan\usbscan.conf` before `install`.
- **Linux (Ansible / Salt / shell):** copy the binary and run `usbscan install`;
  distribute `/etc/usbscan.conf` with your configuration manager.
- **macOS (Jamf / Intune / Kandji):** package or script running
  `usbscan-macos-<arch> install`, plus a **PPPC** profile granting
  `SystemPolicyAllFiles` (Full Disk Access) to `/usr/local/bin/usbscan`.

For central monitoring, set `log_format = json` and forward the log file with
your SIEM agent, alerting on `event=scan_alert` and `event=scan_failed`.

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| Nothing logged when a drive is connected (Linux) | The drive was not mounted: set `auto_mount = true`. Confirm with `usbscan devices --all` |
| `mode=cli but no scanner binary found` | No on-demand scanner at that path: set `scanner =` or use `mode = touch` |
| `scan_failed ... scanner exit code N` | Scanner error, or a threat code missing from `threat_exit_codes`; check the `scanner_output` lines of that scan with `usbscan logs --scan ID` |
| macOS: `touch_end files=0` / read errors | Full Disk Access missing for `/usr/local/bin/usbscan` |
| Windows: `Access is denied` | The prompt is not elevated (Administrator) |
| Drive is not rescanned | It is cached (`scan_bypass`); use `usbscan cache clear` or `cache_ttl = 0` |
| `status` shows stale data | The service is not running: check `usbscan doctor` and the service manager |
| Need full detail | `usbscan debug trace`, reproduce, `usbscan debug off` |

## Validation status and known limitations

| Area | Status |
|------|--------|
| Linux x86_64 binary | Run and tested: scan strategies, threat vs. error results, cache, log levels, runtime `debug on/off`, `status`, `doctor`, JSON logs, mount event detection |
| `install.sh` | Tested: root/systemd checks, `curl` and `wget` download, pinned version, wrong repository, checksum mismatch |
| Windows, macOS, Linux ARM64 binaries | Built by CI on native runners; **not yet run on real machines** |
| `install.ps1` | Reviewed; **not yet executed on Windows** |
| Service install (`systemd`, `launchd`, Windows SCM) | **Not yet tested on real machines** |
| Real USB drive + real Sophos | **Not yet tested**; verify scanner arguments and `threat_exit_codes` for your Sophos version |

Known limitations:

- The Windows binary is not code-signed; SmartScreen or application-control
  policies may require an allow rule.
- On Linux, `install` requires systemd; on other init systems run
  `usbscan run` under your own supervisor.
- `debug on|trace|off` lasts until the service restarts.
- The cache identifies devices by hardware serial and volume id: a drive
  modified elsewhere and reconnected within `cache_ttl` is not rescanned
  (use `cache_ttl = 0` where that matters).

## Releasing a version

The `.github/workflows/build.yml` workflow builds the 5 binaries on every push.
When a `v*` tag is pushed, it also publishes a Release with the binaries and
the `SHA256SUMS` file used by the installers:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

## License

MIT — see [LICENSE](LICENSE).
