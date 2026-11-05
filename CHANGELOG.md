# Changelog

## v0.2.0

- Log rotation across multiple files: `usbscan.log` + `.1` … `.6`, 10 MB each
  by default (~70 MB cap). New `log_max_files` setting; `log_max_bytes`
  accepts `K`/`M`/`G` suffixes.
- `usbscan logs` reads rotated files when needed; `usbscan doctor` reports the
  rotation limit and current log disk usage.
- Installers: `install.sh` checks for systemd up front and falls back to
  `wget`; `install.ps1` runs isolated when piped into `iex`, disables the slow
  progress bar on Windows PowerShell 5.1 and checks the architecture.
- README: RHEL `sudo` path note, Windows `PATH`/ExecutionPolicy notes,
  validation status and known limitations.

## v0.1.0

- First release: USB detection on Linux, Windows and macOS; Sophos on-demand
  (`cli`) and on-access (`touch`) scan strategies; device cache; service
  install for systemd, launchd and Windows SCM.
- Observability: leveled and JSON logs with per-scan correlation ids,
  `status`, `logs`, `doctor`, `devices --all`, `cache`, runtime
  `debug on|trace|off`.
