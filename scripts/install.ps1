# usbscan installer for Windows. Run in an elevated PowerShell (5.1 or 7+):
#   irm https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.ps1 | iex
# Optional: $env:USBSCAN_VERSION = 'v0.1.0' ; $env:USBSCAN_REPO = 'owner/repo'
#
# Everything runs inside a script block so that settings and variables do not
# leak into the caller's session when the script is piped into iex.
& {
    $ErrorActionPreference = 'Stop'
    # Windows PowerShell 5.1 downloads extremely slowly while drawing the
    # progress bar.
    $ProgressPreference = 'SilentlyContinue'

    $repo    = if ($env:USBSCAN_REPO)    { $env:USBSCAN_REPO }    else { 'loardracoon/sophos-auto-usbscan' }
    $version = if ($env:USBSCAN_VERSION) { $env:USBSCAN_VERSION } else { 'latest' }

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated (Administrator) PowerShell.'
    }

    # x64 binary: native on AMD64, emulated on Windows 11 ARM64.
    $arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($arch -notin @('AMD64', 'ARM64')) {
        throw "Unsupported architecture '$arch': usbscan requires 64-bit Windows (x64, or ARM64 with x64 emulation)."
    }

    $asset = 'usbscan-windows-x86_64.exe'
    $base  = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
             else { "https://github.com/$repo/releases/download/$version" }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("usbscan-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $exe  = Join-Path $tmp 'usbscan.exe'
        $sums = Join-Path $tmp 'SHA256SUMS'
        Write-Host "downloading $base/$asset"
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $exe
        Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sums

        $line = Get-Content $sums | Where-Object { $_ -match "\s\*?$([regex]::Escape($asset))$" } | Select-Object -First 1
        $expected = if ($line) { ($line -split '\s+')[0].ToLower() } else { '' }
        $actual = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
        if (-not $expected) { throw "no checksum for $asset in SHA256SUMS" }
        if ($expected -ne $actual) { throw "checksum mismatch for $asset (expected $expected, got $actual)" }
        Write-Host "checksum OK"

        Unblock-File $exe
        & $exe install
        if ($LASTEXITCODE -ne 0) { throw "usbscan install failed (exit code $LASTEXITCODE)" }
        Write-Host ""
        Write-Host "Next: & 'C:\Program Files\usbscan\usbscan.exe' doctor"
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
