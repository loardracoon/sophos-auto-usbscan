# usbscan installer for Windows. Run in an elevated PowerShell:
#   irm https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.ps1 | iex
# Optional: $env:USBSCAN_VERSION = 'v0.1.0' ; $env:USBSCAN_REPO = 'owner/repo'
$ErrorActionPreference = 'Stop'

$repo    = if ($env:USBSCAN_REPO)    { $env:USBSCAN_REPO }    else { 'loardracoon/sophos-auto-usbscan' }
$version = if ($env:USBSCAN_VERSION) { $env:USBSCAN_VERSION } else { 'latest' }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) PowerShell.'
}

$asset = 'usbscan-windows-x86_64.exe'
$base  = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
         else { "https://github.com/$repo/releases/download/$version" }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path $env:TEMP ("usbscan-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $exe = Join-Path $tmp 'usbscan.exe'
    Write-Host "downloading $base/$asset"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $exe
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')

    $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { $_ -match " $([regex]::Escape($asset))$" }
    $expected = ($line -split ' ')[0]
    $actual = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
    if (-not $expected -or $expected -ne $actual) { throw 'checksum mismatch' }

    Unblock-File $exe
    & $exe install
    if ($LASTEXITCODE -ne 0) { throw "usbscan install failed ($LASTEXITCODE)" }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
