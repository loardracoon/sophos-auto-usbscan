#!/bin/sh
# usbscan installer for Linux (systemd) and macOS (launchd).
#   curl -fsSL https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
#   wget -qO- https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
# Env: USBSCAN_VERSION=v0.1.0 (default: latest)  USBSCAN_REPO=owner/repo
set -eu

REPO="${USBSCAN_REPO:-loardracoon/sophos-auto-usbscan}"
VERSION="${USBSCAN_VERSION:-latest}"

die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=macos ;;
  *) die "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) die "unsupported architecture: $(uname -m) (64-bit x86 or ARM required)" ;;
esac

# The service manager is required by 'usbscan install'; fail before downloading.
if [ "$os" = linux ] && [ ! -d /run/systemd/system ]; then
  die "systemd is not running on this host; download the binary manually and run 'usbscan run' under your init system"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl or wget is required"
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required"
fi

asset="usbscan-$os-$arch"
if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
echo "downloading $base/$asset"
fetch "$base/$asset" "$tmp/usbscan" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

expected="$(grep " \*\{0,1\}$asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1 | head -n1)"
actual="$(sha256 "$tmp/usbscan")"
[ -n "$expected" ] || die "no checksum for $asset in SHA256SUMS"
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
echo "checksum OK"

chmod 755 "$tmp/usbscan"
if [ "$os" = macos ]; then
  xattr -d com.apple.quarantine "$tmp/usbscan" 2>/dev/null || true
fi
"$tmp/usbscan" install
echo
echo "Next: sudo /usr/local/bin/usbscan doctor"
