#!/bin/sh
# usbscan installer for Linux (systemd) and macOS (launchd).
#   curl -fsSL https://raw.githubusercontent.com/loardracoon/sophos-auto-usbscan/main/scripts/install.sh | sudo sh
# Env: USBSCAN_VERSION=v0.1.0 (default: latest)  USBSCAN_REPO=owner/repo
set -eu

REPO="${USBSCAN_REPO:-loardracoon/sophos-auto-usbscan}"
VERSION="${USBSCAN_VERSION:-latest}"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=macos ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

asset="usbscan-$os-$arch"
if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "downloading $base/$asset"
curl -fsSL -o "$tmp/usbscan" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

expected="$(grep " $asset\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
if command -v sha256sum >/dev/null; then actual="$(sha256sum "$tmp/usbscan" | cut -d' ' -f1)"
else actual="$(shasum -a 256 "$tmp/usbscan" | cut -d' ' -f1)"; fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch" >&2; exit 1; }

chmod 755 "$tmp/usbscan"
[ "$os" = macos ] && xattr -d com.apple.quarantine "$tmp/usbscan" 2>/dev/null || true
"$tmp/usbscan" install
