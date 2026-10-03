#!/bin/sh
# Install agent-connect: detects your OS/arch, downloads the right binary,
# and verifies its SHA-256 checksum.
# Usage: curl -sSL https://raw.githubusercontent.com/RooAGI/agent-connect/main/install.sh | sh
set -e

REPO="RooAGI/agent-connect"
BASE="https://raw.githubusercontent.com/$REPO/main"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="agent-connect-linux-x86_64" ;;
      *) echo "unsupported: $OS $ARCH (only x86_64 linux builds published)" >&2; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ASSET="agent-connect-macos-arm64" ;;
      *) echo "unsupported: $OS $ARCH (only arm64 macOS builds published)" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "unsupported OS: $OS" >&2
    exit 1
    ;;
esac

verify_sha256() {
  file="$1"; sums="$2"; name="$3"
  want=$(grep " $name\$" "$sums" 2>/dev/null | awk '{print $1}')
  if [ -z "$want" ]; then
    echo "warning: no checksum published for $name, skipping verification" >&2
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    got=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    echo "warning: no sha256 tool found, skipping verification" >&2
    return 0
  fi
  if [ "$got" = "$want" ]; then
    echo "checksum OK ($name)"
  else
    echo "CHECKSUM MISMATCH for $name — refusing to install" >&2
    exit 1
  fi
}

echo "downloading $ASSET ..."
curl -sSL -o agent-connect "$BASE/dist/$ASSET"
curl -sSL -o /tmp/agent-connect-SHA256SUMS "$BASE/dist/SHA256SUMS"
verify_sha256 agent-connect /tmp/agent-connect-SHA256SUMS "$ASSET"
rm -f /tmp/agent-connect-SHA256SUMS
chmod +x agent-connect
echo "installed ./agent-connect ($ASSET)"
echo "next: ./agent-connect init && ./agent-connect run"
