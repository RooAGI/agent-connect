#!/bin/sh
# Install agent-connect: detects your OS/arch and downloads the right binary.
# Usage: curl -sSL https://raw.githubusercontent.com/RooAGI/agent-connect/main/install.sh | sh
set -e

REPO="RooAGI/agent-connect"

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

echo "downloading $ASSET ..."
curl -sSL -o agent-connect "https://raw.githubusercontent.com/$REPO/main/dist/$ASSET"
chmod +x agent-connect
echo "installed ./agent-connect ($ASSET)"
echo "next: ./agent-connect init && ./agent-connect run"
