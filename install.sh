#!/usr/bin/env bash
set -euo pipefail

PROTOC_VERSION="27.3"

# (1) SP1 toolchain
if [ -x "$HOME/.sp1/bin/cargo-prove" ]; then
  echo "==> SP1 toolchain already installed, skipping."
else
  echo "==> Installing SP1 toolchain..."
  curl -L https://sp1.succinct.xyz | bash
  "$HOME/.sp1/bin/sp1up"
fi

# (2) protoc
if [ -x "$HOME/.local/bin/protoc" ] || command -v protoc >/dev/null 2>&1; then
  echo "==> protoc already installed, skipping."
else
  echo "==> Installing protoc v${PROTOC_VERSION}..."
  ARCH=$(uname -m)
  OS=$(uname -s)

  case "${OS}-${ARCH}" in
    Linux-x86_64)  PROTOC_ARCH="linux-x86_64" ;;
    Linux-aarch64) PROTOC_ARCH="linux-aarch_64" ;;
    Darwin-x86_64) PROTOC_ARCH="osx-x86_64" ;;
    Darwin-arm64)  PROTOC_ARCH="osx-aarch_64" ;;
    *) echo "Unsupported platform: ${OS}-${ARCH}" && exit 1 ;;
  esac

  PROTOC_ZIP="protoc-${PROTOC_VERSION}-${PROTOC_ARCH}.zip"
  curl -LO "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"
  unzip -o "${PROTOC_ZIP}" -d "$HOME/.local"
  rm "${PROTOC_ZIP}"
fi

echo ""
echo "Done. Make sure these are on your PATH:"
echo "  export PATH=\"\$HOME/.sp1/bin:\$HOME/.local/bin:\$PATH\""
