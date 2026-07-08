#!/usr/bin/env bash
set -euo pipefail

# PentestCode installer
# Usage: curl -fsSL https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.sh | bash
#
# Options (env vars):
#   PENTESTCODE_VERSION   — specific version (default: latest)
#   PENTESTCODE_INSTALL   — install directory (default: ~/.local/bin)
#   PENTESTCODE_REPO      — GitHub repo (default: s0ld13rr/pentestcode)

REPO="${PENTESTCODE_REPO:-s0ld13rr/pentestcode}"
INSTALL_DIR="${PENTESTCODE_INSTALL:-$HOME/.local/bin}"
VERSION="${PENTESTCODE_VERSION:-latest}"
BIN_NAME="pentestcode"

# --- helpers ---

info()  { printf '\033[1;34m→\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m✓\033[0m %s\n' "$*"; }
err()   { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; }
die()   { err "$@"; exit 1; }

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) die "Unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "x64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
  esac
}

detect_libc() {
  if [ "$(detect_os)" != "linux" ]; then
    echo ""
    return
  fi
  if ldd --version 2>&1 | grep -qi musl; then
    echo "-musl"
  elif command -v ldd >/dev/null 2>&1; then
    echo ""
  elif [ -f /etc/alpine-release ]; then
    echo "-musl"
  else
    echo ""
  fi
}

check_avx2() {
  if [ "$(detect_arch)" != "x64" ]; then
    echo ""
    return
  fi
  local os
  os="$(detect_os)"
  if [ "$os" = "linux" ]; then
    if grep -q avx2 /proc/cpuinfo 2>/dev/null; then
      echo ""
    else
      echo "-baseline"
    fi
  elif [ "$os" = "darwin" ]; then
    if sysctl -n machdep.cpu.leaf7_features 2>/dev/null | grep -qi avx2; then
      echo ""
    else
      echo "-baseline"
    fi
  else
    echo ""
  fi
}

# --- main ---

main() {
  info "Installing PentestCode..."

  local os arch libc avx2 asset_name ext download_url tmp_dir

  os="$(detect_os)"
  arch="$(detect_arch)"
  libc="$(detect_libc)"
  avx2="$(check_avx2)"

  asset_name="${BIN_NAME}-${os}-${arch}${avx2}${libc}"

  if [ "$os" = "linux" ]; then
    ext="tar.gz"
  else
    ext="zip"
  fi

  info "Platform: ${os}/${arch}${libc}${avx2}"

  # resolve version
  if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' | head -1 | sed 's/.*"v\(.*\)".*/\1/' || true)
    if [ -z "$VERSION" ]; then
      die "Could not determine latest version. Set PENTESTCODE_VERSION manually."
    fi
  fi

  info "Version: v${VERSION}"

  download_url="https://github.com/${REPO}/releases/download/v${VERSION}/${asset_name}.${ext}"

  # download
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT

  info "Downloading ${download_url}..."
  if ! curl -fsSL -o "${tmp_dir}/archive.${ext}" "$download_url"; then
    die "Download failed. Check version and platform: ${asset_name}"
  fi

  # extract
  info "Extracting..."
  if [ "$ext" = "tar.gz" ]; then
    tar -xzf "${tmp_dir}/archive.${ext}" -C "$tmp_dir"
  else
    unzip -qo "${tmp_dir}/archive.${ext}" -d "$tmp_dir"
  fi

  # install
  mkdir -p "$INSTALL_DIR"
  local binary="${tmp_dir}/${BIN_NAME}"
  if [ "$os" = "windows" ]; then
    binary="${binary}.exe"
  fi

  if [ ! -f "$binary" ]; then
    die "Binary not found in archive. Contents: $(ls "$tmp_dir")"
  fi

  chmod +x "$binary"
  mv "$binary" "${INSTALL_DIR}/${BIN_NAME}"

  ok "Installed ${BIN_NAME} v${VERSION} to ${INSTALL_DIR}/${BIN_NAME}"

  # check PATH
  if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    echo ""
    info "Add to your PATH:"
    echo ""
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    echo "  # Add to ~/.bashrc or ~/.zshrc to make permanent:"
    echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
    echo ""
  fi

  # verify
  if command -v "$BIN_NAME" >/dev/null 2>&1 || [ -x "${INSTALL_DIR}/${BIN_NAME}" ]; then
    ok "Run 'pentestcode' to start"
  fi
}

main "$@"
