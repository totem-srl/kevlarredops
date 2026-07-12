#!/usr/bin/env sh
set -eu

REPO="s0ld13rr/pentestcode"
BINARY="pentestcode"
INSTALL_DIR="${PENTESTCODE_INSTALL_DIR:-$HOME/.pentestcode/bin}"

main() {
  need_cmd curl
  need_cmd uname
  need_cmd chmod
  need_cmd mkdir

  platform=$(detect_platform)
  arch=$(detect_arch)
  version=$(resolve_version)
  variant=$(detect_variant "$platform" "$arch")

  artifact="${BINARY}-${platform}-${arch}${variant}"

  if [ "$platform" = "linux" ]; then
    ext="tar.gz"
    need_cmd tar
  else
    ext="zip"
    need_cmd unzip
  fi

  url="https://github.com/${REPO}/releases/download/v${version}/${artifact}.${ext}"

  printf "  Installing %s v%s (%s)\n" "$BINARY" "$version" "$artifact"
  printf "  From: %s\n" "$url"

  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  printf "  Downloading...\n"
  curl -fsSL "$url" -o "$tmpdir/archive.${ext}"

  printf "  Extracting...\n"
  if [ "$ext" = "tar.gz" ]; then
    tar -xzf "$tmpdir/archive.tar.gz" -C "$tmpdir"
  else
    unzip -qo "$tmpdir/archive.zip" -d "$tmpdir"
  fi

  mkdir -p "$INSTALL_DIR"
  mv "$tmpdir/${BINARY}"* "$INSTALL_DIR/${BINARY}"
  chmod +x "$INSTALL_DIR/${BINARY}"

  printf "  Installed to %s/%s\n" "$INSTALL_DIR" "$BINARY"

  # Skills — bundled attack knowledge. Best-effort: keep current on each upgrade,
  # but never fail the whole install if the archive is missing (older releases).
  skills_dir="$HOME/.pentestcode/skills"
  skills_url="https://github.com/${REPO}/releases/download/v${version}/skills.tar.gz"
  if curl -fsSL "$skills_url" -o "$tmpdir/skills.tar.gz" 2>/dev/null; then
    mkdir -p "$skills_dir"
    if tar -xzf "$tmpdir/skills.tar.gz" -C "$skills_dir" 2>/dev/null; then
      printf "  Skills installed to %s (editable)\n" "$skills_dir"
    else
      printf "  Warning: could not extract skills archive; skipping\n"
    fi
  else
    printf "  Note: no skills archive for this release; skipping\n"
  fi
  printf "\n"

  if ! echo "$PATH" | tr ':' '\n' | grep -qx "$INSTALL_DIR"; then
    shell_name=$(basename "${SHELL:-/bin/sh}")
    case "$shell_name" in
      zsh)  rc="$HOME/.zshrc" ;;
      bash) rc="$HOME/.bashrc" ;;
      fish) rc="$HOME/.config/fish/config.fish" ;;
      *)    rc="" ;;
    esac
    printf "  Add to your PATH:\n"
    if [ "$shell_name" = "fish" ]; then
      printf "    fish_add_path %s\n" "$INSTALL_DIR"
    else
      printf "    export PATH=\"%s:\$PATH\"\n" "$INSTALL_DIR"
    fi
    if [ -n "$rc" ]; then
      printf "  Or append to %s and restart your shell.\n" "$rc"
    fi
    printf "\n"
  fi

  printf "  Run '%s --help' to get started.\n" "$BINARY"
}

detect_platform() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    linux*)  echo "linux" ;;
    darwin*) echo "darwin" ;;
    mingw*|msys*|cygwin*) echo "windows" ;;
    *) err "Unsupported platform: $os" ;;
  esac
}

detect_arch() {
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64)  echo "x64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) err "Unsupported architecture: $arch" ;;
  esac
}

detect_variant() {
  platform=$1
  arch=$2

  if [ "$platform" != "linux" ]; then
    echo ""
    return
  fi

  is_musl=false
  if [ -f /etc/alpine-release ]; then
    is_musl=true
  elif command -v ldd >/dev/null 2>&1; then
    if ldd --version 2>&1 | grep -qi musl; then
      is_musl=true
    fi
  fi

  if [ "$is_musl" = "true" ]; then
    echo "-musl"
  else
    echo ""
  fi
}

resolve_version() {
  if [ -n "${VERSION:-}" ]; then
    echo "$VERSION"
    return
  fi
  tag=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
  if [ -z "$tag" ]; then
    err "Could not determine latest version"
  fi
  echo "$tag"
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required command not found: $1"
  fi
}

err() {
  printf "  Error: %s\n" "$1" >&2
  exit 1
}

main "$@"
