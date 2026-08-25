#!/bin/sh
# pentestcode installer — installs the CLI from a git remote or an existing checkout.
#
# Usage:
#   ./script/install.sh                          # use current repo checkout
#   PENTESTCODE_REPO=git@github.com:you/repo.git ./script/install.sh
#
# Options via env:
#   PENTESTCODE_REPO   git URL to clone when not run from a checkout
#   PENTESTCODE_BRANCH branch to clone (default: main)
#   PENTESTCODE_DIR    where to keep the source (default: ~/.pentestcode/src)
set -eu

BRANCH="${PENTESTCODE_BRANCH:-main}"
SRC="${PENTESTCODE_DIR:-$HOME/.pentestcode/src}"
DEST="${PENTESTCODE_DEST:-$HOME/.local/bin}"

have_build_script() {
  test -f "$1/packages/opencode/script/build.ts"
}

if have_build_script "$(pwd)"; then
  REPO_DIR="$(pwd)"
elif [ -n "${PENTESTCODE_REPO:-}" ]; then
  if [ -d "$SRC/.git" ]; then
    git -C "$SRC" fetch origin && git -C "$SRC" reset --hard "origin/$BRANCH"
  else
    git clone --depth 1 -b "$BRANCH" "$PENTESTCODE_REPO" "$SRC"
  fi
  REPO_DIR="$SRC"
else
  echo "error: run from a pentestcode checkout or set PENTESTCODE_REPO" >&2
  exit 1
fi

cd "$REPO_DIR/packages/opencode"

PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
esac
TARGET="pentestcode-${PLATFORM}-${ARCH}"

if [ ! -x "dist/$TARGET/bin/pentestcode" ] || [ "${PENTESTCODE_FORCE_BUILD:-0}" = "1" ]; then
  echo "==> installing dependencies (bun)"
  bun install
  echo "==> building $TARGET (this can take a few minutes)"
  bun run script/build.ts
fi

mkdir -p "$DEST"
ln -sf "$(pwd)/dist/$TARGET/bin/pentestcode" "$DEST/pentestcode"

echo "==> installed: $DEST/pentestcode -> $(pwd)/dist/$TARGET/bin/pentestcode"
"$DEST/pentestcode" --version
