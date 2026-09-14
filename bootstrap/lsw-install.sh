#!/usr/bin/env bash
# lsw-install.sh - Minimal LSW installer for the curl quick-start
#
#   curl -fsSL https://raw.githubusercontent.com/Pratech1015/lsw/main/bootstrap/lsw-install.sh | bash
#
# Installs a small, rootless `lsw` (source + launcher under ~/.lsw) from which
# you can run `lsw --install windows-11`. Does not touch system package
# managers, so it never conflicts with other software named `lsw`.
#
# Environment overrides:
#   LSW_HOME   - where LSW lives (default: $HOME/.lsw)
#   LSW_BRANCH - git branch/tag to fetch (default: main)

set -euo pipefail

LSW_HOME="${LSW_HOME:-${HOME}/.lsw}"
LSW_BRANCH="${LSW_BRANCH:-main}"
LSW_REPO="${LSW_REPO:-Pratech1015/lsw}"

c() { printf '\033[0;32minfo:\033[0m %s\n' "$*"; }
e() { printf '\033[0;31merror:\033[0m %s\n' "$*" >&2; }

for tool in curl tar; do
    command -v "$tool" >/dev/null 2>&1 || {
        e "$tool is required (on Arch: sudo pacman -S curl tar)"
        exit 1
    }
done

echo "  LSW - Linux Subsystem for Windows (minimal installer)"
c "Installing lsw to ${LSW_HOME} (branch: ${LSW_BRANCH})"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

URL="https://github.com/${LSW_REPO}/archive/refs/heads/${LSW_BRANCH}.tar.gz"
c "Fetching ${URL} ..."
curl -fsSLo "${TMP_DIR}/lsw.tar.gz" "$URL" || {
    e "download failed - are you offline?"
    exit 1
}

tar -xzf "${TMP_DIR}/lsw.tar.gz" -C "${TMP_DIR}"
SRC_DIR="$(find "${TMP_DIR}" -maxdepth 1 -type d -name 'lsw-*' | head -n1 || true)"
if [[ -z "${SRC_DIR}" ]]; then
    e "couldn't unpack LSW source"
    exit 1
fi

mkdir -p "${LSW_HOME}"
# Copy only what the CLI + runtime build need. The repo's distros/ holds
# packaging templates - it is NOT installed state, so it stays out (~/.lsw/distros
# is created on demand by lsw --install).
for item in Makefile src lib ntll config bash-completion; do
    cp -a "${SRC_DIR}/${item}" "${LSW_HOME}/"
done
c "Source installed under ${LSW_HOME}"

# Pick a directory from PATH to expose the `lsw` command
BIN_DIR=""
for cand in "${HOME}/.local/bin" "${HOME}/bin"; do
    if [[ ":$PATH:" == *":${cand}:"* ]]; then
        BIN_DIR="$cand"
        break
    fi
done
if [[ -z "${BIN_DIR}" ]]; then
    if [[ -w /usr/local/bin ]]; then
        BIN_DIR="/usr/local/bin"
    else
        c "~/.local/bin is not on your PATH - using it anyway; add it if needed"
        BIN_DIR="${HOME}/.local/bin"
    fi
fi

mkdir -p "${BIN_DIR}"
ln -sf "${LSW_HOME}/src/lsw" "${BIN_DIR}/lsw"
c "'lsw' is now available (${BIN_DIR}/lsw)"

echo
echo "  Next steps:"
echo "    lsw --install windows-11      install the Windows 11 runtime"
echo "    lsw --install windows-10      install the Windows 10 runtime"
echo "    lsw --list                    list installed versions"
echo "    lsw cmd                       enter the Windows environment"
echo
echo "  Tip: to update LSW later, run this installer again."