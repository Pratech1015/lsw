#!/usr/bin/env bash
# Setup script for windows-11 distro
# This runs as part of: lsw --install windows-11

set -euo pipefail

DISTRO=windows-11
BUILD=22631
ROOTFS="${LSW_DATA_DIR:-/var/lib/lsw}/distros/${DISTRO}/rootfs"

echo "Setting up ${DISTRO} (build ${BUILD})..."

# Create Windows directory tree
mkdir -p "${ROOTFS}/drive_c/Windows/System32"
mkdir -p "${ROOTFS}/drive_c/Windows/System"
mkdir -p "${ROOTFS}/drive_c/Windows/Fonts"
mkdir -p "${ROOTFS}/drive_c/Windows/Temp"
mkdir -p "${ROOTFS}/drive_c/Windows/System32/drivers"
mkdir -p "${ROOTFS}/drive_c/Windows/System32/config"
mkdir -p "${ROOTFS}/drive_c/Program Files"
mkdir -p "${ROOTFS}/drive_c/Program Files (x86)"
mkdir -p "${ROOTFS}/drive_c/ProgramData"
mkdir -p "${ROOTFS}/drive_c/Users/Public"
mkdir -p "${ROOTFS}/drive_c/Users/Administrator/AppData/Local/Temp"
mkdir -p "${ROOTFS}/drive_c/Users/Administrator/AppData/Roaming"

# Create version marker
cat > "${ROOTFS}/drive_c/Windows/System32/winver.txt" <<EOF
Microsoft Windows 11 Pro
Version 10.0.${BUILD}
LSW Runtime 1.0.0
EOF

# Copy bundled System32 CLI executables (shipped in this template's rootfs)
if [[ -d "$(dirname "${BASH_SOURCE[0]}")/rootfs/drive_c" ]]; then
    echo "Installing bundled Windows system tools..."
    cp -a "$(dirname "${BASH_SOURCE[0]}")/rootfs/drive_c/." "${ROOTFS}/drive_c/"
fi

echo "${DISTRO} setup complete."