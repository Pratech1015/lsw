#!/usr/bin/env bash
# Setup script for windows-10 distro
# This runs as part of: lsw --install windows-10

set -euo pipefail

DISTRO=windows-10
BUILD=19045
ROOTFS="${LSW_DATA_DIR:-/var/lib/lsw}/distros/${DISTRO}/rootfs"

echo "Setting up ${DISTRO} (build ${BUILD})..."

mkdir -p "${ROOTFS}/drive_c/Windows/System32"
mkdir -p "${ROOTFS}/drive_c/Windows/System"
mkdir -p "${ROOTFS}/drive_c/Windows/System32/drivers"
mkdir -p "${ROOTFS}/drive_c/Windows/System32/config"
mkdir -p "${ROOTFS}/drive_c/Program Files"
mkdir -p "${ROOTFS}/drive_c/Program Files (x86)"
mkdir -p "${ROOTFS}/drive_c/ProgramData"
mkdir -p "${ROOTFS}/drive_c/Users/Public"
mkdir -p "${ROOTFS}/drive_c/Users/Administrator"

cat > "${ROOTFS}/drive_c/Windows/System32/winver.txt" <<EOF
Microsoft Windows 10 Pro
Version 10.0.${BUILD}
LSW Runtime 1.0.0
EOF

echo "${DISTRO} setup complete."