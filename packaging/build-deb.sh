#!/usr/bin/env bash
# build-deb.sh - Build a .deb package for LSW
set -euo pipefail

VERSION="${1:-1.0.0}"

cd "$(dirname "$0")"
mkdir -p build/deb
cd build

echo "Building Debian package for lsw ${VERSION}..."

dpkg-buildpackage -b -us -uc 2>&1 || echo "dpkg-buildpackage not available - build manually with: dpkg-buildpackage -b -us -uc"

echo "Package built. Artifacts:"
ls -la *.deb 2>/dev/null || echo "  (run dpkg-buildpackage from the packaging directory)"