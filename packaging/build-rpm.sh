#!/usr/bin/env bash
# build-rpm.sh - Build an RPM package for LSW
set -euo pipefail

VERSION="${1:-1.0.0}"

cd "$(dirname "$0")"
mkdir -p build/rpm/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

echo "Building RPM package for lsw ${VERSION}..."

SPEC="lsw.spec"
rpmbuild -bb --define "_topdir $(pwd)/build/rpm" --define "lsw_version ${VERSION}" "$SPEC" 2>&1 || {
    echo "rpmbuild failed - is it installed? Try: sudo dnf install rpm-build"
    exit 1
}

echo "Package built."
find build/rpm/RPMS -name "*.rpm" -print