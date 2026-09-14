#!/usr/bin/env bash
# submit-aur.sh - Prepare and optionally push the lsw-win-11 / lsw-win-10
# edition packages to the AUR.
#
# Each AUR package is its own git repository:
#   ssh://aur@aur.archlinux.org/<pkgname>.git
#
# Usage:
#   ./submit-aur.sh              # prepare PKGBUILD + .SRCINFO only
#   ./submit-aur.sh --push       # prepare and push to AUR (requires SSH key)
#
# Requires: makepkg (on Arch: sudo pacman -S pacman)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUSH=false
[[ "${1:-}" == "--push" ]] && PUSH=true

command -v makepkg >/dev/null 2>&1 || {
    echo "error: makepkg not found" >&2
    exit 1
}

for pkg in lsw-win-11 lsw-win-10; do
    work="$(mktemp -d)"
    echo "==> preparing ${pkg}"
    cp "${HERE}/aur/${pkg}/PKGBUILD" "${work}/PKGBUILD"

    if [[ "$PUSH" == "true" ]]; then
        if [[ ! -d "${HERE}/.dist/${pkg}" ]]; then
            git clone -q "ssh://aur@aur.archlinux.org/${pkg}.git" "${HERE}/.dist/${pkg}"
        fi
        git -C "${HERE}/.dist/${pkg}" checkout -q -- PKGBUILD .SRCINFO 2>/dev/null || true
        cp "${work}/PKGBUILD" "${HERE}/.dist/${pkg}/PKGBUILD"
        (cd "${HERE}/.dist/${pkg}" && makepkg --printsrcinfo > .SRCINFO)
        git -C "${HERE}/.dist/${pkg}" add PKGBUILD .SRCINFO
        git -C "${HERE}/.dist/${pkg}" commit -qm "Update lsw-${pkg##*-} edition to latest" || true
        git -C "${HERE}/.dist/${pkg}" push -q origin master
        echo "==> pushed ${pkg}"
    else
        (cd "${work}" && makepkg --printsrcinfo > .SRCINFO)
        echo "    PKGBUILD + .SRCINFO ready in ${work}"
        cp "${work}/PKGBUILD" "${HERE}/aur/${pkg}/PKGBUILD"
        cp "${work}/.SRCINFO" "${HERE}/aur/${pkg}/.SRCINFO"
        echo "    staged under packaging/aur/${pkg}/"
    fi
    rm -rf "$work"
done

echo "done."