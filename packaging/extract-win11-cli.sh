#!/usr/bin/env bash
# extract-win11-cli.sh - Extract Windows 11 CLI-only executables from an ISO
# Copyright (c) 2026 LSW Contributors
#
# Usage: ./extract-win11-cli.sh /path/to/Win11.iso [scratch-dir]
#    or: LSW_WIM=/path/to/install.wim ./extract-win11-cli.sh [scratch-dir]
#
# Extracts a curated set of console-only (non-GUI) Windows executables from
# the Windows 11 ISO's install.wim/install.esd into a scratch directory
# laid out like a drive_c so it can later be assembled into the distro
# template (distros/windows-11/rootfs).
#
# Env controls:
#   LSW_WIM     Extracted install.wim/esd file to use instead of an ISO
#   LSW_IMAGES  Space-separated WIM image indices (default "1 4": Home+Pro,
#               which together cover the full console toolset)
#
# Requires: 7z (p7zip / 7-Zip with WIM support)
set -euo pipefail

ISO="${1:-}"
SCRATCH="${2:-/tmp/lsw-win11-extract}"
EXISTING_WIM="${LSW_WIM:-}"
IMAGES="${LSW_IMAGES:-1 4}"

if [[ -z "$ISO" && -z "$EXISTING_WIM" ]]; then
    echo "Usage: $0 <windows-11.iso> [scratch-dir]"
    echo "   or: LSW_WIM=/path/to/install.wim $0 [scratch-dir]"
    echo ""
    echo "  windows-11.iso   Path to a Windows 11 ISO image"
    echo "  scratch-dir      Where to extract (default: /tmp/lsw-win11-extract)"
    echo "  LSW_WIM          Use an already-extracted install.wim/esd instead of an ISO"
    exit 1
fi

if [[ -n "$EXISTING_WIM" && ! -f "$EXISTING_WIM" ]]; then
    echo "Error: LSW_WIM file not found: $EXISTING_WIM" >&2
    exit 1
fi

if [[ -z "$EXISTING_WIM" && ! -f "$ISO" ]]; then
    echo "Error: ISO file not found: $ISO" >&2
    exit 1
fi

if ! command -v 7z &>/dev/null; then
    echo "Error: 7z with WIM support is required (p7zip / 7zip)." >&2
    exit 1
fi

# Console-only Windows 11 executables, curated from a Windows 11 24H2 image.
# These are the standard System32 command-line tools. GUI programs
# (explorer, notepad, mstsc, msconfig, ...) are intentionally excluded.
# Note: conhost.exe (the console host) and regsvr32/unregmp2 are PE
# GUI-subsystem binaries but are genuinely command-line utilities.
readarray -t CLI_TOOLS <<'EOF'
attrib.exe
bcdboot.exe
bcdedit.exe
bitsadmin.exe
bootsect.exe
certutil.exe
change.exe
chcp.com
chkdsk.exe
chkntfs.exe
cipher.exe
cmd.exe
cmdkey.exe
compact.exe
conhost.exe
convert.exe
diskpart.exe
dism.exe
doskey.exe
driverquery.exe
esentutl.exe
expand.exe
fc.exe
find.exe
findstr.exe
fltmc.exe
forfiles.exe
format.com
fsutil.exe
ftp.exe
getmac.exe
gpresult.exe
hostname.exe
icacls.exe
ipconfig.exe
label.exe
lodctr.exe
logman.exe
logoff.exe
mofcomp.exe
more.com
mountvol.exe
net.exe
net1.exe
netsh.exe
netstat.exe
nltest.exe
nslookup.exe
openfiles.exe
pathping.exe
ping.exe
pnputil.exe
powercfg.exe
qwinsta.exe
quser.exe
recover.exe
reg.exe
regini.exe
regsvr32.exe
relog.exe
replace.exe
route.exe
runas.exe
sc.exe
schtasks.exe
secedit.exe
setx.exe
sfc.exe
shutdown.exe
sort.exe
subst.exe
systeminfo.exe
takeown.exe
taskkill.exe
tasklist.exe
tpmtool.exe
tracerpt.exe
tracert.exe
tree.com
tsdiscon.exe
typeperf.exe
tzutil.exe
unlodctr.exe
unregmp2.exe
vssadmin.exe
w32tm.exe
wevtutil.exe
where.exe
whoami.exe
xcopy.exe
EOF

DEST="${SCRATCH}/drive_c/Windows/System32"
mkdir -p "$DEST"

echo "Extracting Windows 11 CLI-only executables..."
echo "  ISO:       $ISO"
echo "  Scratch:   $SCRATCH"
echo "  Tool count: ${#CLI_TOOLS[@]}"
echo ""

TMPDIR="$(mktemp -d /tmp/lsw-wim.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT

# Locate the WIM: either from LSW_WIM or inside the ISO
if [[ -n "$EXISTING_WIM" ]]; then
    WIM="$EXISTING_WIM"
else
    if 7z l "$ISO" 2>/dev/null | grep -q "install\.esd"; then
        WIM_NAME="install.esd"
    elif 7z l "$ISO" 2>/dev/null | grep -q "install\.wim"; then
        WIM_NAME="install.wim"
    else
        echo "Error: no install.wim / install.esd found in ISO" >&2
        exit 1
    fi

    echo "Found sources/${WIM_NAME} in ISO, extracting..."
    7z x -y -o"$TMPDIR" "$ISO" "sources/${WIM_NAME}" >/dev/null 2>&1
    WIM="${TMPDIR}/sources/${WIM_NAME}"

    if [[ ! -f "$WIM" ]]; then
        echo "Error: failed to extract WIM from ISO" >&2
        exit 1
    fi
fi

EXTRACTED=0
MISSING=0

# Multi-edition install.wim contains 11 images. Image "1" (Home) and image
# "4" (Pro) together cover the full console toolset: some tools (change,
# logoff, qwinsta/quser, tsdiscon) only ship on the Pro image. WIM filenames
# are stored in mixed case and 7z wildcards are case-sensitive, so we extract
# every System32 executable from both images with each case variant.
echo "  Extracting all System32 executables from images ${IMAGES}..."
for IMAGE in ${IMAGES}; do
    7z x -y -o"$TMPDIR/wim" "$WIM" "${IMAGE}/Windows/System32/*.exe" \
        "${IMAGE}/Windows/System32/*.EXE" \
        "${IMAGE}/Windows/System32/*.com" \
        "${IMAGE}/Windows/System32/*.COM" >/dev/null 2>&1
    # some tools live in subdirectories (e.g. wbem/ for MOF, winsxs)
    7z x -y -o"$TMPDIR/wim" "$WIM" "${IMAGE}/Windows/System32/wbem/*.exe" \
        "${IMAGE}/Windows/System32/wbem/*.EXE" >/dev/null 2>&1
done

EXTRACTED=0
MISSING=0

for tool in "${CLI_TOOLS[@]}"; do
    # Find the on-disk (UPPERCASE) name case-insensitively across all images
    found=$(find "${TMPDIR}/wim" -type f -iname "${tool}" -print -quit 2>/dev/null || true)
    if [[ -n "$found" ]]; then
        cp -f "$found" "${DEST}/${tool}"
        EXTRACTED=$((EXTRACTED + 1))
    else
        MISSING=$((MISSING + 1))
        printf "  [--]  %s (not in image)\n" "$tool" >&2
    fi
done

echo ""
echo "Done. Extracted: ${EXTRACTED}   Missing/absent: ${MISSING}"
echo "Scratch rootfs:  ${SCRATCH}"
du -sh "$DEST" 2>/dev/null || true

cat > "${SCRATCH}/README.txt" <<EOF
Windows 11 CLI-only executables extracted from ${ISO:-$EXISTING_WIM}
by packaging/extract-win11-cli.sh

Layout: drive_c/Windows/System32
Assemble into the bundled distro template:
    cp -a "${SCRATCH}/drive_c" distros/windows-11/rootfs/
EOF