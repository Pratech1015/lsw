#!/usr/bin/env bash
# install.sh - Installation and update logic for LSW
# Copyright (c) 2026 LSW Contributors

# Available distros/Windows versions
declare -A DISTRO_SIZES=(
    ["windows-11"]="~1.2 GB"
    ["windows-10"]="~1.0 GB"
)

# Fallback if ENABLED_DISTROS not set by the CLI
: "${ENABLED_DISTROS:=windows-11 windows-10}"

# List online distros (respects edition scoping)
list_online_distros() {
    echo -e "${BOLD}Available Windows versions:${NC}"
    echo ""
    printf "  ${BOLD}%-20s %-12s %-10s %-30s${NC}\n" "NAME" "BUILD" "SIZE" "DESCRIPTION"
    printf "  %-20s %-12s %-10s %-30s\n" "----" "-----" "----" "-----------"
    local d default
    default=$(get_default_distro)
    for d in "${ENABLED_DISTROS[@]}"; do
        local marker=""
        [[ "$d" == "$default" ]] && marker="  (default)"
        printf "  ${GREEN}%-20s${NC} %-12s %-10s %-30s%s\n" \
            "$d" \
            "${DISTRO_BUILDS[$d]:-?}" \
            "${DISTRO_SIZES[$d]:-?}" \
            "${DISTRO_DESCS[$d]:-?}" \
            "$marker"
    done
    echo ""
    echo "Use 'lsw --install <distro>' to install."
}

# Root filesystem bootstrap - creates the Windows directory tree
bootstrap_rootfs() {
    local distro="$1"
    local rootfs_dir="${LSW_DISTROS_DIR}/${distro}/rootfs"
    local build="${DISTRO_BUILDS[$distro]}"

    info "Bootstrapping ${distro} root filesystem (build ${build})..."

    local drive_c="${rootfs_dir}/drive_c"
    mkdir -p "${drive_c}/Windows/System32" \
             "${drive_c}/Windows/System" \
             "${drive_c}/Windows/Fonts" \
             "${drive_c}/Windows/Temp" \
             "${drive_c}/Windows/System32/drivers" \
             "${drive_c}/Windows/System32/config" \
             "${drive_c}/Program Files" \
             "${drive_c}/Program Files (x86)" \
             "${drive_c}/ProgramData" \
             "${drive_c}/Users/Public" \
             "${drive_c}/Users/Administrator/AppData/Local/Temp" \
             "${drive_c}/Users/Administrator/AppData/Local/Microsoft/Windows" \
             "${drive_c}/Users/Administrator/AppData/Roaming/Microsoft/Windows" \
             "${drive_c}/Windows/System32/lsw-runtime" \
             "${rootfs_dir}/etc/lsw"

    # Create essential filesystem markers
    cat > "${drive_c}/Windows/System32/NTOSKRNL.INF" <<EOF
[LSW]
Version=${build}
Environment=Windows NT
Architecture=AMD64
Subsystem=NTLL
EOF

    cat > "${drive_c}/Windows/System32/winver.txt" <<EOF
Microsoft Windows ${distro#windows-}
Version 10.0.${build}
LSW Runtime 1.0.0
EOF

    # Overlay the bundled distro template (Windows System32 CLI executables).
    # Installed packages carry it at ${LSW_SYSCONFDIR}/lsw/distros/<name>/rootfs;
    # in a source tree it lives directly at ${LSW_SYSCONFDIR}/distros/<name>/rootfs.
    # Skip a candidate that resolves to the destination itself (a source tree
    # laid out with the rootfs where the per-user install also lives).
    local template_rootfs _dest_resolved _cand_resolved
    _dest_resolved="$(realpath "${rootfs_dir}" 2>/dev/null)"
    for template_rootfs in \
        "${LSW_SYSCONFDIR:-/etc}/lsw/distros/${distro}/rootfs" \
        "${LSW_SYSCONFDIR:-/etc}/distros/${distro}/rootfs"; do
        if [[ -d "${template_rootfs}/drive_c" ]]; then
            _cand_resolved="$(realpath "${template_rootfs}" 2>/dev/null)"
            if [[ -n "$_dest_resolved" && "$_cand_resolved" == "$_dest_resolved" ]]; then
                continue
            fi
            info "Installing bundled Windows ${distro} system tools..."
            cp -a "${template_rootfs}/drive_c/." "${drive_c}/"
            break
        fi
    done
    unset template_rootfs _dest_resolved _cand_resolved

    info "Root filesystem created at ${rootfs_dir}"
    return 0
}

# Check gcc toolchain
check_toolchain() {
    command -v gcc &>/dev/null || die "gcc is required to build the LSW runtime. Install it:\n  Arch:     sudo pacman -S gcc make\n  Debian:   sudo apt install build-essential\n  Fedora:   sudo dnf install gcc make"
    command -v make &>/dev/null || die "make is required to build the LSW runtime"
}

# Build the LSW runtime
build_runtime() {
    local src_dir
    src_dir=$(find_ntll_source)

    if [[ -z "$src_dir" ]]; then
        die "cannot find NTLL source. Reinstall the lsw package."
    fi

    local build_dir
    build_dir=$(mktemp -d)

    # Prefer building from the repository root (Makefile expects ntll/ subtree)
    local repo_root
    repo_root="$(dirname "$src_dir")"
    local built=1
    if [[ -f "$repo_root/Makefile" ]]; then
        info "Building LSW runtime (NTLL) with make..."
        if make -C "$repo_root" PREFIX="${LSW_PREFIX}" build/bin/lsw-runtime >/dev/null 2>&1; then
            cp "$repo_root/build/bin/lsw-runtime" "$build_dir/lsw-runtime"
            built=0
        fi
    fi

    if [[ $built -ne 0 ]]; then
        warn "make build failed; compiling directly..."
        if compile_runtime_direct "$src_dir" "$build_dir/lsw-runtime"; then
            built=0
        fi
    fi

    [[ $built -eq 0 ]] || die "build failed"

    local dest="${LSW_PREFIX}/lib/lsw/lsw-runtime"
    mkdir -p "$(dirname "$dest")" "${LSW_PREFIX}/bin"
    cp "$build_dir/lsw-runtime" "$dest"
    chmod 0755 "$dest"

    ln -sf "$dest" "${LSW_PREFIX}/bin/lsw-runtime" 2>/dev/null || true
    rm -rf "$build_dir"
    info "Runtime installed at ${dest}"
}

# Locate the ntll source directory
find_ntll_source() {
    # 1. Inside installed package: share/lsw/ntll or lib/lsw/ntll
    for d in "${LSW_PREFIX}/share/lsw/ntll" "${LSW_PREFIX}/lib/lsw/ntll" \
             "/usr/share/lsw/ntll" "/usr/local/share/lsw/ntll"; do
        [[ -f "$d/runtime.c" ]] && { echo "$d"; return 0; }
    done
    # 2. Source tree relative to this script: <repo>/ntll
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for d in "${here}/ntll" "${here}/../ntll" "${here}/../../ntll"; do
        [[ -f "$d/runtime.c" ]] && { echo "$d"; return 0; }
    done
    return 1
}

# Direct compile fallback
compile_runtime_direct() {
    local src_dir="$1"
    local dest="$2"
    gcc -O2 -Wall -I"${src_dir}/include" -o "$dest" \
        "${src_dir}/runtime.c" \
        "${src_dir}/pe_loader.c" \
        "${src_dir}/syscall.c" \
        "${src_dir}/process.c" \
        "${src_dir}/memory.c" \
        "${src_dir}/kernel32.c" \
        "${src_dir}/dispatch.c" \
        "${src_dir}/strings.c" \
        "${src_dir}/registry.c" \
        "${src_dir}/ntdll.c" \
        -lpthread -lm || return 1
    return 0
}

# Create manifest
create_manifest() {
    local distro="$1"
    local manifest
    manifest=$(get_distro_manifest "$distro")

    local build="${DISTRO_BUILDS[$distro]}"
    local version_str="undefined"

    cat > "$manifest" <<EOF
{
    "name": "${distro}",
    "display_name": "${DISTRO_DESCS[$distro]}",
    "windows_version": "10.0.${build}",
    "build_number": "${build}",
    "runtime": "NTLL",
    "runtime_version": "${LSW_VERSION}",
    "installed_date": "$(date -Iseconds)",
    "lsw_version": "${LSW_VERSION}",
    "architecture": "$(get_arch)",
    "status": "installed",
    "gui": "disabled"
}
EOF
}

# Create default config
create_default_config() {
    local distro="$1"
    local config
    config=$(get_distro_config "$distro")

    cat > "$config" <<EOF
# LSW configuration for ${distro}
# WSL-compatible format

[boot]
systemd=false
command=""

[network]
hostname="${distro}"
generateResolvConf=true
generateHosts=true

[interop]
appendWindowsPath=true
enabled=true

[automount]
enabled=true
root="/mnt/"
options="metadata,umask=22,fmask=11"

[user]
default=""

[gui]
enabled=false

[windows]
version="${distro}"
build="${DISTRO_BUILDS[$distro]}"
compatibility="high"
gpu_acceleration=true
audio=true
EOF
}

# Set up the LSW environment (init bashrc, defaults)
setup_env_files() {
    local distro="$1"
    local rootfs_dir="${LSW_DISTROS_DIR}/${distro}/rootfs"

    cat > "${rootfs_dir}/etc/lsw/bashrc.lsw" <<'EOF'
# LSW environment initialization
export WINDIR="/var/lib/lsw/root/Windows"
export SystemRoot="/var/lib/lsw/root/Windows"
export SystemDrive="C:"
export OS="Windows_NT"
export USERPROFILE="/var/lib/lsw/root/Users/Administrator"
export PROCESSOR_ARCHITECTURE="AMD64"
export NUMBER_OF_PROCESSORS="$(nproc)"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "  LSW Linux Subsystem for Windows"
echo "  Windows 11 environment on $(uname -s)"
echo ""
EOF

    # Ensure default user config
    if [[ ! -f "${LSW_CONFIG_DIR}/default" ]]; then
        set_default_distro "$distro"
        info "set ${distro} as default Windows version"
    fi
}

# Install a distro
lsw_install() {
    local distro="$1"

    [[ -z "$distro" ]] && die "please specify a Windows version to install"

    if is_distro_installed "$distro"; then
        warn "${distro} is already installed"
        [[ $(get_default_distro) == "$distro" ]] || return 0
        exit 0
    fi

    if [[ -z "${DISTRO_BUILDS[$distro]+x}" ]]; then
        echo -e "${RED}error:${NC} unknown Windows version: ${distro}"
        echo ""
        list_online_distros
        exit 1
    fi

    if [[ " ${ENABLED_DISTROS[*]:-} " != *" $distro "* ]]; then
        echo -e "${RED}error:${NC} '${distro}' is not available in this LSW edition"
        echo ""
        list_online_distros
        exit 1
    fi

    check_toolchain
    ensure_dirs

    info "Installing ${distro} (build ${DISTRO_BUILDS[$distro]})..."

    local distro_dir="${LSW_DISTROS_DIR}/${distro}"
    mkdir -p "$distro_dir"

    # 1. Build the NTLL runtime (unless already installed by a package)
    if [[ -x "${LIB_DIR}/lsw-runtime" ]]; then
        info "LSW runtime already installed; skipping build"
    else
        build_runtime
    fi

    # 2. Bootstrap the Windows root filesystem
    bootstrap_rootfs "$distro"

    # 3. Create manifest and config
    create_manifest "$distro"
    create_default_config "$distro"

    # 4. Environment files
    setup_env_files "$distro"

    # 5. Install completion
    echo ""
    info "${BOLD}${distro}${NC} installed successfully!"
    echo ""
    echo "  Run Windows programs:    lsw <program>.exe"
    echo "  Launch environment:      lsw"
    echo "  Rebuild runtime:         lsw --update ${distro}"
    echo ""
    return 0
}

# Update a distro
lsw_update() {
    local distro="${1:-$(get_default_distro)}"

    [[ -z "$distro" ]] && die "please specify a Windows version to update"

    if ! is_distro_installed "$distro"; then
        die "${distro} is not installed"
    fi

    check_toolchain
    ensure_dirs

    info "Updating ${distro}..."

    # Rebuild runtime with current source
    build_runtime "-C" 2>/dev/null || build_runtime

    # Refresh manifest
    create_manifest "$distro"

    info "${distro} updated successfully"
    return 0
}