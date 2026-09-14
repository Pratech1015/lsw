#!/usr/bin/env bash
# common.sh - Shared utility functions for LSW
# Copyright (c) 2026 LSW Contributors

# Shared Windows distro metadata (used by manage.sh, install.sh, runner.sh)
declare -A DISTRO_BUILDS=(
    ["windows-11"]="22631"
    ["windows-10"]="19045"
)

declare -A DISTRO_DESCS=(
    ["windows-11"]="Windows 11 Pro"
    ["windows-10"]="Windows 10 Pro"
)

declare -A DISTRO_VERSION_FLAG=(
    ["windows-11"]="11"
    ["windows-10"]="10"
)

# Ensure required directories exist
ensure_dirs() {
    mkdir -p "$LSW_DATA_DIR" "$LSW_DISTROS_DIR" "$LSW_CONFIG_DIR" \
             "${LSW_DATA_DIR}/instances" "${LSW_DATA_DIR}/logs" 2>/dev/null || true
}

# Get the default distro
get_default_distro() {
    local default_file="${LSW_CONFIG_DIR}/default"
    if [[ -f "$default_file" ]]; then
        cat "$default_file"
    else
        echo "$LSW_DEFAULT_DISTRO"
    fi
}

# Set the default distro
set_default_distro() {
    local distro="$1"
    echo "$distro" > "${LSW_CONFIG_DIR}/default"
}

# Check if a distro is installed
is_distro_installed() {
    local distro="$1"
    [[ -d "${LSW_DISTROS_DIR}/${distro}" ]]
}

# Get distro root path
get_distro_root() {
    local distro="$1"
    echo "${LSW_DISTROS_DIR}/${distro}/rootfs"
}

# Get distro config
get_distro_config() {
    local distro="$1"
    echo "${LSW_DISTROS_DIR}/${distro}/lsw.conf"
}

# Get distro manifest
get_distro_manifest() {
    local distro="$1"
    echo "${LSW_DISTROS_DIR}/${distro}/manifest.json"
}

# Parse JSON value (simple parser, no jq dependency)
json_get() {
    local file="$1"
    local key="$2"
    grep -o "\"${key}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$file" 2>/dev/null | \
        sed "s/\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\"/\1/"
}

# Get running instances
get_running_instances() {
    local pid_dir="${LSW_DATA_DIR}/instances"
    local running=()
    if [[ -d "$pid_dir" ]]; then
        for pid_file in "${pid_dir}"/*.pid; do
            [[ -f "$pid_file" ]] || continue
            local pid
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                running+=("$(basename "$pid_file" .pid)")
            else
                rm -f "$pid_file"
            fi
        done
    fi
    echo "${running[@]}"
}

# Register an instance
register_instance() {
    local name="$1"
    local pid="$2"
    echo "$pid" > "${LSW_DATA_DIR}/instances/${name}.pid"
}

# Unregister an instance
unregister_instance() {
    local name="$1"
    rm -f "${LSW_DATA_DIR}/instances/${name}.pid"
}

# Log message
lsw_log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${msg}" >> "${LSW_DATA_DIR}/logs/lsw.log"
}

# Get Windows version from distro
get_windows_version() {
    local distro="$1"
    local manifest
    manifest=$(get_distro_manifest "$distro")
    if [[ -f "$manifest" ]]; then
        json_get "$manifest" "windows_version"
    else
        echo "unknown"
    fi
}

# Get build number from distro
get_build_number() {
    local distro="$1"
    local manifest
    manifest=$(get_distro_manifest "$distro")
    if [[ -f "$manifest" ]]; then
        json_get "$manifest" "build_number"
    else
        echo "0"
    fi
}

# Format bytes
human_readable_size() {
    local bytes="$1"
    if (( bytes >= 1073741824 )); then
        echo "$(echo "scale=2; $bytes/1073741824" | bc) GB"
    elif (( bytes >= 1048576 )); then
        echo "$(echo "scale=2; $bytes/1048576" | bc) MB"
    elif (( bytes >= 1024 )); then
        echo "$(echo "scale=2; $bytes/1024" | bc) KB"
    else
        echo "${bytes} B"
    fi
}

# Check if port is in use
port_in_use() {
    local port="$1"
    ss -tlnp 2>/dev/null | grep -q ":${port} " && return 0 || return 1
}

# Find available port
find_available_port() {
    local port=3000
    while port_in_use "$port"; do
        ((port++))
    done
    echo "$port"
}

# Progress indicator
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
}

# Confirmation prompt
confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local yn

    if [[ "$default" == "y" ]]; then
        prompt="${prompt} [Y/n]: "
    else
        prompt="${prompt} [y/N]: "
    fi

    read -rp "$prompt" yn
    case "$yn" in
        [Yy]*) return 0 ;;
        [Nn]*) return 1 ;;
        *)
            if [[ "$default" == "y" ]]; then
                return 0
            else
                return 1
            fi
            ;;
    esac
}

# Check if a command exists
command_exists() {
    command -v "$1" &>/dev/null
}

# Get architecture
get_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        armv7l|armhf) echo "armv7l" ;;
        *) echo "$arch" ;;
    esac
}

# Get Windows version constraint
get_windows_build() {
    local distro="$1"
    local manifest
    manifest=$(get_distro_manifest "$distro")
    if [[ -f "$manifest" ]]; then
        json_get "$manifest" "build_number"
    else
        echo "22631"
    fi
}
