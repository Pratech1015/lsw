#!/usr/bin/env bash
# manage.sh - Distro management operations for LSW
# Copyright (c) 2026 LSW Contributors

# List installed distros
lsw_list() {
    local online="${1:-false}"

    if [[ "$online" == "true" ]]; then
        # shellcheck source=/dev/null
        source "$(dirname "${BASH_SOURCE[0]}")/install.sh"
        list_online_distros
        return 0
    fi

    ensure_dirs

    echo -e "${BOLD}Windows versions installed:${NC}"
    echo ""
    printf "  ${BOLD}%-20s %-10s %-8s %-20s${NC}\n" "NAME" "BUILD" "STATE" "INSTALLED"
    printf "  %-20s %-10s %-8s %-20s\n" "----" "-----" "-----" "---------"

    local default
    default=$(get_default_distro)
    local found=0

    for distro_dir in "${LSW_DISTROS_DIR}"/*/; do
        [[ -d "$distro_dir" ]] || continue
        local name
        name=$(basename "$distro_dir")
        local manifest="${distro_dir}manifest.json"
        local build="?"
        local date="?"

        if [[ -f "$manifest" ]]; then
            build=$(json_get "$manifest" "build_number" 2>/dev/null || echo "?")
            date=$(json_get "$manifest" "installed_date" 2>/dev/null || echo "?"; true)
        fi

        local marker=""
        [[ "$name" == "$default" ]] && marker=" *"
        printf "  ${GREEN}%-20s${NC} %-10s %-8s %-20s%s\n" "$name" "$build" "installed" "$date" "$marker"
        found=1
    done

    if [[ $found -eq 0 ]]; then
        echo "  (none installed)"
        echo ""
        echo "  Install with: lsw --install windows-11"
    else
        echo ""
        echo "  * = default Windows version"
    fi
}

# Set default distro
lsw_set_default() {
    local distro="$1"
    ensure_dirs

    if ! is_distro_installed "$distro"; then
        die "${distro} is not installed. Run 'lsw --install ${distro}' first."
    fi

    set_default_distro "$distro"
    info "set ${distro} as default Windows version"
}

# Toggle/query Windows version emulation
lsw_set_version() {
    local distro="$1"
    [[ -z "$distro" ]] && die "please specify 'windows-11' or 'windows-10'"

    ensure_dirs
    local build="${DISTRO_BUILDS[$distro]:-}"
    if [[ -n "$build" ]]; then
        info "Windows version set to ${distro} (build ${build})"
    else
        die "unknown Windows version: ${distro}"
    fi
}

# Terminate a specific instance
lsw_terminate() {
    local distro="$1"
    local pidfile="${LSW_DATA_DIR}/pids/${distro}.pid"

    if [[ ! -f "$pidfile" ]]; then
        warn "${distro} is not running"
        return 0
    fi

    local pid
    pid=$(cat "$pidfile")
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$pidfile"
        warn "${distro} was not running"
        return 0
    fi

    kill -TERM "$pid" 2>/dev/null
    rm -f "$pidfile"
    info "terminated ${distro} (pid ${pid})"
}

# Shutdown all instances
lsw_shutdown() {
    ensure_dirs
    local terminated=0
    local pid_dir="${LSW_DATA_DIR}/pids"

    if [[ -d "$pid_dir" ]]; then
        for pid_file in "${pid_dir}"/*.pid; do
            [[ -f "$pid_file" ]] || continue
            local pid
            pid=$(cat "$pid_file")
            local name
            name=$(basename "$pid_file" .pid)

            if kill -TERM "$pid" 2>/dev/null; then
                info "terminated ${name} (pid ${pid})"
                ((terminated++))
            fi
            rm -f "$pid_file"
        done
    fi

    if [[ $terminated -eq 0 ]]; then
        warn "no running Windows versions"
    else
        info "shut down ${terminated} Windows version(s)"
    fi
}

# Unregister a distro
lsw_unregister() {
    local distro="$1"
    ensure_dirs

    if ! is_distro_installed "$distro"; then
        die "${distro} is not installed"
    fi

    if ! confirm "Unregister ${distro}? This will remove it permanently."; then
        info "aborted"
        return 0
    fi

    # Terminate if running
    lsw_terminate "$distro" 2>/dev/null

    rm -rf "${LSW_DISTROS_DIR}/${distro}"
    info "${distro} unregistered"

    # Clear default if needed
    if [[ $(get_default_distro) == "$distro" ]]; then
        rm -f "${LSW_CONFIG_DIR}/default"
        info "cleared default Windows version"
    fi
}

# Show status of a distro
lsw_status() {
    local distro="${1:-$(get_default_distro)}"
    ensure_dirs

    echo -e "${BOLD}Status for ${distro}:${NC}"
    echo ""

    if ! is_distro_installed "$distro"; then
        echo "  STATE: not installed"
        echo "  Install with: lsw --install ${distro}"
        return 0
    fi

    local manifest
    manifest=$(get_distro_manifest "$distro")
    local rootfs
    rootfs=$(get_distro_root "$distro")
    local pidfile="${LSW_DATA_DIR}/pids/${distro}.pid"

    echo "  State:      installed"
    if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
        echo "  Running:    yes (pid $(cat "$pidfile"))"
    else
        echo "  Running:    no"
    fi

    if [[ -f "$manifest" ]]; then
        echo "  Version:    $(json_get "$manifest" "windows_version" 2>/dev/null || echo unknown)"
        echo "  Build:      $(json_get "$manifest" "build_number" 2>/dev/null || echo unknown)"
        echo "  Runtime:    $(json_get "$manifest" "runtime" 2>/dev/null || echo unknown)"
        echo "  Installed:  $(json_get "$manifest" "installed_date" 2>/dev/null || echo unknown)"
    fi

    if [[ -d "$rootfs" ]]; then
        local size
        size=$(du -sh "$rootfs" 2>/dev/null | cut -f1)
        echo "  Root FS:    ${rootfs} (${size})"
    fi
}

# Export a distro to a tar file
lsw_export() {
    local distro="$1"
    local out_file="${2:-${distro}.tar.gz}"
    ensure_dirs

    if ! is_distro_installed "$distro"; then
        die "${distro} is not installed"
    fi

    pkill -0 "" 2>/dev/null # no-op, keep shellcheck quiet

    info "Exporting ${distro} to ${out_file}..."
    tar -czf "$out_file" -C "${LSW_DISTROS_DIR}" "${distro}" 2>/dev/null || {
        die "export failed"
    }
    info "exported to ${out_file} ($(du -h "$out_file" | cut -f1))"
}

# Import a distro from a tar file
lsw_import() {
    local distro="$1"
    local in_file="${2:-}"
    ensure_dirs

    [[ -z "$in_file" ]] && die "please specify a file to import"
    [[ -f "$in_file" ]] || die "file not found: ${in_file}"

    if is_distro_installed "$distro"; then
        die "${distro} already installed"
    fi

    info "Importing ${distro} from ${in_file}..."
    mkdir -p "${LSW_DISTROS_DIR}/${distro}"
    tar -xzf "$in_file" -C "${LSW_DISTROS_DIR}" 2>/dev/null || {
        rm -rf "${LSW_DISTROS_DIR}/${distro}"
        die "import failed (invalid archive)"
    }

    if [[ ! -f "$(get_distro_manifest "$distro")" ]]; then
        # Recreate manifest if missing
        create_manifest "$distro"
    fi

    # Set default if first
    if [[ ! -f "${LSW_CONFIG_DIR}/default" ]]; then
        set_default_distro "$distro"
        info "set ${distro} as default Windows version"
    fi

    info "${distro} imported successfully"
}

# Edit configuration
lsw_config() {
    local distro="${1:-$(get_default_distro)}"
    local file="${2:-}"
    ensure_dirs

    if ! is_distro_installed "$distro"; then
        die "${distro} is not installed"
    fi

    local config_file
    config_file=$(get_distro_config "$distro")

    if [[ -n "$file" ]]; then
        if [[ ! -f "$file" ]]; then
            die "configuration file not found: ${file}"
        fi
        cp "$file" "$config_file"
        info "configuration updated for ${distro}"
        info "changes take effect on next launch"
        return 0
    fi

    if ! command -v "${EDITOR:-vi}" &>/dev/null; then
        die "no editor found (please set EDITOR)"
    fi
    "${EDITOR:-vi}" "$config_file"
}