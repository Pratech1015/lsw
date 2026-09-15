#!/usr/bin/env bash
# runner.sh - Execute Windows programs via the NTLL compatibility layer
# Copyright (c) 2026 LSW Contributors

# Locate the runtime binary
find_runtime() {
    local candidates=(
        "${LSW_PREFIX}/lib/lsw/lsw-runtime"
        "${LSW_PREFIX}/bin/lsw-runtime"
        "/usr/lib/lsw/lsw-runtime"
        "/usr/local/lib/lsw/lsw-runtime"
        "${LSW_PREFIX}/sbin/lsw-runtime"
    )
    for c in "${candidates[@]}"; do
        if [[ -x "$c" ]]; then
            echo "$c"
            return 0
        fi
    done
    return 1
}

# Check environment status
env_running() {
    local version="${1:-windows-11}"
    local pidfile="${LSW_DATA_DIR}/pids/${version}.pid"
    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        rm -f "$pidfile"
    fi
    return 1
}

# Send a command to the daemon
lswd_ctrl() {
    local cmd="$1"
    if [[ ! -S /tmp/lswd.sock ]]; then
        return 1
    fi
    local resp
    resp=$(printf '%s' "$cmd" | timeout 2 nc -U /tmp/lswd.sock 2>/dev/null)
    echo "$resp"
}

# Enter an interactive LSW environment shell (host bash with Windows env set)
enter_lsw_shell() {
    local rcfile="${LSW_DISTROS_DIR}/$(get_default_distro)/rootfs/etc/lsw/bashrc.lsw"
    if [[ -f "$rcfile" ]]; then
        # shellcheck source=/dev/null
        source "$rcfile"
    fi
    exec /bin/bash -i "$@"
}

# Main command runner
lsw_run() {
    local distro="${1:-}"
    shift 2>/dev/null || true

    local runtime
    runtime=$(find_runtime)
    if [[ -z "$runtime" ]]; then
        die "LSW runtime not found. Run 'lsw --install windows-11' first."
    fi

    local winver="windows-11"
    [[ -n "$distro" && "$distro" != "windows-11" && "$distro" != "windows-10" ]] && winver="windows-11"

    # Convert distro name to windows version flag
    local version_opt="--windows=11"
    [[ "$distro" == "windows-10" ]] && version_opt="--windows=10"

    # Rootfs the builtin cmd.exe / NTLL path helpers operate on
    local rootfs="${LSW_DISTROS_DIR}/$(get_default_distro)/rootfs"
    export LSW_ROOTFS="$rootfs"

    # Built-in console commands
    if [[ -z "$distro" ]] && [[ $# -eq 0 ]]; then
        warn "no command specified; launching default environment"
        enter_lsw_shell
        return 0
    fi

    local cmd="${1:-}"
    case "$cmd" in
        cmd|cmd.exe)
            shift 2>/dev/null
            exec "$runtime" "$version_opt" "$cmd" "$@"
            ;;
        powershell|powershell.exe|pwsh)
            shift 2>/dev/null
            if command -v pwsh &>/dev/null; then
                exec pwsh "$@"
            else
                die "PowerShell not available. Install it:  sudo snap install powershell --classic"
            fi
            ;;
        notepad|notepad.exe)
            shift 2>/dev/null
            die "notepad is not yet available in the Windows 11 environment"
            ;;
        *)
            # Windows executable path
            local path="${cmd:-}"
            if [[ -n "$path" && -e "$path" ]]; then
                exec "$runtime" "$version_opt" "$path" "${@:2}"
            elif [[ -n "$path" ]]; then
                # Builtin Windows software / console tools shipped with LSW
                case "$path" in
                    winver|winver.exe|hostname|hostname.exe|whoami|whoami.exe|\
                    echo|echo.exe|ver|ver.exe|date|date.exe|time|time.exe|\
                    *.bat|*.cmd)
                        exec "$runtime" "$version_opt" "$path" "${@:2}"
                        ;;
                esac
                # Native tool dispatch (ipconfig, ping, netstat, ...) — the
                # runtime resolves these via nt_tool_dispatch before PE load.
                exec "$runtime" "$version_opt" "$path" "${@:2}"
                die "Windows program '$path' not found"
            else
                warn "no command specified; entering LSW environment"
                enter_lsw_shell
            fi
            ;;
    esac
}