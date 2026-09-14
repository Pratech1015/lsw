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

    # Built-in console commands
    if [[ -z "$distro" ]] && [[ $# -eq 0 ]]; then
        warn "no command specified; launching default environment"
        exec "$runtime" --windows=11 /bin/sh -c \
            "echo 'LSW: Linux Subsystem for Windows'; echo 'Type exit to quit'; exec /bin/bash --rcfile /etc/lsw/bashrc.lsw"
        return 0
    fi

    local cmd="${1:-}"
    case "$cmd" in
        cmd|cmd.exe)
            shift 2>/dev/null
            warn "cmd.exe is not fully implemented; dropping to LSW shell"
            exec "$runtime" "$@" \
                /bin/bash --rcfile /etc/lsw/bashrc.lsw
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
                # Resolve win32 path if given
                local winpath
                winpath=$(python3 - "$path" <<'PYEOF' 2>/dev/null || echo "$path"
import os,sys
p=os.path.abspath(sys.argv[1])
print(p)
PYEOF
)
                exec "$runtime" "$version_opt" "$winpath" "${@:2}"
            elif [[ -n "$path" ]]; then
                # Try system32 lookup
                local sys_search
                sys_search=$(find "${LSW_DISTROS_DIR}/windows-11/rootfs" -name "$path" -type f 2>/dev/null | head -1)
                if [[ -n "$sys_search" ]]; then
                    exec "$runtime" "$version_opt" "$sys_search" "${@:2}"
                fi
                die "Windows program '$path' not found"
            else
                warn "no command specified; entering LSW environment"
                exec "$runtime" "$version_opt" /bin/sh -c "echo 'LSW environment'; exec /bin/bash --rcfile /etc/lsw/bashrc.lsw"
            fi
            ;;
    esac
}