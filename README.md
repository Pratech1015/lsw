# LSW - Linux Subsystem for Windows

> You've heard of WSL. Now meet its mirror: **run Windows 11 on Linux** — completely from scratch, with our own compatibility engine. Zero Wine.

LSW brings Windows to Linux the same way WSL brought Linux to Windows. Same command syntax, same workflow, **own runtime**.

- **Keep all the syntax and commands** — `lsw --install`, `lsw --list`, `lsw cmd`, identical flags to `wsl`
- **Own compatibility layer (NTLL)** — our from-scratch PE32+ loader, NT syscall translator, and Win32 API stack. No Wine, no dependencies.
- **Windows 11 first** — targeting build 22631 today; `windows-10` planned and structured for more.

```
Linux  ◄──►  WSL                     Windows  ◄──►  LSW
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                       lsw (CLI)                          │
│              wsl-compatible command surface              │
└──────────────┬──────────────────────────┬────────────────┘
               │                          │
       ┌───────▼────────┐         ┌───────▼────────┐
       │    lswd        │         │  lsw-runtime   │
       │  environment   │         │  NTLL engine   │
       │  daemon        │         │  PE loader     │
       └───────┬────────┘         │  syscall trans │
               │                  │  Win32 API     │
       ┌───────▼────────┐         └───────┬────────┘
       │   distros/     │                 │
       │  windows-11    │         ┌───────▼────────┐
       │  rootfs + reg  │         │  /var/lib/lsw  │
       └────────────────┘         │  instance data │
                                  └────────────────┘
```

### Components

| Component   | What it does |
|-------------|--------------|
| `lsw`       | CLI — mirrors `wsl` command syntax |
| `lswd`      | Daemon managing environments, pids, control socket |
| `lsw-runtime` | The NTLL engine — loads `.exe`, translates syscalls, implements Win32 |
| `lsw-init`  | First process in a Windows environment |
| `ntll/`     | NT Layer Library source (`ntll/pe_loader.c`, `ntll/syscall.c`, `ntll/kernel32.c`, …) |

### The NTLL runtime (own compatibility layer — no Wine)

`ntll/` is a from-scratch implementation of:

- **PE loader** (`pe_loader.c`) — parses DOS/NT headers, maps sections, applies relocations, resolves imports
- **Syscall translator** (`syscall.c`) — maps NT syscalls (`NtCreateFile`, `NtReadFile`, …) onto Linux syscalls
- **Win32 API** (`kernel32.c`, `ntdll.c`) — console, file I/O, time, threads, sync, TLS, environment
- **Registry emulation** (`registry.c`) — hive-backed registry under `/var/lib/lsw/registry`
- **Virtual memory** (`memory.c`) — VirtualAlloc/VirtualFree equivalents on `mmap`

---

## Install

### From a package manager

| Distro / PM       | Command |
|-------------------|---------|
| Arch / Manjaro    | `yay -S lsw` *(or pacman after publishing)* |
| Debian / Ubuntu   | `sudo apt install lsw` |
| Fedora / RHEL     | `sudo dnf install lsw` |
| Homebrew (Linux)  | `brew install lsw` |
| openSUSE          | `zypper in lsw` |

### From source

```bash
git clone https://github.com/lsw-project/lsw.git
cd lsw
make && sudo make install
```

---

## Usage — mirrors WSL

```bash
# Install a Windows version
lsw --install windows-11

# List versions
lsw --list
lsw --list --online

# Set default
lsw --set-default windows-11

# Show status
lsw --status
lsw --status windows-11

# Run a Windows program
lsw notepad.exe notes.txt
lsw app.exe --flag value

# Windows console aliases (same as WSL mappings)
lsw cmd
lsw powershell

# Manage environments
lsw --shutdown
lsw --terminate windows-11
lsw --update windows-11

# Portability (same as wsl --export / wsl --import)
lsw --export windows-11 windows11-backup.tar.gz
lsw --import windows-11 windows11-backup.tar.gz

# Configuration (WSL-compatible /etc/wsl.conf format)
lsw --config windows-11
```

### Output resembles WSL

```
$ lsw --list
Windows versions installed:
  Name           Build   State      Installed
  windows-11     22631   installed  2026-09-14T00:00:00+00:00  *
  * = default Windows version
```

---

## Releases & targets

| Version | State | Build |
|---------|-------|-------|
| **Windows 11** | ✅ primary target | 22631 |
| Windows 10 | 🚧 planned | 19045 |
| Windows 12+ | 🚧 future | — |

**GUI** — a graphical desktop bridge (taskbar, explorer, input) ships as a separate project: **LSWg**.

---

## Building

```bash
make                # build runtime + daemon
make test           # run test suite (pass even with skipped items)
make PREFIX=/usr install
make uninstall
```

### Cross-compile a Windows test binary (requires mingw)

```bash
x86_64-w64-mingw32-gcc -o test-app.exe tests/test-app.c
lsw test-app.exe
```

---

## Configuration

Same format as `/etc/wsl.conf`, at `/etc/lsw/lsw.conf`:

```ini
[windows]
version="windows-11"
build="22631"
compatibility="high"
gpu_acceleration=true
audio=true

[gui]
enabled=false
```

---

## License

GPL-3.0. See [LICENSE](LICENSE).

## Project status

Early engineering. The NTLL runtime loads PE images and exposes a working
Win32 surface; expect both growing coverage in the 1.x series.