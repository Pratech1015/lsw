# LSW2 — Linux Subsystem for Windows 2

The **WSL2 approach** to running Windows on Linux: boot a **real Windows
kernel** inside a lightweight virtual machine instead of translating one binary
ABI onto another.

This branch (`master`, the repository default) tracks LSW2.

## Branch policy

| Branch | Line | Design |
|--------|------|--------|
| `master` (default) | **LSW2** | Real Windows kernel, virtualized (WSL2 model) |
| `main` | **LSW1** | `ntll`: from-scratch PE loader, NT syscall translator, Win32 API stack (WSL1 model) |

The two branches have **no shared history**. `main` is the harder line: every
Windows API has to be re-implemented correctly by hand, because there is no
Windows kernel underneath. `master` trades that per-API work for a
virtualization layer.

## Why two approaches

WSL itself shipped both designs:

- **WSL1** translated Linux syscalls onto the NT kernel in user mode. Tiny and
  instant to start, but only as compatible as the translation layer was.
- **LSW2** mirrors **WSL2**: keep a real kernel, and fix compatibility by
  running the real thing rather than approximating it.

| | LSW1 (`main`) | LSW2 (`master`) |
|---|---|---|
| Windows kernel | none — `ntll` stands in for it | real, virtualized |
| Compatibility | exactly what `ntll` implements | whatever Windows actually provides |
| Startup cost | process launch | VM boot |
| Runtime dependency | none | KVM + QEMU (or equivalent) |
| Filesystem | directly mapped rootfs, `/var/lib/lsw` | guest disk + paravirtual share |
| Dominant bug class | per-API semantic mismatches | paravirt/device-model issues |

## Status

Early scaffold. Nothing is implemented yet — `make` builds a placeholder CLI
that reports this line's intent and implements no commands.

## Build

```sh
make            # build/lsw2
make test
./build/lsw2 --version
```

## License

GPL-3.0 — see `LICENSE`.
