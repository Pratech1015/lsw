# LSW2 architecture

This is the **WSL2** line of LSW: run a real Windows kernel instead of
substituting one (`ntll`) in user mode.

For contrast, the `main` branch documents the LSW1 design. The two share no
history and no code.

## Reference: how WSL2 works

WSL2's predecessor, WSL1, translated Linux syscalls onto the NT kernel from
user mode. WSL2 changed the shape of the problem:

1. A lightweight utility VM boots, containing a **real Linux kernel**.
2. The guest kernel is booted with a minimal init, not a full distro.
3. Windows and the guest talk over **paravirtual devices** (VIRTIO).
4. The guest filesystem is shared back to Windows with a **9p/Plan9** or
   **virtiofs** mount, so there is no per-file translation.
5. `wsl.exe` remains the user-facing command surface; it talks to a service
   that owns the VM's lifetime.

Compatibility stops being a per-syscall engineering problem and becomes a
device-model problem.

## LSW2 design

Mirror the above, with roles reversed.

```
 host Linux
 ┌─────────────────────────────────────────────┐
 │  lsw  (wsl-compatible CLI)                  │
 │  lswd (environment + VM lifecycle)          │
 │  qemu-system-x86_64  +  KVM                 │
 │                                             │
 │   ├─ virtio-blk  → guest Windows disk       │
 │   ├─ virtio-net  → host networking          │
 │   ├─ virtio-serial → init/handshake channel │
 │   └─ virtiofs   → shared filesystem         │
 └───────────────┬─────────────────────────────┘
                 │  paravirtual devices
 guest ┌─────────▼──────────┐
       │  Windows kernel    │  (real, unmodified)
       │  boot agent        │
       └────────────────────┘
```

| Component | Responsibility |
|-----------|----------------|
| `lsw` | CLI surface, identical flags to `wsl` |
| `lswd` | Owns VM lifetime, env registry, control socket |
| VM monitor | QEMU + KVM process management, snapshot/restore |
| boot agent | First code in the guest; publishes ready state |
| filesystem share | Host↔guest path mapping (replaces LSW1's rootfs mapping) |

### Boot sequence

1. `lsw <command>` resolves the environment and asks `lswd`.
2. `lswd` starts (or reuses) the VM for that environment.
3. Guest boots the kernel, hands off to the boot agent.
4. The agent signals ready over virtio-serial with the guest's service state.
5. The command is executed *inside the guest*; stdio is proxied back over the
   same channel.

### Filesystem

LSW1 maps `distros/windows-11/rootfs/drive_c/...` directly onto host paths.
LSW2 instead gives the guest its own virtual disk, and exposes selected host
directories through a paravirtual share. This is the direct analogue of why
WSL2 dropped plan9-on-NT for a real kernel plus a shared mount.

### What this removes

- No hand-written Win32 API implementations (the bulk of `main`'s `ntll/`).
- No per-call ABI translation bugs of the kind that required a complete
  rewrite of `FormatMessageW` insert handling, UTF-32 vs UTF-16LE pointer
  decoding, and handle-table encoding.
- No need to keep a PE loader, relocation, and import resolver in sync.

### What this adds

- QEMU/KVM as a hard runtime dependency.
- Boot latency and resident memory for the guest.
- A paravirt device model to get right (block, net, console, filesystem).
- Image management: acquiring, unpacking, and versioning Windows disk images.
- A licensing/redistribution question around shipping a Windows kernel image.

## Roadmap

- [x] Repository scaffold for this line.
- [ ] VM monitor: start/stop/reuse a guest, wire lifetime into `lswd`.
- [ ] Guest boot agent + ready handshake over virtio-serial.
- [ ] stdio proxying so `lsw cmd.exe` is interactive.
- [ ] Filesystem share with `wsl --mount`-equivalent semantics.
- [ ] `lsw --list` / `--shutdown` backed by the real environment manager.
- [ ] Distro image import/export matching `wsl --import` / `wsl --export`.

## Open questions

- **Image source.** Where the Windows kernel image comes from, and whether it
  is ever redistributed versus built from user-provided media.
- **Backends.** KVM-only, or a pluggable backend (e.g. software fallback) so
  the CLI still works without hardware virtualization.
- **Guest OS target.** Windows 11 first (matching `main`), or a smaller target
  to start since a real kernel removes most compatibility work.
- **Relationship to `main`.** Whether LSW1's rootfs/registry work survives as
  a lightweight mode alongside LSW2.
