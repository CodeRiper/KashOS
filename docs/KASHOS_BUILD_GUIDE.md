# KashOS: make it real, secure and fast (agent build guide)

## 0. Read this first: rules for the AI agent

This guide turns KashOS from a ring-0 prototype into a real, tested, secure OS. Every claim in the README must end up true, proven by a test you can run, or be deleted. Nobody can promise "the most secure OS in the world"; the honest target is a small, capability-based system with a measurable attack surface, real isolation, and public evidence.

### The 10 non-negotiable rules
1. **No simulation.** Never hardcode output that looks like system state (`ps`, `free`, `df`, `dmesg`, `opsec`, `security`, `top`). Every number shown must be read from real kernel state.
2. **No fake `[OK]`.** A status line prints `OK` only after the code just checked the thing. Keep and extend `status.rs` as the single source of truth.
3. **A feature is "done" only when:** code exists, it is reachable from a running boot, a test proves it, and the status registry says `Real`.
4. **Every security claim gets a row in the claim-to-evidence table (`docs/CLAIMS.md`).** No evidence, no claim.
5. **Fail closed.** If hardware support (IOMMU, RNG, TPM) is missing, say so, disable the dependent feature, and do not pretend.
6. **Remove dead code or wire it in.** `kash_kernel.rs`, `kscheduler` and `kipc` must be used by the kernel or deleted.
7. **Every setting in the GUI is backed by a real kernel or service API.** A toggle that does nothing is a bug, not a placeholder.
8. **Work in small phases.** Do not start phase N+1 until phase N's acceptance tests pass in CI and in QEMU.
9. **Minimise `unsafe`.** Each `unsafe` block gets a `// SAFETY:` comment stating the invariant, and lives in a small module that is tested.
10. **Never write "verified", "proven" or "mathematically"** unless a machine-checked proof (Verus, Kani, Coq, Isabelle) is in the repo and runs in CI.

---

## 1. Honest baseline (from the code audit, Oct 2026)

The code is about 29.7k lines of Rust and assembly. The kernel boots via GRUB (Multiboot2), builds a W^X page table, and draws a desktop to the framebuffer, all in ring 0. No user process has ever run.

| Area | Today | Gap to "real" |
| :--- | :--- | :--- |
| **Boot, GDT/IDT/APIC, heap** | Works (BIOS/Multiboot2) | UEFI loader is a stub; SMP not started (CPU count hardcoded to 1) |
| **W^X paging** | Real, identity-mapped | No higher-half kernel, no per-process address spaces, no KASLR/KPTI |
| **Ring 3 / syscalls** | Entry asm and GDT exist | `enter_user_mode()` never called; all syscalls run as PID 1 |
| **Scheduler / IPC** | `kscheduler`, `kipc` pass unit tests | Not linked into the kernel; no context switch |
| **Capabilities** | `kcore` and `cap/` solid and tested | Nothing unprivileged exists to be confined |
| **kash_kernel.rs** | Model code | Wire in or delete |
| **VT-d** | Register code, legacy 128-bit entries | Off unless DMAR found; no driver domains use it; no AMD-Vi |
| **Drivers** | PS/2 works; e1000 and virtio-net partial; kblock drivers have unit tests | xHCI stub; no integrated disk filesystem; no Wi-Fi |
| **Storage crypto (`kvault`)** | Argon2id, XChaCha20-Poly1305, Merkle CoW tree, hidden volume, duress: 20 tests pass | AES-256-XTS not implemented; not mounted as the OS filesystem |
| **Network** | `knet` passive analysis only | No TCP/IP stack, no Tor, no kill switch |
| **GUI (`kash-ui`)** | Real renderer, dock, lock, files, terminal, settings | Apps are built-in widgets in ring 0; settings not wired to real state |
| **Shell commands** | Several print hardcoded text | Replace with real reads or remove |
| **Verification** | Unit tests on libraries | Zero Verus/Kani/Coq proofs; "Verus-verified" claims are false |

---

## 2. Target, threat model, and what "most secure" can mean

**Target**: A capability-based microkernel workstation OS in Rust, where drivers, network, storage and the GUI run as separate unprivileged user-mode services, with hardware isolation (IOMMU, NX, SMEP/SMAP), encrypted storage, measured boot, and an honest, public verification record.

### Design decisions
- **Isolation model**: Process-based capability compartments first (like seL4/Genode/Redox). A VT-x/AMD-V hypervisor for full VM compartments (Qubes-style) is a later, optional phase.
- **Keep the kernel tiny**: Scheduler, address spaces, capabilities, IPC, interrupts, IOMMU programming. Everything else is a user-mode service.
- **Language**: Rust `#![no_std]` kernel; user services in Rust. A Linux/POSIX compatibility layer is a later, sandboxed service, not part of the kernel.
- **Boot**: UEFI first (GOP framebuffer, ACPI, Secure Boot signing), with the Multiboot2/BIOS path kept for VMs.

---

## 3. Roadmap: Phases 0 to 5

### Phase 0: Honesty cleanup (days)
- Rewrite `README.md` and `ARCHITECTURAL_SECURITY_REPORT.md`: remove "formally verified", Verus, seL4 and GrapheneOS comparisons; add a status table and a roadmap section.
- Delete or replace every hardcoded shell output (`ps`, `free`, `df`, `dmesg`, `uname`, `opsec`, `security`, `top`). Each command reads real state or prints "not implemented".
- Remove unconditional `[OK]` boot lines; print only from `status.rs`.
- Fix the duplicate domain ID in the colour table (personal and sys-usb are both 2).
- Add `docs/THREAT_MODEL.md` and `docs/CLAIMS.md` (claim-to-evidence table).
- **Gate**: `grep -r "OK\]"` shows only registry-driven prints; a CI check fails the build if the README contains the words "verified" or "proven" without a linked proof.

### Phase 1: Kernel core (weeks)
- Higher-half kernel mapping; per-process page tables (`kpaging`); a physical frame allocator that tracks ownership.
- Interrupt-safe spinlocks (disable IRQs while held) and lock ordering rules; ticket or MCS locks for SMP.
- Enable and verify NX, SMEP, SMAP, UMIP, WP; KASLR; guard pages on every kernel stack; stack canaries or Rust equivalents.
- Real timer-driven preemptive scheduler: wire in `kscheduler`, per-thread kernel stacks, context switch (save/restore FPU and SSE state), idle thread.
- SMP bring-up from the ACPI MADT (AP start via INIT-SIPI), per-CPU data, TLB shootdown IPIs.
- Replace hardcoded `current_pid = 1` with the real current process.
- **Gate**: QEMU boots with 4 CPUs; two kernel threads preempt each other 1M times without corruption; a deliberate NX/SMEP violation test is caught and logged; unit tests for the frame allocator and mapper run in CI.

### Phase 2: Real user mode (weeks)
- ELF loader that maps segments with exact permissions into a fresh address space, builds the user stack, then calls `enter_user_mode`.
- Syscall layer: validate that user pointers are mapped, user-owned and in range; copy with SMAP toggles; return errors, never panic.
- Process lifecycle: spawn, exit, wait, fault handling (a user fault kills the process, never the kernel).
- Ship a tiny `init` and a test program written in Rust (`no_std`).
- **Gate**: A user program prints through a syscall; a program that dereferences null, kernel memory, or an unmapped page is killed while the kernel keeps running; 10k random-syscall fuzz run causes no kernel panic.

### Phase 3: Capabilities and IPC enforced (weeks)
- Make `kcore` / `cap/` the only way a process names a resource: handles in a per-process capability space, with rights, badges, derive, revoke.
- Synchronous IPC with capability transfer (use `kipc`); shared-memory grants with explicit revoke; notifications.
- Delete ambient authority: no global namespaces, no path-based open without a granted directory capability.
- Decide on `kash_kernel.rs`: move the untyped-memory watermark allocator into the real kernel object allocator, or delete it. Same for the ARINC scheduler: implement fixed time slices as a scheduling class, or delete the claim.
- **Gate**: Process A cannot read process B's memory or use a capability it was never given (negative tests); revoke removes access in under 1 ms for 1,000 derived caps; a kernel-object quota stops one process from exhausting kernel memory while others keep running.

### Phase 4: Userspace services and drivers (months)
- Move out of the kernel into user-mode services: storage, network, input, display server, USB. Each gets only its device MMIO, IRQ and DMA capabilities.
- Real VT-d (and AMD-Vi): parse DMAR/IVRS, program second-stage tables per device, enable fault logging, never use pass-through for untrusted devices; use scalable mode where the CPU supports it.
- Drivers, in priority order: virtio-blk, virtio-net, virtio-gpu, NVMe, AHCI, xHCI (USB keyboard, mouse, storage), e1000/e1000e/igc, then Intel Wi-Fi.
- Hardware discovery: full ACPI (MADT, MCFG, DMAR, FADT), PCIe enumeration, MSI/MSI-X, UEFI GOP framebuffer.
- **Gate**: Each driver passes its own test in QEMU; a malicious device model in QEMU that DMA-writes outside its window is blocked and logged by the IOMMU; killing and restarting a driver service does not crash the system.

### Phase 5: Boot chain and measured boot (months)
- UEFI loader (PE32+) that verifies the Ed25519 or SHA-256 signature of kernel and init; Secure Boot signing instructions.
- TPM 2.0 driver: extend PCRs for each boot stage; seal vault keys to PCRs; fail closed if measurements change.
- **Gate**: Tampering with one byte of the kernel image prevents unseal and boot in a test run; the PCR values are reproducible across two clean boots.

---

## 4. Roadmap: Phases 6 to 10

- **Phase 6: Storage and crypto**: Mount `kvault` as real root filesystem; block driver integration; key management service; zeroize on lock; TPM-sealed key; CSPRNG with hardware entropy.
- **Phase 7: Network**: User-mode network service with `smoltcp`; default-deny firewall; WireGuard/Tor integration; MAC randomization; TLS via `rustls`.
- **Phase 8: Compartments**: Process-based domains (Personal, Work, Vault, Net, USB, Disposable); FLASK policy enforcement; unforgeable powerbox file/clipboard transfer dialogs.
- **Phase 9: GUI and display server**: `kash-ui` as user-mode display service; damage tracking; unforgeable 4px security borders; keyboard routed only to focused window.
- **Phase 10: Verification and hardening**: Small-core proofs with Verus or Kani; fuzzing of syscalls, ELF, IPC, network, and kvault; `miri`, `cargo-geiger`, and `cargo-audit` in CI; reproducible container builds.
