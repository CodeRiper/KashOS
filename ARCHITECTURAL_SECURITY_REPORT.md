# Architectural Security Report & Gap Analysis
**KashOS: From Ring-0 Prototype to a Capability-Based Microkernel Workstation**

**Author**: Akash ([`akash.official.j@gmail.com`](mailto:akash.official.j@gmail.com))  
**Date**: October 2026 (Phase 0 Audit)

---

## 1. Executive Summary & Honest Baseline

KashOS is a capability-based workstation operating system implemented in `#![no_std]` Rust for x86_64 hardware.

### 1.1 Current Prototype State
The operating system today is a functional **ring-0 prototype (~29.7k lines of Rust and assembly)** that boots via Multiboot2, builds an identity-mapped $W\oplus X$ page table, initializes GDT/IDT/APIC, and renders a 60 FPS retained-scene desktop to the linear framebuffer.

However, an honest security audit reveals significant architectural gaps between the current prototype and a complete, capability-isolated microkernel:
- **No User Mode**: All kernel and user interface code currently executes in ring 0. `enter_user_mode()` has not yet been invoked.
- **Single Address Space**: Paging is identity-mapped. There are currently no per-process address spaces, no higher-half kernel split, and no KASLR/KPTI.
- **Unlinked Scheduler & IPC**: High-quality crates for 3-band strict-priority scheduling (`kscheduler`) and lock-free SPSC IPC (`kipc`) exist and pass host unit tests, but are not yet linked to active timer interrupt preemption or context switching.
- **Model Code**: Architectural models in `kash_kernel.rs` (untyped memory watermark, ARINC 653 cyclic scheduling) are currently uncalled by the runtime boot path.
- **Proof Status**: Zero machine-checked proofs (Verus, Kani, Coq) exist in the repository. All claims of "mathematical proof" or "formal verification" have been retracted.

### 1.2 Target System Architecture
The target system is a capability-based microkernel workstation operating system structured as follows:
1. **Tiny Microkernel TCB**: Restricted strictly to thread scheduling, per-process address spaces, capability spaces, synchronous IPC, hardware interrupt routing, and IOMMU configuration.
2. **User-Space Service Isolation**: Drivers (storage, networking, input), display servers, and user applications execute as separate, unprivileged user-mode processes.
3. **Zero Ambient Authority**: Resources cannot be accessed via global paths or ambient tokens; access requires explicit capability handles with unforgeable rights and badges.
4. **Hardware-Enforced Containment**: IOMMU (Intel VT-d / AMD-Vi) blocks rogue DMA; page-table NX, SMEP, and SMAP prevent privilege escalation; full-disk AEAD encryption protects data at rest.

---

## 2. Subsystem Audit & Roadmap Matrix

The table below reflects the single source of truth across the codebase, matching [`docs/KASHOS_BUILD_GUIDE.md`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/docs/KASHOS_BUILD_GUIDE.md) and [`kernel/src/status.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kernel/src/status.rs):

| Area | Current Implementation | Target Implementation | Roadmap Phase |
| :--- | :--- | :--- | :---: |
| **Boot & Platform** | BIOS/Multiboot2 bootloader, 64-bit GDT/IDT, Local APIC timer, single CPU. | UEFI GOP bootloader (PE32+), ACPI MADT parsing, multi-core SMP bringup via INIT-SIPI. | Phase 1 & 5 |
| **Paging & Memory** | Identity-mapped 4-level page tables with $W\oplus X$ permission bits. | Higher-half kernel mapping, per-process page tables (`kpaging`), physical frame allocator with domain quotas. | Phase 1 |
| **Privilege Levels** | Ring 0 execution only; GDT TSS and IST stack tables prepared. | Real ring-3 transition via `sysretq`/`iretq`, SMAP user-pointer validation, fault containment (process crash $\ne$ kernel panic). | Phase 2 |
| **Scheduler** | Cooperative spinloop with PS/2 fast-break polling. | Preemptive timer-driven scheduler wiring in `kscheduler`, per-thread kernel stacks, FPU/SSE save/restore. | Phase 1 |
| **Capability Engine** | `kcore` library implementing Capability Derivation Trees (CDT) with rights and badges. | Per-process capability spaces enforced on every syscall, object quota limits, synchronous capability transfer via `kipc`. | Phase 3 |
| **IOMMU & DMA** | ACPI DMAR parser and register structures. | Second-stage translation tables programmed per PCIe peripheral; fault logging enabled; pass-through disabled. | Phase 4 |
| **Device Drivers** | PS/2 keyboard/mouse active; e1000/virtio-net partial in ring 0. | VirtIO-blk, VirtIO-net, AHCI, and xHCI isolated in unprivileged user-space driver services with IOMMU isolation. | Phase 4 |
| **Storage & Crypto** | `kvault` library: Argon2id, XChaCha20-Poly1305, Merkle CoW tree (20 tests pass). | Root filesystem mounted through block storage service; AES-256-XTS support; RAM zeroization on lock; TPM-sealed keys. | Phase 6 |
| **Network Stack** | `knet` passive packet parser tested. | User-mode network service running `smoltcp` (IPv4/IPv6, TCP, UDP, DHCP, DNS), default-deny firewall, WireGuard. | Phase 7 |
| **GUI & Display** | Ring-0 `kash-ui` compositor with dirty-rect blitting and Nitpicker X-Ray mode (F12). | Unprivileged user-mode display service; apps draw into shared buffers granted by capability; compositor owns framebuffer. | Phase 9 |
| **Verification** | Host unit tests across workspace crates. | Invariant proofs of small cores (frame allocator, capability table, page-table mapper) using Kani or Verus in CI. | Phase 10 |

---

## 3. Threat Model and Boundary Definitions

The system security boundaries are structured to defend against threats defined in [`docs/THREAT_MODEL.md`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/docs/THREAT_MODEL.md):

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User Applications                               │
│        (Unprivileged Ring 3, Scoped Capability Spaces)                 │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ IPC with Capability Grants
┌───────────────────────────────────▼────────────────────────────────────┐
│                    User-Mode Core Services                             │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│   │   sys-net   │  │   sys-usb   │  │   storage   │  │   display   │   │
│   │ (smoltcp)   │  │ (xHCI sDDF) │  │ (kvault-fs) │  │  (kash-ui)  │   │
│   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
└──────────┼────────────────┼────────────────┼────────────────┼──────────┘
           │ Hardware MMIO  │ Hardware MMIO  │ DMA Window     │ Framebuffer
┌──────────▼────────────────▼────────────────▼────────────────▼──────────┐
│              KashOS Microkernel Core (Ring 0, Minimal TCB)             │
│   • Preemptive kscheduler           • Capability Derivation Engine     │
│   • Per-Process kpaging Spaces      • Synchronous kipc Messaging       │
│   • Interrupt & Fault Routing       • Hardware IOMMU Second-Stage      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                  Physical Bare-Metal Hardware                          │
│   • CPU: x86_64, NX, SMEP, SMAP, UMIP, WP                              │
│   • Virtualization: Intel VT-d / AMD-Vi IOMMU, PCIe ACS                │
│   • Cryptographic HW: RDRAND / RDSEED, TPM 2.0, CMOS RTC               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Compartmentalization & Domain Model

Every running compartment possesses an isolated domain ID and an immutable, unforgeable border color enforced by the compositor:

- **`kash-dom0` (ID: 0)**: Obsidian Admin (`#E1E6F0`) — Administrative policy control.
- **`sys-net` (ID: 1)**: Red Untrusted Net (`#D93025`) — Untrusted PCIe network adapter and stack.
- **`personal` (ID: 2)**: Mint Green (`#81C995`) — Trusted personal workspace.
- **`work-app` (ID: 3)**: Blue Work (`#1A73E8`) — General enterprise tasks.
- **`sys-usb` (ID: 4)**: Amber USB (`#FA903E`) — Untrusted xHCI USB controller jail.
- **`disp-vm` (ID: 5)**: Magenta Disposable (`#F538A0`) — Ephemeral zero-persistence sandbox.
- **`vault-keys` (ID: 6)**: Purple Vault (`#C58AF9`) — Air-gapped offline cryptographic store.

---

## 5. Performance Engineering for Low and High Hardware

Testing in minimal environments (1 vCPU, 256 MiB RAM, standard VGA) demonstrated that full-canvas framebuffer blitting ($1024\times768\times4\text{ B} = 3.14\text{ MB}$) across virtual MMIO causes CPU starvation.

To achieve smooth 60 FPS across all hardware tiers:
1. **Adaptive Dirty-Rectangle Blitting**: When the mouse cursor moves, only the bounding box covering the old and new cursor positions ($48\times48$ to $80\times80$ pixels, or $25.6\text{ KB}$) is written to VRAM. This produces a **$99.2\%$ reduction in bus write traffic**.
2. **PS/2 Port 0x64 Fast-Break Polling**: Hardware input checking wakes the compositor loop immediately on user action, dropping idle CPU utilization to $< 2\%$.
3. **No Swap on Low Tiers**: Memory budgets are strictly accounted; no swapping is enabled on systems with $< 1\text{ GiB}$ RAM.

---

## 6. Verification and Hardening Commitment

In accordance with Rule 10 of the KashOS Build Guide:
- No claims of "verified" or "proven" are permitted in documentation without a machine-checked proof in the repository and a green CI pipeline.
- All security guarantees are tracked in [`docs/CLAIMS.md`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/docs/CLAIMS.md) with their required empirical evidence.
- An independent security audit will serve as the final milestone before any general-purpose release.
