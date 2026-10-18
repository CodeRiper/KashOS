# Rust-Based Drivers & Open-Source Ecosystem Roadmap

## Overview
This document specifies how KashOS leverages pure-Rust `no_std` driver architectures and open-source operating system crates to complete its microkernel driver framework and userland ecosystem.

In accordance with **Build Guide v2 Rule 13 (Real Means Separate)** and **Phase 4 (Services and Drivers)**, all peripheral drivers are structured as modular, capability-constrained services.

---

## 1. Rust Driver & Subsystem Architecture

```
                               ┌────────────────────────────────┐
                               │   KashOS Ring 3 Applications   │
                               │  (Files, Terminal, Browser)    │
                               └──────────────┬─────────────────┘
                                              │ IPC via kipc / Capabilities
                               ┌──────────────▼─────────────────┐
                               │  Ring 3 Driver Services (ELF)  │
                               │ ┌────────────┐ ┌─────────────┐ │
                               │ │  Storage   │ │   Network   │ │
                               │ │  (IDE/AHCI)│ │  (smoltcp)  │ │
                               │ └────────────┘ └─────────────┘ │
                               │ ┌────────────┐ ┌─────────────┐ │
                               │ │   Input    │ │   Display   │ │
                               │ │ (PS2/USB)  │ │(Framebuffer)│ │
                               │ └────────────┘ └─────────────┘ │
                               └──────────────┬─────────────────┘
                                              │ Syscall Grants (IOPort / MMIO)
                               ┌──────────────▼─────────────────┐
                               │   KashOS Microkernel (Ring 0)  │
                               │   Memory, Scheduling, Caps     │
                               └────────────────────────────────┘
```

---

## 2. Recommended Open-Source Rust Crates for KashOS

The following pure-Rust `no_std` crates can be directly integrated or referenced across KashOS milestones:

### A. Network Drivers & Protocol Stack (Phase 7 / Phase 4)
- **`smoltcp`**:
  - **Role**: Standalone event-driven TCP/IP stack in `no_std`.
  - **Protocols**: ARP, IPv4, IPv6, ICMP, UDP, TCP, DHCP, DNS.
  - **Integration**: Plugs into the KashOS network driver interface to provide real sockets to userland without bringing standard Linux socket code into Ring 0.
- **`virtio-drivers`**:
  - **Role**: Paravirtualized driver support for QEMU, KVM, and cloud hypervisors.
  - **Devices**: `VirtIONet`, `VirtIOBlk`, `VirtIOGpu`, `VirtIOConsole`.
- **Intel e1000 & Realtek RTL8139**:
  - Pure-Rust drivers for Gigabit and Fast Ethernet PCI controllers found on vintage laptops and PCs.

### B. Storage Drivers & File Systems (Phase 4 / Phase 6)
- **`kblock` (Integrated)**:
  - Custom C-LOOK elevator scheduler designed for rotating hard drives and CompactFlash cards.
  - PATA / IDE PIO driver on ports `0x1F0`–`0x1F7`.
- **Rust AHCI Controller**:
  - Pure-Rust SATA AHCI driver using FIS command lists and PRDT tables for modern SATA hard drives and SSDs.
- **`fatfs` / `kvault`**:
  - `kvault` provides authenticated, encrypted, plausible-deniability storage.
  - `fatfs` provides read/write access to standard FAT32 / EFI System Partitions for installation and boot media.

### C. Input & Peripheral Drivers (Phase 4 / Phase H)
- **PS/2 Controller (`kernel/src/arch/x86_64/input.rs`)**:
  - Microsoft IntelliMouse 4-byte streaming protocol with wheel delta decoding.
  - Scancode Set 1/2 translation for standard 104-key US/international keyboards.
- **`pc-keyboard`**:
  - Pure-Rust crate for layout translation (QWERTY, AZERTY, Dvorak) and stateful key events.
- **USB Host Controllers (Phase H)**:
  - UHCI / EHCI for 2006-era vintage hardware.
  - xHCI for modern PCs.

### D. System Architecture & Low-Level Hardware
- **`x86_64`**:
  - Phil Oppermann's `x86_64` crate for type-safe control register manipulation (CR0, CR3, CR4, EFER), page table manipulation, and TSS structures.
- **`raw-cpuid`**:
  - Comprehensive CPUID feature discovery without hand-rolled inline assembly.

---

## 3. Step-by-Step Transition to Complete OS

| Phase | Milestone | Focus Areas | Primary Rust Drivers / Crates |
|:---|:---|:---|:---|
| **Stage A** | **M0: Honest Prototype** | Baseline cleanups, fail-closed entropy, CPU feature detection, claims audit | `khal`, `kcore`, `kheap`, `csprng` |
| **Stage B** | **M1: Real Kernel** | APIC/PIT timer calibration, Userland SDK (`kash-sys`, `kash-rt`), Ring 3 `init` | `targets/x86_64-unknown-kash.json`, `kipc` |
| **Stage C** | **M2: Usable VM Desktop** | Drivers as separate processes, persistent vault keys, disk installer | `kblock`, `ahci`, `virtio-drivers`, `kash-ui` |
| **Stage D** | **M3: Real Hardware** | Real hardware enablement on vintage Core 2 laptops, ACPI, network | `smoltcp`, `e1000`, `rtl8139`, `ps2` |
| **Stage E** | **M4: Hardened Release** | Linux POSIX compatibility layer, lightweight web browser engine | `relibc` / Linux shim, `NetSurf` / `Dillo` |
