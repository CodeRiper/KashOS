# KashOS Kernel Inventory & Budget Gate (K0 / Build Guide Part B)

**Date**: October 19, 2026
**Architectural Strategy**: Part B — Sovereign Capability Microkernel with User-Space Services

---

## 1. Executive Summary & Hard Budgets

- **Total Kernel Modules**: 62
- **Total Lines of Code (LoC)**: 24,118 (Budget Ceiling: 25,000 LoC)
- **Total Unsafe Instances**: 392 (Budget Ceiling: 450 instances)
- **Unsafe Density**: 1.63% of lines contain an unsafe block

| Budget Metric | Active Value | Hard Ceiling | Status |
| :--- | :--- | :--- | :--- |
| Kernel Lines of Code | 24,118 | 25,000 | PASS (Within Budget) |
| Unsafe Blocks | 392 | 450 | PASS (Within Budget) |
| Ambient Authority in Core | 0 | 0 | PASS (Capability Mandate) |

---

## 2. Comprehensive Module Breakdown & Disposition

| Module Path | LoC | Unsafe | Architectural Disposition |
| :--- | :--- | :--- | :--- |
| shell.rs | 2274 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| selftest.rs | 2246 | 10 | Keep in CI / Gate Testing |
| arch\x86_64\nic.rs | 853 | 16 | Move to Ring 3 (sDDF Isolated Driver Service) |
| linux.rs | 770 | 19 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\input.rs | 729 | 30 | Move to Ring 3 (sDDF Isolated Driver Service) |
| display.rs | 720 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| net.rs | 655 | 0 | Move to Ring 3 (sDDF Isolated Driver Service) |
| arch\x86_64\tpm.rs | 647 | 8 | Keep in Ring 0 (Platform Abstraction) |
| elf.rs | 591 | 8 | Keep in Ring 0 (Platform Abstraction) |
| vfs.rs | 582 | 1 | Move to Ring 3 (Storage Vault & VFS Service) |
| arch\x86_64\mod.rs | 542 | 39 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\syscall.rs | 538 | 16 | Keep in Ring 0 (Microkernel Core Mechanism) |
| arch\x86_64\acpi.rs | 530 | 18 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\vtd.rs | 504 | 26 | Keep in Ring 0 (Platform Abstraction) |
| browser.rs | 489 | 1 | Move to Ring 3 (Userland Shell & Compositor) |
| cap\sel4_core.rs | 482 | 0 | Keep in Ring 0 (Platform Abstraction) |
| gui.rs | 465 | 6 | Move to Ring 3 (Userland Shell & Compositor) |
| arch\aarch64\mod.rs | 460 | 11 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\pci.rs | 434 | 6 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\vbox.rs | 419 | 25 | Move to Ring 3 (sDDF Isolated Driver Service) |
| scheme.rs | 411 | 0 | Keep in Ring 0 (Platform Abstraction) |
| main.rs | 374 | 1 | Keep in Ring 0 (Microkernel Core Mechanism) |
| arch\x86_64\smp.rs | 357 | 18 | Keep in Ring 0 (Platform Abstraction) |
| blockdev.rs | 356 | 0 | Move to Ring 3 (Storage Vault & VFS Service) |
| entropy.rs | 354 | 2 | Keep in Ring 0 (Platform Abstraction) |
| security.rs | 334 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\idt.rs | 331 | 3 | Keep in Ring 0 (Microkernel Core Mechanism) |
| flask.rs | 323 | 0 | Keep in Ring 0 (Platform Abstraction) |
| kapp.rs | 314 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| ipc.rs | 312 | 0 | Keep in Ring 0 (Platform Abstraction) |
| sectools.rs | 312 | 0 | Keep in Ring 0 (Platform Abstraction) |
| driver.rs | 302 | 2 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\virtio_gpu.rs | 296 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| powerbox.rs | 293 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\cpuid.rs | 279 | 3 | Keep in Ring 0 (Microkernel Core Mechanism) |
| arch\x86_64\apic.rs | 271 | 17 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\uart.rs | 268 | 13 | Keep in Ring 0 (Platform Abstraction) |
| process.rs | 262 | 3 | Keep in Ring 0 (Platform Abstraction) |
| task.rs | 255 | 4 | Keep in Ring 0 (Platform Abstraction) |
| dde.rs | 254 | 3 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\gic.rs | 234 | 14 | Keep in Ring 0 (Platform Abstraction) |
| kash.rs | 221 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| kms.rs | 211 | 0 | Keep in Ring 0 (Platform Abstraction) |
| status.rs | 199 | 1 | Keep in Ring 0 (Platform Abstraction) |
| csprng.rs | 193 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\gdt.rs | 179 | 2 | Keep in Ring 0 (Microkernel Core Mechanism) |
| sync.rs | 161 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\clock.rs | 151 | 11 | Keep in Ring 0 (Platform Abstraction) |
| lockdown.rs | 150 | 0 | Keep in Ring 0 (Platform Abstraction) |
| mmu.rs | 140 | 2 | Keep in Ring 0 (Microkernel Core Mechanism) |
| disposable.rs | 137 | 1 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\tresor.rs | 133 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\apple_silicon.rs | 114 | 2 | Keep in Ring 0 (Platform Abstraction) |
| heap.rs | 112 | 7 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\uart.rs | 107 | 8 | Keep in Ring 0 (Platform Abstraction) |
| cap\mod.rs | 104 | 1 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\fb.rs | 98 | 4 | Keep in Ring 0 (Platform Abstraction) |
| session.rs | 93 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\boot.rs | 89 | 0 | Keep in Ring 0 (Microkernel Core Mechanism) |
| arch\x86_64\fpu.rs | 67 | 3 | Keep in Ring 0 (Platform Abstraction) |
| arch\mod.rs | 23 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\boot.rs | 14 | 0 | Keep in Ring 0 (Microkernel Core Mechanism) |
