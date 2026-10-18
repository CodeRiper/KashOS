# KashOS Kernel Inventory & Budget Gate (K0 / Build Guide Part B)

**Date**: October 18, 2026
**Architectural Strategy**: Part B — Sovereign Capability Microkernel with User-Space Services

---

## 1. Executive Summary & Hard Budgets

- **Total Kernel Modules**: 60
- **Total Lines of Code (LoC)**: 21638 (Budget Ceiling: 25,000 LoC)
- **Total Unsafe Instances**: 412 (Budget Ceiling: 450 instances)
- **Unsafe Density**: 1.90% of lines contain an unsafe block

| Budget Metric | Active Value | Hard Ceiling | Status |
| :--- | :--- | :--- | :--- |
| Kernel Lines of Code | 21638 | 25,000 | PASS (Within Budget) |
| Unsafe Blocks | 412 | 450 | PASS (Within Budget) |
| Ambient Authority in Core | 0 | 0 | PASS (Capability Mandate) |

---

## 2. Comprehensive Module Breakdown & Disposition

| Module Path | LoC | Unsafe | Architectural Disposition |
| :--- | :--- | :--- | :--- |
| shell.rs | 2253 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| selftest.rs | 2077 | 10 | Keep in CI / Gate Testing |
| linux.rs | 770 | 19 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\vtd.rs | 684 | 31 | Keep in Ring 0 (Platform Abstraction) |
| net.rs | 650 | 0 | Move to Ring 3 (sDDF Isolated Driver Service) |
| arch\x86_64\input.rs | 599 | 27 | Move to Ring 3 (sDDF Isolated Driver Service) |
| elf.rs | 591 | 8 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\syscall.rs | 538 | 16 | Keep in Ring 0 (Microkernel Core Mechanism) |
| vfs.rs | 533 | 1 | Move to Ring 3 (Storage Vault & VFS Service) |
| browser.rs | 521 | 1 | Move to Ring 3 (Userland Shell & Compositor) |
| arch\x86_64\mod.rs | 518 | 38 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\nic.rs | 490 | 14 | Move to Ring 3 (sDDF Isolated Driver Service) |
| cap\sel4_core.rs | 482 | 0 | Keep in Ring 0 (Platform Abstraction) |
| gui.rs | 460 | 6 | Move to Ring 3 (Userland Shell & Compositor) |
| arch\aarch64\mod.rs | 430 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\pci.rs | 424 | 48 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\vbox.rs | 419 | 25 | Move to Ring 3 (sDDF Isolated Driver Service) |
| scheme.rs | 411 | 0 | Keep in Ring 0 (Platform Abstraction) |
| main.rs | 381 | 1 | Keep in Ring 0 (Microkernel Core Mechanism) |
| entropy.rs | 354 | 2 | Keep in Ring 0 (Platform Abstraction) |
| display.rs | 352 | 0 | Keep in Ring 0 (Platform Abstraction) |
| security.rs | 334 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\idt.rs | 331 | 3 | Keep in Ring 0 (Microkernel Core Mechanism) |
| flask.rs | 323 | 0 | Keep in Ring 0 (Platform Abstraction) |
| sectools.rs | 319 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\tpm.rs | 317 | 3 | Keep in Ring 0 (Platform Abstraction) |
| kapp.rs | 314 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| ipc.rs | 312 | 0 | Keep in Ring 0 (Platform Abstraction) |
| driver.rs | 304 | 3 | Keep in Ring 0 (Platform Abstraction) |
| powerbox.rs | 293 | 0 | Keep in Ring 0 (Platform Abstraction) |
| blockdev.rs | 280 | 0 | Move to Ring 3 (Storage Vault & VFS Service) |
| arch\x86_64\cpuid.rs | 279 | 3 | Keep in Ring 0 (Microkernel Core Mechanism) |
| arch\x86_64\uart.rs | 268 | 13 | Keep in Ring 0 (Platform Abstraction) |
| process.rs | 262 | 3 | Keep in Ring 0 (Platform Abstraction) |
| task.rs | 255 | 4 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\apic.rs | 255 | 16 | Keep in Ring 0 (Platform Abstraction) |
| dde.rs | 254 | 3 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\gic.rs | 234 | 14 | Keep in Ring 0 (Platform Abstraction) |
| kash.rs | 208 | 0 | Move to Ring 3 (Userland Shell & Compositor) |
| status.rs | 196 | 1 | Keep in Ring 0 (Platform Abstraction) |
| csprng.rs | 193 | 0 | Keep in Ring 0 (Platform Abstraction) |
| kms.rs | 185 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\gdt.rs | 179 | 2 | Keep in Ring 0 (Microkernel Core Mechanism) |
| sync.rs | 161 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\clock.rs | 151 | 11 | Keep in Ring 0 (Platform Abstraction) |
| lockdown.rs | 150 | 0 | Keep in Ring 0 (Platform Abstraction) |
| mmu.rs | 140 | 2 | Keep in Ring 0 (Microkernel Core Mechanism) |
| disposable.rs | 137 | 1 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\tresor.rs | 133 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\smp.rs | 127 | 9 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\apple_silicon.rs | 114 | 2 | Keep in Ring 0 (Platform Abstraction) |
| heap.rs | 112 | 7 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\uart.rs | 107 | 8 | Keep in Ring 0 (Platform Abstraction) |
| cap\mod.rs | 104 | 1 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\fb.rs | 98 | 4 | Keep in Ring 0 (Platform Abstraction) |
| arch\aarch64\boot.rs | 89 | 0 | Keep in Ring 0 (Microkernel Core Mechanism) |
| arch\x86_64\acpi.rs | 80 | 13 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\fpu.rs | 67 | 3 | Keep in Ring 0 (Platform Abstraction) |
| arch\mod.rs | 22 | 0 | Keep in Ring 0 (Platform Abstraction) |
| arch\x86_64\boot.rs | 14 | 0 | Keep in Ring 0 (Microkernel Core Mechanism) |
