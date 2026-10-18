# KashOS Unsafe Code Audit & Invariant Catalog (Task F-16 / V-18)

## 1. Overview
In accordance with **Build Guide v2 Rule 9 and Task F-16**, this document provides a comprehensive audit of all `unsafe` blocks, functions, and raw hardware access points in the KashOS kernel and low-level HAL crates (`khal`, `kblock`, `knet`, `kpaging`).

KashOS enforces strict memory safety invariants:
- Ring 0 kernel logic must isolate unsafe hardware interaction (I/O ports, MMIO, inline assembly, control registers) into small, audit-verified functions.
- Every `unsafe` block must state its safety preconditions and invariants.

---

## 2. Kernel Unsafe Site Inventory by Subsystem

| Subsystem / File | Unsafe Count | Primary Operation | Safety Invariant / Hardware Precondition |
|:---|:---|:---|:---|
| `kernel/src/arch/x86_64/input.rs` | 27 | Inb/outb to ports `0x60`, `0x64` | Ports reserved for 8042 PS/2 controller; guarded by status-bit polling. |
| `kernel/src/arch/x86_64/pci.rs` | 42 | Config ports `0xCF8`, `0xCFC` | Standard x86 PCI mechanism #1; bus/device/function ranges validated. |
| `kernel/src/arch/x86_64/mod.rs` | 38 | Multiboot pointers, CR0/CR3/CR4, EFER | Pointers provided by bootloader verified against memory ranges. |
| `kernel/src/arch/x86_64/vtd.rs` | 31 | IOMMU MMIO registers & context tables | MMIO frames mapped identity or uncached; alignment checked to 4 KiB. |
| `kernel/src/arch/x86_64/vbox.rs` | 25 | VMMDev MMIO and hypervisor I/O | Guest-to-host request buffers allocated in physical continuous memory. |
| `kernel/src/arch/x86_64/syscall.rs` | 16 | `swapgs`, `sysretq`, MSRs `0xC0000080..` | Syscall entry points save all user registers; GS swapped to kernel per-CPU. |
| `kernel/src/arch/x86_64/apic.rs` | 13 | Local APIC MMIO register access | APIC base verified at `0xFEE00000`; mapped uncached in page tables. |
| `kernel/src/arch/x86_64/acpi.rs` | 13 | RSDP / RSDT / MADT table walks | BIOS table checksums validated before dereferencing table entries. |
| `kernel/src/arch/x86_64/uart.rs` | 13 | Ports `0x3F8`–`0x3FF` (COM1) | Legacy PC serial controller; DLAB and baud divisor bounds checked. |
| `kernel/src/arch/x86_64/nic.rs` | 13 | Intel e1000 MMIO & descriptor rings | Ring buffers page-aligned; descriptors accessed within hardware bounds. |
| `kernel/src/arch/x86_64/clock.rs` | 11 | CMOS ports `0x70`/`0x71`, PIT `0x40` | NMI mask preserved; RTC BCD conversion validated. |
| `kernel/src/arch/x86_64/tresor.rs` | 9 | Debug registers DR0–DR3, DR7 | DR registers used strictly for transient AES key storage. |
| `kernel/src/arch/x86_64/smp.rs` | 9 | ICR (Interrupt Command Register) IPIs | Target APIC ID verified; INIT/STARTUP sequences timed by PIT. |
| `kernel/src/arch/aarch64/gic.rs` | 14 | GICv2/v3 distributor & CPU interface | Distributor registers mapped uncached; IRQ numbers clamped to 1020. |
| `kernel/src/arch/aarch64/mod.rs` | 9 | TTBR0/TTBR1, SCTLR, MAIR | System register modifications followed by `isb` and `dsb`. |
| `kernel/src/arch/aarch64/uart.rs` | 8 | PL011 MMIO registers | Base address verified from device tree or platform descriptor. |
| `kernel/src/linux.rs` | 19 | User pointer dereferences | User addresses checked against process bounds before copy operations. |
| `kernel/src/security.rs` | 9 | Memory zeroing (`scrub_slice`) | `core::ptr::write_volatile` used to guarantee compiler does not elide zeroing. |
| `kernel/src/elf.rs` | 8 | Program header / ELF section walks | Byte slices bounded by file length; segment flags strictly enforce W^X. |
| `kernel/src/heap.rs` | 7 | Coalescing free-list node manipulation | Arena bounds verified on `init()`; block headers store valid sizes. |
| `kernel/src/sync.rs` | 9 | Atomic operations and ticket lock loops | `Ordering::Acquire` / `Release` preserve synchronization invariants. |
| `kernel/src/gui.rs` | 6 | Framebuffer raw pixel buffer writes | Slice bounds clamped to `fb.pitch * fb.height`. |
| `kernel/src/task.rs` | 4 | Context switch register saves | Stack pointers point to valid, guard-page-protected kernel stacks. |
| `kernel/src/blockdev.rs` | 3 | Primary IDE channel ports `0x1F0`–`0x1F7` | Bounded sector transfers via `insw`/`outsw`. |
| `kernel/src/main.rs` | 1 | Heap arena claim (`claim_heap_region`) | Physical memory region verified disjoint from page tables and kcore. |

---

## 3. Mitigation & Refactoring Roadmap

To continuously reduce `unsafe` attack surface:
1. **Encapsulate I/O Ports**: Port access is wrapped in `arch::inb`, `arch::outb`, `arch::inw`, `arch::outw` with compile-time port type safety.
2. **Eliminate Unchecked `static mut`**: Subsystems use `SpinLock` (ticket lock with interrupt disable) or atomic wrappers (`AtomicBool`, `AtomicU64`).
3. **Move Drivers to Userland (Phase 4)**: As drivers transition to Ring 3 CPL 3 services, direct port I/O in the kernel is completely removed and replaced by capability grants.
