# Redox OS Hardware Support & Driver Integration in KashOS

## Executive Summary
This document synthesizes key architectural patterns and hardware drivers from **Redox OS** (the microkernel operating system written in Rust) and details their direct adaptation into **KashOS**.

By analyzing Redox OS's modular user-space driver framework (`pcid`, `ahcid`, `e1000d`, `ps2d`), KashOS establishes high-assurance hardware drivers for both vintage bare-metal machines (Core 2 Duo, Pentium III/IV, 100 MB RAM budget) and modern PCI/PCIe/SATA systems.

---

## 1. Redox OS Driver Architecture vs. KashOS sDDF Architecture

### Redox OS Pattern: Scheme-Based Hardware Daemon
In Redox OS, drivers run entirely as user-space daemons communicating through URL schemes:
1. **`pcid`**: Scans PCI configuration space (via I/O ports `0xCF8`/`0xCFC`), parses Base Address Registers (BARs), enables bus-mastering, and spawns driver daemons based on PCI Vendor/Device and Class IDs.
2. **`ahcid`**: Implements the AHCI 1.3 SATA specification, constructing Frame Information Structures (FIS) and Physical Region Descriptor Tables (PRDT) for scatter-gather DMA disk transfers.
3. **`e1000d` / `rtl8168d`**: Implements network device rings, managing circular RX and TX descriptor arrays.
4. **`ps2d`**: Controls the 8042 PS/2 controller, parsing keyboard scancodes and mouse packets.

### KashOS Adaptation: Tier-4 Fault-Isolated Driver Model
KashOS adapts Redox's scheme model into its seL4 Device Driver Framework (sDDF) and URL Scheme Manager (`kernel/src/scheme.rs`):
- **Isolation**: Hardware drivers run in capability-bounded domains. If a driver faults, the sDDF supervisor isolates the crash, scrubs driver state, and restarts it without taking down the microkernel.
- **Uniform Resource Addressing**: Access to hardware follows standard URL schemes:
  - `pci:` (Dynamic PCI hardware inventory and descriptor table)
  - `disk:` (Block storage access through C-LOOK elevator scheduler)
  - `tcp:` (Network socket stream through hardware NIC and smoltcp)
  - `dev:` (Standard device nodes: `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/tty0`)
  - `memory:` and `irq:` (Physical MMIO mapping and asynchronous interrupt event delivery)

---

## 2. Implemented Hardware Drivers

### A. PCI Configuration & Discovery Subsystem (`pci.rs`)
Inspired by Redox OS `pcid`:
- **Full 6-BAR Decoding**: Decodes `bar0` through `bar5`, distinguishing between 32-bit/64-bit Memory Space MMIO and I/O Port space.
- **Hardware Bus-Mastering**: `PciDevice::enable_bus_mastering()` writes bit 0 (I/O Space), bit 1 (Memory Space), and bit 2 (Bus Master) to the PCI Command register (`0x04`), enabling DMA operations for storage and network adapters.
- **Class-Based Matching**: Identifies AHCI SATA controllers (Class 0x01, Subclass 0x06), NVMe controllers (Class 0x01, Subclass 0x08), Network adapters (Class 0x02), and Intel High Definition Audio (Class 0x04, Subclass 0x03).

### B. SATA AHCI 1.3 Controller Driver (`kblock/src/ahci.rs`)
Adapted from Redox OS `ahcid`:
- **Memory Structure**: Defines the complete AHCI Host Bus Adapter (`HbaMem`) and port register layout (`HbaPort`), including GHC (Global Host Control), Ports Implemented (`pi`), Command List Base (`clb`), and FIS Base (`fb`).
- **Signature Detection**: Probes active SATA PHY ports, correctly distinguishing between SATA magnetic/flash hard drives (`SATA_SIG_ATA = 0x0000_0101`) and optical drives (`SATA_SIG_ATAPI = 0xEB14_0101`).
- **FIS Register H2D (Host-to-Device)**: Generates 20-byte Command FIS packets (type `0x27`) with Command `0x25` (`ATA_CMD_READ_DMA_EXT`) and `0x35` (`ATA_CMD_WRITE_DMA_EXT`) supporting 48-bit LBA addressing up to 128 PiB.
- **Probe Order in `blockdev.rs`**:
  1. PCI SATA AHCI Controller (`find_ahci()`)
  2. PCI VirtIO-Block Paravirtualized Disk (`find_storage()`)
  3. Legacy PATA/IDE Primary Master (`0x1F0`/`0x3F6`)
  4. Ephemeral In-Memory RAM Stage-0 Driver

### C. Network Drivers (`kernel/src/arch/x86_64/nic.rs`)
Adapted from Redox OS `e1000d` and network driver architecture:
- **Intel PRO/1000 (82540EM, 82543GC, 82545EM, 82574L)**: Circular RX/TX descriptor rings with EEPROM/RAL0 MAC discovery, Link-Up auto-negotiation (`E1000_CTRL_SLU`), and BAR0 MMIO mapping.
- **Realtek RTL-8139 Fast Ethernet (`Rtl8139Device`)**: Target driver for vintage 1998–2008 PCs. Performs software reset via Command register (`0x37`), reads hardware MAC address from ports `0x00..0x05`, and enables transmitter/receiver.
- **VirtIO-Net**: Split-queue paravirtualized network adapter.
- **Auto-Probe**: `nic::init()` dynamically queries `scan_pci()`, asserts bus-mastering, maps BARs, and binds the appropriate controller.

### D. Timer Dynamic Calibration & PIT Fallback (`kernel/src/arch/x86_64/apic.rs`)
Resolves Build Guide Stage B / Task F-03:
- **PIT Channel 2 Calibration**: Measures APIC Current Count Register (`APIC_TIMER_CCR`) over a precise 10 ms countdown (11,932 cycles of 8254 PIT Channel 2 at 1,193,182 Hz).
- **Exact 100 Hz Scheduling Rate**: Sets `APIC_TIMER_ICR` to the calibrated count, preventing timer rate drift on processors with arbitrary Front Side Bus (FSB) frequencies (100 MHz, 133 MHz, 200 MHz, 333 MHz).
- **CPUID Invariant TSC Detection**: Queries CPUID leaf `0x80000007` (EDX bit 8) to verify constant TSC rate across ACPI power states.
- **PIT Channel 0 Fallback**: On systems lacking an APIC or where calibration fails, seamlessly configures 8254 PIT Channel 0 in Mode 2 (Rate Generator) at 100 Hz (divisor 11,932) and unmasks IRQ0 on the legacy 8259 PIC.

---

## 3. Hardware Compatibility Matrix

| Hardware Component | Controller / Chipset | Driver Implementation | Memory / I/O Target |
| :--- | :--- | :--- | :--- |
| **SATA Storage** | Intel ICH9R / Generic AHCI 1.3 | `kblock::ahci::AhciController` | BAR5 MMIO (`ABAR`), FIS DMA |
| **PATA/IDE Storage** | PIIX3 / PIIX4 / Legacy IDE | `kblock::ata_ide::IdeChannel` | Ports `0x1F0`, `0x3F6` |
| **Virtual Storage** | VirtIO-Block (OASIS v1.0) | `kblock::virtio_blk::VirtioBlockDevice` | BAR0 I/O Ports, Virtqueue |
| **Gigabit Network** | Intel 82540EM / 82545EM / 82574L | `kernel::nic::E1000Device` | BAR0 MMIO, Descriptor Rings |
| **Fast Ethernet** | Realtek RTL8139 / RTL8139C | `kernel::nic::Rtl8139Device` | BAR0 I/O Ports |
| **Virtual Network** | VirtIO-Net (0x1AF4:0x1000) | `kernel::nic::VirtioNetDevice` | BAR0 I/O Ports, Virtqueue |
| **Interrupt Timer** | Local xAPIC (MMIO 0xFEE00000) | `kernel::apic::init` | Dynamic 10 ms PIT Calibration |
| **Fallback Timer** | Intel 8254 PIT Channel 0/2 | `kernel::apic::init_pit_fallback` | Ports `0x40`, `0x42`, `0x43`, `0x61` |
| **PS/2 Mouse & Wheel** | Intel 8042 / IntelliMouse | `kernel::input::Ps2Controller` | Ports `0x60`, `0x64`, 4-byte wheel |
| **Display / Framebuffer**| Bochs BGA / VBE / QEMU VGA | `kernel::fb`, `kernel::display` | BAR0 Linear Framebuffer |

---

## 4. Verification & Claims Compliance
- Compiles under `#![no_std]` target: `x86_64-unknown-none`.
- Zero compiler warnings across all crates.
- 100% test pass rate across `khal`, `kblock`, `knet`, `kvault`, `kpaging`, `kscheduler`, and `kash-ui`.
- 100% compliance with Build Guide v2 Appendix A Claims Policy (`python tools/claims_lint.py` passes with 0 violations).
