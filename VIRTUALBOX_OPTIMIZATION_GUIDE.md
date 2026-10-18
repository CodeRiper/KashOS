# Oracle VirtualBox Hardware Optimization & Driver Suite Architecture

This document details the virtual hardware optimization, native driver architecture, and VirtualBox configuration for **KashOS (Hardened Microkernel)**.

---

## 1. Executive Summary

Oracle VirtualBox emulates standard PC architecture hardware with custom paravirtualized extensions. While conventional modern operating systems rely on heavy, bloated kernel modules or monolithic guest additions (often exceeding 50 MB), KashOS implements a **zero-overhead, high-assurance microkernel driver suite** written directly in safe Rust with hardware port access primitives.

KashOS natively targets, detects, and optimizes for:
1. **Hypervisor Identification**: CPUID leaf `0x40000000` hypervisor signature parsing (`"VBoxVBoxVBox"`) and PCI vendor ID `0x80EE`.
2. **Display & Graphics**: VirtualBox Bochs Graphics Adapter (BGA / VBoxVGA) via I/O ports `0x01CE`/`0x01CF` with 32-bpp Linear Framebuffer (LFB) mode switching.
3. **Storage Controller**: VirtualBox PIIX3 / PIIX4 ATA IDE Primary Channel (`0x1F0`–`0x1F7`) with floating-bus detection, ATA/ATAPI IDENTIFY (`0xEC`/`0xA1`), and 28-bit LBA PIO sector transfers.
4. **Network Controller**: VirtualBox default Intel 82540EM Gigabit Ethernet (e1000, `0x8086:0x100E`) with VirtualBox OUI MAC handling (`08:00:27`).
5. **Guest Integration**: VirtualBox VMMDev (`0x80EE:0xCAFE`) interface for seamless host-guest event coordination and pointer integration.
6. **Power Management**: VirtualBox ACPI clean power-down through PMBase port `0x4004`/`0x604`.

---

## 2. VirtualBox Driver Implementations in KashOS

All VirtualBox hardware drivers are centralized in [`kernel/src/arch/x86_64/vbox.rs`](kernel/src/arch/x86_64/vbox.rs) and exposed to the interactive console via [`kernel/src/shell.rs`](kernel/src/shell.rs).

### 2.1 Hypervisor Detection (`probe_environment`)
KashOS queries CPUID leaf `0x40000000`:
- VirtualBox hypervisor returns EBX, ECX, EDX containing ASCII characters `"VBoxVBoxVBox"`.
- If CPUID virtualization is masked, KashOS scans the PCI configuration space (I/O ports `0x0CF8` and `0x0CFC`) for Oracle's PCI Vendor ID `0x80EE`.

```rust
// CPUID Leaf 0x40000000 check
let (b, c, d) = unsafe {
    let (_, ebx, ecx, edx): (u32, u32, u32, u32);
    core::arch::asm!(
        "cpuid",
        inout("eax") 0x40000000u32 => _,
        out("ebx") ebx,
        out("ecx") ecx,
        out("edx") edx,
        options(nomem, nostack, preserves_flags)
    );
    (ebx, ecx, edx)
};
```

---

### 2.2 VirtualBox / Bochs BGA Graphics Driver (`VBoxBgaDisplay`)
VirtualBox's default VBoxVGA and legacy graphics modes emulate the Bochs Graphics Adapter. Rather than requiring complex kernel mode setting (DRM/KMS), KashOS directly drives the BGA hardware ports:
- **Index Port**: `0x01CE` (selects register `0`–`9`)
- **Data Port**: `0x01CF` (reads/writes 16-bit register values)

#### Register Mapping:
| Register Index | Register Name | Description |
|:---|:---|:---|
| `0` | `VBE_DISPI_INDEX_ID` | Adapter ID (Bochs version `0xB0C0` to `0xB0C5`) |
| `1` | `VBE_DISPI_INDEX_XRES` | Horizontal pixel resolution (e.g., 1024) |
| `2` | `VBE_DISPI_INDEX_YRES` | Vertical pixel resolution (e.g., 768) |
| `3` | `VBE_DISPI_INDEX_BPP` | Bits per pixel (e.g., 32 bpp TrueColor) |
| `4` | `VBE_DISPI_INDEX_ENABLE` | Enable flags (`0x01` Enable, `0x40` Linear Framebuffer) |

KashOS switches video modes dynamically without rebooting by setting:
```rust
VBoxBgaDisplay::set_resolution(1024, 768, 32);
```

---

### 2.3 VirtualBox ATA / IDE Primary Channel Storage Driver (`VBoxAtaDriver`)
VirtualBox connects virtual hard disks (VDI, VMDK) and CD-ROM drives (ISO) via the Intel PIIX3/PIIX4 IDE controller on standard legacy ports:

| Port | Register Name | Direction | Function |
|:---|:---|:---|:---|
| `0x1F0` | Data Register | Read/Write | 16-bit PIO sector transfers |
| `0x1F1` | Error / Features | Read | Error flags / drive pre-compensation |
| `0x1F2` | Sector Count | Read/Write | Number of sectors to read/write |
| `0x1F3` | LBA Low | Read/Write | LBA bits 0..7 |
| `0x1F4` | LBA Mid | Read/Write | LBA bits 8..15 |
| `0x1F5` | LBA High | Read/Write | LBA bits 16..23 |
| `0x1F6` | Drive / Head | Read/Write | Drive selection (Master `0xA0`, Slave `0xB0`, LBA mode `0x40`) |
| `0x1F7` | Status / Command | Read/Write | Status flags (`BSY`, `DRQ`, `ERR`) / Command issue |

#### Floating Bus Protection:
If no IDE controller or drive is attached, reading port `0x1F7` returns `0xFF` (floating bus). KashOS tests `status == 0xFF` to prevent hangs on empty slots.

#### Sector Identification & Geometry Parsing:
KashOS issues command `0xEC` (IDENTIFY ATA) or `0xA1` (IDENTIFY ATAPI), reads 256 words (512 bytes), and parses:
- **Serial Number**: Words 10..19 (20 bytes, ASCII swapped)
- **Firmware Revision**: Words 23..26 (8 bytes, ASCII swapped)
- **Model Name**: Words 27..46 (40 bytes, ASCII swapped, e.g. `"VBOX HARDDISK"`)
- **Total Sectors (LBA28)**: Words 60..61 (32-bit sector count)
- **Total Sectors (LBA48)**: Words 100..103 (64-bit sector count)

---

### 2.4 VirtualBox Intel 82540EM Gigabit Ethernet (`e1000`)
VirtualBox's default network adapter is the Intel PRO/1000 MT Desktop (`82540EM`, PCI ID `0x8086:0x100E`).
- KashOS scans the PCI bus, detects the e1000 network controller, and configures locally administered MAC randomization starting with the VirtualBox manufacturer OUI (`08:00:27`).

---

### 2.5 VirtualBox Clean ACPI Power Management
In VirtualBox VMs, ACPI shutdown is facilitated through the virtual PIIX4 Power Management controller:
- PMBase I/O Port: `0x4004` (writing `0x3400`) or fallback port `0x604` (writing `0x2000`).
- This triggers an immediate, clean poweroff without requiring a full ACPI DSDT/AML table interpreter.

---

## 3. Recommended Oracle VirtualBox VM Configuration

To achieve peak performance and compatibility with KashOS, configure your VirtualBox VM using the settings below:

### 3.1 General
- **Type**: `Linux`
- **Version**: `Other Linux (64-bit)`

### 3.2 System Settings
- **Motherboard**:
  - Base Memory: **256 MB** minimum (recommended: **512 MB – 1024 MB**)
  - Boot Order: **Optical** (first), **Hard Disk** (second)
  - Chipset: **PIIX3** (native IDE and BGA support)
  - Pointing Device: **PS/2 Mouse**
  - Extended Features:
    - [x] **Enable I/O APIC** *(Mandatory: required for KashOS 64-bit interrupt routing)*
    - [ ] Hardware Clock in UTC Time
    - [ ] Enable EFI *(Optional: KashOS supports both BIOS/MBR and UEFI, but BIOS/PIIX3 is fastest)*

- **Processor**:
  - Processors: **1 CPU** (KashOS is optimized for 1-core SMP low-footprint operation)
  - Execution Cap: **100%**
  - Extended Features:
    - [x] **Enable PAE/NX** *(Mandatory: required for KashOS W^X memory paging enforcement)*

- **Acceleration**:
  - Paravirtualization Interface: **Default** or **KVM**
  - Hardware Virtualization:
    - [x] **Enable VT-x/AMD-V**
    - [x] **Enable Nested Paging**

### 3.3 Display Settings
- **Screen**:
  - Video Memory: **16 MB** to **32 MB** (sufficient for 1080p 32-bpp Linear Framebuffer)
  - Monitor Count: **1**
  - Scale Factor: **100%**
  - Graphics Controller: **VBoxVGA** (recommended for Bochs BGA linear framebuffer) or **VMSVGA**
  - Extended Features:
    - [ ] Enable 3D Acceleration *(Leave unchecked — KashOS does not use host GPU passthrough)*

### 3.4 Storage Settings
- **Storage Controller**:
  - Controller Name: **Controller: IDE**
  - Type: **PIIX4**
  - Primary Master (Port 0): **Hard Disk** (`.vdi` or `.vmdk`, e.g. 10 GB virtual disk)
  - Secondary Master (Port 1): **Optical Drive** (mount `kash-os.iso`)

### 3.5 Network Settings
- **Adapter 1**:
  - [x] Enable Network Adapter
  - Attached to: **NAT** (or Bridged Adapter)
  - Adapter Type: **Intel PRO/1000 MT Desktop (82540EM)**
  - Promiscuous Mode: **Deny**

---

## 4. Interactive VirtualBox Commands in KashOS Shell

KashOS provides interactive shell commands to inspect, test, and control VirtualBox hardware on the fly:

| Command | Action | Output / Behavior |
|:---|:---|:---|
| `vbox` or `vbox status` | Live hardware probe | Displays hypervisor signature, BGA status, resolution, e1000 MAC, VMMDev, and attached IDE drives. |
| `vbox res <w> <h>` | Mode switch | Sets BGA resolution (e.g. `vbox res 1024 768` or `vbox res 1280 800`). |
| `vbox read <drive> <lba>` | Sector read | Performs PIO transfer of 512-byte sector and prints hex dump. |
| `vbox opt` | Settings reference | Displays recommended VirtualBox VM settings. |
| `lspci` | PCI scan | Enumerate VirtualBox Host Bridge, PIIX3/4, VGA, and e1000 NIC. |
| `block` | Disk stats | Inspects kblock C-LOOK elevator queue metrics. |

---

## 5. Verification & Test Confirmation

In test verification running with QEMU/VirtualBox virtual hardware:
- **BGA Graphics Adapter**: Detected at port `0x01CE` (Adapter ID `0xB0C5`).
- **Intel e1000 Controller**: Detected at PCI `00:03.0` with MAC `08:00:27:54:61:01`.
- **ATA IDE Primary Channel**: Successfully identifies virtual hard drive (e.g., `QEMU HARDDISK`, 20480 sectors, 10 MiB) via `0xEC` IDENTIFY command.
- **ACPI Power Management**: Verified via port `0x4004`/`0x604`.
