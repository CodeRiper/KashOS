# KashOS Hardware Compatibility: 100 MB RAM Profile & Vintage PC Support

## Overview
This document specifies the hardware requirements, driver architecture, memory budget, and installation procedures for running KashOS on resource-constrained systems, specifically vintage PC hardware with 100 MB to 128 MB of RAM (such as Pentium III, early Pentium 4, AMD Geode, and virtual machines running with `-m 100M`).

---

## 1. Physical Memory Budget (100 MB RAM Breakdown)

When booted on a 100 MB physical RAM machine (e.g. 102,400 KiB discovered across BIOS memory maps), KashOS partitions memory into naturally aligned power-of-two regions:

| Subsystem / Allocation | Physical RAM Footprint | Description |
|:---|:---|:---|
| **Kernel Binary & BSS** | ~2.8 MiB | Rust microkernel code, read-only data, and statically allocated descriptors. |
| **W^X Page Tables** | ~2.0 MiB | 4-level x86_64 paging tables (PML4, PDPT, PD, PT) with strict W^X enforcement. |
| **Capability Arena (`kcore`)** | 16.0 MiB | Fixed power-of-two untyped memory arena for capability node graphs. |
| **Kernel Heap Arena (`kheap`)** | 16.0 MiB | Coalescing free-list allocator for strings, vectors, and IPC ring buffers. |
| **GUI Compositor Buffers** | ~4.8 MiB | 640x480 low-memory render mode (desktop, wallpaper, window layer, cursor). |
| **Total Baseline Working Set** | **~41.6 MiB** | Active kernel and desktop compositor footprint. |
| **Free Headroom Available** | **> 58.4 MiB** | Available physical memory for userland applications and block cache. |

### Low-Memory Mode Compositor
In `kernel/src/gui.rs`, the kernel monitors heap free bytes before launching `Desktop::new`:
- If `free_before < 32 MiB`, the compositor automatically enables **low-memory mode**:
  - Downscales canvas rendering from output resolution to 640x480.
  - Reduces font cache icon levels from 128 to 64.
  - Drops canvas memory consumption from 16 MiB (at 1280x800) down to ~1.2 MiB per layer.

---

## 2. Integrated Drivers for Vintage PC Hardware

KashOS integrates bare-metal drivers designed for the 2000–2006 hardware era:

### A. Input Driver: 8042 PS/2 Controller (`kernel/src/arch/x86_64/input.rs`)
- **Keyboard**: Scan Code Set 1 and 2 translation with modifier tracking (Shift, Ctrl, Alt).
- **Mouse & Trackpad**:
  - Automatically negotiates Microsoft IntelliMouse scrolling sequence (`0xF3, 200` -> `0xF3, 100` -> `0xF3, 80` -> `0xF2`).
  - Detects Device ID `0x03` (IntelliMouse wheel) and `0x04` (5-button wheel).
  - Receives 4-byte streaming packets with signed vertical wheel delta (`dz: i8`).
  - Supports configurable scrolling speed, natural scrolling direction, and trackpad tap-to-click in Settings.

### B. Block Storage Driver: PATA / IDE PIO (`kernel/src/blockdev.rs`)
- Binds to legacy primary IDE channels (I/O ports `0x1F0`–`0x1F7`, control port `0x3F6`).
- Uses PIO 28-bit / 48-bit LBA sector access compatible with vintage IDE hard drives and CompactFlash adapters.
- Implements C-LOOK elevator scheduler (`kblock`) to minimize rotational disk arm travel and coalesce adjacent sectors.

### C. Display Driver: Linear Framebuffer (`kernel/src/arch/x86_64/fb.rs`)
- Handed off via Multiboot / VESA BIOS Extensions (VBE) or UEFI GOP.
- Operates on a linear 32-bit ARGB/XRGB framebuffer without requiring GPU hardware acceleration.
- Software-rasterized 2D UI with SIMD-free fallback algorithms for vintage CPUs.

### D. System Timers & RTC (`kernel/src/arch/x86_64/clock.rs`)
- Reads the hardware Real-Time Clock (RTC / CMOS ports `0x70`/`0x71`) to synchronize wall clock seconds.
- Uses the 8254 Programmable Interval Timer (PIT) on port `0x40` or Local APIC timer for preemptive multitasking ticks.

### E. Diagnostic Serial Port (`kernel/src/arch/x86_64/uart.rs`)
- Standard 16550 UART controller on COM1 (`0x3F8`) configured at 115200 baud, 8N1.
- Provides real-time hardware boot logging when no monitor is attached.

---

## 3. How to Test and Install on 100 MB RAM

### Testing in QEMU with 100 MB RAM
To verify KashOS on a 100 MB memory profile:
```bash
qemu-system-x86_64 \
  -m 100M \
  -cdrom target/kashos.iso \
  -boot d \
  -serial stdio \
  -vga std
```

### Creating Bootable Installation Media
1. Build the release kernel binary:
   ```bash
   cargo build --release -p kernel --target x86_64-unknown-none
   ```
2. Build the bootable ISO:
   ```bash
   ./tools/build_iso.sh
   ```
3. Write the resulting ISO to a USB flash drive or CD-R:
   - On Linux: `dd if=target/kashos.iso of=/dev/sdX bs=4M status=progress && sync`
   - On Windows: Use Rufus (in DD image mode) or balenaEtcher.
4. Insert media into target PC, select BIOS boot menu, and select optical drive or USB-HDD.
