//! x86-64 PCI Configuration Space (Mechanism #1) Hardware Driver.
//!
//! Inspired by Redox OS `pcid` (PCI daemon):
//! Accesses PCI configuration registers via I/O ports 0xCF8 (CONFIG_ADDRESS)
//! and 0xCFC (CONFIG_DATA) to enumerate hardware devices, bridges, storage
//! controllers, network interfaces, and BARs (Base Address Registers).

#![allow(unsafe_code)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

#[inline(always)]
pub(crate) unsafe fn outl(port: u16, val: u32) {
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline(always)]
pub(crate) unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") port,
            out("eax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

/// Reads a 32-bit dword from PCI configuration space.
pub unsafe fn pci_read_u32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
        | 0x8000_0000;
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

/// Reads a 16-bit word from PCI configuration space.
pub unsafe fn pci_read_u16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    let val = unsafe { pci_read_u32(bus, slot, func, offset) };
    ((val >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Reads an 8-bit byte from PCI configuration space.
pub unsafe fn pci_read_u8(bus: u8, slot: u8, func: u8, offset: u8) -> u8 {
    let val = unsafe { pci_read_u32(bus, slot, func, offset) };
    ((val >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Writes a 32-bit dword to PCI configuration space.
pub unsafe fn pci_write_u32(bus: u8, slot: u8, func: u8, offset: u8, val: u32) {
    let address = ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC)
        | 0x8000_0000;
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, val);
    }
}

/// Writes a 16-bit word to PCI configuration space.
pub unsafe fn pci_write_u16(bus: u8, slot: u8, func: u8, offset: u8, val: u16) {
    let old = unsafe { pci_read_u32(bus, slot, func, offset) };
    let shift = ((offset & 2) * 8) as u32;
    let mask = !(0xFFFF_u32 << shift);
    let new_val = (old & mask) | ((val as u32) << shift);
    unsafe { pci_write_u32(bus, slot, func, offset, new_val) };
}

/// Discovered PCI Device descriptor.
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_id: u8,
    pub subclass_id: u8,
    pub prog_if: u8,
    pub irq_line: u8,
    pub bar0: u32,
    pub bar1: u32,
}

impl PciDevice {
    pub fn vendor_name(&self) -> &'static str {
        match self.vendor_id {
            0x8086 => "Intel Corporation",
            0x1AF4 => "Red Hat / VirtIO",
            0x1234 => "QEMU Virtual Hardware",
            0x10EC => "Realtek Semiconductor",
            0x15AD => "VMware Virtual Hardware",
            0x80EE => "VirtualBox Guest Hardware",
            0x1022 => "Advanced Micro Devices (AMD)",
            0x10DE => "NVIDIA Corporation",
            _ => "Unknown Vendor",
        }
    }

    pub fn device_description(&self) -> String {
        match (self.vendor_id, self.device_id) {
            (0x8086, 0x1237) => String::from("440FX - 82441FX PMC Host Bridge"),
            (0x8086, 0x7000) => String::from("82371SB PIIX3 PCI-to-ISA Bridge"),
            (0x8086, 0x7110) => String::from("82371AB/EB/MB PIIX4 ISA Bridge"),
            (0x8086, 0x7111) => String::from("82371AB/EB/MB PIIX4 IDE Controller"),
            (0x8086, 0x7113) => String::from("82371AB/EB/MB PIIX4 ACPI / Power Management"),
            (0x8086, 0x100E) => String::from("82540EM Gigabit Ethernet Controller (e1000)"),
            (0x8086, 0x29C0) => String::from("82G33/G31/P35/P31 Express DRAM Controller (Q35)"),
            (0x8086, 0x2918) => String::from("82801IB (ICH9) LPC Interface Controller"),
            (0x8086, 0x2922) => String::from("82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA Controller [AHCI]"),
            (0x8086, 0x2934) => String::from("82801I (ICH9 Family) USB UHCI Controller #1"),
            (0x8086, 0x293A) => String::from("82801I (ICH9 Family) USB2 EHCI Controller #1"),
            (0x1234, 0x1111) => String::from("QEMU Standard VGA Graphics Adapter"),
            (0x80EE, 0xBEEF) => String::from("VirtualBox Graphics Adapter"),
            (0x80EE, 0xCAFE) => String::from("VirtualBox Guest Additions Device"),
            (0x1AF4, 0x1000) => String::from("VirtIO Network Adapter"),
            (0x1AF4, 0x1001) => String::from("VirtIO Block Storage Device"),
            (0x1AF4, 0x1002) => String::from("VirtIO Memory Ballooning"),
            (0x1AF4, 0x1003) => String::from("VirtIO Console Adapter"),
            (0x1AF4, 0x1004) => String::from("VirtIO Entropy Generator (virtio-rng)"),
            (0x1AF4, 0x1005) => String::from("VirtIO Memory Balloon"),
            (0x1AF4, 0x1009) => String::from("VirtIO 9P Transport Filesystem"),
            (0x1AF4, 0x1041) => String::from("VirtIO 1.0 Modern Network Adapter"),
            (0x1AF4, 0x1042) => String::from("VirtIO 1.0 Modern Block Device"),
            _ => format!("Class {:02x}:{:02x} (ID {:04x}:{:04x})",
                         self.class_id, self.subclass_id, self.vendor_id, self.device_id),
        }
    }

    pub fn class_name(&self) -> &'static str {
        match self.class_id {
            0x00 => "Legacy Device",
            0x01 => "Mass Storage Controller",
            0x02 => "Network Controller",
            0x03 => "Display Controller",
            0x04 => "Multimedia Controller",
            0x05 => "Memory Controller",
            0x06 => "Bridge Device",
            0x07 => "Communication Controller",
            0x08 => "Generic System Peripheral",
            0x09 => "Input Device Controller",
            0x0C => "Serial Bus Controller (USB/SMBus)",
            _ => "Unknown Class",
        }
    }
}

/// Scans PCI buses 0..8, slots 0..32, functions 0..8 and returns all active devices.
pub fn scan_bus() -> Vec<PciDevice> {
    let mut devices = Vec::new();

    for bus in 0..8u8 {
        for slot in 0..32u8 {
            // Function 0
            let vendor_id = unsafe { pci_read_u16(bus, slot, 0, 0) };
            if vendor_id == 0xFFFF || vendor_id == 0x0000 {
                continue; // No device present
            }

            let header_type = unsafe { pci_read_u8(bus, slot, 0, 0x0E) };
            let max_func = if (header_type & 0x80) != 0 { 8 } else { 1 };

            for func in 0..max_func {
                let v_id = unsafe { pci_read_u16(bus, slot, func, 0) };
                if v_id == 0xFFFF || v_id == 0x0000 {
                    continue;
                }
                let d_id = unsafe { pci_read_u16(bus, slot, func, 2) };
                let class_id = unsafe { pci_read_u8(bus, slot, func, 0x0B) };
                let subclass_id = unsafe { pci_read_u8(bus, slot, func, 0x0A) };
                let prog_if = unsafe { pci_read_u8(bus, slot, func, 0x09) };
                let irq_line = unsafe { pci_read_u8(bus, slot, func, 0x3C) };
                let bar0 = unsafe { pci_read_u32(bus, slot, func, 0x10) };
                let bar1 = unsafe { pci_read_u32(bus, slot, func, 0x14) };

                devices.push(PciDevice {
                    bus,
                    slot,
                    func,
                    vendor_id: v_id,
                    device_id: d_id,
                    class_id,
                    subclass_id,
                    prog_if,
                    irq_line,
                    bar0,
                    bar1,
                });
            }
        }
    }

    devices
}

/// Finds the BAR0 physical address of the primary display controller
/// without performing any heap allocation (safe to call before heap::init).
pub fn find_display_bar0() -> Option<u64> {
    for bus in 0..8u8 {
        for slot in 0..32u8 {
            let vendor_id = unsafe { pci_read_u16(bus, slot, 0, 0) };
            if vendor_id == 0xFFFF || vendor_id == 0x0000 {
                continue;
            }

            let header_type = unsafe { pci_read_u8(bus, slot, 0, 0x0E) };
            let max_func = if (header_type & 0x80) != 0 { 8 } else { 1 };

            for func in 0..max_func {
                let v_id = unsafe { pci_read_u16(bus, slot, func, 0) };
                if v_id == 0xFFFF || v_id == 0x0000 {
                    continue;
                }
                let d_id = unsafe { pci_read_u16(bus, slot, func, 2) };
                let class_id = unsafe { pci_read_u8(bus, slot, func, 0x0B) };
                let subclass_id = unsafe { pci_read_u8(bus, slot, func, 0x0A) };

                // Match Bochs/QEMU VGA (1234:1111), VBox VGA (80EE:BEEF), or Class 0x03 (Display)
                if (v_id == 0x1234 && d_id == 0x1111)
                    || (v_id == 0x80EE && d_id == 0xBEEF)
                    || (class_id == 0x03 && subclass_id == 0x00)
                {
                    // Enable Memory Space (bit 1), I/O Space (bit 0), Bus Master (bit 2)
                    let cmd = unsafe { pci_read_u16(bus, slot, func, 0x04) };
                    unsafe { pci_write_u16(bus, slot, func, 0x04, cmd | 0x0007) };

                    let bar0 = unsafe { pci_read_u32(bus, slot, func, 0x10) };
                    let paddr = (bar0 & 0xFFFF_FFF0) as u64;
                    if paddr != 0 {
                        return Some(paddr);
                    }
                }
            }
        }
    }
    None
}
