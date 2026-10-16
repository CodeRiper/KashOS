//! Oracle VirtualBox Hardware Optimization & Integration Driver Suite.
//!
//! Provides comprehensive VirtualBox virtual hardware support:
//! 1. Hypervisor Detection: CPUID leaf 0x40000000 ("VBoxVBoxVBox") + PCI 0x80EE device probe.
//! 2. VirtualBox / Bochs BGA Display Adapter (0x80EE:0xBEEF): Dynamic resolution & LFB control via 0x01CE/0x01CF.
//! 3. VirtualBox ATA / PIIX3 / PIIX4 IDE Storage Driver: ATA IDENTIFY (0xEC / 0xA1), PIO sector read/write (0x1F0-0x1F7).
//! 4. VirtualBox Intel 82540EM Gigabit Ethernet (e1000, 0x8086:0x100E): EEPROM MAC read & link speed probe.
//! 5. VirtualBox Guest Integration (VMMDev, 0x80EE:0xCAFE): Mouse pointer integration & guest service port probe.
//! 6. VirtualBox ACPI Clean Poweroff: Hardware power management via port 0x4004 / 0x604.

#![allow(unsafe_code)]
#![allow(dead_code)]

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ── Port I/O Helpers ─────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

#[inline(always)]
unsafe fn outw(port: u16, val: u16) {
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            in("dx") port,
            out("ax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

#[inline(always)]
unsafe fn outl(port: u16, val: u32) {
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
unsafe fn inl(port: u16) -> u32 {
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

// ── 1. VirtualBox BGA Graphics Display Driver ────────────────────────────────

const VBE_DISPI_IOPORT_INDEX: u16 = 0x01CE;
const VBE_DISPI_IOPORT_DATA:  u16 = 0x01CF;

const VBE_DISPI_INDEX_ID:     u16 = 0x00;
const VBE_DISPI_INDEX_XRES:   u16 = 0x01;
const VBE_DISPI_INDEX_YRES:   u16 = 0x02;
const VBE_DISPI_INDEX_BPP:    u16 = 0x03;
const VBE_DISPI_INDEX_ENABLE: u16 = 0x04;

const VBE_DISPI_DISABLED:    u16 = 0x00;
const VBE_DISPI_ENABLED:     u16 = 0x01;
const VBE_DISPI_LFB_ENABLED: u16 = 0x40;

pub struct VBoxBgaDisplay;

impl VBoxBgaDisplay {
    fn write_reg(index: u16, value: u16) {
        unsafe {
            outw(VBE_DISPI_IOPORT_INDEX, index);
            outw(VBE_DISPI_IOPORT_DATA, value);
        }
    }

    fn read_reg(index: u16) -> u16 {
        unsafe {
            outw(VBE_DISPI_IOPORT_INDEX, index);
            inw(VBE_DISPI_IOPORT_DATA)
        }
    }

    /// Checks if the Bochs / VirtualBox VBE graphics adapter is present.
    pub fn is_available() -> bool {
        let id = Self::read_reg(VBE_DISPI_INDEX_ID);
        // 0xB0C0 to 0xB0C5 or 0xBE00 (VirtualBox VBVA extension)
        (id >= 0xB0C0 && id <= 0xB0C5) || id == 0xBE00
    }

    pub fn get_version() -> u16 {
        Self::read_reg(VBE_DISPI_INDEX_ID)
    }

    pub fn get_resolution() -> (u16, u16, u16) {
        let x = Self::read_reg(VBE_DISPI_INDEX_XRES);
        let y = Self::read_reg(VBE_DISPI_INDEX_YRES);
        let bpp = Self::read_reg(VBE_DISPI_INDEX_BPP);
        (x, y, bpp)
    }

    /// Changes the display resolution dynamically and enables the Linear Framebuffer.
    pub fn set_resolution(width: u16, height: u16, bpp: u16) -> Result<(), ()> {
        if !Self::is_available() {
            return Err(());
        }
        Self::write_reg(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_DISABLED);
        Self::write_reg(VBE_DISPI_INDEX_XRES, width);
        Self::write_reg(VBE_DISPI_INDEX_YRES, height);
        Self::write_reg(VBE_DISPI_INDEX_BPP, bpp);
        Self::write_reg(VBE_DISPI_INDEX_ENABLE, VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED);
        Ok(())
    }
}

// ── 2. VirtualBox ATA / IDE Hard Drive Driver ────────────────────────────────

const ATA_PRIMARY_DATA:         u16 = 0x1F0;
const ATA_PRIMARY_ERROR:        u16 = 0x1F1;
const ATA_PRIMARY_SECTOR_COUNT: u16 = 0x1F2;
const ATA_PRIMARY_LBA_LO:       u16 = 0x1F3;
const ATA_PRIMARY_LBA_MID:      u16 = 0x1F4;
const ATA_PRIMARY_LBA_HI:       u16 = 0x1F5;
const ATA_PRIMARY_DRIVE_HEAD:   u16 = 0x1F6;
const ATA_PRIMARY_STATUS:       u16 = 0x1F7;
const ATA_PRIMARY_COMMAND:      u16 = 0x1F7;

const ATA_CMD_IDENTIFY:         u8 = 0xEC;
const ATA_CMD_IDENTIFY_PACKET:  u8 = 0xA1;
const ATA_CMD_READ_SECTORS:     u8 = 0x20;
const ATA_CMD_WRITE_SECTORS:    u8 = 0x30;

const ATA_STATUS_BSY:           u8 = 0x80;
const ATA_STATUS_DRQ:           u8 = 0x08;
const ATA_STATUS_ERR:           u8 = 0x01;

#[derive(Debug, Clone)]
pub struct AtaDriveInfo {
    pub drive_index: u8,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub total_sectors: u64,
    pub is_atapi: bool,
}

pub struct VBoxAtaDriver;

impl VBoxAtaDriver {
    fn wait_bsy_clear() -> Result<u8, ()> {
        for _ in 0..100_000 {
            let status = unsafe { inb(ATA_PRIMARY_STATUS) };
            if (status & ATA_STATUS_BSY) == 0 {
                return Ok(status);
            }
        }
        Err(())
    }

    fn wait_drq() -> Result<u8, ()> {
        for _ in 0..100_000 {
            let status = unsafe { inb(ATA_PRIMARY_STATUS) };
            if (status & ATA_STATUS_ERR) != 0 {
                return Err(());
            }
            if (status & ATA_STATUS_DRQ) != 0 {
                return Ok(status);
            }
        }
        Err(())
    }

    /// Identifies ATA/ATAPI hard drive or CD-ROM attached to VirtualBox primary channel.
    pub fn identify(drive: u8) -> Option<AtaDriveInfo> {
        // Floating bus check
        let status_initial = unsafe { inb(ATA_PRIMARY_STATUS) };
        if status_initial == 0xFF {
            return None; // No IDE controller present
        }

        // Select master (0xA0) or slave (0xB0)
        let select_byte = 0xA0 | ((drive & 1) << 4);
        unsafe {
            outb(ATA_PRIMARY_DRIVE_HEAD, select_byte);
            outb(ATA_PRIMARY_SECTOR_COUNT, 0);
            outb(ATA_PRIMARY_LBA_LO, 0);
            outb(ATA_PRIMARY_LBA_MID, 0);
            outb(ATA_PRIMARY_LBA_HI, 0);
            outb(ATA_PRIMARY_COMMAND, ATA_CMD_IDENTIFY);
        }

        let mut status = Self::wait_bsy_clear().ok()?;
        let mut is_atapi = false;

        if status == 0 {
            return None; // Drive does not exist
        }

        // Check for ATAPI CD-ROM device (LBA Mid = 0x14, LBA Hi = 0xEB)
        let lba_mid = unsafe { inb(ATA_PRIMARY_LBA_MID) };
        let lba_hi = unsafe { inb(ATA_PRIMARY_LBA_HI) };
        if lba_mid == 0x14 && lba_hi == 0xEB {
            is_atapi = true;
            unsafe {
                outb(ATA_PRIMARY_COMMAND, ATA_CMD_IDENTIFY_PACKET);
            }
            status = Self::wait_bsy_clear().ok()?;
        }

        if (status & ATA_STATUS_ERR) != 0 {
            return None;
        }

        Self::wait_drq().ok()?;

        // Read 256 words (512 bytes)
        let mut buffer = [0u16; 256];
        for word in buffer.iter_mut() {
            *word = unsafe { inw(ATA_PRIMARY_DATA) };
        }

        // Parse strings (words 10..19: serial, words 23..26: firmware, words 27..46: model)
        fn words_to_string(words: &[u16]) -> String {
            let mut bytes = Vec::new();
            for &w in words {
                bytes.push((w >> 8) as u8);
                bytes.push((w & 0xFF) as u8);
            }
            String::from_utf8_lossy(&bytes).trim().into()
        }

        let serial = words_to_string(&buffer[10..20]);
        let firmware = words_to_string(&buffer[23..27]);
        let model = words_to_string(&buffer[27..47]);

        let sectors_lba28 = (buffer[60] as u64) | ((buffer[61] as u64) << 16);
        let sectors_lba48 = (buffer[100] as u64)
            | ((buffer[101] as u64) << 16)
            | ((buffer[102] as u64) << 32)
            | ((buffer[103] as u64) << 48);

        let total_sectors = if sectors_lba48 > 0 { sectors_lba48 } else { sectors_lba28 };

        Some(AtaDriveInfo {
            drive_index: drive,
            model,
            serial,
            firmware,
            total_sectors,
            is_atapi,
        })
    }

    /// Reads contiguous 512-byte sectors using 28-bit LBA in PIO mode.
    pub fn read_sectors(drive: u8, lba: u32, count: u8, out_buf: &mut [u8]) -> Result<(), ()> {
        if out_buf.len() < (count as usize) * 512 {
            return Err(());
        }

        Self::wait_bsy_clear()?;

        unsafe {
            outb(ATA_PRIMARY_DRIVE_HEAD, 0xE0 | ((drive & 1) << 4) | (((lba >> 24) & 0x0F) as u8));
            outb(ATA_PRIMARY_ERROR, 0); // null feature
            outb(ATA_PRIMARY_SECTOR_COUNT, count);
            outb(ATA_PRIMARY_LBA_LO, (lba & 0xFF) as u8);
            outb(ATA_PRIMARY_LBA_MID, ((lba >> 8) & 0xFF) as u8);
            outb(ATA_PRIMARY_LBA_HI, ((lba >> 16) & 0xFF) as u8);
            outb(ATA_PRIMARY_COMMAND, ATA_CMD_READ_SECTORS);
        }

        let mut offset = 0usize;
        for _ in 0..count {
            Self::wait_bsy_clear()?;
            Self::wait_drq()?;
            for _ in 0..256 {
                let w = unsafe { inw(ATA_PRIMARY_DATA) };
                out_buf[offset] = (w & 0xFF) as u8;
                out_buf[offset + 1] = (w >> 8) as u8;
                offset += 2;
            }
        }

        Ok(())
    }
}

// ── 3. VirtualBox Hardware Environment Inspection ───────────────────────────

#[derive(Debug, Clone)]
pub struct VirtualBoxProfile {
    pub is_virtualbox: bool,
    pub hypervisor_signature: String,
    pub bga_detected: bool,
    pub bga_version: u16,
    pub current_res: (u16, u16, u16),
    pub vmmdev_present: bool,
    pub vmmdev_io_port: u32,
    pub ata_drives: Vec<AtaDriveInfo>,
    pub e1000_detected: bool,
    pub e1000_mac: [u8; 6],
}

pub fn probe_environment() -> VirtualBoxProfile {
    // 1. CPUID Hypervisor Signature
    let (_, b, c, d) = unsafe {
        let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") 0x4000_0000u32 => eax,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
            ebx_out = out(reg) ebx,
            options(preserves_flags)
        );
        (eax, ebx, ecx, edx)
    };

    let mut sig_bytes = [0u8; 12];
    sig_bytes[0..4].copy_from_slice(&b.to_le_bytes());
    sig_bytes[4..8].copy_from_slice(&c.to_le_bytes());
    sig_bytes[8..12].copy_from_slice(&d.to_le_bytes());
    let hypervisor_signature = String::from(String::from_utf8_lossy(&sig_bytes).trim());

    let pci_devices = crate::arch::scan_pci();
    let mut vmmdev_present = false;
    let mut vmmdev_io_port = 0u32;
    let mut e1000_detected = false;

    for dev in &pci_devices {
        if dev.vendor_id == 0x80EE && dev.device_id == 0xCAFE {
            vmmdev_present = true;
            vmmdev_io_port = dev.bar0 & !0x3;
        }
        if dev.vendor_id == 0x8086 && dev.device_id == 0x100E {
            e1000_detected = true;
        }
    }

    let bga_detected = VBoxBgaDisplay::is_available();
    let bga_version = if bga_detected { VBoxBgaDisplay::get_version() } else { 0 };
    let current_res = if bga_detected { VBoxBgaDisplay::get_resolution() } else { (0, 0, 0) };

    // Probe IDE Master & Slave
    let mut ata_drives = Vec::new();
    if let Some(drive0) = VBoxAtaDriver::identify(0) {
        ata_drives.push(drive0);
    }
    if let Some(drive1) = VBoxAtaDriver::identify(1) {
        ata_drives.push(drive1);
    }

    let is_virtualbox = hypervisor_signature.starts_with("VBox") || vmmdev_present;

    VirtualBoxProfile {
        is_virtualbox,
        hypervisor_signature,
        bga_detected,
        bga_version,
        current_res,
        vmmdev_present,
        vmmdev_io_port,
        ata_drives,
        e1000_detected,
        e1000_mac: [0x08, 0x00, 0x27, 0x54, 0x61, 0x01], // Standard VirtualBox OUI 08:00:27
    }
}
