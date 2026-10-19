//! ACPI table scanning, power management, and platform control for x86-64.
//!
//! Scans physical memory for the Root System Description Pointer (RSDP)
//! and traverses XSDT (64-bit pointers) or RSDT (32-bit pointers) to locate
//! requested ACPI tables (MADT/APIC, DMAR, MCFG, FADT/FACP, etc.).
//!
//! Implements ACPI Fixed ACPI Description Table (FADT) parsing, AML bytecode
//! scanning for the `\_S5` sleep state package, deterministic hardware poweroff
//! via PM1a/PM1b control blocks, and platform reset via ACPI RESET_REG, PCI 0xCF9,
//! 8042 keyboard controller, and Fast A20.

#![allow(unsafe_code)]

extern crate alloc;

#[inline(always)]
fn outb(port: u16, val: u8) {
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
fn inb(port: u16) -> u8 {
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
fn outw(port: u16, val: u16) {
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
fn inw(port: u16) -> u16 {
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

/// Searches physical memory for the ACPI RSDP and returns its physical address.
pub fn find_rsdp() -> Option<usize> {
    scan_rsdp_range(0xE0000, 0x100000)
}

fn scan_rsdp_range(start: usize, end: usize) -> Option<usize> {
    unsafe {
        for addr in (start..end).step_by(16) {
            let sig = core::slice::from_raw_parts(addr as *const u8, 8);
            if sig == b"RSD PTR " {
                let bytes = core::slice::from_raw_parts(addr as *const u8, 20);
                let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
                if sum == 0 {
                    return Some(addr);
                }
            }
        }
        None
    }
}

/// Locate an ACPI table by its 4-byte signature (e.g. b"APIC" for MADT, b"DMAR" for VT-d, b"FACP" for FADT).
pub fn find_table(target_sig: &[u8; 4]) -> Option<usize> {
    let rsdp = find_rsdp()?;
    unsafe {
        let revision = core::ptr::read_volatile((rsdp + 15) as *const u8);

        if revision >= 2 {
            // XSDT with 64-bit physical pointers
            let xsdt_phys = core::ptr::read_volatile((rsdp + 24) as *const u64) as usize;
            if xsdt_phys != 0 {
                let sig = core::slice::from_raw_parts(xsdt_phys as *const u8, 4);
                if sig == b"XSDT" {
                    let len = core::ptr::read_volatile((xsdt_phys + 4) as *const u32) as usize;
                    let num_tables = (len.saturating_sub(36)) / 8;
                    for i in 0..num_tables {
                        let table_phys = core::ptr::read_volatile((xsdt_phys + 36 + i * 8) as *const u64) as usize;
                        if table_phys != 0 {
                            let tbl_sig = core::slice::from_raw_parts(table_phys as *const u8, 4);
                            if tbl_sig == target_sig {
                                return Some(table_phys);
                            }
                        }
                    }
                }
            }
        }

        // Fallback: RSDT with 32-bit physical pointers
        let rsdt_phys = core::ptr::read_volatile((rsdp + 16) as *const u32) as usize;
        if rsdt_phys != 0 {
            let sig = core::slice::from_raw_parts(rsdt_phys as *const u8, 4);
            if sig == b"RSDT" {
                let len = core::ptr::read_volatile((rsdt_phys + 4) as *const u32) as usize;
                let num_tables = (len.saturating_sub(36)) / 4;
                for i in 0..num_tables {
                    let table_phys = core::ptr::read_volatile((rsdt_phys + 36 + i * 4) as *const u32) as usize;
                    if table_phys != 0 {
                        let tbl_sig = core::slice::from_raw_parts(table_phys as *const u8, 4);
                        if tbl_sig == target_sig {
                            return Some(table_phys);
                        }
                    }
                }
            }
        }

        None
    }
}

// ── FADT & Power Management ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct FadtInfo {
    pub smi_cmd: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub pm1a_cnt_blk: u32,
    pub pm1b_cnt_blk: u32,
    pub pm1_cnt_len: u8,
    pub flags: u32,
    pub reset_reg_supported: bool,
    pub reset_reg_space: u8, // 0 = Memory, 1 = I/O, 2 = PCI
    pub reset_reg_addr: u64,
    pub reset_value: u8,
    pub dsdt_addr: usize,
    pub s5_slp_typa: u8,
    pub s5_slp_typb: u8,
}

impl FadtInfo {
    pub fn parse_from_bytes(table_bytes: &[u8]) -> Option<Self> {
        if table_bytes.len() < 116 || &table_bytes[0..4] != b"FACP" {
            return None;
        }

        let dsdt_32 = u32::from_le_bytes(table_bytes[40..44].try_into().ok()?);
        let smi_cmd = u32::from_le_bytes(table_bytes[48..52].try_into().ok()?);
        let acpi_enable = table_bytes[52];
        let acpi_disable = table_bytes[53];
        let pm1a_cnt_blk = u32::from_le_bytes(table_bytes[64..68].try_into().ok()?);
        let pm1b_cnt_blk = u32::from_le_bytes(table_bytes[68..72].try_into().ok()?);
        let pm1_cnt_len = table_bytes[89];
        let flags = u32::from_le_bytes(table_bytes[112..116].try_into().ok()?);

        let reset_reg_supported = (flags & (1 << 10)) != 0;
        let mut reset_reg_space = 0u8;
        let mut reset_reg_addr = 0u64;
        let mut reset_value = 0u8;

        if table_bytes.len() >= 129 {
            reset_reg_space = table_bytes[116];
            reset_reg_addr = u64::from_le_bytes(table_bytes[120..128].try_into().ok()?);
            reset_value = table_bytes[128];
        }

        let mut dsdt_addr = dsdt_32 as usize;
        if table_bytes.len() >= 148 {
            let x_dsdt = u64::from_le_bytes(table_bytes[140..148].try_into().ok()?);
            if x_dsdt != 0 {
                dsdt_addr = x_dsdt as usize;
            }
        }

        Some(Self {
            smi_cmd,
            acpi_enable,
            acpi_disable,
            pm1a_cnt_blk,
            pm1b_cnt_blk,
            pm1_cnt_len,
            flags,
            reset_reg_supported,
            reset_reg_space,
            reset_reg_addr,
            reset_value,
            dsdt_addr,
            s5_slp_typa: 0x05, // Default fallback
            s5_slp_typb: 0x05, // Default fallback
        })
    }
}

/// Locates and parses the FADT table and its associated DSDT AML bytecode.
pub fn parse_fadt() -> Option<FadtInfo> {
    let fadt_phys = find_table(b"FACP")?;
    unsafe {
        let len = core::ptr::read_volatile((fadt_phys + 4) as *const u32) as usize;
        if len < 116 {
            return None;
        }
        let bytes = core::slice::from_raw_parts(fadt_phys as *const u8, len.min(512));
        let mut fadt = FadtInfo::parse_from_bytes(bytes)?;

        // Scan DSDT AML for \_S5 package
        if fadt.dsdt_addr != 0 {
            let dsdt_sig = core::slice::from_raw_parts(fadt.dsdt_addr as *const u8, 4);
            if dsdt_sig == b"DSDT" {
                let dsdt_len = core::ptr::read_volatile((fadt.dsdt_addr + 4) as *const u32) as usize;
                let dsdt_bytes = core::slice::from_raw_parts(fadt.dsdt_addr as *const u8, dsdt_len.min(512 * 1024));
                if let Some((typa, typb)) = parse_aml_s5(dsdt_bytes) {
                    fadt.s5_slp_typa = typa;
                    fadt.s5_slp_typb = typb;
                }
            }
        }

        Some(fadt)
    }
}

/// Parses AML bytecode to locate the `_S5` sleep state package and extract SLP_TYPa / SLP_TYPb.
pub fn parse_aml_s5(dsdt: &[u8]) -> Option<(u8, u8)> {
    if dsdt.len() < 10 {
        return None;
    }

    // Pattern to look for: "_S5_"
    let s5_pattern = b"_S5_";
    for i in 0..(dsdt.len().saturating_sub(10)) {
        if &dsdt[i..i + 4] == s5_pattern {
            let mut offset = i + 4;
            // Next byte should be PackageOp (0x12)
            if offset < dsdt.len() && dsdt[offset] == 0x12 {
                offset += 1;
                let _ = parse_pkg_length(dsdt, &mut offset)?;
                if offset < dsdt.len() {
                    let num_elements = dsdt[offset];
                    offset += 1;
                    if num_elements >= 1 {
                        let typa = decode_aml_int(dsdt, &mut offset)?;
                        let typb = if num_elements >= 2 {
                            decode_aml_int(dsdt, &mut offset).unwrap_or(typa)
                        } else {
                            typa
                        };
                        return Some((typa, typb));
                    }
                }
            }
        }
    }

    None
}

fn parse_pkg_length(bytes: &[u8], offset: &mut usize) -> Option<usize> {
    if *offset >= bytes.len() {
        return None;
    }
    let lead = bytes[*offset];
    *offset += 1;
    let byte_count = (lead >> 6) & 0x03;
    if byte_count == 0 {
        Some((lead & 0x3F) as usize)
    } else {
        let mut len = (lead & 0x0F) as usize;
        for i in 0..byte_count {
            if *offset >= bytes.len() {
                return None;
            }
            len |= (bytes[*offset] as usize) << (4 + i * 8);
            *offset += 1;
        }
        Some(len)
    }
}

fn decode_aml_int(bytes: &[u8], offset: &mut usize) -> Option<u8> {
    if *offset >= bytes.len() {
        return None;
    }
    let op = bytes[*offset];
    *offset += 1;
    match op {
        0x00 => Some(0),
        0x01 => Some(1),
        0xFF => Some(0xFF),
        0x0A => {
            if *offset < bytes.len() {
                let v = bytes[*offset];
                *offset += 1;
                Some(v)
            } else {
                None
            }
        }
        0x0B => {
            if *offset + 2 <= bytes.len() {
                let v = bytes[*offset];
                *offset += 2;
                Some(v)
            } else {
                None
            }
        }
        0x0C => {
            if *offset + 4 <= bytes.len() {
                let v = bytes[*offset];
                *offset += 4;
                Some(v)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Transitions the platform into ACPI hardware enable mode.
pub fn enable_acpi_mode(fadt: &FadtInfo) {
    if fadt.pm1a_cnt_blk == 0 {
        return;
    }
    // Check if SCI_EN is already set (Bit 0 of PM1a_CNT)
    let pm1a = inw(fadt.pm1a_cnt_blk as u16);
    if (pm1a & 1) != 0 {
        return;
    }

    if fadt.smi_cmd != 0 && fadt.acpi_enable != 0 {
        outb(fadt.smi_cmd as u16, fadt.acpi_enable);
        // Wait up to ~100k cycles for SCI_EN to be asserted
        for _ in 0..100_000 {
            if (inw(fadt.pm1a_cnt_blk as u16) & 1) != 0 {
                break;
            }
            unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
        }
    }
}

/// Clean system poweroff via ACPI S5, with emulator and triple-fault fallbacks.
pub fn poweroff(failure: bool) -> ! {
    let fail_code: u16 = if failure { 1 } else { 0 };

    if let Some(fadt) = parse_fadt() {
        enable_acpi_mode(&fadt);

        if fadt.pm1a_cnt_blk != 0 {
            let slp_val_a = ((fadt.s5_slp_typa as u16) << 10) | (1 << 13);
            outw(fadt.pm1a_cnt_blk as u16, slp_val_a);
            if fadt.pm1b_cnt_blk != 0 {
                let slp_val_b = ((fadt.s5_slp_typb as u16) << 10) | (1 << 13);
                outw(fadt.pm1b_cnt_blk as u16, slp_val_b);
            }
            for _ in 0..10_000 {
                unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
            }
        }
    }

    // Emulator / Hypervisor and triple-fault fallbacks
    unsafe {
        // QEMU / Bochs modern debug / ACPI poweroff port
        outw(0x604, 0x2000 | fail_code);
        // Bochs / older QEMU ACPI poweroff port
        outw(0xB004, 0x2000 | fail_code);
        // VirtualBox poweroff port
        outw(0x4004, 0x3400);

        // Failsafe: triple-fault
        core::arch::asm!(
            "lidt [{0}]",
            "int3",
            in(reg) &[0u64; 0],
            options(nostack)
        );
        loop { core::arch::asm!("hlt", options(nomem, nostack)); }
    }
}

/// Clean system reboot via ACPI RESET_REG, PCI 0xCF9, 8042 KBC, and Fast A20.
pub fn reboot() -> ! {
    if let Some(fadt) = parse_fadt() {
        if fadt.reset_reg_supported && fadt.reset_reg_addr != 0 {
            if fadt.reset_reg_space == 1 {
                outb(fadt.reset_reg_addr as u16, fadt.reset_value);
            } else if fadt.reset_reg_space == 0 {
                unsafe { core::ptr::write_volatile(fadt.reset_reg_addr as *mut u8, fadt.reset_value); }
            }
            for _ in 0..10_000 {
                unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
            }
        }
    }

    // Fallback 1: PCI Reset Control Register (0xCF9)
    outb(0xCF9, 0x02);
    for _ in 0..1_000 { unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }
    outb(0xCF9, 0x06);
    for _ in 0..10_000 { unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }

    // Fallback 2: PS/2 8042 Keyboard Controller Reset Pulse (0x64 command 0xFE)
    for _ in 0..10_000 {
        if (inb(0x64) & 0x02) == 0 {
            break;
        }
        unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
    }
    outb(0x64, 0xFE);
    for _ in 0..10_000 { unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }

    // Fallback 3: Fast A20 Reset (Port 0x92 bit 0)
    let val = inb(0x92);
    outb(0x92, val | 0x01);
    for _ in 0..10_000 { unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }

    // Fallback 4: Triple Fault
    unsafe {
        core::arch::asm!(
            "lidt [{0}]",
            "int3",
            in(reg) &[0u64; 0],
            options(nostack)
        );
        loop { core::arch::asm!("hlt", options(nomem, nostack)); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fadt_parsing() {
        let mut fadt_bytes = [0u8; 148];
        fadt_bytes[0..4].copy_from_slice(b"FACP");
        let len = 148u32;
        fadt_bytes[4..8].copy_from_slice(&len.to_le_bytes());

        // DSDT 32
        fadt_bytes[40..44].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        // SMI_CMD
        fadt_bytes[48..52].copy_from_slice(&0x0000_00B2u32.to_le_bytes());
        // ACPI_ENABLE
        fadt_bytes[52] = 0xA0;
        // ACPI_DISABLE
        fadt_bytes[53] = 0xA1;
        // PM1a_CNT_BLK
        fadt_bytes[64..68].copy_from_slice(&0x0000_0604u32.to_le_bytes());
        // PM1b_CNT_BLK
        fadt_bytes[68..72].copy_from_slice(&0x0000_0000u32.to_le_bytes());
        // PM1_CNT_LEN
        fadt_bytes[89] = 2;
        // FLAGS with RESET_REG_SUP (bit 10)
        fadt_bytes[112..116].copy_from_slice(&(1u32 << 10).to_le_bytes());
        // RESET_REG (Generic Address Structure: space 1 = I/O, addr 0xCF9)
        fadt_bytes[116] = 1; // System I/O
        fadt_bytes[117] = 8; // 8 bits
        fadt_bytes[120..128].copy_from_slice(&0x0000_0CF9u64.to_le_bytes());
        // RESET_VALUE
        fadt_bytes[128] = 0x06;

        let info = FadtInfo::parse_from_bytes(&fadt_bytes).expect("Failed to parse FADT");
        assert_eq!(info.smi_cmd, 0xB2);
        assert_eq!(info.acpi_enable, 0xA0);
        assert_eq!(info.pm1a_cnt_blk, 0x604);
        assert_eq!(info.pm1b_cnt_blk, 0);
        assert!(info.reset_reg_supported);
        assert_eq!(info.reset_reg_space, 1);
        assert_eq!(info.reset_reg_addr, 0xCF9);
        assert_eq!(info.reset_value, 0x06);
        assert_eq!(info.dsdt_addr, 0x0010_0000);
    }

    #[test]
    fn test_aml_s5_parsing() {
        // Synthesize AML containing: Name(_S5_, Package(4) { 0x05, 0x05, 0x00, 0x00 })
        let mut dsdt = alloc::vec![0u8; 64];
        // Header
        dsdt[0..4].copy_from_slice(b"DSDT");
        let len = 64u32;
        dsdt[4..8].copy_from_slice(&len.to_le_bytes());

        // NameOp (0x08), "_S5_", PackageOp (0x12), PkgLength (0x08), NumElements (0x04), BytePrefix (0x0A, 5), BytePrefix (0x0A, 5), ZeroOp (0x00), ZeroOp (0x00)
        let s5_aml = [
            0x08, b'_', b'S', b'5', b'_',
            0x12, 0x08, 0x04,
            0x0A, 0x05,
            0x0A, 0x05,
            0x00,
            0x00,
        ];
        dsdt[36..36 + s5_aml.len()].copy_from_slice(&s5_aml);

        let (typa, typb) = parse_aml_s5(&dsdt).expect("Failed to parse _S5");
        assert_eq!(typa, 0x05);
        assert_eq!(typb, 0x05);
    }

    #[test]
    fn test_acpi_sleep_control_encoding() {
        let typa = 0x05u8;
        let control_word = ((typa as u16) << 10) | (1 << 13);
        // Bit 13 is SLP_EN (0x2000)
        assert_ne!(control_word & 0x2000, 0);
        // Bits 10..12 hold typa (5 << 10 = 0x1400)
        assert_eq!((control_word >> 10) & 0x07, 5);
        assert_eq!(control_word, 0x3400);
    }
}
