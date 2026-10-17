//! ACPI table scanning and discovery for x86-64.
//!
//! Scans physical memory for the Root System Description Pointer (RSDP)
//! and traverses XSDT (64-bit pointers) or RSDT (32-bit pointers) to locate
//! requested ACPI tables (MADT/APIC, DMAR, MCFG, FADT, etc.).
#![allow(unsafe_code)]

/// Searches physical memory for the ACPI RSDP and returns its physical address.
pub fn find_rsdp() -> Option<usize> {
    // 1. Search Extended BIOS Data Area (EBDA)
    let ebda_ptr = unsafe { *((0x40E) as *const u16) } as usize * 16;
    if ebda_ptr != 0 && ebda_ptr < 0xA0000 {
        if let Some(addr) = scan_rsdp_range(ebda_ptr, ebda_ptr + 1024) {
            return Some(addr);
        }
    }

    // 2. Search BIOS read-only memory range 0xE0000..0x100000 on 16-byte boundaries
    scan_rsdp_range(0xE0000, 0x100000)
}

fn scan_rsdp_range(start: usize, end: usize) -> Option<usize> {
    for addr in (start..end).step_by(16) {
        let sig = unsafe { core::slice::from_raw_parts(addr as *const u8, 8) };
        if sig == b"RSD PTR " {
            // Validate checksum of first 20 bytes
            let bytes = unsafe { core::slice::from_raw_parts(addr as *const u8, 20) };
            let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if sum == 0 {
                return Some(addr);
            }
        }
    }
    None
}

/// Locate an ACPI table by its 4-byte signature (e.g. b"APIC" for MADT, b"DMAR" for VT-d).
pub fn find_table(target_sig: &[u8; 4]) -> Option<usize> {
    let rsdp = find_rsdp()?;
    let revision = unsafe { core::ptr::read_volatile((rsdp + 15) as *const u8) };

    if revision >= 2 {
        // XSDT with 64-bit physical pointers
        let xsdt_phys = unsafe { core::ptr::read_volatile((rsdp + 24) as *const u64) } as usize;
        if xsdt_phys != 0 {
            let sig = unsafe { core::slice::from_raw_parts(xsdt_phys as *const u8, 4) };
            if sig == b"XSDT" {
                let len = unsafe { core::ptr::read_volatile((xsdt_phys + 4) as *const u32) } as usize;
                let num_tables = (len.saturating_sub(36)) / 8;
                for i in 0..num_tables {
                    let table_phys = unsafe {
                        core::ptr::read_volatile((xsdt_phys + 36 + i * 8) as *const u64)
                    } as usize;
                    if table_phys != 0 {
                        let tbl_sig = unsafe { core::slice::from_raw_parts(table_phys as *const u8, 4) };
                        if tbl_sig == target_sig {
                            return Some(table_phys);
                        }
                    }
                }
            }
        }
    }

    // Fallback: RSDT with 32-bit physical pointers
    let rsdt_phys = unsafe { core::ptr::read_volatile((rsdp + 16) as *const u32) } as usize;
    if rsdt_phys != 0 {
        let sig = unsafe { core::slice::from_raw_parts(rsdt_phys as *const u8, 4) };
        if sig == b"RSDT" {
            let len = unsafe { core::ptr::read_volatile((rsdt_phys + 4) as *const u32) } as usize;
            let num_tables = (len.saturating_sub(36)) / 4;
            for i in 0..num_tables {
                let table_phys = unsafe {
                    core::ptr::read_volatile((rsdt_phys + 36 + i * 4) as *const u32)
                } as usize;
                if table_phys != 0 {
                    let tbl_sig = unsafe { core::slice::from_raw_parts(table_phys as *const u8, 4) };
                    if tbl_sig == target_sig {
                        return Some(table_phys);
                    }
                }
            }
        }
    }

    None
}
