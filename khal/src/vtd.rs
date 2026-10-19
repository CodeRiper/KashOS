//! Intel VT-d (Virtualization Technology for Directed I/O) Architecture Types & ACPI DMAR Parser.
//!
//! Provides hardware-neutral, safe definitions for:
//! 1. ACPI DMAR (DMA Remapping Reporting) table parsing (DRHD, RMRR, Device Scopes).
//! 2. VT-d Root Table Entry & Context Table Entry 128-bit descriptors.
//! 3. Second-Level Page Table Entry (SLPTE) 64-bit descriptors.
//! 4. 4-level SLPT translation model with superpage and permission enforcement.

extern crate alloc;
use alloc::vec::Vec;
use crate::PciBdf;

// ── ACPI DMAR Structures ────────────────────────────────────────────────────

pub const ACPI_DMAR_SIG: &[u8; 4] = b"DMAR";

pub const DMAR_TYPE_DRHD: u16 = 0x0000;
pub const DMAR_TYPE_RMRR: u16 = 0x0001;
pub const DMAR_TYPE_ATSR: u16 = 0x0002;
pub const DMAR_TYPE_RHSA: u16 = 0x0003;
pub const DMAR_TYPE_ANDD: u16 = 0x0004;

pub const DRHD_FLAG_INCLUDE_PCI_ALL: u8 = 1 << 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmarDeviceScope {
    pub scope_type: u8,
    pub enumeration_id: u8,
    pub start_bus: u8,
    pub dev: u8,
    pub func: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmarDrhd {
    pub include_pci_all: bool,
    pub segment: u16,
    pub register_base: u64,
    pub device_scopes: Vec<DmarDeviceScope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmarRmrr {
    pub segment: u16,
    pub base_address: u64,
    pub limit_address: u64,
    pub device_scopes: Vec<DmarDeviceScope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedDmar {
    pub haw: u8,
    pub intr_remap: bool,
    pub x2apic_opt_out: bool,
    pub drhd_units: Vec<DmarDrhd>,
    pub rmrr_regions: Vec<DmarRmrr>,
}

/// Parses an ACPI DMAR table from raw memory bytes.
pub fn parse_dmar_bytes(bytes: &[u8]) -> Result<ParsedDmar, &'static str> {
    if bytes.len() < 48 {
        return Err("DMAR table too short");
    }

    if &bytes[0..4] != ACPI_DMAR_SIG {
        return Err("Invalid DMAR signature");
    }

    let length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if length > bytes.len() || length < 48 {
        return Err("Invalid DMAR table length");
    }

    // Verify ACPI checksum
    let mut sum: u8 = 0;
    for &b in &bytes[..length] {
        sum = sum.wrapping_add(b);
    }
    if sum != 0 {
        return Err("DMAR table checksum mismatch");
    }

    let haw = bytes[36].saturating_add(1);
    let flags = bytes[37];
    let intr_remap = (flags & (1 << 0)) != 0;
    let x2apic_opt_out = (flags & (1 << 1)) != 0;

    let mut drhd_units = Vec::new();
    let mut rmrr_regions = Vec::new();

    let mut offset = 48;
    while offset + 4 <= length {
        let struct_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let struct_len = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;

        if struct_len < 4 || offset + struct_len > length {
            return Err("Malformed DMAR sub-structure length");
        }

        match struct_type {
            DMAR_TYPE_DRHD => {
                if struct_len < 16 {
                    return Err("DRHD structure too short");
                }
                let drhd_flags = bytes[offset + 4];
                let include_pci_all = (drhd_flags & DRHD_FLAG_INCLUDE_PCI_ALL) != 0;
                let segment = u16::from_le_bytes([bytes[offset + 6], bytes[offset + 7]]);
                let register_base = u64::from_le_bytes([
                    bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11],
                    bytes[offset + 12], bytes[offset + 13], bytes[offset + 14], bytes[offset + 15],
                ]);

                let mut scopes = Vec::new();
                let mut scope_off = offset + 16;
                while scope_off + 6 <= offset + struct_len {
                    let s_type = bytes[scope_off];
                    let s_len = bytes[scope_off + 1] as usize;
                    if s_len < 6 || scope_off + s_len > offset + struct_len {
                        break;
                    }
                    let enum_id = bytes[scope_off + 4];
                    let start_bus = bytes[scope_off + 5];
                    let dev = if s_len >= 8 { bytes[scope_off + 6] } else { 0 };
                    let func = if s_len >= 8 { bytes[scope_off + 7] } else { 0 };

                    scopes.push(DmarDeviceScope {
                        scope_type: s_type,
                        enumeration_id: enum_id,
                        start_bus,
                        dev,
                        func,
                    });
                    scope_off += s_len;
                }

                drhd_units.push(DmarDrhd {
                    include_pci_all,
                    segment,
                    register_base,
                    device_scopes: scopes,
                });
            }
            DMAR_TYPE_RMRR => {
                if struct_len < 24 {
                    return Err("RMRR structure too short");
                }
                let segment = u16::from_le_bytes([bytes[offset + 4], bytes[offset + 5]]);
                let base_address = u64::from_le_bytes([
                    bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11],
                    bytes[offset + 12], bytes[offset + 13], bytes[offset + 14], bytes[offset + 15],
                ]);
                let limit_address = u64::from_le_bytes([
                    bytes[offset + 16], bytes[offset + 17], bytes[offset + 18], bytes[offset + 19],
                    bytes[offset + 20], bytes[offset + 21], bytes[offset + 22], bytes[offset + 23],
                ]);

                let mut scopes = Vec::new();
                let mut scope_off = offset + 24;
                while scope_off + 6 <= offset + struct_len {
                    let s_type = bytes[scope_off];
                    let s_len = bytes[scope_off + 1] as usize;
                    if s_len < 6 || scope_off + s_len > offset + struct_len {
                        break;
                    }
                    let enum_id = bytes[scope_off + 4];
                    let start_bus = bytes[scope_off + 5];
                    let dev = if s_len >= 8 { bytes[scope_off + 6] } else { 0 };
                    let func = if s_len >= 8 { bytes[scope_off + 7] } else { 0 };

                    scopes.push(DmarDeviceScope {
                        scope_type: s_type,
                        enumeration_id: enum_id,
                        start_bus,
                        dev,
                        func,
                    });
                    scope_off += s_len;
                }

                rmrr_regions.push(DmarRmrr {
                    segment,
                    base_address,
                    limit_address,
                    device_scopes: scopes,
                });
            }
            _ => {
                // Ignore other ACPI DMAR sub-tables (ATSR, RHSA, ANDD)
            }
        }

        offset += struct_len;
    }

    Ok(ParsedDmar {
        haw,
        intr_remap,
        x2apic_opt_out,
        drhd_units,
        rmrr_regions,
    })
}

// ── Root Entry & Context Entry Structures ───────────────────────────────────

/// 128-bit Intel VT-d Root Table Entry.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VtdRootEntry {
    pub lower: u64,
    pub upper: u64,
}

impl VtdRootEntry {
    pub const PRESENT: u64 = 1 << 0;
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    pub fn set_context_table(&mut self, context_phys: u64) {
        self.lower = (context_phys & Self::ADDR_MASK) | Self::PRESENT;
        self.upper = 0;
    }

    pub fn is_present(&self) -> bool {
        (self.lower & Self::PRESENT) != 0
    }

    pub fn context_table_addr(&self) -> u64 {
        self.lower & Self::ADDR_MASK
    }
}

/// 128-bit Intel VT-d Context Table Entry.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VtdContextEntry {
    pub lower: u64,
    pub upper: u64,
}

impl VtdContextEntry {
    pub const PRESENT: u64        = 1 << 0;
    pub const FPD: u64            = 1 << 1;
    pub const TT_TRANSLATED: u64  = 0b00 << 2;
    pub const TT_PASSTHROUGH: u64 = 0b01 << 2;
    pub const AW_39BIT: u64       = 0b001; // 3-level page walk
    pub const AW_48BIT: u64       = 0b010; // 4-level page walk
    pub const ADDR_MASK: u64      = 0x000F_FFFF_FFFF_F000;

    pub fn set_translation(&mut self, slpt_root_phys: u64, domain_id: u16, address_width_48: bool) {
        self.lower = (slpt_root_phys & Self::ADDR_MASK) | Self::PRESENT | Self::TT_TRANSLATED;
        let aw = if address_width_48 { Self::AW_48BIT } else { Self::AW_39BIT };
        self.upper = (aw & 0x07) | ((domain_id as u64) << 8);
    }

    pub fn set_passthrough(&mut self, domain_id: u16) {
        self.lower = Self::PRESENT | Self::TT_PASSTHROUGH;
        self.upper = (Self::AW_48BIT & 0x07) | ((domain_id as u64) << 8);
    }

    pub fn is_present(&self) -> bool {
        (self.lower & Self::PRESENT) != 0
    }

    pub fn slpt_root_addr(&self) -> u64 {
        self.lower & Self::ADDR_MASK
    }

    pub fn domain_id(&self) -> u16 {
        ((self.upper >> 8) & 0xFFFF) as u16
    }
}

// ── Second-Level Page Table (SLPT) Structures ───────────────────────────────

/// 64-bit Second-Level Page Table Entry (SLPTE) for DMA memory mapping.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlptEntry(pub u64);

impl SlptEntry {
    pub const READ: u64      = 1 << 0;
    pub const WRITE: u64     = 1 << 1;
    pub const SUPERPAGE: u64 = 1 << 7; // 2MB superpage at level 2
    pub const SNOOP: u64     = 1 << 11; // Hardware cache snooping
    pub const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    pub fn new_leaf(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut val = phys_addr & Self::ADDR_MASK;
        if read { val |= Self::READ; }
        if write { val |= Self::WRITE; }
        val |= Self::SNOOP;
        Self(val)
    }

    pub fn new_superpage(phys_addr: u64, read: bool, write: bool) -> Self {
        let mut val = (phys_addr & !0x1F_FFFF) | Self::SUPERPAGE;
        if read { val |= Self::READ; }
        if write { val |= Self::WRITE; }
        val |= Self::SNOOP;
        Self(val)
    }

    pub fn new_table(table_phys: u64) -> Self {
        Self((table_phys & Self::ADDR_MASK) | Self::READ | Self::WRITE)
    }

    pub fn is_present(&self) -> bool {
        (self.0 & (Self::READ | Self::WRITE)) != 0
    }

    pub fn is_superpage(&self) -> bool {
        (self.0 & Self::SUPERPAGE) != 0
    }

    pub fn has_read(&self) -> bool {
        (self.0 & Self::READ) != 0
    }

    pub fn has_write(&self) -> bool {
        (self.0 & Self::WRITE) != 0
    }

    pub fn phys_addr(&self) -> u64 {
        self.0 & Self::ADDR_MASK
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtdFaultReason {
    RootEntryNotPresent,
    ContextEntryNotPresent,
    TranslationNotPresent,
    WritePermissionViolation,
    ReadPermissionViolation,
    PcieAcsViolation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VtdFaultRecord {
    pub fault_addr: u64,
    pub bdf: PciBdf,
    pub domain_id: u16,
    pub is_write: bool,
    pub reason: VtdFaultReason,
}

// ── 4-Level SLPT Page Table Implementation ──────────────────────────────────

use alloc::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct SlptPageTable {
    /// Maps domain_id -> root table (PML4) physical address
    domain_roots: BTreeMap<u16, u64>,
    /// Maps table_phys -> 512 entries
    tables: BTreeMap<u64, [SlptEntry; 512]>,
    /// Device domain bindings: bdf -> domain_id
    device_domains: BTreeMap<PciBdf, u16>,
    /// Simulated physical frame allocator counter (4 KiB page aligned)
    next_phys_frame: u64,
}

impl SlptPageTable {
    pub fn new() -> Self {
        Self {
            domain_roots: BTreeMap::new(),
            tables: BTreeMap::new(),
            device_domains: BTreeMap::new(),
            next_phys_frame: 0x4000_0000, // 1 GiB base for allocated SLPT structures
        }
    }

    fn alloc_frame(&mut self) -> u64 {
        let frame = self.next_phys_frame;
        self.next_phys_frame += 0x1000;
        self.tables.insert(frame, [SlptEntry(0); 512]);
        frame
    }

    pub fn bind_device(&mut self, bdf: PciBdf, domain_id: u16) {
        self.device_domains.insert(bdf, domain_id);
        if !self.domain_roots.contains_key(&domain_id) {
            let pml4 = self.alloc_frame();
            self.domain_roots.insert(domain_id, pml4);
        }
    }

    pub fn map_dma(
        &mut self,
        bdf: PciBdf,
        domain_id: u16,
        guest_phys: u64,
        host_phys: u64,
        size: usize,
        read: bool,
        write: bool,
    ) -> Result<(), &'static str> {
        self.bind_device(bdf, domain_id);
        let pml4_phys = *self.domain_roots.get(&domain_id).ok_or("Domain not found")?;

        let pages = (size + 4095) / 4096;
        for i in 0..pages {
            let g_addr = guest_phys + (i as u64 * 4096);
            let h_addr = host_phys + (i as u64 * 4096);

            let l4_idx = ((g_addr >> 39) & 0x1FF) as usize;
            let l3_idx = ((g_addr >> 30) & 0x1FF) as usize;
            let l2_idx = ((g_addr >> 21) & 0x1FF) as usize;
            let l1_idx = ((g_addr >> 12) & 0x1FF) as usize;

            // Level 4 -> Level 3
            let l3_phys = {
                let pml4 = self.tables.get_mut(&pml4_phys).ok_or("Missing PML4 table")?;
                if !pml4[l4_idx].is_present() {
                    let frame = self.next_phys_frame;
                    self.next_phys_frame += 0x1000;
                    pml4[l4_idx] = SlptEntry::new_table(frame);
                    frame
                } else {
                    pml4[l4_idx].phys_addr()
                }
            };
            self.tables.entry(l3_phys).or_insert([SlptEntry(0); 512]);

            // Level 3 -> Level 2
            let l2_phys = {
                let pdpt = self.tables.get_mut(&l3_phys).ok_or("Missing PDPT table")?;
                if !pdpt[l3_idx].is_present() {
                    let frame = self.next_phys_frame;
                    self.next_phys_frame += 0x1000;
                    pdpt[l3_idx] = SlptEntry::new_table(frame);
                    frame
                } else {
                    pdpt[l3_idx].phys_addr()
                }
            };
            self.tables.entry(l2_phys).or_insert([SlptEntry(0); 512]);

            // Level 2 -> Level 1
            let l1_phys = {
                let pd = self.tables.get_mut(&l2_phys).ok_or("Missing PD table")?;
                if !pd[l2_idx].is_present() {
                    let frame = self.next_phys_frame;
                    self.next_phys_frame += 0x1000;
                    pd[l2_idx] = SlptEntry::new_table(frame);
                    frame
                } else {
                    pd[l2_idx].phys_addr()
                }
            };
            self.tables.entry(l1_phys).or_insert([SlptEntry(0); 512]);

            // Level 1 leaf entry
            let pt = self.tables.get_mut(&l1_phys).ok_or("Missing PT table")?;
            pt[l1_idx] = SlptEntry::new_leaf(h_addr, read, write);
        }

        Ok(())
    }

    pub fn unmap_dma(&mut self, bdf: PciBdf, guest_phys: u64, size: usize) -> Result<(), &'static str> {
        let domain_id = *self.device_domains.get(&bdf).ok_or("Device not bound")?;
        let pml4_phys = *self.domain_roots.get(&domain_id).ok_or("Domain not found")?;

        let pages = (size + 4095) / 4096;
        for i in 0..pages {
            let g_addr = guest_phys + (i as u64 * 4096);
            let l4_idx = ((g_addr >> 39) & 0x1FF) as usize;
            let l3_idx = ((g_addr >> 30) & 0x1FF) as usize;
            let l2_idx = ((g_addr >> 21) & 0x1FF) as usize;
            let l1_idx = ((g_addr >> 12) & 0x1FF) as usize;

            if let Some(pml4) = self.tables.get(&pml4_phys) {
                if !pml4[l4_idx].is_present() { continue; }
                let l3_phys = pml4[l4_idx].phys_addr();

                if let Some(pdpt) = self.tables.get(&l3_phys) {
                    if !pdpt[l3_idx].is_present() { continue; }
                    let l2_phys = pdpt[l3_idx].phys_addr();

                    if let Some(pd) = self.tables.get(&l2_phys) {
                        if !pd[l2_idx].is_present() { continue; }
                        let l1_phys = pd[l2_idx].phys_addr();

                        if let Some(pt) = self.tables.get_mut(&l1_phys) {
                            pt[l1_idx] = SlptEntry(0);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn translate_dma(
        &self,
        bdf: PciBdf,
        domain_id: u16,
        guest_phys: u64,
        is_write: bool,
    ) -> Result<u64, VtdFaultReason> {
        let bound_domain = match self.device_domains.get(&bdf) {
            Some(&d) => d,
            None => return Err(VtdFaultReason::TranslationNotPresent),
        };

        if bound_domain != domain_id {
            return Err(VtdFaultReason::TranslationNotPresent);
        }

        let pml4_phys = match self.domain_roots.get(&domain_id) {
            Some(&p) => p,
            None => return Err(VtdFaultReason::ContextEntryNotPresent),
        };

        let l4_idx = ((guest_phys >> 39) & 0x1FF) as usize;
        let l3_idx = ((guest_phys >> 30) & 0x1FF) as usize;
        let l2_idx = ((guest_phys >> 21) & 0x1FF) as usize;
        let l1_idx = ((guest_phys >> 12) & 0x1FF) as usize;
        let offset = guest_phys & 0xFFF;

        let pml4 = self.tables.get(&pml4_phys).ok_or(VtdFaultReason::TranslationNotPresent)?;
        if !pml4[l4_idx].is_present() {
            return Err(VtdFaultReason::TranslationNotPresent);
        }

        let pdpt = self.tables.get(&pml4[l4_idx].phys_addr()).ok_or(VtdFaultReason::TranslationNotPresent)?;
        if !pdpt[l3_idx].is_present() {
            return Err(VtdFaultReason::TranslationNotPresent);
        }

        let pd = self.tables.get(&pdpt[l3_idx].phys_addr()).ok_or(VtdFaultReason::TranslationNotPresent)?;
        if !pd[l2_idx].is_present() {
            return Err(VtdFaultReason::TranslationNotPresent);
        }

        if pd[l2_idx].is_superpage() {
            let entry = pd[l2_idx];
            if is_write && !entry.has_write() {
                return Err(VtdFaultReason::WritePermissionViolation);
            }
            if !is_write && !entry.has_read() {
                return Err(VtdFaultReason::ReadPermissionViolation);
            }
            let super_offset = guest_phys & 0x1F_FFFF;
            return Ok((entry.phys_addr() & !0x1F_FFFF) | super_offset);
        }

        let pt = self.tables.get(&pd[l2_idx].phys_addr()).ok_or(VtdFaultReason::TranslationNotPresent)?;
        let entry = pt[l1_idx];
        if !entry.is_present() {
            return Err(VtdFaultReason::TranslationNotPresent);
        }

        if is_write && !entry.has_write() {
            return Err(VtdFaultReason::WritePermissionViolation);
        }
        if !is_write && !entry.has_read() {
            return Err(VtdFaultReason::ReadPermissionViolation);
        }

        Ok((entry.phys_addr() & !0xFFF) | offset)
    }
}
