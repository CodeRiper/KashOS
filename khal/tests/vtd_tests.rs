use khal::vtd::*;
use khal::PciBdf;

fn build_test_dmar_bytes(drhd_base: u64, include_all: bool) -> Vec<u8> {
    let mut bytes = Vec::new();

    // 1. ACPI Header (36 bytes)
    bytes.extend_from_slice(b"DMAR"); // Signature
    bytes.extend_from_slice(&[0u8; 4]); // Length placeholder at 4..8
    bytes.push(1); // Revision
    bytes.push(0); // Checksum placeholder at 9
    bytes.extend_from_slice(b"KASHOS"); // OEM ID (6 bytes)
    bytes.extend_from_slice(b"KASHVTD "); // OEM Table ID (8 bytes)
    bytes.extend_from_slice(&1u32.to_le_bytes()); // OEM Revision
    bytes.extend_from_slice(b"KASH"); // Creator ID (4 bytes)
    bytes.extend_from_slice(&1u32.to_le_bytes()); // Creator Revision

    // 2. DMAR Fields (12 bytes, offset 36..48)
    bytes.push(38); // Host Address Width (38 + 1 = 39-bit)
    bytes.push(0x01); // Flags (INTR_REMAP = 1)
    bytes.extend_from_slice(&[0u8; 10]); // Reserved

    // 3. DRHD Structure (Type 0)
    let drhd_start = bytes.len();
    bytes.extend_from_slice(&0x0000u16.to_le_bytes()); // Type = DRHD
    bytes.extend_from_slice(&[0u8; 2]); // Length placeholder at offset + 2
    bytes.push(if include_all { 1 } else { 0 }); // Flags: INCLUDE_PCI_ALL
    bytes.push(0); // Reserved
    bytes.extend_from_slice(&0u16.to_le_bytes()); // Segment = 0
    bytes.extend_from_slice(&drhd_base.to_le_bytes()); // Register Base Address (64-bit)

    // Device Scope for DRHD (e.g. IOAPIC at 00:14.0)
    bytes.push(3); // Scope Type = IOAPIC
    bytes.push(8); // Scope Length = 8
    bytes.extend_from_slice(&[0u8; 2]); // Reserved
    bytes.push(2); // Enumeration ID
    bytes.push(0); // Start Bus
    bytes.push(20); // Dev = 20
    bytes.push(0); // Func = 0

    let drhd_len = (bytes.len() - drhd_start) as u16;
    bytes[drhd_start + 2..drhd_start + 4].copy_from_slice(&drhd_len.to_le_bytes());

    // 4. RMRR Structure (Type 1)
    let rmrr_start = bytes.len();
    bytes.extend_from_slice(&0x0001u16.to_le_bytes()); // Type = RMRR
    bytes.extend_from_slice(&[0u8; 2]); // Length placeholder
    bytes.extend_from_slice(&[0u8; 2]); // Reserved
    bytes.extend_from_slice(&0u16.to_le_bytes()); // Segment = 0
    bytes.extend_from_slice(&0x000E_0000u64.to_le_bytes()); // Base Address
    bytes.extend_from_slice(&0x000E_FFFFu64.to_le_bytes()); // Limit Address

    // Device Scope for RMRR (e.g. Legacy USB at 00:1D.0)
    bytes.push(1); // Scope Type = PCI Endpoint
    bytes.push(8); // Scope Length = 8
    bytes.extend_from_slice(&[0u8; 2]); // Reserved
    bytes.push(0); // Enumeration ID
    bytes.push(0); // Start Bus
    bytes.push(29); // Dev = 29
    bytes.push(0); // Func = 0

    let rmrr_len = (bytes.len() - rmrr_start) as u16;
    bytes[rmrr_start + 2..rmrr_start + 4].copy_from_slice(&rmrr_len.to_le_bytes());

    // Fix up total ACPI table length
    let total_len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&total_len.to_le_bytes());

    // Calculate valid ACPI checksum (sum of all bytes == 0 mod 256)
    let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    let checksum = (0u8).wrapping_sub(sum);
    bytes[9] = checksum;

    bytes
}

#[test]
fn test_acpi_dmar_parser_valid_table() {
    let dmar_bytes = build_test_dmar_bytes(0xFED9_0000, true);
    let parsed = parse_dmar_bytes(&dmar_bytes).expect("Valid DMAR should parse cleanly");

    assert_eq!(parsed.haw, 39);
    assert!(parsed.intr_remap);
    assert!(!parsed.x2apic_opt_out);

    assert_eq!(parsed.drhd_units.len(), 1);
    let drhd = &parsed.drhd_units[0];
    assert!(drhd.include_pci_all);
    assert_eq!(drhd.segment, 0);
    assert_eq!(drhd.register_base, 0xFED9_0000);
    assert_eq!(drhd.device_scopes.len(), 1);
    assert_eq!(drhd.device_scopes[0].scope_type, 3); // IOAPIC
    assert_eq!(drhd.device_scopes[0].dev, 20);
    assert_eq!(drhd.device_scopes[0].func, 0);

    assert_eq!(parsed.rmrr_regions.len(), 1);
    let rmrr = &parsed.rmrr_regions[0];
    assert_eq!(rmrr.base_address, 0x000E_0000);
    assert_eq!(rmrr.limit_address, 0x000E_FFFF);
    assert_eq!(rmrr.device_scopes.len(), 1);
    assert_eq!(rmrr.device_scopes[0].scope_type, 1); // Endpoint
    assert_eq!(rmrr.device_scopes[0].dev, 29);
}

#[test]
fn test_acpi_dmar_parser_rejects_corrupted_tables() {
    // 1. Too short
    assert!(parse_dmar_bytes(&[0u8; 32]).is_err());

    // 2. Bad signature
    let mut bad_sig = build_test_dmar_bytes(0xFED9_0000, true);
    bad_sig[0] = b'X';
    assert!(parse_dmar_bytes(&bad_sig).is_err());

    // 3. Bad checksum
    let mut bad_csum = build_test_dmar_bytes(0xFED9_0000, true);
    bad_csum[9] ^= 0xFF;
    assert!(parse_dmar_bytes(&bad_csum).is_err());

    // 4. Truncated length header
    let mut bad_len = build_test_dmar_bytes(0xFED9_0000, true);
    bad_len[4] = 0xFF;
    bad_len[5] = 0xFF;
    assert!(parse_dmar_bytes(&bad_len).is_err());
}

#[test]
fn test_vtd_root_and_context_entry_bitfields() {
    let mut root = VtdRootEntry::default();
    assert!(!root.is_present());
    root.set_context_table(0x1234_5000);
    assert!(root.is_present());
    assert_eq!(root.context_table_addr(), 0x1234_5000);

    let mut ctx = VtdContextEntry::default();
    assert!(!ctx.is_present());
    ctx.set_translation(0x5678_9000, 42, true);
    assert!(ctx.is_present());
    assert_eq!(ctx.slpt_root_addr(), 0x5678_9000);
    assert_eq!(ctx.domain_id(), 42);
}

#[test]
fn test_slpt_entry_descriptors() {
    let leaf_rw = SlptEntry::new_leaf(0x8000_1000, true, true);
    assert!(leaf_rw.is_present());
    assert!(leaf_rw.has_read());
    assert!(leaf_rw.has_write());
    assert!(!leaf_rw.is_superpage());
    assert_eq!(leaf_rw.phys_addr(), 0x8000_1000);

    let leaf_ro = SlptEntry::new_leaf(0x9000_2000, true, false);
    assert!(leaf_ro.is_present());
    assert!(leaf_ro.has_read());
    assert!(!leaf_ro.has_write());

    let superpage = SlptEntry::new_superpage(0xA000_0000, true, true);
    assert!(superpage.is_present());
    assert!(superpage.is_superpage());

    let table = SlptEntry::new_table(0x4000_1000);
    assert!(table.is_present());
    assert!(!table.is_superpage());
}

#[test]
fn test_slpt_page_table_4level_translation_and_dma_containment() {
    let mut slpt = SlptPageTable::new();
    let bdf_nic = PciBdf::new(0, 3, 0);
    let domain_id = 1u16;

    // 1. Map legitimate DMA buffer: 8 KiB at 0x1000_0000 -> 0x2000_0000 (Read/Write)
    slpt.map_dma(bdf_nic, domain_id, 0x1000_0000, 0x2000_0000, 8192, true, true).expect("map_dma");

    // 2. Map read-only descriptor ring: 4 KiB at 0x1000_2000 -> 0x2000_2000 (Read Only)
    slpt.map_dma(bdf_nic, domain_id, 0x1000_2000, 0x2000_2000, 4096, true, false).expect("map_dma");

    // 3. Legitimate translation check
    assert_eq!(slpt.translate_dma(bdf_nic, domain_id, 0x1000_0050, true), Ok(0x2000_0050));
    assert_eq!(slpt.translate_dma(bdf_nic, domain_id, 0x1000_1100, false), Ok(0x2000_1100));
    assert_eq!(slpt.translate_dma(bdf_nic, domain_id, 0x1000_2020, false), Ok(0x2000_2020));

    // 4. Negative Check: Rogue write to read-only descriptor ring
    assert_eq!(
        slpt.translate_dma(bdf_nic, domain_id, 0x1000_2000, true),
        Err(VtdFaultReason::WritePermissionViolation)
    );

    // 5. Negative Check: Rogue DMA to unmapped host physical memory (e.g. kernel text 0x0010_0000)
    assert_eq!(
        slpt.translate_dma(bdf_nic, domain_id, 0x0010_0000, true),
        Err(VtdFaultReason::TranslationNotPresent)
    );

    // 6. Negative Check: DMA from unauthorized peripheral (unbound BDF)
    let bdf_unauth = PciBdf::new(0, 31, 0);
    assert_eq!(
        slpt.translate_dma(bdf_unauth, domain_id, 0x1000_0000, false),
        Err(VtdFaultReason::TranslationNotPresent)
    );

    // 7. Unmap buffer and verify translation drops immediately
    slpt.unmap_dma(bdf_nic, 0x1000_0000, 4096).expect("unmap_dma");
    assert_eq!(
        slpt.translate_dma(bdf_nic, domain_id, 0x1000_0050, true),
        Err(VtdFaultReason::TranslationNotPresent)
    );
}
