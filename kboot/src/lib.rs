//! kboot — Dual UEFI & BIOS Secure Bootloader Protocol for KashOS.
//!
//! Provides bare-metal boot abstractions and handoff structures for:
//! 1. Modern UEFI systems: PE32+ (BOOTX64.EFI), GOP framebuffer, UEFI memory map,
//!    ExitBootServices handoff, Anti-Evil Maid measured boot PCR attestation.
//! 2. Vintage BIOS systems: MBR stage 1 sector (0xAA55 signature), Multiboot2, PVH.
//! 3. Unified `KashBootInfo` handoff protocol to the microkernel.
#![no_std]

#[cfg(test)]
extern crate std;

/// Unique 64-bit magic identifying KashBootInfo handoff ("KASHOSBO").
pub const KASH_BOOT_MAGIC: u64 = 0x4B41_5348_4F53_424F;

/// Bootloader architecture source.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSource {
    BiosMbr = 1,
    BiosMultiboot2 = 2,
    XenPvh = 3,
    Uefi = 4,
}

/// Graphics framebuffer information passed from bootloader (UEFI GOP or VBE).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferInfo {
    pub base_paddr: u64,
    pub size_bytes: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bits_per_pixel: u8,
    pub red_mask_size: u8,
    pub green_mask_size: u8,
    pub blue_mask_size: u8,
}

impl FramebufferInfo {
    pub const EMPTY: Self = Self {
        base_paddr: 0,
        size_bytes: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bits_per_pixel: 0,
        red_mask_size: 0,
        green_mask_size: 0,
        blue_mask_size: 0,
    };

    pub fn is_valid(&self) -> bool {
        self.base_paddr != 0 && self.width > 0 && self.height > 0
    }
}

/// Unified boot descriptor passed from bootloader into `kmain`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KashBootInfo {
    pub magic: u64,
    pub boot_source: BootSource,
    pub acpi_rsdp_paddr: u64,
    pub framebuffer: FramebufferInfo,
    pub measured_kernel_hash: [u8; 32],
    pub memory_map_paddr: u64,
    pub memory_map_entries: u32,
    pub smbios_paddr: u64,
}

impl KashBootInfo {
    pub const fn new(boot_source: BootSource) -> Self {
        Self {
            magic: KASH_BOOT_MAGIC,
            boot_source,
            acpi_rsdp_paddr: 0,
            framebuffer: FramebufferInfo::EMPTY,
            measured_kernel_hash: [0u8; 32],
            memory_map_paddr: 0,
            memory_map_entries: 0,
            smbios_paddr: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.magic == KASH_BOOT_MAGIC
    }
}

// ── UEFI Protocol Definitions ────────────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfiMemoryType {
    ReservedMemoryType = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    ACPIReclaimMemory = 9,
    ACPIMemoryNVS = 10,
    MemoryMappedIO = 11,
    MemoryMappedIOPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    MaxMemoryType = 15,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub mem_type: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl EfiMemoryDescriptor {
    pub fn is_usable_ram(&self) -> bool {
        self.mem_type == EfiMemoryType::ConventionalMemory as u32
            || self.mem_type == EfiMemoryType::LoaderCode as u32
            || self.mem_type == EfiMemoryType::LoaderData as u32
            || self.mem_type == EfiMemoryType::BootServicesCode as u32
            || self.mem_type == EfiMemoryType::BootServicesData as u32
    }

    pub fn size_bytes(&self) -> u64 {
        self.number_of_pages * 4096
    }
}

// ── BIOS MBR Sector Definitions ──────────────────────────────────────────────

pub const MBR_SIGNATURE: u16 = 0xAA55;
pub const MBR_BOOTSTRAP_SIZE: usize = 446;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartitionEntry {
    pub status: u8,
    pub chs_first_abs: [u8; 3],
    pub partition_type: u8,
    pub chs_last_abs: [u8; 3],
    pub lba_first: u32,
    pub sector_count: u32,
}

#[repr(C, packed)]
pub struct MbrSector {
    pub bootstrap_code: [u8; MBR_BOOTSTRAP_SIZE],
    pub partitions: [MbrPartitionEntry; 4],
    pub signature: u16,
}

impl MbrSector {
    pub fn is_valid(&self) -> bool {
        self.signature == MBR_SIGNATURE
    }
}

// ── PE32+ (UEFI Executable) Definitions ──────────────────────────────────────

pub const PE_DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const PE32PLUS_OPTIONAL_HEADER_MAGIC: u16 = 0x020B;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PeDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32, // Offset to PE Header
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PeCoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PeOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PeSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// Validates that a raw binary buffer represents a valid PE32+ (x86_64 UEFI) executable.
pub fn validate_pe32plus_binary(data: &[u8]) -> Result<(u32, u64), &'static str> {
    if data.len() < core::mem::size_of::<PeDosHeader>() {
        return Err("Binary too small for DOS header");
    }

    let dos = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const PeDosHeader) };
    if dos.e_magic != PE_DOS_MAGIC {
        return Err("Invalid DOS magic (expected MZ)");
    }

    let pe_offset = dos.e_lfanew as usize;
    if pe_offset + 4 + core::mem::size_of::<PeCoffHeader>() + core::mem::size_of::<PeOptionalHeader64>() > data.len() {
        return Err("PE header offset out of bounds");
    }

    let pe_sig = unsafe { core::ptr::read_unaligned(data.as_ptr().add(pe_offset) as *const u32) };
    if pe_sig != PE_SIGNATURE {
        return Err("Invalid PE signature (expected PE\\0\\0)");
    }

    let coff = unsafe {
        core::ptr::read_unaligned(data.as_ptr().add(pe_offset + 4) as *const PeCoffHeader)
    };
    // Machine 0x8664 is IMAGE_FILE_MACHINE_AMD64
    if coff.machine != 0x8664 {
        return Err("Unsupported PE machine type (expected x86_64)");
    }

    let opt = unsafe {
        core::ptr::read_unaligned(data.as_ptr().add(pe_offset + 4 + core::mem::size_of::<PeCoffHeader>()) as *const PeOptionalHeader64)
    };
    if opt.magic != PE32PLUS_OPTIONAL_HEADER_MAGIC {
        return Err("Invalid optional header magic (expected PE32+)");
    }

    Ok((opt.address_of_entry_point, opt.image_base))
}

// ── TCG PC Client TPM 2.0 PCR Definitions ───────────────────────────────────

/// Core Root of Trust for Measurement (CRTM), BIOS / UEFI firmware code.
pub const PCR_CRTM_FIRMWARE: usize = 0;
/// Platform hardware configuration (SMBIOS, ACPI tables).
pub const PCR_HARDWARE_CONFIG: usize = 1;
/// Bootloader code and options (`kboot`, EFI boot application).
pub const PCR_BOOTLOADER: usize = 2;
/// Boot options and parameter state.
pub const PCR_BOOT_OPTIONS: usize = 3;
/// Microkernel executable code measurement.
pub const PCR_KERNEL_CODE: usize = 4;
/// Initial Program Load (IPL) partition and filesystem metadata.
pub const PCR_IPL_PARTITION: usize = 5;
/// Power state transitions and wake events.
pub const PCR_STATE_TRANSITION: usize = 6;
/// Secure Boot policy, PK, KEK, db, dbx measurement.
pub const PCR_SECURE_BOOT_POLICY: usize = 7;
/// Kernel command line arguments and boot flags.
pub const PCR_COMMAND_LINE: usize = 8;
/// Initial ramdisk, init ELF, and system manifest (`/manifest.toml`).
pub const PCR_MANIFEST_INITRD: usize = 9;

/// Total number of standard hardware PCRs in the TPM 2.0 SHA-256 bank.
pub const PCR_COUNT: usize = 24;

// ── Anti-Evil Maid / Measured Boot Attestation ───────────────────────────────

/// Computes a standard SHA-256 digest over arbitrary binary data.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Verifies that the kernel executable hash matches the expected PCR measurement.
pub fn verify_measured_boot_hash(actual_hash: &[u8; 32], expected_hash: &[u8; 32]) -> bool {
    // Constant-time comparison to prevent timing side channels
    let mut diff = 0u8;
    for (a, b) in actual_hash.iter().zip(expected_hash.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Verifies payload integrity against an expected SHA-256 hash.
pub fn verify_payload_integrity(payload: &[u8], expected_hash: &[u8; 32]) -> bool {
    let actual = compute_sha256(payload);
    verify_measured_boot_hash(&actual, expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kash_boot_info_validity() {
        let mut info = KashBootInfo::new(BootSource::Uefi);
        assert!(info.is_valid());
        assert_eq!(info.boot_source, BootSource::Uefi);

        info.magic = 0xDEADBEEF;
        assert!(!info.is_valid());
    }

    #[test]
    fn test_efi_memory_descriptor_classification() {
        let desc = EfiMemoryDescriptor {
            mem_type: EfiMemoryType::ConventionalMemory as u32,
            pad: 0,
            physical_start: 0x100000,
            virtual_start: 0,
            number_of_pages: 256,
            attribute: 0,
        };
        assert!(desc.is_usable_ram());
        assert_eq!(desc.size_bytes(), 256 * 4096);

        let reserved = EfiMemoryDescriptor {
            mem_type: EfiMemoryType::ReservedMemoryType as u32,
            pad: 0,
            physical_start: 0,
            virtual_start: 0,
            number_of_pages: 16,
            attribute: 0,
        };
        assert!(!reserved.is_usable_ram());
    }

    #[test]
    fn test_measured_boot_constant_time_comparison() {
        let hash1 = [0x42u8; 32];
        let hash2 = [0x42u8; 32];
        let mut hash3 = [0x42u8; 32];
        hash3[31] = 0x43;

        assert!(verify_measured_boot_hash(&hash1, &hash2));
        assert!(!verify_measured_boot_hash(&hash1, &hash3));
    }

    #[test]
    fn test_payload_integrity_sha256() {
        let payload = b"KashOS High-Assurance Verified Kernel Image";
        let hash = compute_sha256(payload);
        assert!(verify_payload_integrity(payload, &hash));

        let mut tampered = payload.to_vec();
        tampered[0] ^= 0x01; // 1-bit tamper
        assert!(!verify_payload_integrity(&tampered, &hash));
    }

    #[test]
    fn test_pe32plus_binary_validation() {
        // Construct minimal valid PE32+ buffer
        let mut buffer = [0u8; 512];
        let dos = buffer.as_mut_ptr() as *mut PeDosHeader;
        unsafe {
            (*dos).e_magic = PE_DOS_MAGIC;
            (*dos).e_lfanew = 128;
            let pe_sig = buffer.as_mut_ptr().add(128) as *mut u32;
            *pe_sig = PE_SIGNATURE;
            let coff = buffer.as_mut_ptr().add(132) as *mut PeCoffHeader;
            (*coff).machine = 0x8664; // AMD64
            (*coff).size_of_optional_header = core::mem::size_of::<PeOptionalHeader64>() as u16;
            let opt = buffer.as_mut_ptr().add(132 + core::mem::size_of::<PeCoffHeader>()) as *mut PeOptionalHeader64;
            (*opt).magic = PE32PLUS_OPTIONAL_HEADER_MAGIC;
            (*opt).address_of_entry_point = 0x1000;
            (*opt).image_base = 0x400000;
        }

        let res = validate_pe32plus_binary(&buffer);
        assert!(res.is_ok());
        let (entry, base) = res.unwrap();
        assert_eq!(entry, 0x1000);
        assert_eq!(base, 0x400000);

        // Tamper with magic
        buffer[0] = 0x00;
        assert!(validate_pe32plus_binary(&buffer).is_err());
    }

    #[test]
    fn test_framebuffer_validity() {
        let mut fb = FramebufferInfo::EMPTY;
        assert!(!fb.is_valid());

        fb.base_paddr = 0xE0000000;
        fb.width = 1920;
        fb.height = 1080;
        fb.pitch = 1920 * 4;
        fb.bits_per_pixel = 32;
        assert!(fb.is_valid());
    }
}
