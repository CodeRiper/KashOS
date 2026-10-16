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

// ── Anti-Evil Maid / Measured Boot Attestation ───────────────────────────────

/// Verifies that the kernel executable hash matches the expected PCR measurement.
pub fn verify_measured_boot_hash(actual_hash: &[u8; 32], expected_hash: &[u8; 32]) -> bool {
    // Constant-time comparison to prevent timing side channels
    let mut diff = 0u8;
    for (a, b) in actual_hash.iter().zip(expected_hash.iter()) {
        diff |= a ^ b;
    }
    diff == 0
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
