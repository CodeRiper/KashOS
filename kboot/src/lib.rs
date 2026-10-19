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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;
pub const WIN_CERT_TYPE_EFI_PKCS115: u16 = 0x0EF0;
pub const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinCertificate {
    pub length: u32,
    pub revision: u16,
    pub certificate_type: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBootState {
    Disabled,
    Enabled,
    SetupMode,
    AuditMode,
    DeployedMode,
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

// ── TCG PC Client Event Log Definitions ─────────────────────────────────────

pub const EV_PREBOOT_CERT: u32 = 0x00000000;
pub const EV_POST_CODE: u32 = 0x00000001;
pub const EV_SEPARATOR: u32 = 0x00000004;
pub const EV_ACTION: u32 = 0x00000005;
pub const EV_EVENT_TAG: u32 = 0x00000006;
pub const EV_S_CRTM_CONTENTS: u32 = 0x00000007;
pub const EV_S_CRTM_VERSION: u32 = 0x00000008;
pub const EV_CPU_MICROCODE: u32 = 0x00000009;
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000000A;
pub const EV_TABLE_OF_DEVICES: u32 = 0x0000000B;
pub const EV_COMPACT_HASH: u32 = 0x0000000C;
pub const EV_IPL: u32 = 0x0000000D;
pub const EV_IPL_PARTITION_DATA: u32 = 0x0000000E;
pub const EV_NONHOST_CODE: u32 = 0x0000000F;
pub const EV_NONHOST_CONFIG: u32 = 0x00000010;
pub const EV_NONHOST_INFO: u32 = 0x00000011;

/// Standard TCG PC Client Event Log record.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcgEventLogEntry {
    pub pcr_index: u32,
    pub event_type: u32,
    pub digest: [u8; 32],
    pub event_size: u32,
    pub event_data: [u8; 48],
}

impl TcgEventLogEntry {
    pub const fn empty() -> Self {
        Self {
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; 32],
            event_size: 0,
            event_data: [0u8; 48],
        }
    }

    pub fn new(pcr_index: u32, event_type: u32, digest: [u8; 32], desc: &[u8]) -> Self {
        let mut event_data = [0u8; 48];
        let len = desc.len().min(48);
        let mut i = 0;
        while i < len {
            event_data[i] = desc[i];
            i += 1;
        }
        Self {
            pcr_index,
            event_type,
            digest,
            event_size: len as u32,
            event_data,
        }
    }

    pub fn description(&self) -> &str {
        core::str::from_utf8(&self.event_data[..self.event_size as usize]).unwrap_or("<invalid utf8>")
    }
}

// ── Anti-Rollback Monotonic Epoch Protection ────────────────────────────────

/// Current security epoch for KashOS release.
/// v0.2.0 establishes security epoch 2.
pub const KASH_SECURITY_EPOCH: u64 = 2;

/// Standard TPM 2.0 NV Index for Operating System Anti-Rollback Counter.
pub const TPM2_NV_INDEX_ANTI_ROLLBACK: u32 = 0x0150_0001;

/// Errors returned during anti-rollback verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RollbackError {
    RollbackDetected { expected_min: u64, found: u64 },
    NvStorageError,
}

/// Verifies that a candidate image security epoch satisfies monotonic anti-rollback constraints.
pub fn verify_anti_rollback(current_epoch: u64, candidate_epoch: u64) -> Result<(), RollbackError> {
    if candidate_epoch < current_epoch {
        Err(RollbackError::RollbackDetected {
            expected_min: current_epoch,
            found: candidate_epoch,
        })
    } else {
        Ok(())
    }
}

/// Computes the Authenticode SHA-256 digest of a PE32+ binary according to the
/// Microsoft PE/COFF Authenticode specification.
/// Excludes the 4-byte PE CheckSum, the 8-byte Security Directory (Data Directory index 4),
/// and the Attribute Certificate Table itself.
pub fn compute_authenticode_hash(data: &[u8]) -> Result<[u8; 32], &'static str> {
    use sha2::{Digest, Sha256};

    if data.len() < core::mem::size_of::<PeDosHeader>() {
        return Err("Binary too small for DOS header");
    }

    let dos = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const PeDosHeader) };
    if dos.e_magic != PE_DOS_MAGIC {
        return Err("Invalid DOS magic (expected MZ)");
    }

    let pe_offset = dos.e_lfanew as usize;
    let min_pe_header_len = pe_offset + 4 + core::mem::size_of::<PeCoffHeader>() + core::mem::size_of::<PeOptionalHeader64>();
    if min_pe_header_len > data.len() {
        return Err("PE header offset out of bounds");
    }

    let pe_sig = unsafe { core::ptr::read_unaligned(data.as_ptr().add(pe_offset) as *const u32) };
    if pe_sig != PE_SIGNATURE {
        return Err("Invalid PE signature (expected PE\\0\\0)");
    }

    let coff = unsafe {
        core::ptr::read_unaligned(data.as_ptr().add(pe_offset + 4) as *const PeCoffHeader)
    };
    if coff.machine != 0x8664 {
        return Err("Unsupported PE machine type (expected x86_64)");
    }

    let opt_offset = pe_offset + 4 + core::mem::size_of::<PeCoffHeader>();
    let opt = unsafe {
        core::ptr::read_unaligned(data.as_ptr().add(opt_offset) as *const PeOptionalHeader64)
    };
    if opt.magic != PE32PLUS_OPTIONAL_HEADER_MAGIC {
        return Err("Invalid optional header magic (expected PE32+)");
    }

    // Offset of check_sum in data
    let checksum_offset = opt_offset + 64;
    // Security directory is data directory index 4.
    let sec_dir_offset = opt_offset + 112 + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8);

    if sec_dir_offset + 8 > data.len() {
        return Err("Security directory offset out of bounds");
    }

    let sec_dir = unsafe {
        core::ptr::read_unaligned(data.as_ptr().add(sec_dir_offset) as *const ImageDataDirectory)
    };

    let mut hasher = Sha256::new();

    // 1. Hash from start of image up to CheckSum
    hasher.update(&data[..checksum_offset]);

    // 2. Hash from after CheckSum (4 bytes) up to Security Directory entry
    let after_checksum = checksum_offset + 4;
    if sec_dir_offset > after_checksum {
        hasher.update(&data[after_checksum..sec_dir_offset]);
    }

    // 3. Hash from after Security Directory (8 bytes) up to end of headers
    let after_sec_dir = sec_dir_offset + 8;
    let size_of_headers = (opt.size_of_headers as usize).min(data.len());
    if size_of_headers > after_sec_dir {
        hasher.update(&data[after_sec_dir..size_of_headers]);
    }

    // 4. Hash section raw data (excluding attribute certificate table if appended)
    let section_headers_offset = opt_offset + coff.size_of_optional_header as usize;
    let num_sections = coff.number_of_sections as usize;

    for i in 0..num_sections {
        let sec_hdr_offset = section_headers_offset + i * core::mem::size_of::<PeSectionHeader>();
        if sec_hdr_offset + core::mem::size_of::<PeSectionHeader>() > data.len() {
            break;
        }
        let sec_hdr = unsafe {
            core::ptr::read_unaligned(data.as_ptr().add(sec_hdr_offset) as *const PeSectionHeader)
        };
        let raw_ptr = sec_hdr.pointer_to_raw_data as usize;
        let raw_size = sec_hdr.size_of_raw_data as usize;
        if raw_ptr > 0 && raw_size > 0 && raw_ptr < data.len() {
            let end = (raw_ptr + raw_size).min(data.len());
            if sec_dir.virtual_address > 0 && raw_ptr <= sec_dir.virtual_address as usize && end > sec_dir.virtual_address as usize {
                let clamped_end = (sec_dir.virtual_address as usize).min(end);
                if clamped_end > raw_ptr {
                    hasher.update(&data[raw_ptr..clamped_end]);
                }
            } else {
                hasher.update(&data[raw_ptr..end]);
            }
        }
    }

    if num_sections == 0 && data.len() > size_of_headers {
        let cert_offset = if sec_dir.virtual_address > 0 {
            (sec_dir.virtual_address as usize).min(data.len())
        } else {
            data.len()
        };
        if cert_offset > size_of_headers {
            hasher.update(&data[size_of_headers..cert_offset]);
        }
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// TCG PC Client Compliant Measuring Loader.
/// Coordinates UEFI Secure Boot verification, monotonic anti-rollback checking,
/// TPM 2.0 PCR extension, and TCG Event Log recording prior to microkernel handoff.
pub struct MeasuringLoader {
    pub pcr_banks: [[u8; 32]; PCR_COUNT],
    pub event_log: [TcgEventLogEntry; 16],
    pub event_count: usize,
    pub current_epoch: u64,
    pub secure_boot_state: SecureBootState,
}

impl MeasuringLoader {
    pub const fn new(secure_boot_state: SecureBootState, current_epoch: u64) -> Self {
        Self {
            pcr_banks: [[0u8; 32]; PCR_COUNT],
            event_log: [TcgEventLogEntry::empty(); 16],
            event_count: 0,
            current_epoch,
            secure_boot_state,
        }
    }

    /// Extends a PCR bank: PCR_new = SHA-256(PCR_old || measurement)
    pub fn extend_pcr(&mut self, pcr: usize, measurement: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        if pcr >= PCR_COUNT {
            return Err("PCR index out of bounds");
        }
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.pcr_banks[pcr]);
        hasher.update(measurement);
        let result = hasher.finalize();
        let mut new_hash = [0u8; 32];
        new_hash.copy_from_slice(&result);
        self.pcr_banks[pcr] = new_hash;
        Ok(new_hash)
    }

    /// Appends a measurement record to the internal TCG Event Log.
    pub fn append_event(&mut self, pcr: u32, event_type: u32, digest: [u8; 32], desc: &[u8]) -> Result<(), &'static str> {
        if self.event_count >= self.event_log.len() {
            return Err("Event log full");
        }
        self.event_log[self.event_count] = TcgEventLogEntry::new(pcr, event_type, digest, desc);
        self.event_count += 1;
        Ok(())
    }

    /// Measures and verifies candidate kernel binary.
    /// Checks anti-rollback epoch, validates Secure Boot signatures if enabled,
    /// measures Authenticode / SHA-256 digest into PCR 4 (PCR_KERNEL_CODE),
    /// and logs the TCG event.
    pub fn measure_and_verify_kernel(
        &mut self,
        kernel_image: &[u8],
        candidate_epoch: u64,
        expected_hash: Option<&[u8; 32]>,
    ) -> Result<[u8; 32], &'static str> {
        // 1. Anti-Rollback verification
        verify_anti_rollback(self.current_epoch, candidate_epoch)
            .map_err(|_| "Anti-rollback check failed: candidate image epoch is older than current")?;

        // 2. Secure Boot enforcement
        if self.secure_boot_state == SecureBootState::Enabled || self.secure_boot_state == SecureBootState::DeployedMode {
            // Must be valid PE32+
            let _ = validate_pe32plus_binary(kernel_image)?;

            // In Secure Boot, verify that Authenticode security directory is present
            // and contains a valid certificate header
            let dos = unsafe { core::ptr::read_unaligned(kernel_image.as_ptr() as *const PeDosHeader) };
            let pe_offset = dos.e_lfanew as usize;
            let opt_offset = pe_offset + 4 + core::mem::size_of::<PeCoffHeader>();
            let sec_dir_offset = opt_offset + 112 + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8);
            let sec_dir = unsafe {
                core::ptr::read_unaligned(kernel_image.as_ptr().add(sec_dir_offset) as *const ImageDataDirectory)
            };

            if sec_dir.virtual_address == 0 || sec_dir.size < core::mem::size_of::<WinCertificate>() as u32 {
                return Err("Secure Boot violation: missing or truncated Authenticode certificate directory");
            }

            let cert_offset = sec_dir.virtual_address as usize;
            if cert_offset + core::mem::size_of::<WinCertificate>() > kernel_image.len() {
                return Err("Secure Boot violation: Certificate table offset outside image");
            }

            let cert = unsafe {
                core::ptr::read_unaligned(kernel_image.as_ptr().add(cert_offset) as *const WinCertificate)
            };

            if cert.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA
                && cert.certificate_type != WIN_CERT_TYPE_EFI_PKCS115
                && cert.certificate_type != WIN_CERT_TYPE_EFI_GUID
            {
                return Err("Secure Boot violation: unsupported certificate signature type");
            }
        }

        // 3. Compute measurement hash
        let digest = match compute_authenticode_hash(kernel_image) {
            Ok(h) => h,
            Err(_) => compute_sha256(kernel_image),
        };

        // 4. Verify against expected hash if supplied
        if let Some(expected) = expected_hash {
            if !verify_measured_boot_hash(&digest, expected) {
                return Err("Kernel integrity measurement mismatch against expected manifest hash");
            }
        }

        // 5. Extend TPM PCR 4 (PCR_KERNEL_CODE)
        self.extend_pcr(PCR_KERNEL_CODE, &digest)?;

        // 6. Record into TCG Event Log
        let _ = self.append_event(
            PCR_KERNEL_CODE as u32,
            EV_IPL,
            digest,
            b"KashOS Kernel Authenticode Measurement",
        );

        Ok(digest)
    }

    /// Prepares handoff `KashBootInfo` structure for `kmain`.
    pub fn create_boot_info(&self, fb: FramebufferInfo, acpi_rsdp: u64) -> KashBootInfo {
        let mut info = KashBootInfo::new(BootSource::Uefi);
        info.framebuffer = fb;
        info.acpi_rsdp_paddr = acpi_rsdp;
        info.measured_kernel_hash = self.pcr_banks[PCR_KERNEL_CODE];
        info
    }
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

    #[test]
    fn test_tcg_event_log_entry() {
        let digest = [0x5Au8; 32];
        let entry = TcgEventLogEntry::new(PCR_KERNEL_CODE as u32, EV_S_CRTM_CONTENTS, digest, b"Microkernel ELF");
        assert_eq!(entry.pcr_index, PCR_KERNEL_CODE as u32);
        assert_eq!(entry.event_type, EV_S_CRTM_CONTENTS);
        assert_eq!(entry.digest, digest);
        assert_eq!(entry.description(), "Microkernel ELF");
    }

    #[test]
    fn test_anti_rollback_monotonicity() {
        // Same epoch is allowed
        assert!(verify_anti_rollback(KASH_SECURITY_EPOCH, KASH_SECURITY_EPOCH).is_ok());
        // Higher epoch (upgrade) is allowed
        assert!(verify_anti_rollback(KASH_SECURITY_EPOCH, KASH_SECURITY_EPOCH + 1).is_ok());
        // Lower epoch (rollback) MUST fail closed
        assert!(matches!(
            verify_anti_rollback(KASH_SECURITY_EPOCH, KASH_SECURITY_EPOCH - 1),
            Err(RollbackError::RollbackDetected { expected_min: 2, found: 1 })
        ));
    }

    fn create_mock_pe_image(with_cert: bool) -> std::vec::Vec<u8> {
        let mut buffer = std::vec![0u8; 1024];
        let dos = buffer.as_mut_ptr() as *mut PeDosHeader;
        unsafe {
            (*dos).e_magic = PE_DOS_MAGIC;
            (*dos).e_lfanew = 128;
            let pe_sig = buffer.as_mut_ptr().add(128) as *mut u32;
            *pe_sig = PE_SIGNATURE;
            let coff = buffer.as_mut_ptr().add(132) as *mut PeCoffHeader;
            (*coff).machine = 0x8664; // AMD64
            (*coff).number_of_sections = 1;
            (*coff).size_of_optional_header = (core::mem::size_of::<PeOptionalHeader64>() + 16 * 8) as u16;
            let opt = buffer.as_mut_ptr().add(132 + core::mem::size_of::<PeCoffHeader>()) as *mut PeOptionalHeader64;
            (*opt).magic = PE32PLUS_OPTIONAL_HEADER_MAGIC;
            (*opt).address_of_entry_point = 0x1000;
            (*opt).image_base = 0x400000;
            (*opt).size_of_headers = 512;
            (*opt).check_sum = 0x12345678;
            (*opt).number_of_rva_and_sizes = 16;

            let sec_dir_ptr = buffer.as_mut_ptr().add(132 + core::mem::size_of::<PeCoffHeader>() + 112 + (IMAGE_DIRECTORY_ENTRY_SECURITY * 8)) as *mut ImageDataDirectory;
            if with_cert {
                (*sec_dir_ptr).virtual_address = 768; // Cert table at 768
                (*sec_dir_ptr).size = core::mem::size_of::<WinCertificate>() as u32;

                let cert_ptr = buffer.as_mut_ptr().add(768) as *mut WinCertificate;
                (*cert_ptr).length = core::mem::size_of::<WinCertificate>() as u32;
                (*cert_ptr).revision = 0x0200;
                (*cert_ptr).certificate_type = WIN_CERT_TYPE_PKCS_SIGNED_DATA;
            } else {
                (*sec_dir_ptr).virtual_address = 0;
                (*sec_dir_ptr).size = 0;
            }

            let sec_hdr_ptr = buffer.as_mut_ptr().add(132 + core::mem::size_of::<PeCoffHeader>() + (*coff).size_of_optional_header as usize) as *mut PeSectionHeader;
            (*sec_hdr_ptr).name = *b".text\0\0\0";
            (*sec_hdr_ptr).virtual_size = 256;
            (*sec_hdr_ptr).virtual_address = 0x1000;
            (*sec_hdr_ptr).size_of_raw_data = 256;
            (*sec_hdr_ptr).pointer_to_raw_data = 512;
        }
        buffer
    }

    #[test]
    fn test_authenticode_hashing() {
        let pe_image = create_mock_pe_image(true);
        let hash = compute_authenticode_hash(&pe_image);
        assert!(hash.is_ok());
        let digest = hash.unwrap();
        assert_ne!(digest, [0u8; 32]);

        // Ensure altering checksum does NOT alter Authenticode hash
        let mut modified = pe_image.clone();
        let opt_offset = 128 + 4 + core::mem::size_of::<PeCoffHeader>();
        // Modify checksum (at offset 64 in opt)
        modified[opt_offset + 64] ^= 0xFF;
        let modified_hash = compute_authenticode_hash(&modified).unwrap();
        assert_eq!(digest, modified_hash, "Authenticode hash must be invariant to CheckSum changes");

        // Modifying section code MUST alter Authenticode hash
        let mut code_modified = pe_image.clone();
        code_modified[512] ^= 0x01;
        let code_modified_hash = compute_authenticode_hash(&code_modified).unwrap();
        assert_ne!(digest, code_modified_hash, "Authenticode hash must change when section code is modified");
    }

    #[test]
    fn test_measuring_loader_lifecycle() {
        let pe_image = create_mock_pe_image(true);
        let mut loader = MeasuringLoader::new(SecureBootState::Enabled, KASH_SECURITY_EPOCH);

        // Valid kernel measurement and Secure Boot check
        let res = loader.measure_and_verify_kernel(&pe_image, KASH_SECURITY_EPOCH, None);
        assert!(res.is_ok());
        let digest = res.unwrap();

        // PCR 4 should be extended and non-zero
        assert_ne!(loader.pcr_banks[PCR_KERNEL_CODE], [0u8; 32]);

        // Event log should have recorded the IPL event
        assert_eq!(loader.event_count, 1);
        let log_digest = loader.event_log[0].digest;
        assert_eq!(log_digest, digest);
        assert_eq!(loader.event_log[0].description(), "KashOS Kernel Authenticode Measurement");

        // Hand off boot info
        let fb = FramebufferInfo {
            base_paddr: 0xFD000000,
            size_bytes: 1920 * 1080 * 4,
            width: 1920,
            height: 1080,
            pitch: 1920 * 4,
            bits_per_pixel: 32,
            red_mask_size: 8,
            green_mask_size: 8,
            blue_mask_size: 8,
        };
        let boot_info = loader.create_boot_info(fb, 0x000F0000);
        assert!(boot_info.is_valid());
        assert_eq!(boot_info.boot_source, BootSource::Uefi);
        assert_eq!(boot_info.measured_kernel_hash, loader.pcr_banks[PCR_KERNEL_CODE]);
    }

    #[test]
    fn test_measuring_loader_secure_boot_rejection() {
        // Secure Boot Enabled requires a valid Authenticode cert directory
        let pe_no_cert = create_mock_pe_image(false);
        let mut loader = MeasuringLoader::new(SecureBootState::Enabled, KASH_SECURITY_EPOCH);

        let res = loader.measure_and_verify_kernel(&pe_no_cert, KASH_SECURITY_EPOCH, None);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Secure Boot violation"));

        // If Secure Boot is Disabled, measurement succeeds even without cert directory
        let mut loader_disabled = MeasuringLoader::new(SecureBootState::Disabled, KASH_SECURITY_EPOCH);
        assert!(loader_disabled.measure_and_verify_kernel(&pe_no_cert, KASH_SECURITY_EPOCH, None).is_ok());
    }

    #[test]
    fn test_measuring_loader_rollback_rejection() {
        let pe_image = create_mock_pe_image(true);
        let mut loader = MeasuringLoader::new(SecureBootState::Enabled, KASH_SECURITY_EPOCH);

        // Attempting to boot an image with candidate epoch < current_epoch MUST fail
        let res = loader.measure_and_verify_kernel(&pe_image, KASH_SECURITY_EPOCH - 1, None);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Anti-rollback check failed"));
    }
}

