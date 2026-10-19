//! MBR and GPT Partition Table Parser and Disk Layout Engine
//!
//! Master Engineering Plan Task A12:
//! - Authoritative disk layout:
//!   - Partition 1: ESP (FAT32, EFI System Partition)
//!   - Partition 2: Boot (Kernel, read-only measured)
//!   - Partition 3: kvault Encrypted Root Pool (XChaCha20-Poly1305)
//! - Supports MBR (Master Boot Record) and GPT (GUID Partition Table)
//! - Binds KBlockDeviceAdapter dynamically to partition boundaries

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use crate::{BlockError, PersistentBlockDriver, SECTOR_SIZE};

/// Well-known GPT Partition Type GUIDs (in mixed-endian binary layout)
pub const GUID_ESP: [u8; 16] = [
    0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
]; // C12A7328-F81F-11D2-BA4B-00A0C93EC93B
pub const GUID_LINUX_DATA: [u8; 16] = [
    0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4,
]; // 0FC63DAF-8483-4772-8E79-3D69D8477DE4
pub const GUID_KASH_BOOT: [u8; 16] = [
    0x66, 0x83, 0xC0, 0x0B, 0x74, 0xD5, 0xF1, 0x45, 0x96, 0x24, 0xE4, 0x47, 0x6D, 0x30, 0x46, 0xB7,
]; // 0BC08366-D574-45F1-9624-E4476D3046B7
pub const GUID_KASH_VAULT: [u8; 16] = [
    0x0D, 0xE3, 0x47, 0x83, 0x4B, 0x29, 0x2A, 0x4B, 0x89, 0xA5, 0x7A, 0x4C, 0xB2, 0xF5, 0xE5, 0xA2,
]; // 8347E30D-294B-4B2A-89A5-7A4CB2F5E5A2

pub const MBR_TYPE_GPT_PROTECTIVE: u8 = 0xEE;
pub const MBR_TYPE_ESP: u8 = 0xEF;
pub const MBR_TYPE_LINUX: u8 = 0x83;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionScheme {
    Mbr,
    Gpt,
    RawDisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionRole {
    Esp,
    Boot,
    VaultRoot,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskPartition {
    pub partition_number: u32,
    pub scheme: PartitionScheme,
    pub role: PartitionRole,
    pub start_lba: u64,
    pub sector_count: u64,
}

impl DiskPartition {
    pub fn end_lba(&self) -> u64 {
        if self.sector_count == 0 {
            self.start_lba
        } else {
            self.start_lba + self.sector_count - 1
        }
    }

    pub fn contains_lba(&self, lba: u64) -> bool {
        lba >= self.start_lba && lba <= self.end_lba()
    }
}

/// Computes standard IEEE 802.3 CRC-32 (polynomial 0xEDB88320)
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = -((crc & 1) as i32) as u32;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Parses standard MBR partition table from Sector 0 (512 bytes)
pub fn parse_mbr(sector0: &[u8; SECTOR_SIZE]) -> Option<Vec<DiskPartition>> {
    // Check boot signature 0x55, 0xAA at offsets 510..512
    if sector0[510] != 0x55 || sector0[511] != 0xAA {
        return None;
    }

    // Check if this is a protective MBR for GPT
    for i in 0..4 {
        let offset = 446 + i * 16;
        let part_type = sector0[offset + 4];
        if part_type == MBR_TYPE_GPT_PROTECTIVE {
            return None; // Caller should parse GPT
        }
    }

    let mut partitions = Vec::new();
    for i in 0..4 {
        let offset = 446 + i * 16;
        let part_type = sector0[offset + 4];
        if part_type == 0x00 {
            continue; // Empty entry
        }

        let start_lba = u32::from_le_bytes([
            sector0[offset + 8],
            sector0[offset + 9],
            sector0[offset + 10],
            sector0[offset + 11],
        ]) as u64;

        let sector_count = u32::from_le_bytes([
            sector0[offset + 12],
            sector0[offset + 13],
            sector0[offset + 14],
            sector0[offset + 15],
        ]) as u64;

        if sector_count == 0 {
            continue;
        }

        let part_num = (i + 1) as u32;
        let role = match part_type {
            MBR_TYPE_ESP => PartitionRole::Esp,
            MBR_TYPE_LINUX => {
                if part_num == 1 {
                    PartitionRole::Esp
                } else if part_num == 2 {
                    PartitionRole::Boot
                } else if part_num == 3 {
                    PartitionRole::VaultRoot
                } else {
                    PartitionRole::Data
                }
            }
            _ => PartitionRole::Unknown,
        };

        partitions.push(DiskPartition {
            partition_number: part_num,
            scheme: PartitionScheme::Mbr,
            role,
            start_lba,
            sector_count,
        });
    }

    if partitions.is_empty() {
        None
    } else {
        Some(partitions)
    }
}

/// GPT Header structure representation
#[derive(Debug, Clone)]
pub struct GptHeader {
    pub current_lba: u64,
    pub backup_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entries_lba: u64,
    pub num_partition_entries: u32,
    pub partition_entry_size: u32,
    pub partition_array_crc32: u32,
}

/// Parses and validates GPT Header at Sector 1 (512 bytes)
pub fn parse_gpt_header(sector1: &[u8; SECTOR_SIZE]) -> Option<GptHeader> {
    // Magic: "EFI PART" (0x5452415020494645)
    if &sector1[0..8] != b"EFI PART" {
        return None;
    }

    let header_size = u32::from_le_bytes([sector1[12], sector1[13], sector1[14], sector1[15]]) as usize;
    if header_size < 92 || header_size > SECTOR_SIZE {
        return None;
    }

    let stored_crc = u32::from_le_bytes([sector1[16], sector1[17], sector1[18], sector1[19]]);
    
    // Verify header CRC32 with CRC field zeroed
    let mut header_copy = [0u8; SECTOR_SIZE];
    header_copy[..header_size].copy_from_slice(&sector1[..header_size]);
    header_copy[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let computed_crc = crc32(&header_copy[..header_size]);
    if computed_crc != stored_crc {
        return None;
    }

    let current_lba = u64::from_le_bytes([
        sector1[24], sector1[25], sector1[26], sector1[27],
        sector1[28], sector1[29], sector1[30], sector1[31],
    ]);
    let backup_lba = u64::from_le_bytes([
        sector1[32], sector1[33], sector1[34], sector1[35],
        sector1[36], sector1[37], sector1[38], sector1[39],
    ]);
    let first_usable_lba = u64::from_le_bytes([
        sector1[40], sector1[41], sector1[42], sector1[43],
        sector1[44], sector1[45], sector1[46], sector1[47],
    ]);
    let last_usable_lba = u64::from_le_bytes([
        sector1[48], sector1[49], sector1[50], sector1[51],
        sector1[52], sector1[53], sector1[54], sector1[55],
    ]);

    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&sector1[56..72]);

    let partition_entries_lba = u64::from_le_bytes([
        sector1[72], sector1[73], sector1[74], sector1[75],
        sector1[76], sector1[77], sector1[78], sector1[79],
    ]);
    let num_partition_entries = u32::from_le_bytes([
        sector1[80], sector1[81], sector1[82], sector1[83],
    ]);
    let partition_entry_size = u32::from_le_bytes([
        sector1[84], sector1[85], sector1[86], sector1[87],
    ]);
    let partition_array_crc32 = u32::from_le_bytes([
        sector1[88], sector1[89], sector1[90], sector1[91],
    ]);

    Some(GptHeader {
        current_lba,
        backup_lba,
        first_usable_lba,
        last_usable_lba,
        disk_guid,
        partition_entries_lba,
        num_partition_entries,
        partition_entry_size,
        partition_array_crc32,
    })
}

/// Parses GPT Partition Entry array and classifies partition roles
pub fn parse_gpt_entries(
    entries_bytes: &[u8],
    num_entries: usize,
    entry_size: usize,
) -> Vec<DiskPartition> {
    let mut partitions = Vec::new();
    if entry_size < 128 {
        return partitions;
    }

    for i in 0..num_entries {
        let offset = i * entry_size;
        if offset + entry_size > entries_bytes.len() {
            break;
        }

        let entry = &entries_bytes[offset..offset + entry_size];
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&entry[0..16]);

        // Unused partition entry has an all-zero type GUID
        if type_guid == [0u8; 16] {
            continue;
        }

        let start_lba = u64::from_le_bytes([
            entry[32], entry[33], entry[34], entry[35],
            entry[36], entry[37], entry[38], entry[39],
        ]);
        let end_lba = u64::from_le_bytes([
            entry[40], entry[41], entry[42], entry[43],
            entry[44], entry[45], entry[46], entry[47],
        ]);

        if end_lba < start_lba {
            continue;
        }

        let sector_count = end_lba - start_lba + 1;
        let part_num = (i + 1) as u32;

        let role = if type_guid == GUID_ESP {
            PartitionRole::Esp
        } else if type_guid == GUID_KASH_BOOT {
            PartitionRole::Boot
        } else if type_guid == GUID_KASH_VAULT {
            PartitionRole::VaultRoot
        } else if type_guid == GUID_LINUX_DATA {
            if part_num == 1 {
                PartitionRole::Esp
            } else if part_num == 2 {
                PartitionRole::Boot
            } else if part_num == 3 {
                PartitionRole::VaultRoot
            } else {
                PartitionRole::Data
            }
        } else {
            PartitionRole::Unknown
        };

        partitions.push(DiskPartition {
            partition_number: part_num,
            scheme: PartitionScheme::Gpt,
            role,
            start_lba,
            sector_count,
        });
    }

    partitions
}

/// Scans physical or simulated drive for MBR or GPT partition tables.
/// Falls back to single raw disk partition if neither is detected.
pub fn scan_partitions(driver: &mut dyn PersistentBlockDriver) -> Result<Vec<DiskPartition>, BlockError> {
    let mut sector0 = [0u8; SECTOR_SIZE];
    driver.read_sectors(0, 1, &mut sector0)?;

    // 1. Try parsing MBR at LBA 0
    let is_protective_mbr = {
        let mut found_protective = false;
        if sector0[510] == 0x55 && sector0[511] == 0xAA {
            for i in 0..4 {
                let offset = 446 + i * 16;
                if sector0[offset + 4] == MBR_TYPE_GPT_PROTECTIVE {
                    found_protective = true;
                    break;
                }
            }
        }
        found_protective
    };

    // 2. Try parsing GPT if protective MBR found or at LBA 1
    let mut sector1 = [0u8; SECTOR_SIZE];
    let gpt_header_opt = if driver.capacity_sectors() > 2 {
        if driver.read_sectors(1, 1, &mut sector1).is_ok() {
            parse_gpt_header(&sector1)
        } else {
            None
        }
    } else {
        None
    };

    if let Some(gpt) = gpt_header_opt {
        let entry_count = (gpt.num_partition_entries as usize).min(128);
        let entry_size = gpt.partition_entry_size as usize;
        let total_bytes = entry_count * entry_size;
        let sectors_needed = ((total_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE) as u16;

        let mut entries_buf = vec![0u8; (sectors_needed as usize) * SECTOR_SIZE];
        if driver.read_sectors(gpt.partition_entries_lba, sectors_needed, &mut entries_buf).is_ok() {
            let partitions = parse_gpt_entries(&entries_buf[..total_bytes], entry_count, entry_size);
            if !partitions.is_empty() {
                return Ok(partitions);
            }
        }
    }

    // 3. Fall back to standard MBR if not protective
    if !is_protective_mbr {
        if let Some(mbr_parts) = parse_mbr(&sector0) {
            return Ok(mbr_parts);
        }
    }

    // 4. Default: Raw unpartitioned disk
    let capacity = driver.capacity_sectors();
    Ok(vec![DiskPartition {
        partition_number: 1,
        scheme: PartitionScheme::RawDisk,
        role: PartitionRole::VaultRoot,
        start_lba: 0,
        sector_count: capacity,
    }])
}

/// Finds the authoritative kvault root partition according to KashOS layout:
/// - Explicit `PartitionRole::VaultRoot`
/// - Or Partition 3
/// - Or the largest data partition
/// - Or fallback to the first available partition
pub fn find_vault_partition(partitions: &[DiskPartition]) -> Option<&DiskPartition> {
    if partitions.is_empty() {
        return None;
    }

    // First preference: Explicitly tagged VaultRoot
    if let Some(p) = partitions.iter().find(|p| p.role == PartitionRole::VaultRoot) {
        return Some(p);
    }

    // Second preference: Partition 3 (KashOS standard layout)
    if let Some(p) = partitions.iter().find(|p| p.partition_number == 3) {
        return Some(p);
    }

    // Third preference: Largest partition
    partitions.iter().max_by_key(|p| p.sector_count)
}
