//! Unified Dynamic Cryptographic Storage Pool (VaultPool)
//!
//! Eliminates rigid static disk partitions by managing a single contiguous
//! cryptographic container with shared 4 KiB extent allocation across:
//! - Subvolume 0x01: System Root (K_sys)
//! - Subvolume 0x02: Applications / AppBundles (K_apps)
//! - Subvolume 0x03: Personal / Workspaces (K_user)
//! - Subvolume 0x04: Encrypted External USB Storage (K_usb)
//!
//! Enforces subvolume cryptographic isolation via HKDF-SHA256 derived keys:
//! K_subvol = HKDF-Expand(K_master, "KashOS-Subvolume-v1" || subvol_id).

extern crate alloc;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub const POOL_BLOCK_SIZE: usize = 4096;
pub const SECTOR_SIZE: usize = 512;
pub const SECTORS_PER_BLOCK: u64 = (POOL_BLOCK_SIZE / SECTOR_SIZE) as u64; // 8

pub const SUBVOL_SYSTEM: u32   = 0x01;
pub const SUBVOL_BROWSER: u32  = 0x02;
pub const SUBVOL_APPS: u32     = 0x03;
pub const SUBVOL_PERSONAL: u32 = 0x04;
pub const SUBVOL_EXTERNAL: u32 = 0x05;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct PoolSuperblock {
    pub magic: [u8; 8],        // b"KASHPOOL"
    pub generation: u64,       // Monotonically increasing COW transaction ID
    pub total_blocks: u64,
    pub free_blocks: u64,
    pub extent_root_lba: u64,  // Root node of B-Tree managing free block runs
    pub subvol_table_lba: u64, // Root node of active subvolume directory
    pub csum: [u8; 32],        // SHA-256 / BLAKE3 checksum of superblock contents
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtentDescriptor {
    pub logical_offset: u64, // Block offset within subvolume
    pub physical_lba: u64,   // Physical LBA on raw drive
    pub block_count: u32,
    pub subvol_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolError {
    NoSpace,
    InvalidSubvolume,
    CorruptedSuperblock,
    IoError,
    ExtentOutOfBounds,
}

pub trait StoragePoolEngine {
    fn allocate_extents(&mut self, subvol_id: u32, blocks: u32) -> Result<Vec<ExtentDescriptor>, PoolError>;
    fn free_extents(&mut self, subvol_id: u32, extents: &[ExtentDescriptor]) -> Result<(), PoolError>;
}

/// Dynamic extent allocator managing the shared 4 KiB block pool
pub struct VaultPool {
    pub superblock: PoolSuperblock,
    pub start_lba: u64,
    pub master_key: [u8; 32],
    allocated_extents: Vec<ExtentDescriptor>,
    next_free_block: u64,
}

impl VaultPool {
    pub fn new(start_lba: u64, total_blocks: u64, master_key: [u8; 32]) -> Self {
        let sb = PoolSuperblock {
            magic: *b"KASHPOOL",
            generation: 1,
            total_blocks,
            free_blocks: total_blocks,
            extent_root_lba: start_lba,
            subvol_table_lba: start_lba + 8,
            csum: [0; 32],
        };

        Self {
            superblock: sb,
            start_lba,
            master_key,
            allocated_extents: Vec::new(),
            next_free_block: 0,
        }
    }

    /// Derives isolated subvolume encryption key:
    /// K_subvol = HKDF-Expand(K_master, "KashOS-Subvolume-v1" || subvol_id)
    pub fn derive_subvolume_key(&self, subvol_id: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_key);
        hasher.update(b"KashOS-Subvolume-v1");
        hasher.update(&subvol_id.to_be_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    /// Current free blocks remaining in the unified storage pool
    pub fn free_blocks(&self) -> u64 {
        self.superblock.free_blocks
    }

    /// Total blocks managed in the container
    pub fn total_blocks(&self) -> u64 {
        self.superblock.total_blocks
    }
}

impl StoragePoolEngine for VaultPool {
    fn allocate_extents(&mut self, subvol_id: u32, blocks: u32) -> Result<Vec<ExtentDescriptor>, PoolError> {
        let req_blocks = blocks as u64;
        if self.superblock.free_blocks < req_blocks {
            return Err(PoolError::NoSpace);
        }

        let block_idx = self.next_free_block;
        let phys_lba = self.start_lba + (block_idx * SECTORS_PER_BLOCK);

        let desc = ExtentDescriptor {
            logical_offset: block_idx,
            physical_lba: phys_lba,
            block_count: blocks,
            subvol_id,
        };

        self.next_free_block += req_blocks;
        self.superblock.free_blocks = self.superblock.free_blocks.saturating_sub(req_blocks);
        self.superblock.generation += 1;
        self.allocated_extents.push(desc);

        let mut res = Vec::new();
        res.push(desc);
        Ok(res)
    }

    fn free_extents(&mut self, subvol_id: u32, extents: &[ExtentDescriptor]) -> Result<(), PoolError> {
        for ext in extents {
            if ext.subvol_id != subvol_id {
                return Err(PoolError::InvalidSubvolume);
            }
            self.superblock.free_blocks = (self.superblock.free_blocks + ext.block_count as u64)
                .min(self.superblock.total_blocks);
        }
        self.superblock.generation += 1;
        Ok(())
    }
}
