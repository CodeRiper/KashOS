//! kblock — Adaptive Block Storage Subsystem & Hardware Driver Engine
//!
//! Grounded in the seL4 Device Driver Framework (sDDF) and the KashOS Architectural Blueprint:
//! - Hardware drivers: Legacy PATA/IDE (0x1F0/0x3F6 PIO & DMA), VirtIO-Block (OASIS spec),
//!   SATA AHCI (FIS DMA), and NVMe PCIe queues.
//! - I/O Elevator Scheduler (C-LOOK / SCAN algorithm) with 64-entry static request ring
//!   and adjacent 4 KiB block write coalescing up to 64 KiB.
//! - Deterministic Hardware-Level Block Zeroing: Immediate synchronous write of 0x00
//!   or fresh ChaCha20 stream noise followed by hardware cache flush (ATA 0xEA/0xE7).
#![no_std]

extern crate alloc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

pub mod ahci;
pub mod ata_ide;
pub mod nvme;
pub mod usb_msc;
pub mod virtio_blk;

pub use ahci::AhciController;
pub use ata_ide::IdeChannel;
pub use nvme::NvmeController;
pub use usb_msc::{CommandBlockWrapper, CommandStatusWrapper, UsbMassStorageDevice};
pub use virtio_blk::VirtioBlockDevice;

pub const SECTOR_SIZE: usize = 512;
pub const BLOCK_SIZE: usize = 4096; // 8 physical 512B sectors per KashOS Vault block

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    DeviceNotFound,
    DeviceError,
    Timeout,
    InvalidSector,
    MediaWriteProtected,
    DmaFault,
    CryptoAuthFailed,
    OutOfBounds,
    Unsupported,
    AlignmentError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    DeterministicZero, // Anti-forensic immediate hardware overwrite
}

/// Core hardware abstraction for all #![no_std] persistent disk drivers
pub trait PersistentBlockDriver: Send + Sync {
    fn driver_name(&self) -> &'static str;
    fn capacity_sectors(&self) -> u64;
    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError>;
    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError>;
    fn flush_cache(&mut self) -> Result<(), BlockError>;
}

/// C-LOOK Elevator Request Slot for 20-year-old HDD seek optimization
#[derive(Clone, Copy)]
pub struct ElevatorSlot {
    pub lba: u64,
    pub sector_count: u16,
    pub op: IoOperation,
    pub compartment_badge: u64,
    pub active: bool,
}

const EMPTY_SLOT: ElevatorSlot = ElevatorSlot {
    lba: 0,
    sector_count: 0,
    op: IoOperation::Read,
    compartment_badge: 0,
    active: false,
};

/// C-LOOK Elevator Scheduler and Hardware I/O Dispatcher
pub struct KBlockScheduler {
    pub driver: Box<dyn PersistentBlockDriver>,
    current_head_lba: AtomicU64,
    queue: [ElevatorSlot; 64],
}

impl KBlockScheduler {
    pub fn new(driver: Box<dyn PersistentBlockDriver>) -> Self {
        Self {
            driver,
            current_head_lba: AtomicU64::new(0),
            queue: [EMPTY_SLOT; 64],
        }
    }

    pub fn get_slot(&self, idx: usize) -> Option<&ElevatorSlot> {
        if idx < self.queue.len() && self.queue[idx].active {
            Some(&self.queue[idx])
        } else {
            None
        }
    }

    /// Submits a request to the C-LOOK elevator queue, coalescing adjacent writes
    pub fn submit(&mut self, lba: u64, sector_count: u16, op: IoOperation, compartment_badge: u64) -> Result<(), BlockError> {
        // Coalesce adjacent writes if possible
        if op == IoOperation::Write {
            for slot in self.queue.iter_mut() {
                if slot.active && slot.op == IoOperation::Write && slot.compartment_badge == compartment_badge {
                    if slot.lba + (slot.sector_count as u64) == lba && slot.sector_count + sector_count <= 128 {
                        slot.sector_count += sector_count;
                        return Ok(());
                    }
                }
            }
        }

        // Find empty slot
        for slot in self.queue.iter_mut() {
            if !slot.active {
                *slot = ElevatorSlot {
                    lba,
                    sector_count,
                    op,
                    compartment_badge,
                    active: true,
                };
                return Ok(());
            }
        }

        Err(BlockError::DeviceError) // Queue full
    }

    /// Selects the next request in ascending LBA order from current head position (C-LOOK)
    pub fn next_scheduled_slot(&mut self) -> Option<usize> {
        let head = self.current_head_lba.load(Ordering::Relaxed);
        let mut best_idx: Option<usize> = None;
        let mut best_lba = u64::MAX;

        // Pass 1: Find lowest LBA >= current_head_lba
        for (i, slot) in self.queue.iter().enumerate() {
            if slot.active && slot.lba >= head && slot.lba < best_lba {
                best_lba = slot.lba;
                best_idx = Some(i);
            }
        }
        if best_idx.is_some() {
            return best_idx;
        }

        // Pass 2: Wrap around to the lowest LBA on the disk platter
        for (i, slot) in self.queue.iter().enumerate() {
            if slot.active && slot.lba < best_lba {
                best_lba = slot.lba;
                best_idx = Some(i);
            }
        }
        best_idx
    }

    /// Deterministic Anti-Forensic Sector Zeroing with immediate hardware cache flush
    pub fn deterministic_zero_lba(&mut self, lba: u64, sectors: u16) -> Result<(), BlockError> {
        let zero_block = [0u8; BLOCK_SIZE];
        let mut remaining = sectors;
        let mut cur_lba = lba;

        while remaining > 0 {
            let chunk = remaining.min((BLOCK_SIZE / SECTOR_SIZE) as u16);
            let byte_len = (chunk as usize) * SECTOR_SIZE;
            self.driver.write_sectors(cur_lba, chunk, &zero_block[..byte_len])?;
            cur_lba += chunk as u64;
            remaining -= chunk;
        }
        self.current_head_lba.store(cur_lba, Ordering::Relaxed);
        self.driver.flush_cache()
    }
}

// ── Legacy Compatibility Layer ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOperation {
    Read,
    Write,
    FlushBarrier,
}

pub struct BlockRequest {
    pub op: BlockOperation,
    pub start_sector: u64,
    pub sector_count: u32,
    pub memory_buffer: *mut u8,
    pub callback: Option<fn(Result<(), BlockError>)>,
}

unsafe impl Send for BlockRequest {}
unsafe impl Sync for BlockRequest {}

pub trait BlockDevice: Send + Sync {
    fn sector_size_bytes(&self) -> u32;
    fn total_sectors(&self) -> u64;
    fn is_rotational(&self) -> bool;
    fn submit_request(&self, req: BlockRequest) -> Result<(), BlockError>;
    fn poll_completions(&self);
}

pub struct ElevatorScheduler {
    read_queue: BTreeMap<u64, BlockRequest>,
    write_queue: BTreeMap<u64, BlockRequest>,
    head_sector: u64,
}

impl Default for ElevatorScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl ElevatorScheduler {
    pub const fn new() -> Self {
        ElevatorScheduler {
            read_queue: BTreeMap::new(),
            write_queue: BTreeMap::new(),
            head_sector: 0,
        }
    }

    pub fn insert_and_coalesce(&mut self, request: BlockRequest) {
        let queue = match request.op {
            BlockOperation::Read => &mut self.read_queue,
            BlockOperation::Write => &mut self.write_queue,
            BlockOperation::FlushBarrier => return,
        };

        if let Some((&prev_sector, prev_req)) = queue.range_mut(..=request.start_sector).next_back() {
            if prev_sector + (prev_req.sector_count as u64) == request.start_sector {
                prev_req.sector_count += request.sector_count;
                return;
            }
        }

        queue.insert(request.start_sector, request);
    }

    pub fn pop_next_request(&mut self) -> Option<BlockRequest> {
        if let Some(req) = Self::pop_from_queue(&mut self.read_queue, &mut self.head_sector) {
            return Some(req);
        }
        Self::pop_from_queue(&mut self.write_queue, &mut self.head_sector)
    }

    fn pop_from_queue(queue: &mut BTreeMap<u64, BlockRequest>, head_sector: &mut u64) -> Option<BlockRequest> {
        let next_key = queue.range(*head_sector..)
            .map(|(&k, _)| k)
            .next()
            .or_else(|| queue.keys().next().copied());

        if let Some(key) = next_key {
            *head_sector = key;
            return queue.remove(&key);
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.read_queue.is_empty() && self.write_queue.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorGeometry {
    Legacy512n,
    Emulated512e,
    Native4Kn,
}

impl SectorGeometry {
    pub const fn physical_sector_size(&self) -> u32 {
        match self {
            SectorGeometry::Legacy512n | SectorGeometry::Emulated512e => 512,
            SectorGeometry::Native4Kn => 4096,
        }
    }
}
