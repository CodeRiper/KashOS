//! Hardware and Persistent Block Storage Driver for KashOS.
//!
//! Grounded in the seL4 Device Driver Framework (sDDF) and the KashOS Architectural Blueprint:
//! - Direct binding to bare-metal hardware drivers:
//!   - Legacy PATA/IDE (0x1F0/0x3F6 PIO & DMA) for 20-year-old PCs.
//!   - VirtIO-Block for QEMU/KVM paravirtualized hardware.
//!   - AHCI for SATA PCIe controllers.
//! - Managed via `KBlockScheduler` (C-LOOK elevator scheduler with monotonic cylinder sweeping
//!   and adjacent write request coalescing).
//! - Deterministic hardware-level block zeroing (`deterministic_zero_lba`).


extern crate alloc;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use kblock::{
    find_vault_partition, BlockError, DiskPartition, IdeChannel, IoOperation, KBlockScheduler,
    PersistentBlockDriver, SECTOR_SIZE,
};

pub use kblock::{DiskPartition as Partition, PartitionRole, PartitionScheme};

pub const DEFAULT_SECTORS: usize = 20_480; // 10 MiB initial partition baseline

pub struct BlockDevStats {
    pub total_sectors: u64,
    pub sector_size: u32,
    pub read_ops: u64,
    pub write_ops: u64,
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub is_rotational: bool,
    pub active_driver: &'static str,
}

static READ_OPS: AtomicU64 = AtomicU64::new(0);
static WRITE_OPS: AtomicU64 = AtomicU64::new(0);
static SECTORS_READ: AtomicU64 = AtomicU64::new(0);
static SECTORS_WRITTEN: AtomicU64 = AtomicU64::new(0);

pub use crate::sync::{SpinLock, SpinLockGuard, TicketSpinLock, TicketSpinLockGuard};

/// Fallback Hardware Buffer used when no physical disk is detected in bootloader stage
struct FallbackRamDriver {
    sectors: Vec<u8>,
}

impl FallbackRamDriver {
    fn new(total_sectors: usize) -> Self {
        let mut sectors = vec![0u8; total_sectors * SECTOR_SIZE];
        let magic = b"KASHOFS_VAULT_01";
        sectors[..magic.len()].copy_from_slice(magic);
        Self { sectors }
    }
}

impl PersistentBlockDriver for FallbackRamDriver {
    fn driver_name(&self) -> &'static str {
        "Ephemeral In-Memory RAM Stage-0 Driver"
    }

    fn capacity_sectors(&self) -> u64 {
        (self.sectors.len() / SECTOR_SIZE) as u64
    }

    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let offset = (lba as usize) * SECTOR_SIZE;
        let len = (count as usize) * SECTOR_SIZE;
        if offset + len > self.sectors.len() {
            return Err(BlockError::OutOfBounds);
        }
        buf[..len].copy_from_slice(&self.sectors[offset..offset + len]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let offset = (lba as usize) * SECTOR_SIZE;
        let len = (count as usize) * SECTOR_SIZE;
        if offset + len > self.sectors.len() {
            return Err(BlockError::OutOfBounds);
        }
        self.sectors[offset..offset + len].copy_from_slice(&buf[..len]);
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

static SCHEDULER: SpinLock<Option<KBlockScheduler>> = SpinLock::new(None);

/// Initializes the hardware block storage subsystem and elevator scheduler.
pub fn init() {
    let mut sched_lock = SCHEDULER.lock();
    if sched_lock.is_none() {
        // Storage probe order: AHCI (SATA) -> VirtIO-Block -> Legacy PATA/IDE -> Volatile RAM
        let driver: Box<dyn PersistentBlockDriver> = {
            // Attempt 1: Probe PCI for SATA AHCI Controller (inspired by Redox OS ahcid)
            if let Some(ahci_dev) = crate::arch::find_ahci() {
                if let Some(abar) = ahci_dev.bar_mem_address(5) {
                    ahci_dev.enable_bus_mastering();
                    let mut ahci = kblock::AhciController::new(abar);
                    if let Ok(sectors) = ahci.probe() {
                        crate::kprintln!("[kblock] SATA AHCI Controller active at MMIO {:#x} ({} sectors, {} MiB)",
                                         abar, sectors, (sectors * 512) / (1024 * 1024));
                        Some(Box::new(ahci) as Box<dyn PersistentBlockDriver>)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                // Attempt 2: Probe PCI for VirtIO-Block device
                let pci_devs = crate::arch::scan_pci();
                if let Some(vblk_dev) = pci_devs.into_iter().find(|d| d.is_virtio_blk()) {
                    if let Some(io_base) = vblk_dev.bar_io_port(0) {
                        vblk_dev.enable_bus_mastering();
                        let mut vblk = kblock::VirtioBlockDevice::new(io_base);
                        if vblk.init_device().is_ok() {
                            crate::kprintln!("[kblock] VirtIO-Block device active at I/O Port {:#x} ({} sectors, {} MiB)",
                                             io_base, vblk.capacity_sectors, (vblk.capacity_sectors * 512) / (1024 * 1024));
                            Some(Box::new(vblk) as Box<dyn PersistentBlockDriver>)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .or_else(|| {
                // Attempt 3: Probe physical PATA/IDE controller on ports 0x1F0/0x3F6 (Core 2 Duo / vintage PC)
                let mut ide = IdeChannel::new_primary_master();
                match ide.probe() {
                    Ok(sectors) => {
                        crate::kprintln!("[kblock] Legacy PATA/IDE Master detected at Port 0x1F0 ({} sectors, {} MiB)",
                                         sectors, (sectors * 512) / (1024 * 1024));
                        Some(Box::new(ide) as Box<dyn PersistentBlockDriver>)
                    }
                    Err(_) => None,
                }
            })
            .unwrap_or_else(|| {
                crate::kprintln!("[kblock] No physical PATA/AHCI controller detected; using volatile in-memory staging backend");
                Box::new(FallbackRamDriver::new(DEFAULT_SECTORS))
            })
        };

        crate::kprintln!("[kblock] Initializing C-LOOK Elevator Scheduler (64-entry request ring)...");
        let mut scheduler = KBlockScheduler::new(driver);
        let partitions = kblock::scan_partitions(scheduler.driver.as_mut()).unwrap_or_default();
        crate::kprintln!("[kblock] Discovered {} disk partition(s):", partitions.len());
        for p in &partitions {
            crate::kprintln!(
                "  - Partition #{}: {:?} [{:?}] LBA {}..{} ({} sectors, {} KiB)",
                p.partition_number, p.scheme, p.role, p.start_lba, p.end_lba(),
                p.sector_count, (p.sector_count * 512) / 1024
            );
        }
        *sched_lock = Some(scheduler);
    }
}

/// Reads contiguous sectors from the block device starting at `lba`.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> Result<usize, ()> {
    let mut sched_lock = SCHEDULER.lock();
    let sched = sched_lock.as_mut().ok_or(())?;

    let req_sectors = ((buf.len() + SECTOR_SIZE - 1) / SECTOR_SIZE) as u16;
    sched.driver.read_sectors(lba, req_sectors, buf).map_err(|_| ())?;

    READ_OPS.fetch_add(1, Ordering::Relaxed);
    SECTORS_READ.fetch_add(req_sectors as u64, Ordering::Relaxed);

    Ok(buf.len())
}

/// Writes contiguous sectors to the block device starting at `lba` through C-LOOK elevator.
pub fn write_sectors(lba: u64, buf: &[u8]) -> Result<usize, ()> {
    let mut sched_lock = SCHEDULER.lock();
    let sched = sched_lock.as_mut().ok_or(())?;

    let req_sectors = ((buf.len() + SECTOR_SIZE - 1) / SECTOR_SIZE) as u16;
    let _ = sched.submit(lba, req_sectors, IoOperation::Write, /* badge = */ 0x01);
    if let Some(slot_idx) = sched.next_scheduled_slot() {
        sched.complete_slot(slot_idx);
    }
    sched.driver.write_sectors(lba, req_sectors, buf).map_err(|_| ())?;

    WRITE_OPS.fetch_add(1, Ordering::Relaxed);
    SECTORS_WRITTEN.fetch_add(req_sectors as u64, Ordering::Relaxed);

    Ok(buf.len())
}

/// Anti-forensic deterministic hardware sector zeroing with ATA cache flush
pub fn deterministic_zero(lba: u64, sectors: u16) -> Result<(), ()> {
    let mut sched_lock = SCHEDULER.lock();
    let sched = sched_lock.as_mut().ok_or(())?;
    sched.deterministic_zero_lba(lba, sectors).map_err(|_| ())
}

/// Flushes drive write cache to physical magnetic platter / flash cells
pub fn flush_cache() -> Result<(), ()> {
    let mut sched_lock = SCHEDULER.lock();
    let sched = sched_lock.as_mut().ok_or(())?;
    sched.driver.flush_cache().map_err(|_| ())
}

/// Returns device runtime metrics and active driver name.
pub fn get_stats() -> BlockDevStats {
    let sched_lock = SCHEDULER.lock();
    let (total_sectors, active_driver) = match sched_lock.as_ref() {
        Some(s) => (s.driver.capacity_sectors(), s.driver.driver_name()),
        None => (0, "Uninitialized"),
    };

    BlockDevStats {
        total_sectors,
        sector_size: SECTOR_SIZE as u32,
        read_ops: READ_OPS.load(Ordering::Relaxed),
        write_ops: WRITE_OPS.load(Ordering::Relaxed),
        sectors_read: SECTORS_READ.load(Ordering::Relaxed),
        sectors_written: SECTORS_WRITTEN.load(Ordering::Relaxed),
        is_rotational: true,
        active_driver,
    }
}

/// Scans partitions on the active hardware block device.
pub fn scan_partitions() -> Vec<DiskPartition> {
    let mut sched_lock = SCHEDULER.lock();
    if let Some(sched) = sched_lock.as_mut() {
        kblock::scan_partitions(sched.driver.as_mut()).unwrap_or_else(|_| {
            let cap = sched.driver.capacity_sectors();
            vec![DiskPartition {
                partition_number: 1,
                scheme: PartitionScheme::RawDisk,
                role: PartitionRole::VaultRoot,
                start_lba: 0,
                sector_count: cap,
            }]
        })
    } else {
        Vec::new()
    }
}

/// Persistent Block Device Adapter for kvault::BlockDevice.
/// Maps 1 x 4 KiB kvault block to 8 contiguous 512B hardware sectors via kblock.
#[derive(Clone, Copy, Debug)]
pub struct KBlockDeviceAdapter {
    pub start_lba: u64,
    pub block_count: u64,
}

impl KBlockDeviceAdapter {
    pub fn new() -> Self {
        let partitions = scan_partitions();
        if let Some(part) = find_vault_partition(&partitions) {
            let block_count = part.sector_count / 8;
            crate::kprintln!(
                "[kblock] KBlockDeviceAdapter bound to Partition #{} (scheme: {:?}, LBA {}..{}, {} 4KiB blocks)",
                part.partition_number, part.scheme, part.start_lba, part.end_lba(), block_count
            );
            Self {
                start_lba: part.start_lba,
                block_count,
            }
        } else {
            let stats = get_stats();
            let total_blocks = (stats.total_sectors / 8).min(256);
            Self {
                start_lba: 0,
                block_count: total_blocks,
            }
        }
    }

    pub fn with_range(start_lba: u64, block_count: u64) -> Self {
        Self {
            start_lba,
            block_count,
        }
    }
}

impl Default for KBlockDeviceAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl kvault::BlockDevice for KBlockDeviceAdapter {
    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn read_block(&self, idx: u64, out: &mut [u8; kvault::BLOCK_SIZE]) -> kvault::VaultResult<()> {
        if idx >= self.block_count {
            return Err(kvault::VaultError::OutOfBounds);
        }
        let lba = self.start_lba + idx * 8;
        read_sectors(lba, out).map_err(|_| kvault::VaultError::Io)?;
        Ok(())
    }

    fn write_block(&mut self, idx: u64, data: &[u8; kvault::BLOCK_SIZE]) -> kvault::VaultResult<()> {
        if idx >= self.block_count {
            return Err(kvault::VaultError::OutOfBounds);
        }
        let lba = self.start_lba + idx * 8;
        write_sectors(lba, data).map_err(|_| kvault::VaultError::Io)?;
        Ok(())
    }
}

