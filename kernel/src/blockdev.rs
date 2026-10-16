//! Hardware and Simulated Block Storage Driver for KashOS.
//!
//! Provides the concrete block device backing the VFS, Redox-style `disk:` scheme,
//! and `kvault-fs` encrypted Merkle tree storage.
//! Integrates directly with the `kblock` C-LOOK elevator scheduler.

#![allow(dead_code)]

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const SECTOR_SIZE: usize = 512;
pub const DEFAULT_SECTORS: usize = 20_480; // 10 MiB matching the hardware profile

pub struct BlockDevStats {
    pub total_sectors: u64,
    pub sector_size: u32,
    pub read_ops: u64,
    pub write_ops: u64,
    pub sectors_read: u64,
    pub sectors_written: u64,
    pub is_rotational: bool,
}

static READ_OPS: AtomicU64 = AtomicU64::new(0);
static WRITE_OPS: AtomicU64 = AtomicU64::new(0);
static SECTORS_READ: AtomicU64 = AtomicU64::new(0);
static SECTORS_WRITTEN: AtomicU64 = AtomicU64::new(0);

struct DeviceStorage {
    sectors: Vec<u8>,
    elevator: kblock::ElevatorScheduler,
}

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        SpinLock {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }
}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> core::ops::Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

static STORAGE: SpinLock<Option<DeviceStorage>> = SpinLock::new(None);

/// Initializes the system block device with `num_sectors` (default 10 MiB).
pub fn init() {
    let mut storage = STORAGE.lock();
    if storage.is_none() {
        let size = DEFAULT_SECTORS * SECTOR_SIZE;
        let mut sectors = vec![0u8; size];
        
        // Populate superblock signature at LBA 0 (KashOS KVAULT-FS signature)
        let magic = b"KASHOFS_VAULT_01";
        sectors[..magic.len()].copy_from_slice(magic);

        *storage = Some(DeviceStorage {
            sectors,
            elevator: kblock::ElevatorScheduler::new(),
        });
    }
}

/// Reads contiguous sectors from the block device starting at `lba`.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> Result<usize, ()> {
    let mut storage = STORAGE.lock();
    let dev = storage.as_mut().ok_or(())?;

    let req_sectors = (buf.len() + SECTOR_SIZE - 1) / SECTOR_SIZE;
    let byte_offset = (lba as usize) * SECTOR_SIZE;
    let byte_count = req_sectors * SECTOR_SIZE;

    if byte_offset + byte_count > dev.sectors.len() {
        return Err(());
    }

    let src = &dev.sectors[byte_offset..byte_offset + buf.len()];
    buf.copy_from_slice(src);

    READ_OPS.fetch_add(1, Ordering::Relaxed);
    SECTORS_READ.fetch_add(req_sectors as u64, Ordering::Relaxed);

    Ok(buf.len())
}

/// Writes contiguous sectors to the block device starting at `lba`.
pub fn write_sectors(lba: u64, buf: &[u8]) -> Result<usize, ()> {
    let mut storage = STORAGE.lock();
    let dev = storage.as_mut().ok_or(())?;

    let req_sectors = (buf.len() + SECTOR_SIZE - 1) / SECTOR_SIZE;
    let byte_offset = (lba as usize) * SECTOR_SIZE;
    let byte_count = req_sectors * SECTOR_SIZE;

    if byte_offset + byte_count > dev.sectors.len() {
        return Err(());
    }

    // Pass through kblock request coalescer
    let req = kblock::BlockRequest {
        op: kblock::BlockOperation::Write,
        start_sector: lba,
        sector_count: req_sectors as u32,
        memory_buffer: buf.as_ptr() as *mut u8,
        callback: None,
    };
    dev.elevator.insert_and_coalesce(req);

    // Commit write to backing buffer
    let dst = &mut dev.sectors[byte_offset..byte_offset + buf.len()];
    dst.copy_from_slice(buf);

    WRITE_OPS.fetch_add(1, Ordering::Relaxed);
    SECTORS_WRITTEN.fetch_add(req_sectors as u64, Ordering::Relaxed);

    Ok(buf.len())
}

/// Returns device runtime metrics.
pub fn get_stats() -> BlockDevStats {
    let storage = STORAGE.lock();
    let total_sectors = storage.as_ref().map(|s| (s.sectors.len() / SECTOR_SIZE) as u64).unwrap_or(0);

    BlockDevStats {
        total_sectors,
        sector_size: SECTOR_SIZE as u32,
        read_ops: READ_OPS.load(Ordering::Relaxed),
        write_ops: WRITE_OPS.load(Ordering::Relaxed),
        sectors_read: SECTORS_READ.load(Ordering::Relaxed),
        sectors_written: SECTORS_WRITTEN.load(Ordering::Relaxed),
        is_rotational: false,
    }
}
