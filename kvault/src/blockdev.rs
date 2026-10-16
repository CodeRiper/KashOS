use crate::error::{VaultError, VaultResult};
use alloc::{vec, vec::Vec};

pub const BLOCK_SIZE: usize = 4096;

/// What the storage driver (NVMe, SD card, USB mass storage, virtio-blk...) must provide.
/// The vault assumes a single block write is atomic; a torn write is detected by the AEAD tag.
pub trait BlockDevice {
    fn block_count(&self) -> u64;
    fn read_block(&self, idx: u64, out: &mut [u8; BLOCK_SIZE]) -> VaultResult<()>;
    fn write_block(&mut self, idx: u64, data: &[u8; BLOCK_SIZE]) -> VaultResult<()>;
}

/// RAM-backed device for tests and tooling.
pub struct MemDevice {
    data: Vec<u8>,
}

impl MemDevice {
    pub fn new(blocks: u64) -> Self {
        MemDevice { data: vec![0u8; blocks as usize * BLOCK_SIZE] }
    }
    pub fn raw(&self) -> &[u8] {
        &self.data
    }
    pub fn raw_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl BlockDevice for MemDevice {
    fn block_count(&self) -> u64 {
        (self.data.len() / BLOCK_SIZE) as u64
    }
    fn read_block(&self, idx: u64, out: &mut [u8; BLOCK_SIZE]) -> VaultResult<()> {
        let off = (idx as usize).checked_mul(BLOCK_SIZE).ok_or(VaultError::Io)?;
        let src = self.data.get(off..off + BLOCK_SIZE).ok_or(VaultError::Io)?;
        out.copy_from_slice(src);
        Ok(())
    }
    fn write_block(&mut self, idx: u64, data: &[u8; BLOCK_SIZE]) -> VaultResult<()> {
        let off = (idx as usize).checked_mul(BLOCK_SIZE).ok_or(VaultError::Io)?;
        let dst = self.data.get_mut(off..off + BLOCK_SIZE).ok_or(VaultError::Io)?;
        dst.copy_from_slice(data);
        Ok(())
    }
}
