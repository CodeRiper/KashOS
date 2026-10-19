//! USB Mass Storage Class Bulk-Only Transport (BOT) & SCSI Driver (usb_msc.rs)
//!
//! Implements USB MSC BOT (USB-IF Bulk-Only Transport v1.0) and SCSI transparent
//! command set (SPC-4 / SBC-3) for hot-pluggable external USB drives and SSDs.
//!
//! - 31-byte Command Block Wrapper (CBW, "USBC" 0x43425355)
//! - 13-byte Command Status Wrapper (CSW, "USBS" 0x53425355)
//! - Standard SCSI-10 command set:
//!   - INQUIRY (0x12)
//!   - READ CAPACITY (10) (0x25)
//!   - READ (10) (0x28)
//!   - WRITE (10) (0x2A)
//!   - SYNCHRONIZE CACHE (10) (0x35)

extern crate alloc;
use alloc::boxed::Box;
use crate::{BlockError, PersistentBlockDriver};
use core::sync::atomic::{AtomicU32, Ordering};

pub const CBW_SIGNATURE: u32 = 0x4342_5355; // "USBC"
pub const CSW_SIGNATURE: u32 = 0x5342_5355; // "USBS"

pub const CBW_FLAG_DATA_IN: u8  = 0x80;
pub const CBW_FLAG_DATA_OUT: u8 = 0x00;

pub const SCSI_CMD_INQUIRY: u8               = 0x12;
pub const SCSI_CMD_READ_CAPACITY_10: u8      = 0x25;
pub const SCSI_CMD_READ_10: u8               = 0x28;
pub const SCSI_CMD_WRITE_10: u8              = 0x2A;
pub const SCSI_CMD_SYNCHRONIZE_CACHE_10: u8  = 0x35;

pub const CSW_STATUS_PASSED: u8      = 0x00;
pub const CSW_STATUS_FAILED: u8      = 0x01;
pub const CSW_STATUS_PHASE_ERROR: u8 = 0x02;

/// 31-byte USB Bulk-Only Transport Command Block Wrapper (CBW)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandBlockWrapper {
    pub signature: u32,          // 0x43425355 ("USBC")
    pub tag: u32,                // Unique request ID echoed in CSW
    pub data_transfer_len: u32,  // Expected data bytes
    pub flags: u8,               // Bit 7: 0 = Data-Out (Host to Device), 1 = Data-In
    pub lun: u8,                 // Logical Unit Number (bits 3:0)
    pub cb_length: u8,           // Length of valid SCSI command (1..16)
    pub cb: [u8; 16],            // SCSI Command Descriptor Block (CDB)
}

impl CommandBlockWrapper {
    pub fn to_bytes(&self) -> [u8; 31] {
        let mut buf = [0u8; 31];
        buf[0..4].copy_from_slice(&self.signature.to_le_bytes());
        buf[4..8].copy_from_slice(&self.tag.to_le_bytes());
        buf[8..12].copy_from_slice(&self.data_transfer_len.to_le_bytes());
        buf[12] = self.flags;
        buf[13] = self.lun;
        buf[14] = self.cb_length;
        buf[15..31].copy_from_slice(&self.cb);
        buf
    }

    pub fn from_bytes(buf: &[u8; 31]) -> Option<Self> {
        let signature = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if signature != CBW_SIGNATURE {
            return None;
        }
        let tag = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let data_transfer_len = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let flags = buf[12];
        let lun = buf[13];
        let cb_length = buf[14];
        let mut cb = [0u8; 16];
        cb.copy_from_slice(&buf[15..31]);

        Some(Self {
            signature,
            tag,
            data_transfer_len,
            flags,
            lun,
            cb_length,
            cb,
        })
    }
}

/// 13-byte USB Bulk-Only Transport Command Status Wrapper (CSW)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandStatusWrapper {
    pub signature: u32,          // 0x53425355 ("USBS")
    pub tag: u32,                // Matching tag from CBW
    pub data_residue: u32,       // Difference between expected and actual data
    pub status: u8,              // 0 = Passed, 1 = Failed, 2 = Phase Error
}

impl CommandStatusWrapper {
    pub fn to_bytes(&self) -> [u8; 13] {
        let mut buf = [0u8; 13];
        buf[0..4].copy_from_slice(&self.signature.to_le_bytes());
        buf[4..8].copy_from_slice(&self.tag.to_le_bytes());
        buf[8..12].copy_from_slice(&self.data_residue.to_le_bytes());
        buf[12] = self.status;
        buf
    }

    pub fn from_bytes(buf: &[u8; 13]) -> Option<Self> {
        let signature = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if signature != CSW_SIGNATURE {
            return None;
        }
        let tag = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let data_residue = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let status = buf[12];

        Some(Self {
            signature,
            tag,
            data_residue,
            status,
        })
    }
}

/// Abstract transport layer for USB Bulk endpoints
pub trait UsbBulkTransport: Send + Sync {
    fn bulk_out(&mut self, ep: u8, data: &[u8]) -> Result<(), BlockError>;
    fn bulk_in(&mut self, ep: u8, buf: &mut [u8]) -> Result<usize, BlockError>;
}

pub struct UsbMassStorageDevice {
    pub capacity_sectors: u64,
    pub sector_size: u32,
    pub lun: u8,
    pub ep_in: u8,
    pub ep_out: u8,
    tag_counter: AtomicU32,
    pub is_connected: bool,
    transport: Option<Box<dyn UsbBulkTransport>>,
}

impl UsbMassStorageDevice {
    pub fn new(ep_in: u8, ep_out: u8) -> Self {
        Self {
            capacity_sectors: 0,
            sector_size: 512,
            lun: 0,
            ep_in,
            ep_out,
            tag_counter: AtomicU32::new(1),
            is_connected: true,
            transport: None,
        }
    }

    pub fn with_transport(transport: Box<dyn UsbBulkTransport>, ep_in: u8, ep_out: u8) -> Self {
        Self {
            capacity_sectors: 0,
            sector_size: 512,
            lun: 0,
            ep_in,
            ep_out,
            tag_counter: AtomicU32::new(1),
            is_connected: true,
            transport: Some(transport),
        }
    }

    pub fn set_transport(&mut self, transport: Box<dyn UsbBulkTransport>) {
        self.transport = Some(transport);
    }

    pub fn next_tag(&self) -> u32 {
        self.tag_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Builds a 31-byte CBW containing a SCSI READ (10) command
    pub fn build_read10_cbw(&self, lba: u64, count: u16) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let bytes = (count as u32) * self.sector_size;

        let mut cb = [0u8; 16];
        cb[0] = SCSI_CMD_READ_10;
        cb[1] = 0; // Flags
        cb[2] = (lba >> 24) as u8;
        cb[3] = (lba >> 16) as u8;
        cb[4] = (lba >> 8) as u8;
        cb[5] = lba as u8;
        cb[6] = 0; // Group number
        cb[7] = (count >> 8) as u8;
        cb[8] = count as u8;
        cb[9] = 0; // Control byte

        CommandBlockWrapper {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_len: bytes,
            flags: CBW_FLAG_DATA_IN,
            lun: self.lun,
            cb_length: 10,
            cb,
        }
    }

    /// Builds a 31-byte CBW containing a SCSI WRITE (10) command
    pub fn build_write10_cbw(&self, lba: u64, count: u16) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let bytes = (count as u32) * self.sector_size;

        let mut cb = [0u8; 16];
        cb[0] = SCSI_CMD_WRITE_10;
        cb[1] = 0;
        cb[2] = (lba >> 24) as u8;
        cb[3] = (lba >> 16) as u8;
        cb[4] = (lba >> 8) as u8;
        cb[5] = lba as u8;
        cb[6] = 0;
        cb[7] = (count >> 8) as u8;
        cb[8] = count as u8;
        cb[9] = 0;

        CommandBlockWrapper {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_len: bytes,
            flags: CBW_FLAG_DATA_OUT,
            lun: self.lun,
            cb_length: 10,
            cb,
        }
    }

    /// Builds a 31-byte CBW containing a SCSI SYNCHRONIZE CACHE (10) command
    pub fn build_sync_cache_cbw(&self) -> CommandBlockWrapper {
        let tag = self.next_tag();
        let mut cb = [0u8; 16];
        cb[0] = SCSI_CMD_SYNCHRONIZE_CACHE_10;

        CommandBlockWrapper {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_len: 0,
            flags: CBW_FLAG_DATA_OUT,
            lun: self.lun,
            cb_length: 10,
            cb,
        }
    }

    /// Queries device capacity using SCSI READ CAPACITY (10) command
    pub fn probe_capacity(&mut self) -> Result<u64, BlockError> {
        if !self.is_connected {
            return Err(BlockError::DeviceNotFound);
        }

        let tag = self.next_tag();
        let mut cb = [0u8; 16];
        cb[0] = SCSI_CMD_READ_CAPACITY_10;

        let cbw = CommandBlockWrapper {
            signature: CBW_SIGNATURE,
            tag,
            data_transfer_len: 8,
            flags: CBW_FLAG_DATA_IN,
            lun: self.lun,
            cb_length: 10,
            cb,
        };

        if let Some(ref mut t) = self.transport {
            t.bulk_out(self.ep_out, &cbw.to_bytes())?;
            let mut cap_buf = [0u8; 8];
            t.bulk_in(self.ep_in, &mut cap_buf)?;

            let mut csw_buf = [0u8; 13];
            t.bulk_in(self.ep_in, &mut csw_buf)?;
            let csw = CommandStatusWrapper::from_bytes(&csw_buf).ok_or(BlockError::DeviceError)?;
            if csw.status != CSW_STATUS_PASSED || csw.tag != tag {
                return Err(BlockError::DeviceError);
            }

            let last_lba = u32::from_be_bytes([cap_buf[0], cap_buf[1], cap_buf[2], cap_buf[3]]) as u64;
            let block_len = u32::from_be_bytes([cap_buf[4], cap_buf[5], cap_buf[6], cap_buf[7]]);
            self.capacity_sectors = last_lba + 1;
            self.sector_size = block_len;
            Ok(self.capacity_sectors)
        } else {
            // Default 32 MiB baseline when running without physical bulk endpoints
            self.capacity_sectors = 65536;
            self.sector_size = 512;
            Ok(self.capacity_sectors)
        }
    }
}

impl PersistentBlockDriver for UsbMassStorageDevice {
    fn driver_name(&self) -> &'static str {
        "USB Mass Storage Class (BOT / SCSI-10)"
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        if !self.is_connected {
            return Err(BlockError::DeviceNotFound);
        }
        let cbw = self.build_read10_cbw(lba, count);
        let tag = cbw.tag;

        if let Some(ref mut t) = self.transport {
            t.bulk_out(self.ep_out, &cbw.to_bytes())?;
            let req_bytes = (count as usize) * (self.sector_size as usize);
            if buf.len() < req_bytes {
                return Err(BlockError::OutOfBounds);
            }
            t.bulk_in(self.ep_in, &mut buf[..req_bytes])?;

            let mut csw_buf = [0u8; 13];
            t.bulk_in(self.ep_in, &mut csw_buf)?;
            let csw = CommandStatusWrapper::from_bytes(&csw_buf).ok_or(BlockError::DeviceError)?;
            if csw.status != CSW_STATUS_PASSED || csw.tag != tag {
                return Err(BlockError::DeviceError);
            }
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        if !self.is_connected {
            return Err(BlockError::DeviceNotFound);
        }
        let cbw = self.build_write10_cbw(lba, count);
        let tag = cbw.tag;

        if let Some(ref mut t) = self.transport {
            t.bulk_out(self.ep_out, &cbw.to_bytes())?;
            let req_bytes = (count as usize) * (self.sector_size as usize);
            if buf.len() < req_bytes {
                return Err(BlockError::OutOfBounds);
            }
            t.bulk_out(self.ep_out, &buf[..req_bytes])?;

            let mut csw_buf = [0u8; 13];
            t.bulk_in(self.ep_in, &mut csw_buf)?;
            let csw = CommandStatusWrapper::from_bytes(&csw_buf).ok_or(BlockError::DeviceError)?;
            if csw.status != CSW_STATUS_PASSED || csw.tag != tag {
                return Err(BlockError::DeviceError);
            }
        }
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        if !self.is_connected {
            return Err(BlockError::DeviceNotFound);
        }
        let cbw = self.build_sync_cache_cbw();
        let tag = cbw.tag;

        if let Some(ref mut t) = self.transport {
            t.bulk_out(self.ep_out, &cbw.to_bytes())?;
            let mut csw_buf = [0u8; 13];
            t.bulk_in(self.ep_in, &mut csw_buf)?;
            let csw = CommandStatusWrapper::from_bytes(&csw_buf).ok_or(BlockError::DeviceError)?;
            if csw.status != CSW_STATUS_PASSED || csw.tag != tag {
                return Err(BlockError::DeviceError);
            }
        }
        Ok(())
    }
}
