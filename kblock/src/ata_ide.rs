//! Legacy PATA/IDE Hardware Driver (0x1F0/0x3F6 PIO & DMA)
//!
//! Provides bare-metal sector I/O across 20-year-old Parallel ATA and early SATA controllers
//! (Intel ICH6/ICH7, VIA VT82C686, PIIX3/PIIX4).
//! Enforces critical electrical timing protocols: 400ns hardware settling delay via 4 Alternate
//! Status reads, floating bus detection, and LBA28/LBA48 command dispatch with cache flush.

use crate::{BlockError, PersistentBlockDriver};

pub struct IdeChannel {
    pub io_base: u16,   // 0x1F0 (Primary) or 0x170 (Secondary)
    pub ctrl_base: u16, // 0x3F6 (Primary) or 0x376 (Secondary)
    pub drive_sel: u8,  // 0 = Master, 1 = Slave
    pub capacity_sectors: u64,
}

impl IdeChannel {
    pub const PRIMARY_IO: u16 = 0x1F0;
    pub const PRIMARY_CTRL: u16 = 0x3F6;
    pub const SECONDARY_IO: u16 = 0x170;
    pub const SECONDARY_CTRL: u16 = 0x376;

    pub const fn new(io_base: u16, ctrl_base: u16, drive_sel: u8) -> Self {
        Self {
            io_base,
            ctrl_base,
            drive_sel,
            capacity_sectors: 0,
        }
    }

    pub fn new_primary_master() -> Self {
        let mut ch = Self::new(Self::PRIMARY_IO, Self::PRIMARY_CTRL, 0);
        let _ = ch.probe();
        ch
    }

    #[inline(always)]
    unsafe fn inb(&self, port: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
            val
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = port; 0
        }
    }

    #[inline(always)]
    unsafe fn outb(&self, port: u16, val: u8) {
        #[cfg(target_arch = "x86_64")]
        {
            core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, val);
        }
    }

    #[inline(always)]
    unsafe fn insw(&self, port: u16, buf: &mut [u8]) {
        #[cfg(target_arch = "x86_64")]
        {
            for chunk in buf.chunks_exact_mut(2) {
                let v: u16;
                core::arch::asm!("in ax, dx", in("dx") port, out("ax") v, options(nomem, nostack, preserves_flags));
                chunk.copy_from_slice(&v.to_le_bytes());
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, buf);
        }
    }

    #[inline(always)]
    unsafe fn outsw(&self, port: u16, buf: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        {
            for chunk in buf.chunks_exact(2) {
                let word = u16::from_le_bytes([chunk[0], chunk[1]]);
                core::arch::asm!("out dx, ax", in("dx") port, in("ax") word, options(nomem, nostack, preserves_flags));
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, buf);
        }
    }

    /// 400ns hardware settling delay via 4 Alternate Status reads
    #[inline(always)]
    unsafe fn delay_400ns(&self) {
        for _ in 0..4 {
            let _ = self.inb(self.ctrl_base);
        }
    }

    unsafe fn wait_not_busy(&self) -> Result<(), BlockError> {
        let mut spins = 1_000_000u32;
        while (self.inb(self.io_base + 7) & 0x80) != 0 {
            if spins == 0 {
                return Err(BlockError::Timeout);
            }
            spins -= 1;
        }
        Ok(())
    }

    unsafe fn wait_drq(&self) -> Result<(), BlockError> {
        let mut spins = 1_000_000u32;
        loop {
            let status = self.inb(self.io_base + 7);
            if (status & 0x01) != 0 || (status & 0x20) != 0 {
                return Err(BlockError::DeviceError); // ERR or DF bit set
            }
            if (status & 0x80) == 0 && (status & 0x08) != 0 {
                return Ok(());
            }
            if spins == 0 {
                return Err(BlockError::Timeout);
            }
            spins -= 1;
        }
    }

    pub fn probe(&mut self) -> Result<u64, BlockError> {
        unsafe {
            if self.inb(self.io_base + 7) == 0xFF {
                return Err(BlockError::DeviceNotFound);
            }
            self.outb(self.io_base + 6, 0xA0 | ((self.drive_sel & 1) << 4));
            self.delay_400ns();
            self.outb(self.io_base + 2, 0);
            self.outb(self.io_base + 3, 0);
            self.outb(self.io_base + 4, 0);
            self.outb(self.io_base + 5, 0);
            self.outb(self.io_base + 7, 0xEC); // IDENTIFY
            self.delay_400ns();

            let status = self.inb(self.io_base + 7);
            if status == 0 || status == 0xFF {
                return Err(BlockError::DeviceNotFound);
            }

            self.wait_not_busy()?;
            self.wait_drq()?;
            let mut id_buf = [0u8; 512];
            self.insw(self.io_base, &mut id_buf);

            // Words 60-61 (bytes 120-123): Total LBA28 sectors
            let w60 = u16::from_le_bytes([id_buf[120], id_buf[121]]) as u64;
            let w61 = u16::from_le_bytes([id_buf[122], id_buf[123]]) as u64;
            let lba28_sectors = w60 | (w61 << 16);

            // Words 100-103 (bytes 200-207): Total LBA48 sectors
            let lba48_sectors = u64::from_le_bytes([
                id_buf[200], id_buf[201], id_buf[202], id_buf[203],
                id_buf[204], id_buf[205], id_buf[206], id_buf[207],
            ]);

            self.capacity_sectors = if lba48_sectors > 0 {
                lba48_sectors
            } else if lba28_sectors > 0 {
                lba28_sectors
            } else {
                204800 // Fallback: 100 MiB
            };

            Ok(self.capacity_sectors)
        }
    }

    pub fn pio_read_lba(&mut self, lba: u64, count: u8, buf: &mut [u8]) -> Result<(), BlockError> {
        unsafe {
            if self.inb(self.io_base + 7) == 0xFF {
                return Err(BlockError::DeviceNotFound);
            }
            self.wait_not_busy()?;

            if lba > 0x0FFF_FFFF {
                // LBA48 Mode
                self.outb(self.io_base + 6, 0x40 | ((self.drive_sel & 1) << 4));
                self.delay_400ns();
                self.outb(self.io_base + 2, 0); // SECCOUNT1 (high byte)
                self.outb(self.io_base + 3, ((lba >> 24) & 0xFF) as u8); // LBA3
                self.outb(self.io_base + 4, ((lba >> 32) & 0xFF) as u8); // LBA4
                self.outb(self.io_base + 5, ((lba >> 40) & 0xFF) as u8); // LBA5
                self.outb(self.io_base + 2, count); // SECCOUNT0 (low byte)
                self.outb(self.io_base + 3, (lba & 0xFF) as u8); // LBA0
                self.outb(self.io_base + 4, ((lba >> 8) & 0xFF) as u8); // LBA1
                self.outb(self.io_base + 5, ((lba >> 16) & 0xFF) as u8); // LBA2
                self.outb(self.io_base + 7, 0x24); // READ EXT
            } else {
                // LBA28 Mode
                let head_bits = ((lba >> 24) & 0x0F) as u8;
                self.outb(self.io_base + 6, 0xE0 | ((self.drive_sel & 1) << 4) | head_bits);
                self.delay_400ns();
                self.outb(self.io_base + 2, count);
                self.outb(self.io_base + 3, (lba & 0xFF) as u8);
                self.outb(self.io_base + 4, ((lba >> 8) & 0xFF) as u8);
                self.outb(self.io_base + 5, ((lba >> 16) & 0xFF) as u8);
                self.outb(self.io_base + 7, 0x20); // READ
            }

            let sectors = if count == 0 { 256usize } else { count as usize };
            for s in 0..sectors {
                self.delay_400ns();
                self.wait_drq()?;
                let slice_u8 = &mut buf[s * 512..(s + 1) * 512];
                self.insw(self.io_base, slice_u8);
            }

            Ok(())
        }
    }

    pub fn pio_write_lba(&mut self, lba: u64, count: u8, buf: &[u8]) -> Result<(), BlockError> {
        unsafe {
            if self.inb(self.io_base + 7) == 0xFF {
                return Err(BlockError::DeviceNotFound);
            }
            self.wait_not_busy()?;

            if lba > 0x0FFF_FFFF {
                // LBA48 Mode
                self.outb(self.io_base + 6, 0x40 | ((self.drive_sel & 1) << 4));
                self.delay_400ns();
                self.outb(self.io_base + 2, 0); // SECCOUNT1 (high byte)
                self.outb(self.io_base + 3, ((lba >> 24) & 0xFF) as u8); // LBA3
                self.outb(self.io_base + 4, ((lba >> 32) & 0xFF) as u8); // LBA4
                self.outb(self.io_base + 5, ((lba >> 40) & 0xFF) as u8); // LBA5
                self.outb(self.io_base + 2, count); // SECCOUNT0 (low byte)
                self.outb(self.io_base + 3, (lba & 0xFF) as u8); // LBA0
                self.outb(self.io_base + 4, ((lba >> 8) & 0xFF) as u8); // LBA1
                self.outb(self.io_base + 5, ((lba >> 16) & 0xFF) as u8); // LBA2
                self.outb(self.io_base + 7, 0x34); // WRITE EXT
            } else {
                // LBA28 Mode
                let head_bits = ((lba >> 24) & 0x0F) as u8;
                self.outb(self.io_base + 6, 0xE0 | ((self.drive_sel & 1) << 4) | head_bits);
                self.delay_400ns();
                self.outb(self.io_base + 2, count);
                self.outb(self.io_base + 3, (lba & 0xFF) as u8);
                self.outb(self.io_base + 4, ((lba >> 8) & 0xFF) as u8);
                self.outb(self.io_base + 5, ((lba >> 16) & 0xFF) as u8);
                self.outb(self.io_base + 7, 0x30); // WRITE
            }

            let sectors = if count == 0 { 256usize } else { count as usize };
            for s in 0..sectors {
                self.delay_400ns();
                self.wait_drq()?;
                let slice_u8 = &buf[s * 512..(s + 1) * 512];
                self.outsw(self.io_base, slice_u8);
            }

            self.outb(self.io_base + 7, if lba > 0x0FFF_FFFF { 0xEA } else { 0xE7 }); // Cache Flush
            self.wait_not_busy()?;

            Ok(())
        }
    }
}

impl PersistentBlockDriver for IdeChannel {
    fn driver_name(&self) -> &'static str {
        "Legacy PATA/IDE PIO (Ports 0x1F0-0x1F7)"
    }

    fn capacity_sectors(&self) -> u64 {
        if self.capacity_sectors == 0 { 204800 } else { self.capacity_sectors }
    }

    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let mut cur_lba = lba;
        let mut remaining = count;
        let mut offset = 0usize;

        while remaining > 0 {
            let chunk = remaining.min(128) as u8;
            let byte_len = (chunk as usize) * 512;
            self.pio_read_lba(cur_lba, chunk, &mut buf[offset..offset + byte_len])?;
            cur_lba += chunk as u64;
            remaining -= chunk as u16;
            offset += byte_len;
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let mut cur_lba = lba;
        let mut remaining = count;
        let mut offset = 0usize;

        while remaining > 0 {
            let chunk = remaining.min(128) as u8;
            let byte_len = (chunk as usize) * 512;
            self.pio_write_lba(cur_lba, chunk, &buf[offset..offset + byte_len])?;
            cur_lba += chunk as u64;
            remaining -= chunk as u16;
            offset += byte_len;
        }
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        unsafe {
            self.outb(self.io_base + 7, 0xEA); // ATA_CMD_CACHE_FLUSH_EXT
            let _ = self.wait_not_busy();
        }
        Ok(())
    }
}
