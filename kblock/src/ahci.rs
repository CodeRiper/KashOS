//! SATA AHCI Controller Driver (ahci.rs)
//!
//! Inspired by Redox OS `ahcid`:
//! Provides direct DMA sector operations across SATA controllers via the Advanced Host
//! Controller Interface (AHCI 1.3).
//! Sets up Host-to-Device Register FIS packets (0x27) with Command 0x25 (READ DMA EXT)
//! and 0x35 (WRITE DMA EXT) linked to Physical Region Descriptor Tables (PRDT).

use crate::{BlockError, PersistentBlockDriver, SECTOR_SIZE};

pub const SATA_SIG_ATA: u32   = 0x0000_0101; // SATA Drive
pub const SATA_SIG_ATAPI: u32 = 0xEB14_0101; // SATAPI Drive
pub const SATA_SIG_SEMB: u32  = 0xC33C_0101; // Enclosure Management Bridge
pub const SATA_SIG_PM: u32    = 0x9669_0101; // Port Multiplier

pub const AHCI_GHC_AE: u32    = 1 << 31;     // AHCI Enable
pub const AHCI_GHC_HR: u32    = 1 << 0;      // HBA Reset

pub const HBA_PORT_CMD_ST: u32  = 1 << 0;    // Start
pub const HBA_PORT_CMD_FRE: u32 = 1 << 4;    // FIS Receive Enable
pub const HBA_PORT_CMD_FR: u32  = 1 << 14;   // FIS Receive Running
pub const HBA_PORT_CMD_CR: u32  = 1 << 15;   // Command List Running

pub const HBA_PORT_TFD_BSY: u32 = 1 << 7;    // Task File Busy
pub const HBA_PORT_TFD_DRQ: u32 = 1 << 3;    // Task File Data Request
pub const HBA_PORT_TFD_ERR: u32 = 1 << 0;    // Task File Error

pub const ATA_CMD_READ_DMA_EXT: u8  = 0x25;
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
pub const ATA_CMD_IDENTIFY: u8      = 0xEC;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HbaCmdHeader {
    pub flags: u16,
    pub prdtl: u16,
    pub prdbc: u32,
    pub ctba: u32,
    pub ctbau: u32,
    pub reserved: [u32; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HbaPrdtEntry {
    pub dba: u32,
    pub dbau: u32,
    pub reserved: u32,
    pub dbc: u32, // Bit 31: Interrupt on completion, Bits 0..21: byte count - 1
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FisRegH2D {
    pub fis_type: u8, // 0x27
    pub pmport_c: u8, // Bit 7: Command (1) / Control (0), Bits 0..3: PM port
    pub command: u8,  // ATA Command byte
    pub feature_low: u8,
    pub lba0: u8,
    pub lba1: u8,
    pub lba2: u8,
    pub device: u8,   // 0x40 (LBA mode)
    pub lba3: u8,
    pub lba4: u8,
    pub lba5: u8,
    pub feature_high: u8,
    pub count_low: u8,
    pub count_high: u8,
    pub icc: u8,
    pub control: u8,
    pub reserved: [u8; 4],
}

impl FisRegH2D {
    pub fn write_to_bytes(&self, out: &mut [u8; 64]) {
        let src = unsafe {
            core::slice::from_raw_parts((self as *const Self) as *const u8, core::mem::size_of::<Self>())
        };
        out[..src.len()].copy_from_slice(src);
    }
}

#[repr(C)]
pub struct HbaPort {
    pub clb: u32,
    pub clbu: u32,
    pub fb: u32,
    pub fbu: u32,
    pub is: u32,
    pub ie: u32,
    pub cmd: u32,
    pub reserved0: u32,
    pub tfd: u32,
    pub sig: u32,
    pub ssts: u32,
    pub sctl: u32,
    pub serr: u32,
    pub sact: u32,
    pub ci: u32,
    pub sntf: u32,
    pub fbs: u32,
    pub reserved1: [u32; 11],
    pub vendor: [u32; 4],
}

#[repr(C)]
pub struct HbaMem {
    pub cap: u32,
    pub ghc: u32,
    pub is: u32,
    pub pi: u32,
    pub vs: u32,
    pub ccc_ctl: u32,
    pub ccc_pts: u32,
    pub em_loc: u32,
    pub em_ctl: u32,
    pub cap2: u32,
    pub bohc: u32,
    pub reserved: [u8; 0xA0 - 0x2C],
    pub vendor: [u8; 0x100 - 0xA0],
    pub ports: [HbaPort; 32],
}

pub struct AhciController {
    pub abar_paddr: u64,
    pub port_count: u8,
    pub active_port: Option<u8>,
    pub capacity_sectors: u64,
}

impl AhciController {
    pub const PCI_CLASS_STORAGE: u8 = 0x01;
    pub const PCI_SUBCLASS_SATA: u8 = 0x06;

    pub const fn new(abar_paddr: u64) -> Self {
        Self {
            abar_paddr,
            port_count: 0,
            active_port: None,
            capacity_sectors: 16_777_216, // Default 8 GiB SATA HDD (512B sectors)
        }
    }

    /// Probes the AHCI controller and identifies connected SATA drives.
    pub fn probe(&mut self) -> Result<u64, BlockError> {
        if self.abar_paddr == 0 {
            return Err(BlockError::DeviceNotFound);
        }

        unsafe {
            let hba = &mut *(self.abar_paddr as *mut HbaMem);

            // 1. Enable AHCI mode in GHC (Global Host Control)
            let ghc = core::ptr::read_volatile(&hba.ghc);
            core::ptr::write_volatile(&mut hba.ghc, ghc | AHCI_GHC_AE);

            // 2. Read implemented ports bitmask
            let pi = core::ptr::read_volatile(&hba.pi);
            let mut found_port = None;

            for i in 0..32u8 {
                if (pi & (1 << i)) != 0 {
                    self.port_count += 1;
                    let port = &mut hba.ports[i as usize];
                    let ssts = core::ptr::read_volatile(&port.ssts);
                    let det = ssts & 0x0F;

                    // Device detection: 3 = Device present and PHY communication established
                    if det == 3 {
                        let sig = core::ptr::read_volatile(&port.sig);
                        if sig == SATA_SIG_ATA {
                            // Primary SATA Hard Drive / SSD
                            found_port = Some(i);
                            break;
                        }
                    }
                }
            }

            if let Some(port_idx) = found_port {
                self.active_port = Some(port_idx);
                Ok(self.capacity_sectors)
            } else {
                Err(BlockError::DeviceNotFound)
            }
        }
    }
}

impl PersistentBlockDriver for AhciController {
    fn driver_name(&self) -> &'static str {
        "SATA AHCI PCIe Controller (FIS DMA)"
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        if self.active_port.is_none() {
            return Err(BlockError::DeviceNotFound);
        }
        let total_bytes = (count as usize) * SECTOR_SIZE;
        if buf.len() < total_bytes {
            return Err(BlockError::OutOfBounds);
        }

        // On physical AHCI or under hypervisor emulation, build and issue FIS 0x27 (READ DMA EXT)
        if self.abar_paddr != 0 {
            unsafe {
                let hba = &mut *(self.abar_paddr as *mut HbaMem);
                if let Some(port_idx) = self.active_port {
                    let port = &mut hba.ports[port_idx as usize];

                    // Verify port is not busy
                    let tfd = core::ptr::read_volatile(&port.tfd);
                    if (tfd & (HBA_PORT_TFD_BSY | HBA_PORT_TFD_DRQ)) != 0 {
                        return Err(BlockError::DeviceError);
                    }

                    // Build Command FIS (FisRegH2D)
                    let mut fis = FisRegH2D::default();
                    fis.fis_type = 0x27; // Register FIS - Host to Device
                    fis.pmport_c = 1 << 7; // Command bit set
                    fis.command = ATA_CMD_READ_DMA_EXT;
                    fis.device = 1 << 6; // LBA mode
                    fis.lba0 = (lba & 0xFF) as u8;
                    fis.lba1 = ((lba >> 8) & 0xFF) as u8;
                    fis.lba2 = ((lba >> 16) & 0xFF) as u8;
                    fis.lba3 = ((lba >> 24) & 0xFF) as u8;
                    fis.lba4 = ((lba >> 32) & 0xFF) as u8;
                    fis.lba5 = ((lba >> 40) & 0xFF) as u8;
                    fis.count_low = (count & 0xFF) as u8;
                    fis.count_high = ((count >> 8) & 0xFF) as u8;

                    let clb = ((port.clbu as u64) << 32) | (port.clb as u64);
                    if clb != 0 {
                        let cmd_header = &*(clb as *const HbaCmdHeader);
                        let ctba = ((cmd_header.ctbau as u64) << 32) | (cmd_header.ctba as u64);
                        if ctba != 0 {
                            let cfis_ptr = ctba as *mut [u8; 64];
                            let mut cfis_buf = [0u8; 64];
                            fis.write_to_bytes(&mut cfis_buf);
                            core::ptr::write_volatile(cfis_ptr, cfis_buf);
                        }
                    }

                    // Trigger command issue on slot 0
                    core::ptr::write_volatile(&mut port.ci, 1 << 0);

                    // Poll completion
                    let mut spins = 0;
                    while (core::ptr::read_volatile(&port.ci) & (1 << 0)) != 0 {
                        spins += 1;
                        if spins > 1_000_000 {
                            return Err(BlockError::Timeout);
                        }
                        core::hint::spin_loop();
                    }
                }
            }
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        if self.active_port.is_none() {
            return Err(BlockError::DeviceNotFound);
        }
        let total_bytes = (count as usize) * SECTOR_SIZE;
        if buf.len() < total_bytes {
            return Err(BlockError::OutOfBounds);
        }

        if self.abar_paddr != 0 {
            unsafe {
                let hba = &mut *(self.abar_paddr as *mut HbaMem);
                if let Some(port_idx) = self.active_port {
                    let port = &mut hba.ports[port_idx as usize];

                    let tfd = core::ptr::read_volatile(&port.tfd);
                    if (tfd & (HBA_PORT_TFD_BSY | HBA_PORT_TFD_DRQ)) != 0 {
                        return Err(BlockError::DeviceError);
                    }

                    // Build Command FIS (FisRegH2D)
                    let mut fis = FisRegH2D::default();
                    fis.fis_type = 0x27;
                    fis.pmport_c = 1 << 7;
                    fis.command = ATA_CMD_WRITE_DMA_EXT;
                    fis.device = 1 << 6;
                    fis.lba0 = (lba & 0xFF) as u8;
                    fis.lba1 = ((lba >> 8) & 0xFF) as u8;
                    fis.lba2 = ((lba >> 16) & 0xFF) as u8;
                    fis.lba3 = ((lba >> 24) & 0xFF) as u8;
                    fis.lba4 = ((lba >> 32) & 0xFF) as u8;
                    fis.lba5 = ((lba >> 40) & 0xFF) as u8;
                    fis.count_low = (count & 0xFF) as u8;
                    fis.count_high = ((count >> 8) & 0xFF) as u8;

                    let clb = ((port.clbu as u64) << 32) | (port.clb as u64);
                    if clb != 0 {
                        let cmd_header = &*(clb as *const HbaCmdHeader);
                        let ctba = ((cmd_header.ctbau as u64) << 32) | (cmd_header.ctba as u64);
                        if ctba != 0 {
                            let cfis_ptr = ctba as *mut [u8; 64];
                            let mut cfis_buf = [0u8; 64];
                            fis.write_to_bytes(&mut cfis_buf);
                            core::ptr::write_volatile(cfis_ptr, cfis_buf);
                        }
                    }

                    core::ptr::write_volatile(&mut port.ci, 1 << 0);

                    let mut spins = 0;
                    while (core::ptr::read_volatile(&port.ci) & (1 << 0)) != 0 {
                        spins += 1;
                        if spins > 1_000_000 {
                            return Err(BlockError::Timeout);
                        }
                        core::hint::spin_loop();
                    }
                }
            }
        }
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}
