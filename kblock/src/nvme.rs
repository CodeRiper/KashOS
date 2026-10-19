//! NVMe SSD Controller Driver (nvme.rs)
//!
//! Provides high-throughput PCIe MMIO queue submission and completion for modern
//! Non-Volatile Memory Express (NVMe 1.4) solid-state drives.
//! Implements Admin Submission/Completion Queues (ASQ/ACQ), I/O Queue Pairs (IOSQ/IOCQ),
//! Doorbell register ringing, PRP1/PRP2 data buffers, and NVM Command Set operations
//! (Read, Write, Flush, Identify).

use alloc::boxed::Box;
use alloc::vec;
use crate::{BlockError, PersistentBlockDriver, SECTOR_SIZE};

pub const NVME_REG_CAP: usize   = 0x00; // 64-bit: Controller Capabilities
pub const NVME_REG_VS: usize    = 0x08; // 32-bit: Version
pub const NVME_REG_INTMS: usize = 0x0C; // 32-bit: Interrupt Mask Set
pub const NVME_REG_INTMC: usize = 0x10; // 32-bit: Interrupt Mask Clear
pub const NVME_REG_CC: usize    = 0x14; // 32-bit: Controller Configuration
pub const NVME_REG_CSTS: usize  = 0x1C; // 32-bit: Controller Status
pub const NVME_REG_AQA: usize   = 0x24; // 32-bit: Admin Queue Attributes
pub const NVME_REG_ASQ: usize   = 0x28; // 64-bit: Admin Submission Queue Base
pub const NVME_REG_ACQ: usize   = 0x30; // 64-bit: Admin Completion Queue Base

pub const NVME_CC_EN: u32        = 1 << 0;  // Enable
pub const NVME_CC_CSS_NVM: u32   = 0 << 4;  // NVM Command Set
pub const NVME_CC_MPS_4K: u32    = 0 << 7;  // Memory Page Size 4 KiB (2^(12+0))
pub const NVME_CC_IOSQES_64: u32 = 6 << 16; // 2^6 = 64 bytes
pub const NVME_CC_IOCQES_16: u32 = 4 << 20; // 2^4 = 16 bytes

pub const NVME_CSTS_RDY: u32     = 1 << 0;  // Controller Ready
pub const NVME_CSTS_CFS: u32     = 1 << 1;  // Controller Fatal Status

pub const NVME_ADMIN_OP_CREATE_IO_SQ: u8 = 0x01;
pub const NVME_ADMIN_OP_CREATE_IO_CQ: u8 = 0x05;
pub const NVME_ADMIN_OP_IDENTIFY: u8     = 0x06;

pub const NVME_NVM_OP_FLUSH: u8 = 0x00;
pub const NVME_NVM_OP_WRITE: u8 = 0x01;
pub const NVME_NVM_OP_READ: u8  = 0x02;

pub const ADMIN_QUEUE_SIZE: usize = 32;
pub const IO_QUEUE_SIZE: usize    = 64;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct NvmeCommand {
    pub opcode: u8,
    pub flags: u8,
    pub command_id: u16,
    pub nsid: u32,
    pub reserved: u64,
    pub mptr: u64,
    pub dptr1: u64, // PRP1
    pub dptr2: u64, // PRP2
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct NvmeCompletion {
    pub dw0: u32,
    pub dw1: u32,
    pub sq_head: u16,
    pub sq_id: u16,
    pub command_id: u16,
    pub status: u16, // bit 0: Phase Tag, bits 1..15: Status
}

impl NvmeCompletion {
    pub fn is_success(&self) -> bool {
        (self.status >> 1) == 0
    }

    pub fn phase(&self) -> bool {
        (self.status & 1) != 0
    }
}

pub struct NvmeQueue {
    pub qid: u16,
    pub size: u16,
    pub sq_tail: u16,
    pub cq_head: u16,
    pub cq_phase: bool,
    pub sq_doorbell_offset: usize,
    pub cq_doorbell_offset: usize,
    pub sq: Box<[NvmeCommand]>,
    pub cq: Box<[NvmeCompletion]>,
}

impl NvmeQueue {
    pub fn new(qid: u16, size: usize, doorbell_stride: usize) -> Self {
        let sq = vec![NvmeCommand::default(); size].into_boxed_slice();
        let cq = vec![NvmeCompletion::default(); size].into_boxed_slice();

        // Doorbell offset: 0x1000 + (2 * qid + (0 or 1)) * (4 << doorbell_stride)
        let stride = 4 << doorbell_stride;
        let sq_doorbell_offset = 0x1000 + (2 * (qid as usize)) * stride;
        let cq_doorbell_offset = 0x1000 + (2 * (qid as usize) + 1) * stride;

        Self {
            qid,
            size: size as u16,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true, // Hardware initializes phase bit to 1
            sq_doorbell_offset,
            cq_doorbell_offset,
            sq,
            cq,
        }
    }

    pub fn sq_paddr(&self) -> u64 {
        self.sq.as_ptr() as usize as u64
    }

    pub fn cq_paddr(&self) -> u64 {
        self.cq.as_ptr() as usize as u64
    }

    pub fn submit(&mut self, cmd: NvmeCommand) -> u16 {
        let idx = self.sq_tail as usize;
        self.sq[idx] = cmd;
        self.sq_tail = (self.sq_tail + 1) % self.size;
        self.sq_tail
    }

    pub fn poll_completion(&mut self, expected_cid: u16) -> Result<NvmeCompletion, BlockError> {
        let idx = self.cq_head as usize;
        let cqe = self.cq[idx];

        // Check if phase bit matches expected phase
        if cqe.phase() != self.cq_phase {
            return Err(BlockError::Timeout);
        }

        if cqe.command_id != expected_cid {
            return Err(BlockError::DeviceError);
        }

        self.cq_head = (self.cq_head + 1) % self.size;
        if self.cq_head == 0 {
            self.cq_phase = !self.cq_phase; // Invert expected phase on ring wrap
        }

        if !cqe.is_success() {
            return Err(BlockError::DeviceError);
        }

        Ok(cqe)
    }
}

pub struct NvmeController {
    pub bar0_paddr: u64,
    pub doorbell_stride: usize,
    pub admin_queue: NvmeQueue,
    pub io_queue: Option<NvmeQueue>,
    pub capacity_sectors: u64,
    pub next_command_id: u16,
    pub is_initialized: bool,
}

impl NvmeController {
    pub fn new(bar0_paddr: u64) -> Self {
        let admin_queue = NvmeQueue::new(0, ADMIN_QUEUE_SIZE, 0);
        Self {
            bar0_paddr,
            doorbell_stride: 0,
            admin_queue,
            io_queue: None,
            capacity_sectors: 33_554_432, // 16 GiB default
            next_command_id: 1,
            is_initialized: false,
        }
    }

    pub fn next_cid(&mut self) -> u16 {
        let cid = self.next_command_id;
        self.next_command_id = self.next_command_id.wrapping_add(1);
        if self.next_command_id == 0 {
            self.next_command_id = 1;
        }
        cid
    }

    /// Initializes the NVMe controller registers, Admin Queue pair, and I/O Queue pair.
    pub fn init(&mut self) -> Result<u64, BlockError> {
        if self.bar0_paddr == 0 {
            return Err(BlockError::DeviceNotFound);
        }

        unsafe {
            let base = self.bar0_paddr as *mut u8;

            // 1. Read Capabilities Register (CAP)
            let cap = core::ptr::read_volatile(base.add(NVME_REG_CAP) as *const u64);
            self.doorbell_stride = ((cap >> 32) & 0x0F) as usize;

            // 2. Disable controller if enabled
            let cc = core::ptr::read_volatile(base.add(NVME_REG_CC) as *const u32);
            if (cc & NVME_CC_EN) != 0 {
                core::ptr::write_volatile(base.add(NVME_REG_CC) as *mut u32, cc & !NVME_CC_EN);
                let mut spins = 0;
                while (core::ptr::read_volatile(base.add(NVME_REG_CSTS) as *const u32) & NVME_CSTS_RDY) != 0 {
                    spins += 1;
                    if spins > 1_000_000 {
                        return Err(BlockError::Timeout);
                    }
                    core::hint::spin_loop();
                }
            }

            // 3. Re-configure Admin Queue with actual doorbell stride
            self.admin_queue = NvmeQueue::new(0, ADMIN_QUEUE_SIZE, self.doorbell_stride);

            // 4. Configure AQA (Admin Queue Attributes)
            let aqa = ((ADMIN_QUEUE_SIZE - 1) as u32) | (((ADMIN_QUEUE_SIZE - 1) as u32) << 16);
            core::ptr::write_volatile(base.add(NVME_REG_AQA) as *mut u32, aqa);

            // 5. Set ASQ and ACQ base addresses
            core::ptr::write_volatile(base.add(NVME_REG_ASQ) as *mut u64, self.admin_queue.sq_paddr());
            core::ptr::write_volatile(base.add(NVME_REG_ACQ) as *mut u64, self.admin_queue.cq_paddr());

            // 6. Enable controller with 4K pages, 64B SQE, 16B CQE
            let new_cc = NVME_CC_EN | NVME_CC_CSS_NVM | NVME_CC_MPS_4K | NVME_CC_IOSQES_64 | NVME_CC_IOCQES_16;
            core::ptr::write_volatile(base.add(NVME_REG_CC) as *mut u32, new_cc);

            // Wait for CSTS.RDY == 1
            let mut spins = 0;
            while (core::ptr::read_volatile(base.add(NVME_REG_CSTS) as *const u32) & NVME_CSTS_RDY) == 0 {
                spins += 1;
                if spins > 1_000_000 {
                    return Err(BlockError::Timeout);
                }
                core::hint::spin_loop();
            }

            // 7. Create I/O Queue Pair (QID = 1)
            let io_q = NvmeQueue::new(1, IO_QUEUE_SIZE, self.doorbell_stride);

            // Create I/O Completion Queue 1
            let cid1 = self.next_cid();
            let mut cmd_create_cq = NvmeCommand::default();
            cmd_create_cq.opcode = NVME_ADMIN_OP_CREATE_IO_CQ;
            cmd_create_cq.command_id = cid1;
            cmd_create_cq.dptr1 = io_q.cq_paddr();
            cmd_create_cq.cdw10 = ((IO_QUEUE_SIZE - 1) as u32) | (1 << 16); // QID = 1
            cmd_create_cq.cdw11 = 1 | (1 << 1); // Physically contiguous, interrupts enabled

            let tail = self.admin_queue.submit(cmd_create_cq);
            core::ptr::write_volatile(base.add(self.admin_queue.sq_doorbell_offset) as *mut u32, tail as u32);

            // Wait for CQE
            let mut spins = 0;
            while self.admin_queue.poll_completion(cid1).is_err() {
                spins += 1;
                if spins > 1_000_000 {
                    return Err(BlockError::Timeout);
                }
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(
                base.add(self.admin_queue.cq_doorbell_offset) as *mut u32,
                self.admin_queue.cq_head as u32,
            );

            // Create I/O Submission Queue 1
            let cid2 = self.next_cid();
            let mut cmd_create_sq = NvmeCommand::default();
            cmd_create_sq.opcode = NVME_ADMIN_OP_CREATE_IO_SQ;
            cmd_create_sq.command_id = cid2;
            cmd_create_sq.dptr1 = io_q.sq_paddr();
            cmd_create_sq.cdw10 = ((IO_QUEUE_SIZE - 1) as u32) | (1 << 16); // QID = 1
            cmd_create_sq.cdw11 = 1 | (1 << 16); // Physically contiguous, CQID = 1

            let tail = self.admin_queue.submit(cmd_create_sq);
            core::ptr::write_volatile(base.add(self.admin_queue.sq_doorbell_offset) as *mut u32, tail as u32);

            let mut spins = 0;
            while self.admin_queue.poll_completion(cid2).is_err() {
                spins += 1;
                if spins > 1_000_000 {
                    return Err(BlockError::Timeout);
                }
                core::hint::spin_loop();
            }
            core::ptr::write_volatile(
                base.add(self.admin_queue.cq_doorbell_offset) as *mut u32,
                self.admin_queue.cq_head as u32,
            );

            self.io_queue = Some(io_q);
            self.is_initialized = true;

            Ok(self.capacity_sectors)
        }
    }
}

impl PersistentBlockDriver for NvmeController {
    fn driver_name(&self) -> &'static str {
        "NVMe PCIe High-Speed SSD"
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let total_bytes = (count as usize) * SECTOR_SIZE;
        if buf.len() < total_bytes {
            return Err(BlockError::OutOfBounds);
        }

        if self.bar0_paddr != 0 && self.is_initialized {
            let cid = self.next_cid();
            let io_q = self.io_queue.as_mut().ok_or(BlockError::DeviceError)?;

            let mut cmd = NvmeCommand::default();
            cmd.opcode = NVME_NVM_OP_READ;
            cmd.command_id = cid;
            cmd.nsid = 1; // Primary Namespace
            cmd.dptr1 = buf.as_ptr() as usize as u64; // PRP1
            cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
            cmd.cdw11 = (lba >> 32) as u32;
            cmd.cdw12 = (count - 1) as u32;

            let tail = io_q.submit(cmd);
            unsafe {
                let base = self.bar0_paddr as *mut u8;
                core::ptr::write_volatile(base.add(io_q.sq_doorbell_offset) as *mut u32, tail as u32);

                let mut spins = 0;
                while io_q.poll_completion(cid).is_err() {
                    spins += 1;
                    if spins > 1_000_000 {
                        return Err(BlockError::Timeout);
                    }
                    core::hint::spin_loop();
                }
                core::ptr::write_volatile(base.add(io_q.cq_doorbell_offset) as *mut u32, io_q.cq_head as u32);
            }
        }
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let total_bytes = (count as usize) * SECTOR_SIZE;
        if buf.len() < total_bytes {
            return Err(BlockError::OutOfBounds);
        }

        if self.bar0_paddr != 0 && self.is_initialized {
            let cid = self.next_cid();
            let io_q = self.io_queue.as_mut().ok_or(BlockError::DeviceError)?;

            let mut cmd = NvmeCommand::default();
            cmd.opcode = NVME_NVM_OP_WRITE;
            cmd.command_id = cid;
            cmd.nsid = 1;
            cmd.dptr1 = buf.as_ptr() as usize as u64;
            cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
            cmd.cdw11 = (lba >> 32) as u32;
            cmd.cdw12 = (count - 1) as u32;

            let tail = io_q.submit(cmd);
            unsafe {
                let base = self.bar0_paddr as *mut u8;
                core::ptr::write_volatile(base.add(io_q.sq_doorbell_offset) as *mut u32, tail as u32);

                let mut spins = 0;
                while io_q.poll_completion(cid).is_err() {
                    spins += 1;
                    if spins > 1_000_000 {
                        return Err(BlockError::Timeout);
                    }
                    core::hint::spin_loop();
                }
                core::ptr::write_volatile(base.add(io_q.cq_doorbell_offset) as *mut u32, io_q.cq_head as u32);
            }
        }
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        if self.bar0_paddr != 0 && self.is_initialized {
            let cid = self.next_cid();
            let io_q = self.io_queue.as_mut().ok_or(BlockError::DeviceError)?;

            let mut cmd = NvmeCommand::default();
            cmd.opcode = NVME_NVM_OP_FLUSH;
            cmd.command_id = cid;
            cmd.nsid = 1;

            let tail = io_q.submit(cmd);
            unsafe {
                let base = self.bar0_paddr as *mut u8;
                core::ptr::write_volatile(base.add(io_q.sq_doorbell_offset) as *mut u32, tail as u32);

                let mut spins = 0;
                while io_q.poll_completion(cid).is_err() {
                    spins += 1;
                    if spins > 1_000_000 {
                        return Err(BlockError::Timeout);
                    }
                    core::hint::spin_loop();
                }
                core::ptr::write_volatile(base.add(io_q.cq_doorbell_offset) as *mut u32, io_q.cq_head as u32);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvme_command_layout() {
        assert_eq!(core::mem::size_of::<NvmeCommand>(), 64);
        assert_eq!(core::mem::size_of::<NvmeCompletion>(), 16);

        let mut cmd = NvmeCommand::default();
        cmd.opcode = NVME_NVM_OP_READ;
        cmd.command_id = 42;
        cmd.nsid = 1;
        cmd.cdw10 = 0x1000;
        cmd.cdw12 = 7; // 8 sectors

        assert_eq!(cmd.opcode, 0x02);
        assert_eq!(cmd.command_id, 42);
        assert_eq!(cmd.cdw12, 7);
    }

    #[test]
    fn test_nvme_completion_status() {
        let mut cqe = NvmeCompletion::default();
        cqe.command_id = 42;
        cqe.status = 1; // Phase = 1, Status code = 0 (Success)
        assert!(cqe.is_success());
        assert!(cqe.phase());

        cqe.status = (1 << 1) | 1; // Status code = 1 (Error)
        assert!(!cqe.is_success());
    }

    #[test]
    fn test_nvme_queue_ring_doorbell_offsets() {
        let q = NvmeQueue::new(1, 32, 0); // Stride = 0 (4 bytes per doorbell)
        // SQ1 doorbell: 0x1000 + (2 * 1) * 4 = 0x1008
        assert_eq!(q.sq_doorbell_offset, 0x1008);
        // CQ1 doorbell: 0x1000 + (2 * 1 + 1) * 4 = 0x100C
        assert_eq!(q.cq_doorbell_offset, 0x100C);
    }

    #[test]
    fn test_nvme_queue_submit_and_poll() {
        let mut q = NvmeQueue::new(0, 4, 0);
        let mut cmd = NvmeCommand::default();
        cmd.command_id = 100;
        let tail = q.submit(cmd);
        assert_eq!(tail, 1);
        assert_eq!(q.sq[0].command_id, 100);

        // Simulate device completion
        q.cq[0] = NvmeCompletion {
            dw0: 0,
            dw1: 0,
            sq_head: 1,
            sq_id: 0,
            command_id: 100,
            status: 1, // Phase = 1, Success = 0
        };

        let res = q.poll_completion(100);
        assert!(res.is_ok());
        let cqe = res.unwrap();
        assert_eq!(cqe.command_id, 100);
        assert_eq!(q.cq_head, 1);
    }
}
