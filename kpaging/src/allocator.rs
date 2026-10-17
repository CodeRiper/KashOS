//! Physical frame allocator with domain ownership tracking and quotas.
//!
//! Enforces:
//! 1. Memory isolation: frames are tagged with an owning domain ID (0 = kernel/dom0,
//!    1 = sys-net, 2 = personal, etc.).
//! 2. Quota bounding: prevents one domain from consuming more than its designated
//!    budget of physical frames, ensuring no domain can exhaust kernel or system memory.
//! 3. Bounded, safe execution: strictly index-checked without unwraps or panics.

use crate::error::{PageError, PageResult};
use crate::table::{FrameAllocator, PAGE_SIZE};

pub const MAX_DOMAINS: usize = 8;
pub const DEFAULT_FRAME_CAPACITY: usize = 2048;
const FREE_FRAME: u8 = 0xFF;

pub struct QuotaFrameAllocator<const N: usize = DEFAULT_FRAME_CAPACITY> {
    base_paddr: u64,
    frame_count: usize,
    owners: [u8; N],
    domain_quotas: [usize; MAX_DOMAINS],
    domain_usage: [usize; MAX_DOMAINS],
}

impl<const N: usize> QuotaFrameAllocator<N> {
    /// Initialize a quota-tracking frame allocator.
    pub fn new(base_paddr: u64, frame_count: usize, domain_quotas: [usize; MAX_DOMAINS]) -> PageResult<Self> {
        if base_paddr % PAGE_SIZE as u64 != 0 {
            return Err(PageError::Misaligned);
        }
        if frame_count > N {
            return Err(PageError::OutOfFrames);
        }

        Ok(QuotaFrameAllocator {
            base_paddr,
            frame_count,
            owners: [FREE_FRAME; N],
            domain_quotas,
            domain_usage: [0; MAX_DOMAINS],
        })
    }

    /// Allocate a frame specifically on behalf of a compartment/domain.
    pub fn allocate_for_domain(&mut self, domain_id: usize) -> PageResult<u64> {
        if domain_id >= MAX_DOMAINS {
            return Err(PageError::InvalidDomain);
        }

        let quota = self.domain_quotas.get(domain_id).copied().ok_or(PageError::InvalidDomain)?;
        let usage = self.domain_usage.get(domain_id).copied().ok_or(PageError::InvalidDomain)?;

        if usage >= quota {
            return Err(PageError::QuotaExceeded);
        }

        for (i, owner) in self.owners.iter_mut().take(self.frame_count).enumerate() {
            if *owner == FREE_FRAME {
                *owner = domain_id as u8;
                if let Some(u) = self.domain_usage.get_mut(domain_id) {
                    *u += 1;
                }
                let paddr = self.base_paddr.wrapping_add((i as u64).wrapping_mul(PAGE_SIZE as u64));
                return Ok(paddr);
            }
        }

        Err(PageError::OutOfFrames)
    }

    /// Deallocate a physical frame, decrementing the owner's usage counter.
    /// Returns the domain ID that previously owned the frame.
    pub fn deallocate_frame_checked(&mut self, paddr: u64) -> PageResult<usize> {
        if paddr % PAGE_SIZE as u64 != 0 || paddr < self.base_paddr {
            return Err(PageError::Misaligned);
        }

        let offset = paddr.wrapping_sub(self.base_paddr);
        let index = (offset / (PAGE_SIZE as u64)) as usize;

        if index >= self.frame_count {
            return Err(PageError::FrameNotAllocated);
        }

        let owner_byte = self.owners.get_mut(index).ok_or(PageError::FrameNotAllocated)?;
        if *owner_byte == FREE_FRAME {
            return Err(PageError::FrameNotAllocated);
        }

        let domain_id = *owner_byte as usize;
        *owner_byte = FREE_FRAME;

        if let Some(u) = self.domain_usage.get_mut(domain_id) {
            if *u > 0 {
                *u -= 1;
            }
        }

        Ok(domain_id)
    }

    /// Query the domain that owns a specific physical frame.
    pub fn frame_owner(&self, paddr: u64) -> PageResult<usize> {
        if paddr % PAGE_SIZE as u64 != 0 || paddr < self.base_paddr {
            return Err(PageError::Misaligned);
        }

        let offset = paddr.wrapping_sub(self.base_paddr);
        let index = (offset / (PAGE_SIZE as u64)) as usize;

        if index >= self.frame_count {
            return Err(PageError::FrameNotAllocated);
        }

        let owner_byte = self.owners.get(index).copied().ok_or(PageError::FrameNotAllocated)?;
        if owner_byte == FREE_FRAME {
            return Err(PageError::FrameNotAllocated);
        }

        Ok(owner_byte as usize)
    }

    /// Read the number of frames currently allocated by a domain.
    pub fn domain_usage(&self, domain_id: usize) -> PageResult<usize> {
        self.domain_usage.get(domain_id).copied().ok_or(PageError::InvalidDomain)
    }

    /// Read the maximum frame quota granted to a domain.
    pub fn domain_quota(&self, domain_id: usize) -> PageResult<usize> {
        self.domain_quotas.get(domain_id).copied().ok_or(PageError::InvalidDomain)
    }

    /// Return total physical frames managed.
    pub fn total_frames(&self) -> usize {
        self.frame_count
    }
}

impl<const N: usize> FrameAllocator for QuotaFrameAllocator<N> {
    fn allocate_frame(&mut self) -> PageResult<u64> {
        // Default allocation charges domain 0 (kernel/dom0)
        self.allocate_for_domain(0)
    }

    fn deallocate_frame(&mut self, paddr: u64) {
        let _ = self.deallocate_frame_checked(paddr);
    }
}
