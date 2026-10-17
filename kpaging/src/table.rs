use crate::error::{PageError, PageResult};

pub const PAGE_SIZE: usize = 4096;
pub const ENTRIES: usize = 512;

/// Supplies physical page frames to carve new page tables from. Both
/// architectures' 4-level walks use 512-entry, 4 KiB-aligned tables, so one
/// trait and one `PageTable` layout cover both — only the *descriptor
/// encoding* written into each slot differs (see `x86_64.rs` / `aarch64.rs`).
pub trait FrameAllocator {
    /// Return the physical address of a freshly zeroed 4 KiB frame.
    fn allocate_frame(&mut self) -> PageResult<u64>;
    fn deallocate_frame(&mut self, paddr: u64);
}

impl<T: FrameAllocator + ?Sized> FrameAllocator for &mut T {
    fn allocate_frame(&mut self) -> PageResult<u64> {
        (**self).allocate_frame()
    }
    fn deallocate_frame(&mut self, paddr: u64) {
        (**self).deallocate_frame(paddr)
    }
}

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; ENTRIES],
}

impl PageTable {
    pub const fn empty() -> Self {
        PageTable { entries: [0u64; ENTRIES] }
    }
}

/// Split a 4 KiB-aligned virtual address into its four 9-bit level indices.
/// Identical shape on both architectures for a 4-level, 4 KiB-granule walk:
/// x86-64 PML4/PDPT/PD/PT and AArch64 (4 KiB granule) L0/L1/L2/L3.
#[inline]
pub fn split_indices(vaddr: u64) -> PageResult<[usize; 4]> {
    if vaddr % PAGE_SIZE as u64 != 0 {
        return Err(PageError::Misaligned);
    }
    Ok([
        ((vaddr >> 39) & 0x1FF) as usize,
        ((vaddr >> 30) & 0x1FF) as usize,
        ((vaddr >> 21) & 0x1FF) as usize,
        ((vaddr >> 12) & 0x1FF) as usize,
    ])
}
