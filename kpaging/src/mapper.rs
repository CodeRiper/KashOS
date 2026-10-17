use crate::error::{PageError, PageResult};
use crate::perm::{Arch, Perm};
use crate::table::{split_indices, FrameAllocator, PageTable};
use core::marker::PhantomData;

/// A single architecture's address space, as a 4-level, 4 KiB-granule page
/// table tree. Generic over `A: Arch` so the walk logic (this file) is
/// written once and shared by both `x86_64::X86_64` and `aarch64::AArch64`
/// — only each one's `leaf_descriptor`/`table_descriptor` differ.
pub struct VirtualSpace<F: FrameAllocator, A: Arch> {
    pub root_paddr: u64,
    allocator: F,
    _arch: PhantomData<A>,
}

impl<F: FrameAllocator, A: Arch> VirtualSpace<F, A> {
    pub fn new(root_paddr: u64, allocator: F) -> Self {
        VirtualSpace { root_paddr, allocator, _arch: PhantomData }
    }

    /// # Safety
    /// `paddr` must be the real physical (here: host-addressable, in the
    /// test harness) address of a live `PageTable`.
    unsafe fn table_at(paddr: u64) -> *mut PageTable {
        paddr as *mut PageTable
    }

    fn get_or_create_child(&mut self, table_paddr: u64, index: usize) -> PageResult<u64> {
        // SAFETY: `table_paddr` was produced either by the caller's initial
        // `root_paddr` (their contract) or by this same function via
        // `allocator.allocate_frame()`, which returns a fresh, live,
        // 4 KiB-aligned frame — never a dangling or unaligned address.
        let table = unsafe { &mut *Self::table_at(table_paddr) };
        let entry = table.entries[index];

        if A::is_present(entry) {
            return Ok(A::entry_table_paddr(entry));
        }

        let child = self.allocator.allocate_frame()?;
        if child % crate::table::PAGE_SIZE as u64 != 0 {
            return Err(PageError::AllocatorGaveBadFrame);
        }
        // SAFETY: `child` was just handed to us by the allocator as a fresh frame.
        unsafe { *Self::table_at(child) = PageTable::empty() };
        table.entries[index] = A::table_descriptor(child);
        Ok(child)
    }

    /// Map one 4 KiB page. Rejects `writable && executable` unconditionally
    /// — W^X is enforced here, not left to the caller to remember. A kernel
    /// that genuinely needs to write generated code should map it through
    /// two different virtual addresses backed by the same frame (one
    /// writable, one executable) and never hold both at once; this crate
    /// deliberately has no parameter that would make the unsafe case the
    /// easy case.
    pub fn map_4k(&mut self, vaddr: u64, paddr: u64, perm: Perm) -> PageResult<()> {
        if perm.writable && perm.executable {
            return Err(PageError::WriteExecuteViolation);
        }
        if paddr % crate::table::PAGE_SIZE as u64 != 0 {
            return Err(PageError::Misaligned);
        }
        let idx = split_indices(vaddr)?;

        let l1 = self.get_or_create_child(self.root_paddr, idx[0])?;
        let l2 = self.get_or_create_child(l1, idx[1])?;
        let l3 = self.get_or_create_child(l2, idx[2])?;

        // SAFETY: l3 was returned by get_or_create_child, which only ever
        // returns live, 4 KiB-aligned table addresses (see its own SAFETY note).
        let table = unsafe { &mut *Self::table_at(l3) };
        if A::is_present(table.entries[idx[3]]) {
            return Err(PageError::AlreadyMapped);
        }
        table.entries[idx[3]] = A::leaf_descriptor(paddr, perm);
        Ok(())
    }

    /// Unmap one 4 KiB page, flush its TLB entry, and return the physical
    /// frame it was backed by (the caller decides whether to free it).
    pub fn unmap_4k(&mut self, vaddr: u64) -> PageResult<u64> {
        let idx = split_indices(vaddr)?;

        // SAFETY: root_paddr is the caller's contract (a live table they gave us).
        let root = unsafe { &*Self::table_at(self.root_paddr) };
        if !A::is_present(root.entries[idx[0]]) {
            return Err(PageError::NotMapped);
        }
        let l1_paddr = A::entry_table_paddr(root.entries[idx[0]]);

        // SAFETY: l1_paddr came from a present entry this same walk engine wrote.
        let l1 = unsafe { &*Self::table_at(l1_paddr) };
        if !A::is_present(l1.entries[idx[1]]) {
            return Err(PageError::NotMapped);
        }
        let l2_paddr = A::entry_table_paddr(l1.entries[idx[1]]);

        // SAFETY: same reasoning as above.
        let l2 = unsafe { &*Self::table_at(l2_paddr) };
        if !A::is_present(l2.entries[idx[2]]) {
            return Err(PageError::NotMapped);
        }
        let l3_paddr = A::entry_table_paddr(l2.entries[idx[2]]);

        // SAFETY: same reasoning as above; this one we also mutate.
        let l3 = unsafe { &mut *Self::table_at(l3_paddr) };
        if !A::is_present(l3.entries[idx[3]]) {
            return Err(PageError::NotMapped);
        }
        let frame = A::entry_frame_paddr(l3.entries[idx[3]]);
        l3.entries[idx[3]] = 0;

        // SAFETY: the MMU-enabled / valid-vaddr contract is the caller's,
        // documented on `Arch::invalidate`.
        unsafe { A::invalidate(vaddr) };
        Ok(frame)
    }

    /// Look up the physical frame and raw descriptor backing `vaddr`, without
    /// modifying anything. Useful for tests and for a future page-fault handler.
    pub fn translate(&self, vaddr: u64) -> PageResult<(u64, u64)> {
        let idx = split_indices(vaddr)?;
        // SAFETY: see unmap_4k — identical read-only walk.
        let root = unsafe { &*Self::table_at(self.root_paddr) };
        if !A::is_present(root.entries[idx[0]]) {
            return Err(PageError::NotMapped);
        }
        let l1 = unsafe { &*Self::table_at(A::entry_table_paddr(root.entries[idx[0]])) };
        if !A::is_present(l1.entries[idx[1]]) {
            return Err(PageError::NotMapped);
        }
        let l2 = unsafe { &*Self::table_at(A::entry_table_paddr(l1.entries[idx[1]])) };
        if !A::is_present(l2.entries[idx[2]]) {
            return Err(PageError::NotMapped);
        }
        let l3 = unsafe { &*Self::table_at(A::entry_table_paddr(l2.entries[idx[2]])) };
        let entry = l3.entries[idx[3]];
        if !A::is_present(entry) {
            return Err(PageError::NotMapped);
        }
        Ok((A::entry_frame_paddr(entry), entry))
    }

    /// Shares higher-half entries (entries 256..511) of this root PML4 into child_root_paddr.
    /// This establishes shared kernel mappings across per-process address spaces while
    /// keeping lower-half user entries isolated.
    pub fn share_higher_half_with(&self, child_root_paddr: u64) -> PageResult<()> {
        if child_root_paddr % crate::table::PAGE_SIZE as u64 != 0 {
            return Err(PageError::Misaligned);
        }
        // SAFETY: self.root_paddr is a valid PML4; child_root_paddr is guaranteed aligned.
        let parent = unsafe { &*Self::table_at(self.root_paddr) };
        let child = unsafe { &mut *Self::table_at(child_root_paddr) };
        for i in 256..crate::table::ENTRIES {
            if let (Some(dst), Some(src)) = (child.entries.get_mut(i), parent.entries.get(i)) {
                *dst = *src;
            }
        }
        Ok(())
    }

    pub fn allocator(&self) -> &F {
        &self.allocator
    }

    pub fn allocator_mut(&mut self) -> &mut F {
        &mut self.allocator
    }
}
