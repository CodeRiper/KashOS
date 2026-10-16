//! Live paging switchover — shared logic.
//!
//! Builds a real, W^X-correct page table (via `kpaging`) covering the
//! kernel image split by actual section permission (`.text`
//! read+execute-only, `.rodata` read-only, `.data`/`.bss`/stack
//! read+write, never both write and execute anywhere), the regions about
//! to be handed to `kcore`'s self-test and the heap allocator, and known
//! MMIO — then each architecture's own `mod.rs` installs it, replacing the
//! provisional, undifferentiated-permission identity map built in assembly
//! before Rust even started running.
//!
//! This runs from `kmain` *before* `kcore::selftest` and `heap::init`, not
//! after — deliberately. Every region the kernel is about to use is known
//! and mapped before anything claims or writes to it, rather than trying
//! to retroactively map regions that are already live under the old
//! tables. The alternative ordering would mean the switchover itself —
//! the single highest-stakes moment in this whole change, since the very
//! instructions performing it must already be correctly mapped or the CPU
//! faults with no debugger attached — depends on correctly enumerating
//! every region *already in use*, which is a strictly harder thing to get
//! right than "nothing is in use yet, here is everywhere it's about to be."
#![allow(unsafe_code)]

use kpaging::{FrameAllocator as KpFrameAllocator, PageError, PageResult, Perm, VirtualSpace, PAGE_SIZE};

/// Hands out zeroed page-table frames from a dedicated, bump-allocated
/// region. A bump allocator — not kheap's recycling one — is the right
/// tool here: page-table frames in this one-time boot build are never
/// individually freed, only ever handed out once while the tree is built.
pub struct BumpFrameAllocator {
    next: u64,
    end: u64,
}

impl BumpFrameAllocator {
    /// # Safety
    /// `[base, base+len)` must be real, live, exclusively-owned, page-aligned memory.
    pub unsafe fn new(base: u64, len: u64) -> Self {
        BumpFrameAllocator { next: base, end: base + len }
    }
}

impl KpFrameAllocator for BumpFrameAllocator {
    fn allocate_frame(&mut self) -> PageResult<u64> {
        if self.next + PAGE_SIZE as u64 > self.end {
            return Err(PageError::OutOfFrames);
        }
        let f = self.next;
        self.next += PAGE_SIZE as u64;
        // SAFETY: `f` is inside `[base, base+len)` from `new`'s caller
        // contract, has never been handed out before (the bump pointer
        // only moves forward), and `kpaging` requires every frame it's
        // given to come back zeroed.
        unsafe { core::ptr::write_bytes(f as *mut u8, 0, PAGE_SIZE) };
        Ok(f)
    }
    fn deallocate_frame(&mut self, _paddr: u64) {
        // Not supported, and not needed for a one-time boot-time build.
    }
}

/// The kernel's own section boundaries, as provided by the linker script —
/// read once, by each architecture's `mod.rs`, from its own linker symbols.
pub struct KernelSections {
    pub text_start: u64,
    pub text_end: u64,
    pub rodata_start: u64,
    pub rodata_end: u64,
    pub data_start: u64,
    /// End of the whole kernel image (covers `.data`, `.bss`, and the boot
    /// stack, all mapped read+write, not executable).
    pub kernel_end: u64,
}

/// One MMIO device's physical range, mapped read+write and non-executable (W^X).
#[derive(Clone, Copy)]
pub struct MmioRegion {
    pub base: u64,
    pub len: u64,
    pub write_combining: bool,
}

impl MmioRegion {
    pub const fn uncached(base: u64, len: u64) -> Self {
        Self { base, len, write_combining: false }
    }

    #[allow(dead_code)]
    pub const fn write_combining(base: u64, len: u64) -> Self {
        Self { base, len, write_combining: true }
    }
}

/// Build (but do not install) the kernel's W^X page table.
///
/// `identity` is true on both architectures here (every virtual address
/// used equals its physical address) — this kernel has no higher-half
/// split yet, so `vaddr == paddr` for every mapping below.
pub fn build<A: kpaging::Arch>(
    frame_alloc: BumpFrameAllocator,
    root: u64,
    sections: &KernelSections,
    extra_rw_regions: &[(u64, u64)], // (base, len) — the regions about to become kcore's/kheap's arenas
    mmio: &[MmioRegion],
) -> VirtualSpace<BumpFrameAllocator, A> {
    let mut vs = VirtualSpace::new(root, frame_alloc);

    map_range(&mut vs, sections.text_start, sections.text_end, Perm::KERNEL_RX);
    map_range(&mut vs, sections.rodata_start, sections.rodata_end, Perm::KERNEL_RO);
    map_range(&mut vs, sections.data_start, sections.kernel_end, Perm::KERNEL_RW);

    for &(base, len) in extra_rw_regions {
        map_range(&mut vs, base, base + len, Perm::KERNEL_RW);
    }

    for m in mmio {
        let perm = if m.write_combining { Perm::KERNEL_RW } else { Perm::MMIO };
        map_range(&mut vs, m.base, m.base + m.len, perm);
    }

    vs
}

fn map_range<A: kpaging::Arch>(vs: &mut VirtualSpace<BumpFrameAllocator, A>, start: u64, end: u64, perm: Perm) {
    let start = start & !(PAGE_SIZE as u64 - 1);
    let end = (end + PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let mut addr = start;
    while addr < end {
        // A page already mapped by an earlier call in the same build (two
        // requested ranges overlapping by construction) is not an error —
        // it just means this byte's permission was already decided; take
        // the first (and therefore, by call order above, the more
        // specific/narrower) one rather than treating a sane overlap as fatal.
        match vs.map_4k(addr, addr, perm) {
            Ok(()) | Err(PageError::AlreadyMapped) => {}
            Err(e) => panic!("mmu::build: failed to map {addr:#x}: {e:?}"),
        }
        addr += PAGE_SIZE as u64;
    }
}
