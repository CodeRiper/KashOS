//! Host-side tests that exercise the *real* `unsafe` table-walking code in
//! `mapper.rs` — not a simulation of it. `FrameAllocator` here hands out
//! heap-allocated, 4 KiB-aligned `PageTable`s (guaranteed by `PageTable`'s
//! own `#[repr(align(4096))]`) and returns their real process addresses as
//! "physical" addresses; `VirtualSpace` then does genuine raw-pointer reads
//! and writes through those addresses exactly as it would through real
//! physical memory in the kernel. A logic bug in the walk — wrong index
//! math, an off-by-one in which table level gets written, a permission bit
//! landing in the wrong place — shows up here as a real wrong answer or a
//! real crash, not just a type error.
use kpaging::{AArch64, Arch, FrameAllocator, PageError, PageTable, Perm, VirtualSpace, X86_64, PAGE_SIZE};

struct HeapAllocator {
    allocated: std::vec::Vec<u64>,
}
impl HeapAllocator {
    fn new() -> Self {
        HeapAllocator { allocated: std::vec::Vec::new() }
    }
}
impl FrameAllocator for HeapAllocator {
    fn allocate_frame(&mut self) -> Result<u64, PageError> {
        let boxed = std::boxed::Box::new(PageTable::empty());
        let addr = std::boxed::Box::leak(boxed) as *mut PageTable as u64;
        assert_eq!(addr % PAGE_SIZE as u64, 0, "PageTable's align(4096) must hold");
        self.allocated.push(addr);
        Ok(addr)
    }
    fn deallocate_frame(&mut self, _paddr: u64) {
        // Tests intentionally leak — fine for process-lifetime test runs.
    }
}

fn new_space<A: Arch>() -> VirtualSpace<HeapAllocator, A> {
    let mut alloc = HeapAllocator::new();
    let root = alloc.allocate_frame().unwrap();
    VirtualSpace::new(root, alloc)
}

// Run the same logical test against both architectures' real encodings.
macro_rules! both_archs {
    ($name:ident, $body:expr) => {
        mod $name {
            use super::*;
            #[test]
            fn x86_64() {
                let f: fn(VirtualSpace<HeapAllocator, X86_64>) = $body;
                f(new_space::<X86_64>());
            }
            #[test]
            fn aarch64() {
                let f: fn(VirtualSpace<HeapAllocator, AArch64>) = $body;
                f(new_space::<AArch64>());
            }
        }
    };
}

both_archs!(map_then_translate_round_trips, |mut vs| {
    let vaddr = 0x4000_0000u64;
    let paddr = 0x1234_5000u64 & !0xFFFu64; // arbitrary, page-aligned "physical" frame
    vs.map_4k(vaddr, paddr, Perm::KERNEL_RW).unwrap();
    let (frame, _entry) = vs.translate(vaddr).unwrap();
    assert_eq!(frame, paddr);
});

both_archs!(double_map_is_rejected, |mut vs| {
    let vaddr = 0x5000_0000u64;
    vs.map_4k(vaddr, 0x2000, Perm::KERNEL_RW).unwrap();
    assert_eq!(vs.map_4k(vaddr, 0x3000, Perm::KERNEL_RW), Err(PageError::AlreadyMapped));
});

both_archs!(unmap_then_remap_works, |mut vs| {
    let vaddr = 0x6000_0000u64;
    vs.map_4k(vaddr, 0x4000, Perm::KERNEL_RW).unwrap();
    let freed = vs.unmap_4k(vaddr).unwrap();
    assert_eq!(freed, 0x4000);
    assert_eq!(vs.translate(vaddr), Err(PageError::NotMapped));
    vs.map_4k(vaddr, 0x5000, Perm::KERNEL_RO).unwrap();
    assert_eq!(vs.translate(vaddr).unwrap().0, 0x5000);
});

both_archs!(unmap_of_unmapped_address_is_rejected, |mut vs| {
    assert_eq!(vs.unmap_4k(0x7000_0000), Err(PageError::NotMapped));
});

both_archs!(misaligned_addresses_are_rejected, |mut vs| {
    assert_eq!(vs.map_4k(0x1001, 0x2000, Perm::KERNEL_RW), Err(PageError::Misaligned));
    assert_eq!(vs.map_4k(0x1000, 0x2001, Perm::KERNEL_RW), Err(PageError::Misaligned));
});

both_archs!(write_and_execute_together_is_always_rejected, |mut vs| {
    let wx = Perm { user: false, writable: true, executable: true, device: false };
    assert_eq!(vs.map_4k(0x8000_0000, 0x6000, wx), Err(PageError::WriteExecuteViolation));
    // ...and nothing was actually mapped by the rejected call.
    assert_eq!(vs.translate(0x8000_0000), Err(PageError::NotMapped));
});

both_archs!(sibling_pages_in_the_same_2mib_region_share_their_l3_table, |mut vs| {
    // Two addresses 4 KiB apart differ only in the final (L3) index, so the
    // walk should create L1/L2/L3 tables once and reuse them for the second
    // mapping — exercising the "already present, return existing" path in
    // get_or_create_child rather than only ever the "allocate new" path.
    let a = 0x9000_0000u64;
    let b = a + PAGE_SIZE as u64;
    vs.map_4k(a, 0x7000, Perm::KERNEL_RW).unwrap();
    vs.map_4k(b, 0x8000, Perm::KERNEL_RW).unwrap();
    assert_eq!(vs.translate(a).unwrap().0, 0x7000);
    assert_eq!(vs.translate(b).unwrap().0, 0x8000);
});

both_archs!(many_scattered_mappings_all_resolve_correctly, |mut vs| {
    // Spread across many different L1/L2/L3 regions, not just adjacent pages.
    let mut expected = std::vec::Vec::new();
    for i in 0u64..200 {
        let vaddr = 0x1_0000_0000u64 + i * 0x0100_0000; // 16 MiB apart: different L2 entries
        let paddr = 0x1000 + i * PAGE_SIZE as u64;
        vs.map_4k(vaddr, paddr, Perm::KERNEL_RW).unwrap();
        expected.push((vaddr, paddr));
    }
    for (vaddr, paddr) in expected {
        assert_eq!(vs.translate(vaddr).unwrap().0, paddr, "mismatch at {vaddr:#x}");
    }
});

both_archs!(kernel_and_user_pages_are_distinguishable_after_mapping, |mut vs| {
    let kern = 0xA000_0000u64;
    let user = 0xB000_0000u64;
    vs.map_4k(kern, 0x9000, Perm::KERNEL_RW).unwrap();
    vs.map_4k(user, 0xA000, Perm::USER_RW).unwrap();
    let (_, kern_entry) = vs.translate(kern).unwrap();
    let (_, user_entry) = vs.translate(user).unwrap();
    assert_ne!(kern_entry & 0xFFF, user_entry & 0xFFF, "kernel and user leaf flags must differ");
});

#[test]
fn x86_64_executable_pages_are_never_user_and_writable_at_once_even_by_construction() {
    // Belt-and-braces: USER_RX and KERNEL_RX, the only built-in executable
    // Perm constants, must never carry the writable bit — if someone edits
    // `Perm`'s constants later, this fails loudly instead of silently
    // reintroducing a W^X hole.
    assert!(!Perm::USER_RX.writable);
    assert!(!Perm::KERNEL_RX.writable);
}

#[test]
fn quota_allocator_enforces_domain_budgets() {
    use kpaging::QuotaFrameAllocator;
    let mut quotas = [10; 8];
    quotas[1] = 2; // Domain 1 only gets 2 frames
    quotas[2] = 5;

    let mut alloc = QuotaFrameAllocator::<64>::new(0x10_0000, 64, quotas).unwrap();

    // Domain 1 allocates its 2 frames
    let f1 = alloc.allocate_for_domain(1).unwrap();
    let f2 = alloc.allocate_for_domain(1).unwrap();
    assert_ne!(f1, f2);
    assert_eq!(alloc.domain_usage(1).unwrap(), 2);

    // Third allocation fails with QuotaExceeded
    assert_eq!(alloc.allocate_for_domain(1), Err(PageError::QuotaExceeded));

    // Domain 2 can still allocate freely
    let f_dom2 = alloc.allocate_for_domain(2).unwrap();
    assert_eq!(alloc.frame_owner(f_dom2), Ok(2));

    // Freeing a frame for domain 1 allows it to allocate again
    let freed_owner = alloc.deallocate_frame_checked(f1).unwrap();
    assert_eq!(freed_owner, 1);
    assert_eq!(alloc.domain_usage(1).unwrap(), 1);

    let f3 = alloc.allocate_for_domain(1).unwrap();
    assert_eq!(alloc.frame_owner(f3), Ok(1));
}

#[test]
fn quota_allocator_tracks_frame_ownership() {
    use kpaging::QuotaFrameAllocator;
    let quotas = [10; 8];
    let mut alloc = QuotaFrameAllocator::<32>::new(0x20_0000, 32, quotas).unwrap();

    let f = alloc.allocate_for_domain(3).unwrap();
    assert_eq!(alloc.frame_owner(f), Ok(3));

    let prev = alloc.deallocate_frame_checked(f).unwrap();
    assert_eq!(prev, 3);
    assert_eq!(alloc.frame_owner(f), Err(PageError::FrameNotAllocated));
}

#[test]
fn share_higher_half_copies_kernel_entries_while_keeping_lower_half_clean() {
    let mut vs = new_space::<X86_64>();
    let higher_half_vaddr = 0xFFFF_8000_0000_0000u64;
    vs.map_4k(higher_half_vaddr, 0x1000, Perm::KERNEL_RX).unwrap();

    // Allocate child space
    let mut child_alloc = HeapAllocator::new();
    let child_root = child_alloc.allocate_frame().unwrap();

    vs.share_higher_half_with(child_root).unwrap();

    // Check that child table entry at index 256 matches parent table
    let parent_table = unsafe { &*(vs.root_paddr as *const PageTable) };
    let child_table = unsafe { &*(child_root as *const PageTable) };
    let idx256 = ((higher_half_vaddr >> 39) & 0x1FF) as usize;
    assert_eq!(idx256, 256);
    assert_eq!(child_table.entries[256], parent_table.entries[256]);
    assert_ne!(child_table.entries[256], 0);

    // Entry 0 (lower half) is still 0
    assert_eq!(child_table.entries[0], 0);
}
