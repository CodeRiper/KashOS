use kheap::FreeListAllocator;
use std::alloc::{GlobalAlloc, Layout};

const ARENA_SIZE: usize = 1 << 20; // 1 MiB

fn new_allocator() -> (FreeListAllocator, *mut u8) {
    // Allocate directly through the system allocator rather than
    // `Box::new([0u8; ARENA_SIZE])`: the latter builds the full array as a
    // stack temporary before moving it into the box (debug builds don't
    // reliably elide this), which overflows a test thread's default stack
    // for an arena this size — a test-harness artifact, not a kheap bug.
    let layout = Layout::from_size_align(ARENA_SIZE, 4096).unwrap();
    let start = unsafe { std::alloc::alloc(layout) };
    assert!(!start.is_null());
    let a = FreeListAllocator::empty();
    unsafe { a.init(start, ARENA_SIZE) };
    (a, start)
}

#[test]
fn single_alloc_and_dealloc_returns_all_space() {
    let (a, _) = new_allocator();
    let before = a.free_bytes();
    let layout = Layout::from_size_align(256, 8).unwrap();
    let p = unsafe { a.alloc(layout) };
    assert!(!p.is_null());
    assert!(a.free_bytes() < before);
    unsafe { a.dealloc(p, layout) };
    assert_eq!(a.free_bytes(), before, "freeing the only allocation must return the arena to its original size");
}

#[test]
fn allocations_never_overlap() {
    let (a, _) = new_allocator();
    let layout = Layout::from_size_align(128, 8).unwrap();
    let mut ptrs = Vec::new();
    for i in 0..100u8 {
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        unsafe { std::ptr::write_bytes(p, i, 128) }; // stamp a unique pattern
        ptrs.push(p);
    }
    // Every allocation's pattern must still read back exactly as written —
    // if any two allocations overlapped, a later write would have
    // clobbered an earlier one's bytes.
    for (i, &p) in ptrs.iter().enumerate() {
        let slice = unsafe { std::slice::from_raw_parts(p, 128) };
        assert!(slice.iter().all(|&b| b == i as u8), "allocation {i} corrupted — overlap?");
    }
    for p in ptrs {
        unsafe { a.dealloc(p, layout) };
    }
}

#[test]
fn respects_a_range_of_alignments() {
    let (a, _) = new_allocator();
    for &align in &[1usize, 2, 4, 8, 16, 32, 64, 256, 4096] {
        let layout = Layout::from_size_align(37, align).unwrap(); // odd size on purpose
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null(), "alloc failed for align={align}");
        assert_eq!((p as usize) % align, 0, "pointer not aligned to {align}");
        unsafe { a.dealloc(p, layout) };
    }
}

#[test]
fn repeated_same_size_alloc_dealloc_does_not_leak_space() {
    // The whole point of this allocator over a bump allocator: this loop
    // would exhaust a bump arena almost immediately. Here, free space must
    // stay bounded because dealloc genuinely returns it.
    let (a, _) = new_allocator();
    let before = a.free_bytes();
    let layout = Layout::from_size_align(4096, 16).unwrap();
    for _ in 0..10_000 {
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null(), "ran out of space — memory is not being recycled");
        unsafe { a.dealloc(p, layout) };
    }
    assert_eq!(a.free_bytes(), before);
}

#[test]
fn freed_blocks_fully_coalesce_back_into_one() {
    // Fill the arena exactly with fixed-size, suitably-aligned chunks (no
    // alignment padding, so splitting introduces no stray small blocks),
    // free them all in a scrambled, non-sequential order, then prove they
    // coalesced completely by successfully allocating the *entire* arena
    // back as a single block — impossible unless every freed piece merged
    // with its neighbours instead of staying fragmented.
    let (a, start) = new_allocator();
    let chunk = 4096usize;
    let n = ARENA_SIZE / chunk;
    // Reserve the allocator's in-band header while keeping each aligned
    // allocation exactly one chunk wide.
    let layout = Layout::from_size_align(chunk - 2 * std::mem::size_of::<usize>(), 16).unwrap();

    let mut ptrs = Vec::new();
    for _ in 0..n {
        let p = unsafe { a.alloc(layout) };
        assert!(!p.is_null());
        ptrs.push(p);
    }
    assert_eq!(a.free_bytes(), 0, "arena should be exactly full");

    // Free in an order designed to exercise merge-left, merge-right, and
    // merge-both-sides cases, not just sequential free.
    let order = [3usize, 1, 0, 2].into_iter().cycle();
    let mut remaining: Vec<usize> = (0..n).collect();
    let mut scrambled = Vec::new();
    for pick in order {
        if remaining.is_empty() {
            break;
        }
        let idx = pick % remaining.len();
        scrambled.push(remaining.remove(idx));
    }
    for idx in scrambled {
        unsafe { a.dealloc(ptrs[idx], layout) };
    }
    assert_eq!(a.free_bytes(), ARENA_SIZE);

    let (free, blocks, max_block) = a.dump_stats();
    assert_eq!(free, ARENA_SIZE);
    assert_eq!(blocks, 1, "free chunks must coalesce into one arena-sized block");
    assert_eq!(max_block, ARENA_SIZE);
    let whole = unsafe { a.alloc(Layout::from_size_align(ARENA_SIZE - 8192, 16).unwrap()) };
    assert!(!whole.is_null(), "coalesced arena must satisfy one large aligned allocation");
    assert_eq!(whole as usize, start as usize + 16, "aligned payload must preserve its header");
}

#[test]
fn exhaustion_returns_null_not_a_panic() {
    let (a, _) = new_allocator();
    let layout = Layout::from_size_align(ARENA_SIZE * 2, 8).unwrap(); // deliberately too big
    let p = unsafe { a.alloc(layout) };
    assert!(p.is_null());
    // The allocator must still be usable afterwards — a failed alloc must
    // not have corrupted the free list.
    let small = unsafe { a.alloc(Layout::from_size_align(64, 8).unwrap()) };
    assert!(!small.is_null());
}

#[test]
fn zero_sized_allocation_does_not_crash_or_corrupt() {
    let (a, _) = new_allocator();
    let layout = Layout::from_size_align(0, 1).unwrap();
    let p = unsafe { a.alloc(layout) };
    if !p.is_null() {
        unsafe { a.dealloc(p, layout) };
    }
    // Arena must still be fully usable afterwards.
    let normal = unsafe { a.alloc(Layout::from_size_align(64, 8).unwrap()) };
    assert!(!normal.is_null());
}

/// Deterministic xorshift64 — same generator style used in this project's
/// other fuzz-style tests (kcore). No external RNG dependency needed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn fuzz_random_alloc_dealloc_never_corrupts_or_overlaps() {
    let (a, _) = new_allocator();
    let mut rng = Rng(0xA11CE);
    let mut live: Vec<(*mut u8, Layout, u8)> = Vec::new();

    for i in 0..20_000u32 {
        if !live.is_empty() && (rng.below(3) == 0 || live.len() > 200) {
            // Free a random live allocation, checking its canary first.
            let idx = rng.below(live.len() as u64) as usize;
            let (p, layout, tag) = live.swap_remove(idx);
            let slice = unsafe { std::slice::from_raw_parts(p, layout.size()) };
            assert!(slice.iter().all(|&b| b == tag), "corruption detected at iteration {i}");
            unsafe { a.dealloc(p, layout) };
        } else {
            let size = 1 + rng.below(512) as usize;
            let align = [1usize, 2, 4, 8, 16, 32][rng.below(6) as usize];
            let layout = Layout::from_size_align(size, align).unwrap();
            let p = unsafe { a.alloc(layout) };
            if p.is_null() {
                continue; // legitimate under fragmentation/exhaustion — not a bug by itself
            }
            for &(q, q_layout, _) in &live {
                let p0 = p as usize;
                let p1 = p0 + layout.size();
                let q0 = q as usize;
                let q1 = q0 + q_layout.size();
                assert!(p1 <= q0 || q1 <= p0, "overlapping live allocations at iteration {i}: new {p0:#x}..{p1:#x} (size {}, align {}) old {q0:#x}..{q1:#x} (size {}, align {})", layout.size(), layout.align(), q_layout.size(), q_layout.align());
            }
            let tag = (i % 256) as u8;
            unsafe { std::ptr::write_bytes(p, tag, size) };
            live.push((p, layout, tag));
        }
    }
    // Drain everything and confirm no corruption on the way out either.
    for (p, layout, tag) in live {
        let slice = unsafe { std::slice::from_raw_parts(p, layout.size()) };
        assert!(slice.iter().all(|&b| b == tag), "corruption detected during drain");
        unsafe { a.dealloc(p, layout) };
    }
}
