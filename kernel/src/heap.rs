//! Kernel global allocator: kheap's coalescing free-list allocator,
//! initialised from a real, discovered region of hardware RAM once
//! hardware discovery completes (see `main.rs`'s boot sequence) — not from
//! a fixed static-BSS arena.
//!
//! This replaces the previous bump allocator, whose inability to recycle
//! freed memory was a correct, real criticism from the project's own
//! architecture audit: any workload with a dynamic allocation lifecycle
//! would have monotonically exhausted that arena and panicked, no matter
//! how much of it had been logically freed. See `kheap`'s crate docs for
//! the allocator itself; this module is just the kernel's one `static` for
//! it plus the wiring main.rs needs to hand it real memory.
//!
//! Before `init` is called, the allocator is valid but empty — any
//! too-early allocation attempt fails safely (returns null, which
//! `alloc_error_handler` below turns into a clear, diagnostic panic)
//! rather than silently corrupting memory. There is deliberately no
//! implicit fallback arena to paper over that.
#![allow(unsafe_code)]
use core::alloc::{GlobalAlloc, Layout};
use kheap::FreeListAllocator;

static ALLOCATOR: FreeListAllocator = FreeListAllocator::empty();

struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { ALLOCATOR.alloc(layout) };
        if ptr.is_null() {
            let (free, count, max_b) = ALLOCATOR.dump_stats();
            crate::kprintln!("[alloc-fail] size={} align={} | heap: free={} count={} max_block={}",
                             layout.size(), layout.align(), free, count, max_b);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { ALLOCATOR.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static GLOBAL: KernelAllocator = KernelAllocator;

/// Hand the global allocator a real region of hardware RAM. Must be called
/// at most once, with a region no other subsystem also claims — main.rs's
/// boot sequence picks two disjoint entries from `platform.free`
/// specifically to guarantee this (see its region-selection comment).
///
/// # Safety
/// Same contract as `kheap::FreeListAllocator::init`: `start`/`size` must
/// describe real, live, exclusively-owned memory.
pub unsafe fn init(start: u64, size: u64) {
    unsafe { ALLOCATOR.init(start as *mut u8, size as usize) };
}

pub fn free_bytes() -> usize {
    ALLOCATOR.free_bytes()
}

pub fn dump_stats() -> (usize, usize, usize) {
    ALLOCATOR.dump_stats()
}

/// Exercise the real, live global allocator — not a host test, the actual
/// one this kernel is booting with — before claiming it works. Proves
/// recycling happens in practice (free_bytes returns to its starting value
/// after a batch of allocations are all freed), the same property
/// `kheap`'s own `repeated_same_size_alloc_dealloc_does_not_leak_space`
/// host test checks, now checked again here against real hardware memory
/// instead of a host-allocated stand-in for it.
pub fn selftest() {
    extern crate alloc;
    use alloc::string::String;
    use alloc::vec::Vec;

    let before = free_bytes();

    let mut v: Vec<u32> = Vec::new();
    for i in 0..256u32 {
        v.push(i * i);
    }
    for (i, &x) in v.iter().enumerate() {
        if x != (i as u32) * (i as u32) {
            panic!("heap selftest: Vec<u32> content mismatch at index {i}");
        }
    }

    let s = String::from("Kash Kernel heap self-test string, built on real discovered RAM");
    if s.len() != 63 {
        panic!("heap selftest: String length mismatch");
    }

    drop(v);
    drop(s);

    // Recycling proof: a batch of same-size allocations, all freed, must
    // return the allocator to exactly where it started — not "close to",
    // exactly, or something is being lost.
    for _ in 0..500 {
        let scratch: Vec<u8> = alloc::vec![0xAAu8; 4096];
        core::hint::black_box(&scratch);
    }

    let after = free_bytes();
    if after != before {
        panic!("heap selftest: {before} bytes free before, {after} after — memory is leaking, not being recycled");
    }

    kprintln!("[selftest] heap allocator: ok (Vec/String exercised; {before} bytes free, unchanged after 500 alloc/free cycles)");
}
