//! kheap — an intrusive free-list heap allocator with coalescing.
//!
//! Replaces `alloc_boot`'s bump allocator, whose inability to recycle freed
//! memory was a correct, real criticism: any workload with a dynamic
//! allocation lifecycle (parsing a variable number of network packets,
//! building up and tearing down short-lived buffers) would monotonically
//! exhaust the bump arena and panic, even though most of that memory had
//! long since been logically freed.
//!
//! This allocator is still bounded to a fixed-size arena (real, unbounded,
//! kcore-Untyped-backed heap growth is a larger, separate change — see the
//! crate-level note in `kpaging` for the same "don't rewrite two
//! hardware-facing things in one pass" reasoning) — but within that arena,
//! memory genuinely comes back: `dealloc` returns a block to a free list,
//! merging it with any adjacent free neighbour, and `alloc` reuses freed
//! space via first-fit search rather than only ever moving a watermark
//! forward.
//!
//! The free list is intrusive — each free block's own first bytes hold its
//! list node (size + next-pointer) — the classic technique that needs no
//! separate bookkeeping allocation to track free space. `unsafe` is
//! confined to the raw pointer work that technique requires; every block
//! has a SAFETY comment.
#![no_std]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

/// Minimum block size: must be able to hold a `FreeNode` even after the
/// requested allocation is carved out and the remainder becomes a new free
/// block — otherwise a split could produce a free block too small to ever
/// be reused, quietly leaking arena space forever.
const MIN_BLOCK: usize = size_of::<FreeNode>();

#[repr(C)]
struct FreeNode {
    size: usize,
    next: Option<NonNull<FreeNode>>,
}

/// Stored immediately before each returned pointer so deallocation can return
/// alignment padding to the original block and coalesce the exact allocation.
#[repr(C)]
struct AllocationHeader {
    block_start: usize,
    block_size: usize,
}

/// A minimal spinlock — no OS to block on yet, and `GlobalAlloc` requires
/// `Sync`. Single-threaded today (no SMP bring-up), but the lock is real
/// rather than assumed-unnecessary, so turning on a second CPU later
/// doesn't silently reintroduce a race here.
struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}
// SAFETY: `data` is only ever accessed while `locked` is held (see `lock()`
// below), which is exactly what makes exclusive access — and therefore
// `Sync` — sound here.
unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    const fn new(data: T) -> Self {
        SpinLock { locked: AtomicBool::new(false), data: UnsafeCell::new(data) }
    }

    fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }
}

struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}
impl<T> core::ops::Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard means we hold the lock.
        unsafe { &*self.lock.data.get() }
    }
}
impl<T> core::ops::DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard means we hold the lock.
        unsafe { &mut *self.lock.data.get() }
    }
}
impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

struct Inner {
    head: Option<NonNull<FreeNode>>,
    /// Diagnostics only — not required for correctness, but makes "did
    /// fragmentation actually cause this alloc to fail" answerable.
    free_bytes: usize,
}
// SAFETY: `Inner` is only ever reached through the `SpinLock` above, which
// serializes access — there is no path to it that doesn't go through the
// lock, so moving it across threads inside the lock is sound.
unsafe impl Send for Inner {}

pub struct FreeListAllocator {
    inner: SpinLock<Inner>,
}

impl FreeListAllocator {
    pub const fn empty() -> Self {
        FreeListAllocator { inner: SpinLock::new(Inner { head: None, free_bytes: 0 }) }
    }

    /// Hand the allocator a region of memory to manage. `start` must be
    /// valid for `size` bytes, exclusively owned (nothing else reads or
    /// writes it), and `size` must be at least `MIN_BLOCK`.
    ///
    /// # Safety
    /// Caller guarantees the region described above is real, live, and not
    /// aliased by anything else — this is the kernel's one boot-time
    /// opportunity to hand over a real physical range; calling this twice
    /// with overlapping regions, or with memory that's freed or reused
    /// elsewhere, is undefined behaviour same as any other raw-memory API.
    pub unsafe fn init(&self, start: *mut u8, size: usize) {
        let base = start as usize;
        let aligned_start = (base + MIN_BLOCK - 1) & !(MIN_BLOCK - 1);
        let end = (base + size) & !(MIN_BLOCK - 1);
        if end <= aligned_start || end - aligned_start < MIN_BLOCK {
            return;
        }
        let usable_size = end - aligned_start;
        let node_ptr = aligned_start as *mut FreeNode;
        // SAFETY: caller's contract above (`start` valid, exclusively owned,
        // `size >= MIN_BLOCK`) is exactly what makes this write sound.
        unsafe {
            node_ptr.write(FreeNode { size: usable_size, next: None });
        }
        let mut inner = self.inner.lock();
        inner.head = NonNull::new(node_ptr);
        inner.free_bytes = usable_size;
    }

    /// Bytes currently available to satisfy an allocation (sum of the free
    /// list, not counting per-allocation header/splitting overhead that
    /// hasn't happened yet). Diagnostic only.
    pub fn free_bytes(&self) -> usize {
        self.inner.lock().free_bytes
    }

    /// Returns (total_free_bytes, free_block_count, max_free_block_size)
    pub fn dump_stats(&self) -> (usize, usize, usize) {
        let inner = self.inner.lock();
        let mut count = 0;
        let mut max_sz = 0;
        let mut cur = inner.head;
        while let Some(n) = cur {
            count += 1;
            let sz = unsafe { n.as_ref().size };
            if sz > max_sz { max_sz = sz; }
            cur = unsafe { n.as_ref().next };
        }
        (inner.free_bytes, count, max_sz)
    }

    fn do_alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align().max(core::mem::align_of::<FreeNode>()).max(MIN_BLOCK);
        let raw_size = layout.size().max(MIN_BLOCK);
        let Some(size) = raw_size.checked_add(MIN_BLOCK - 1).map(|s| s & !(MIN_BLOCK - 1)) else {
            return core::ptr::null_mut();
        };
        let header_size = size_of::<AllocationHeader>();

        let mut inner = self.inner.lock();
        let mut prev: Option<NonNull<FreeNode>> = None;
        let mut cur = inner.head;

        while let Some(node_ptr) = cur {
            // SAFETY: every pointer in this list was either written by
            // `init` or by `do_dealloc` below, both of which only ever
            // link in live, correctly-sized `FreeNode`s.
            let node = unsafe { node_ptr.as_ref() };
            let block_start = node_ptr.as_ptr() as usize;
            let Some(after_header) = block_start.checked_add(header_size) else { return core::ptr::null_mut(); };
            let Some(alignment_sum) = after_header.checked_add(align - 1) else { return core::ptr::null_mut(); };
            let aligned_payload = alignment_sum & !(align - 1);
            let needed_end = aligned_payload.checked_add(size);

            if let Some(needed_end) = needed_end.filter(|end| *end >= block_start && *end - block_start <= node.size) {
                let block_size = node.size;
                let next = node.next;

                // Include alignment padding in this allocation. The header
                // records the full consumed range so deallocation can return it.
                let allocation_start = block_start;
                let block_end = block_start + block_size;
                let remainder = block_end - needed_end;
                let rem_is_kept = remainder >= MIN_BLOCK;
                let allocation_end = if rem_is_kept { needed_end } else { block_end };
                let mut first_replacement: Option<NonNull<FreeNode>> = next;

                if rem_is_kept {
                    let rem_ptr = allocation_end as *mut FreeNode;
                    unsafe { rem_ptr.write(FreeNode { size: remainder, next: first_replacement }) };
                    first_replacement = NonNull::new(rem_ptr);
                }

                // Link the in-place replacement into the list exactly where `cur` was
                match prev {
                    Some(mut p) => unsafe { p.as_mut().next = first_replacement },
                    None => inner.head = first_replacement,
                }

                let allocated_size = allocation_end - allocation_start;
                inner.free_bytes -= allocated_size;
                let ptr = aligned_payload as *mut u8;
                // SAFETY: the header lies in the allocation's owned prefix and
                // is naturally aligned because both the node and payload are
                // aligned to at least MIN_BLOCK.
                unsafe {
                    ptr.sub(header_size).cast::<AllocationHeader>().write(AllocationHeader {
                        block_start: allocation_start,
                        block_size: allocated_size,
                    });
                }
                return ptr;
            }

            prev = cur;
            cur = node.next;
        }

        core::ptr::null_mut() // no block big enough — caller (alloc_error_handler) decides what to do
    }

    fn do_dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() { return; }
        let header_size = size_of::<AllocationHeader>();
        // SAFETY: GlobalAlloc's contract requires this pointer to have been
        // returned by `do_alloc` with the matching layout. Its header is thus
        // live immediately before the pointer.
        let header = unsafe { ptr.sub(header_size).cast::<AllocationHeader>().read() };

        // GrapheneOS hardened_malloc principle: zero-on-free. Scrub the full
        // consumed block, including alignment padding and allocator metadata.
        unsafe {
            core::ptr::write_bytes(header.block_start as *mut u8, 0x00, header.block_size);
        }

        let mut inner = self.inner.lock();

        // Insert in address order and coalesce with either neighbour whose
        // address range is exactly adjacent. Address-ordering the list is
        // what makes "is my left/right neighbour adjacent" a cheap,
        // single-pass check instead of a search.
        let addr = header.block_start;
        let size = header.block_size;
        let mut prev: Option<NonNull<FreeNode>> = None;
        let mut cur = inner.head;
        while let Some(node_ptr) = cur {
            if node_ptr.as_ptr() as usize > addr {
                break;
            }
            prev = cur;
            // SAFETY: see do_alloc — every linked node is live.
            cur = unsafe { node_ptr.as_ref().next };
        }

        // Try to merge into the previous (left) neighbour.
        let merged_left = if let Some(mut p) = prev {
            // SAFETY: `p` is a live node from the list walk above.
            let p_ref = unsafe { p.as_mut() };
            if (p.as_ptr() as usize) + p_ref.size == addr {
                p_ref.size += size;
                // If the (now-extended) left block also touches `cur`, merge that in too.
                if let Some(next_node) = cur {
                    // SAFETY: `next_node` is a live node from the list walk above.
                    let next_ref = unsafe { next_node.as_ref() };
                    if (p.as_ptr() as usize) + p_ref.size == next_node.as_ptr() as usize {
                        p_ref.size += next_ref.size;
                        p_ref.next = next_ref.next;
                    }
                }
                inner.free_bytes += size;
                true
            } else {
                false
            }
        } else {
            false
        };
        if merged_left {
            return;
        }

        // Try to merge into the next (right) neighbour instead.
        if let Some(next_node) = cur {
            if addr + size == next_node.as_ptr() as usize {
                // SAFETY: `next_node` is a live node from the list walk above.
                let next_size = unsafe { next_node.as_ref().size };
                let next_next = unsafe { next_node.as_ref().next };
                let new_node_ptr = addr as *mut FreeNode;
                // SAFETY: `addr` is the block the caller is freeing (their
                // contract via `GlobalAlloc::dealloc`), now unreferenced by
                // anything live; `next_node` is being absorbed into it and
                // is not read again after this write.
                unsafe { new_node_ptr.write(FreeNode { size: size + next_size, next: next_next }) };
                let new_node = NonNull::new(new_node_ptr);
                match prev {
                    // SAFETY: `p` is a live node from the list walk above.
                    Some(mut p) => unsafe { p.as_mut().next = new_node },
                    None => inner.head = new_node,
                }
                inner.free_bytes += size;
                return;
            }
        }

        // No adjacent neighbour: link in as a standalone free block.
        let new_node_ptr = addr as *mut FreeNode;
        // SAFETY: same as above — this is the caller's just-freed block.
        unsafe { new_node_ptr.write(FreeNode { size, next: cur }) };
        let new_node = NonNull::new(new_node_ptr);
        match prev {
            // SAFETY: `p` is a live node from the list walk above.
            Some(mut p) => unsafe { p.as_mut().next = new_node },
            None => inner.head = new_node,
        }
        inner.free_bytes += size;
    }
}

impl Default for FreeListAllocator {
    fn default() -> Self {
        Self::empty()
    }
}

// SAFETY: `do_alloc`/`do_dealloc` only ever touch memory inside the region
// handed to `init`, and only through the lock-protected free list — the
// standard `GlobalAlloc` contract (caller passes a `Layout` matching the one
// used to allocate, for dealloc) is the caller's, not this impl's, to keep.
unsafe impl GlobalAlloc for FreeListAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.do_alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.do_dealloc(ptr, layout)
    }
}
