//! High-Assurance User-Space Memory Allocator & Rust GlobalAlloc Substrate.
//!
//! Provides standard POSIX `malloc`, `free`, `calloc`, `realloc` and implements
//! `core::alloc::GlobalAlloc` for `#![no_std]` Rust userland applications.
//!
//! Security features:
//! - 16-byte payload alignment.
//! - Guard canary word (`0xDEAD_BEEF_CAFE_BABE`) on every chunk header.
//! - Canary verification on `free` and `realloc` to immediately detect heap buffer underflows.
//! - Free list block coalescing.
//! - Dual backing: `brk` for small-to-medium objects, anonymous `mmap` for large objects (>= 64 KiB).

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};
use crate::posix;

pub const CANARY_MAGIC: u64 = 0xDEAD_BEEF_CAFE_BABE;
pub const FLAG_IN_USE: usize = 0x1;
pub const FLAG_MMAP: usize   = 0x2;
pub const ALIGNMENT: usize   = 16;
pub const MMAP_THRESHOLD: usize = 64 * 1024; // 64 KiB

#[repr(C, align(16))]
pub struct ChunkHeader {
    pub size: usize,
    pub flags: usize,
    pub canary: u64,
    pub next: *mut ChunkHeader,
    pub prev: *mut ChunkHeader,
}

impl ChunkHeader {
    #[inline(always)]
    pub fn is_in_use(&self) -> bool {
        (self.flags & FLAG_IN_USE) != 0
    }

    #[inline(always)]
    pub fn is_mmap(&self) -> bool {
        (self.flags & FLAG_MMAP) != 0
    }

    #[inline(always)]
    pub fn payload_ptr(&self) -> *mut u8 {
        unsafe { (self as *const ChunkHeader as *mut u8).add(core::mem::size_of::<ChunkHeader>()) }
    }

    #[inline(always)]
    pub unsafe fn from_payload(ptr: *mut u8) -> *mut ChunkHeader {
        unsafe { (ptr as *mut ChunkHeader).sub(1) }
    }
}

pub struct UserHeap {
    free_head: *mut ChunkHeader,
    brk_base: *mut u8,
    brk_current: *mut u8,
    initialized: bool,
}

unsafe impl Send for UserHeap {}

impl UserHeap {
    pub const fn new() -> Self {
        Self {
            free_head: core::ptr::null_mut(),
            brk_base: core::ptr::null_mut(),
            brk_current: core::ptr::null_mut(),
            initialized: false,
        }
    }

    /// Initialize the heap break pointer from kernel.
    pub fn init(&mut self) {
        if !self.initialized {
            let current = posix::brk(core::ptr::null());
            self.brk_base = current;
            self.brk_current = current;
            self.initialized = true;
        }
    }

    /// Reset heap state (used during test harnesses).
    pub fn reset(&mut self) {
        self.free_head = core::ptr::null_mut();
        self.brk_base = core::ptr::null_mut();
        self.brk_current = core::ptr::null_mut();
        self.initialized = false;
    }

    /// Allocate `size` bytes of memory with 16-byte alignment.
    pub unsafe fn allocate(&mut self, size: usize) -> *mut u8 {
        if size == 0 {
            return core::ptr::null_mut();
        }
        self.init();

        // Round size up to multiple of 16
        let aligned_size = (size + (ALIGNMENT - 1)) & !(ALIGNMENT - 1);
        let total_size = aligned_size + core::mem::size_of::<ChunkHeader>();

        // Large allocations bypass brk and use anonymous mmap
        if total_size >= MMAP_THRESHOLD {
            let page_aligned = (total_size + 4095) & !4095;
            let mmap_res = posix::mmap(
                core::ptr::null_mut(),
                page_aligned,
                posix::PROT_READ | posix::PROT_WRITE,
                posix::MAP_PRIVATE | posix::MAP_ANONYMOUS,
                -1,
                0,
            );
            if let Ok(addr) = mmap_res {
                let header = addr as *mut ChunkHeader;
                unsafe {
                    (*header).size = page_aligned;
                    (*header).flags = FLAG_IN_USE | FLAG_MMAP;
                    (*header).canary = CANARY_MAGIC;
                    (*header).next = core::ptr::null_mut();
                    (*header).prev = core::ptr::null_mut();
                    return (*header).payload_ptr();
                }
            } else {
                return core::ptr::null_mut();
            }
        }

        // Search free list for best fit
        let mut curr = self.free_head;
        while !curr.is_null() {
            unsafe {
                if (*curr).canary != CANARY_MAGIC {
                    panic!("KashOS User Heap: canary corruption detected in free list");
                }
                if !(*curr).is_in_use() && (*curr).size >= total_size {
                    // Split chunk if remaining size is large enough
                    let remainder = (*curr).size - total_size;
                    if remainder >= core::mem::size_of::<ChunkHeader>() + ALIGNMENT {
                        let new_chunk = (curr as *mut u8).add(total_size) as *mut ChunkHeader;
                        (*new_chunk).size = remainder;
                        (*new_chunk).flags = 0;
                        (*new_chunk).canary = CANARY_MAGIC;
                        (*new_chunk).next = (*curr).next;
                        (*new_chunk).prev = curr;

                        if !(*curr).next.is_null() {
                            (*(*curr).next).prev = new_chunk;
                        }
                        (*curr).next = new_chunk;
                        (*curr).size = total_size;
                    }

                    (*curr).flags |= FLAG_IN_USE;
                    return (*curr).payload_ptr();
                }
                curr = (*curr).next;
            }
        }

        // Expand heap via brk in 64 KiB increments
        let request_expand = total_size.max(64 * 1024);
        let new_brk = unsafe { self.brk_current.add(request_expand) };
        let confirmed_brk = posix::brk(new_brk);
        if confirmed_brk < new_brk {
            return core::ptr::null_mut(); // Out of memory
        }

        let header = self.brk_current as *mut ChunkHeader;
        self.brk_current = confirmed_brk;

        unsafe {
            (*header).size = total_size;
            (*header).flags = FLAG_IN_USE;
            (*header).canary = CANARY_MAGIC;
            (*header).next = core::ptr::null_mut();
            (*header).prev = core::ptr::null_mut();

            // Link to free list
            if self.free_head.is_null() {
                self.free_head = header;
            } else {
                let mut tail = self.free_head;
                while !(*tail).next.is_null() {
                    tail = (*tail).next;
                }
                (*tail).next = header;
                (*header).prev = tail;
            }

            // Remainder becomes free chunk
            let remainder = request_expand - total_size;
            if remainder >= core::mem::size_of::<ChunkHeader>() + ALIGNMENT {
                let rem_header = (header as *mut u8).add(total_size) as *mut ChunkHeader;
                (*rem_header).size = remainder;
                (*rem_header).flags = 0;
                (*rem_header).canary = CANARY_MAGIC;
                (*rem_header).next = core::ptr::null_mut();
                (*rem_header).prev = header;
                (*header).next = rem_header;
            }

            (*header).payload_ptr()
        }
    }

    /// Free a previously allocated buffer.
    pub unsafe fn deallocate(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }

        let header = unsafe { ChunkHeader::from_payload(ptr) };
        unsafe {
            if (*header).canary != CANARY_MAGIC {
                panic!("KashOS User Heap: canary corruption detected during free()!");
            }
            if !(*header).is_in_use() {
                // Double-free guard
                return;
            }

            if (*header).is_mmap() {
                let size = (*header).size;
                let _ = posix::munmap(header as *mut u8, size);
                return;
            }

            (*header).flags &= !FLAG_IN_USE;

            // Coalesce with next chunk if free
            let next = (*header).next;
            if !next.is_null() && !(*next).is_in_use() && !(*next).is_mmap() {
                (*header).size += (*next).size;
                (*header).next = (*next).next;
                if !(*next).next.is_null() {
                    (*(*next).next).prev = header;
                }
            }

            // Coalesce with previous chunk if free
            let prev = (*header).prev;
            if !prev.is_null() && !(*prev).is_in_use() && !(*prev).is_mmap() {
                (*prev).size += (*header).size;
                (*prev).next = (*header).next;
                if !(*header).next.is_null() {
                    (*(*header).next).prev = prev;
                }
            }
        }
    }

    /// Reallocate memory to a new size.
    pub unsafe fn reallocate(&mut self, ptr: *mut u8, new_size: usize) -> *mut u8 {
        if ptr.is_null() {
            return unsafe { self.allocate(new_size) };
        }
        if new_size == 0 {
            unsafe { self.deallocate(ptr) };
            return core::ptr::null_mut();
        }

        let header = unsafe { ChunkHeader::from_payload(ptr) };
        unsafe {
            if (*header).canary != CANARY_MAGIC {
                panic!("KashOS User Heap: canary corruption detected during realloc()!");
            }
            let current_payload_size = (*header).size - core::mem::size_of::<ChunkHeader>();
            if current_payload_size >= new_size {
                return ptr; // Already satisfies request
            }

            let new_ptr = self.allocate(new_size);
            if new_ptr.is_null() {
                return core::ptr::null_mut();
            }

            core::ptr::copy_nonoverlapping(ptr, new_ptr, current_payload_size);
            self.deallocate(ptr);
            new_ptr
        }
    }
}

// ── Thread-Safe Allocator Spinlock ───────────────────────────────────────────

pub struct SpinLock<T> {
    lock: AtomicBool,
    data: core::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            lock: AtomicBool::new(false),
            data: core::cell::UnsafeCell::new(data),
        }
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.lock.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
        SpinLockGuard { parent: self }
    }
}

pub struct SpinLockGuard<'a, T> {
    parent: &'a SpinLock<T>,
}

impl<'a, T> core::ops::Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.parent.data.get() }
    }
}

impl<'a, T> core::ops::DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.parent.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.parent.lock.store(false, Ordering::Release);
    }
}

pub static USER_HEAP: SpinLock<UserHeap> = SpinLock::new(UserHeap::new());

// ── Standard C POSIX Memory Functions ────────────────────────────────────────

#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut u8 {
    let mut heap = USER_HEAP.lock();
    unsafe { heap.allocate(size) }
}

#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    let mut heap = USER_HEAP.lock();
    unsafe { heap.deallocate(ptr) }
}

#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut u8 {
    let total = match nmemb.checked_mul(size) {
        Some(t) => t,
        None => return core::ptr::null_mut(),
    };
    let ptr = unsafe { malloc(total) };
    if !ptr.is_null() {
        for i in 0..total {
            unsafe { *ptr.add(i) = 0 };
        }
    }
    ptr
}

#[cfg_attr(not(any(test, feature = "host_testing")), no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    let mut heap = USER_HEAP.lock();
    unsafe { heap.reallocate(ptr, size) }
}

// ── Rust GlobalAlloc Implementation ──────────────────────────────────────────

pub struct KashUserAllocator;

unsafe impl GlobalAlloc for KashUserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut heap = USER_HEAP.lock();
        unsafe { heap.allocate(layout.size()) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let mut heap = USER_HEAP.lock();
        unsafe { heap.deallocate(ptr) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8 {
        let mut heap = USER_HEAP.lock();
        unsafe { heap.reallocate(ptr, new_size) }
    }
}
