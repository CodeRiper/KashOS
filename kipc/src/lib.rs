//! kipc — lock-free single-producer/single-consumer ring channel.
//!
//! This is the shared-memory transport Kash Kernel's IPC is meant to use
//! between two isolated components (an App VM and the Packet Inspection
//! Proxy, a driver and its Virtualizer, and so on) — each side holds a
//! capability to the *same* physical pages mapped into its own address
//! space, and `RingChannel` is what lives there.
//!
//! Status: built and tested here, including under real concurrent OS
//! threads (see `tests/`) — not yet wired into the kernel's actual IPC
//! path, which doesn't exist yet (that needs seL4 endpoints or this
//! project's own equivalent, whichever the architecture decision in the
//! project's design document ends up being).
//!
//! Memory ordering: the producer only ever writes `tail` and reads `head`;
//! the consumer only ever writes `head` and reads `tail`. A `Release` store
//! of `tail` after the payload is written, paired with an `Acquire` load of
//! `tail` before the consumer reads the payload, is what makes the payload
//! write visible — this is the standard, correct SPSC pattern, not
//! something this crate invented. The payload itself is still copied with
//! `read_volatile`/`write_volatile` on top of that: the Release/Acquire
//! pair alone would be sufficient for memory shared only between threads in
//! one address space, but this channel is meant to sit in memory shared
//! across *address spaces* (two different components, each with their own
//! capability to the same frames) — volatile is the belt-and-suspenders
//! reminder to the compiler that it cannot assume exclusive ownership of
//! that memory, which it otherwise has no way to know.
#![no_std]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelError {
    Full,
    Empty,
}

/// A fixed-capacity SPSC ring channel of `T`, usable over shared memory.
/// Real capacity is `N - 1` (one slot is kept empty as a full/empty
/// sentinel, the standard trick for a wait-free ring buffer that needs no
/// separate "count" field) — `N` must be at least 2.
#[repr(C, align(64))] // own cache line for the struct header; head/tail below get theirs too
pub struct RingChannel<T: Copy, const N: usize> {
    head: AtomicUsize,
    _pad0: [u8; 56],
    tail: AtomicUsize,
    _pad1: [u8; 56],
    slots: UnsafeCell<[T; N]>,
}

// SAFETY: access to `slots` is only ever through the head/tail protocol
// below, which guarantees the producer and consumer never touch the same
// index at the same time (the producer only writes index `tail` once it has
// confirmed, via the Acquire load of `head`, that the slot isn't the one the
// consumer is about to read; symmetrically for the consumer). That's what
// makes a `Sync` impl sound here despite the raw `UnsafeCell`.
unsafe impl<T: Copy + Send, const N: usize> Sync for RingChannel<T, N> {}

impl<T: Copy, const N: usize> RingChannel<T, N> {
    /// `fill` seeds every slot before anything is sent — its value is never
    /// observed by a correctly-used channel (a slot is only ever read after
    /// `try_receive` sees the producer's Release-ordered `tail` advance past
    /// it, by which point `send` has already overwritten it), so any value
    /// works; callers typically pass a zeroed or otherwise-cheap `T`. Taking
    /// it as a parameter rather than requiring `T: Default` is what keeps
    /// this a real `const fn` — `Default::default()` is not `const` for
    /// arbitrary `T`, and a `static CHANNEL: RingChannel<_, _> =
    /// RingChannel::new(...)` is the whole point of a shared-memory channel.
    pub const fn new(fill: T) -> Self {
        assert!(N >= 2, "RingChannel capacity N must be at least 2 (usable capacity is N-1)");
        RingChannel {
            head: AtomicUsize::new(0),
            _pad0: [0; 56],
            tail: AtomicUsize::new(0),
            _pad1: [0; 56],
            slots: UnsafeCell::new([fill; N]),
        }
    }
}

impl<T: Copy, const N: usize> RingChannel<T, N> {
    pub fn capacity(&self) -> usize {
        N - 1
    }

    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Relaxed);
        (tail + N - head) % N
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    /// Producer side only. Returns `Err(Full)` without blocking if the
    /// channel has no room.
    pub fn send(&self, msg: &T) -> Result<(), ChannelError> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire); // must see the consumer's latest progress
        let next_tail = (tail + 1) % N;
        if next_tail == head {
            return Err(ChannelError::Full);
        }
        // SAFETY: `tail` is a slot only the producer ever writes, and we've
        // just confirmed (via the Acquire load above) it isn't the slot the
        // consumer is currently about to read. See the crate-level doc for
        // why this is a volatile write rather than a plain one.
        unsafe {
            let slot = (*self.slots.get()).as_mut_ptr().add(tail);
            core::ptr::write_volatile(slot, *msg);
        }
        self.tail.store(next_tail, Ordering::Release); // publish: payload-then-index
        Ok(())
    }

    /// Consumer side only. Returns `Err(Empty)` without blocking if there's
    /// nothing to read yet.
    pub fn try_receive(&self) -> Result<T, ChannelError> {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire); // must see the producer's latest publish
        if head == tail {
            return Err(ChannelError::Empty);
        }
        // SAFETY: `head` is a slot only the consumer ever reads, and the
        // Acquire load above establishes happens-before with the producer's
        // Release store, so the volatile write above is fully visible here.
        let item = unsafe {
            let slot = (*self.slots.get()).as_ptr().add(head);
            core::ptr::read_volatile(slot)
        };
        self.head.store((head + 1) % N, Ordering::Release);
        Ok(item)
    }
}
