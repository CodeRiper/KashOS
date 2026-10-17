//! Interrupt-safe ticket spinlocks for KashOS.
//!
//! Features:
//! 1. FIFO fairness via ticket ordering (next_ticket / now_serving).
//! 2. Interrupt safety: automatically saves RFLAGS and clears IF (`cli`) upon
//!    acquiring the lock, and restores previous interrupt state upon drop.
//!    This prevents deadlock if an interrupt handler fires on the same CPU
//!    and attempts to acquire the same lock.
//! 3. Zero-allocation, no_std compatible.
#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

#[inline(always)]
fn disable_interrupts() -> u64 {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        let flags: u64;
        unsafe {
            core::arch::asm!(
                "pushfq",
                "pop {0}",
                "cli",
                out(reg) flags,
                options(nomem, nostack)
            );
        }
        flags
    }
    #[cfg(all(target_arch = "aarch64", not(test)))]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, daif",
                "msr daifset, #2",
                out(reg) daif,
                options(nomem, nostack)
            );
        }
        daif
    }
    #[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        0
    }
}

#[inline(always)]
fn restore_interrupts(_saved: u64) {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        // Bit 9 of RFLAGS is IF (Interrupt Flag)
        if (_saved & (1 << 9)) != 0 {
            unsafe {
                core::arch::asm!("sti", options(nomem, nostack));
            }
        }
    }
    #[cfg(all(target_arch = "aarch64", not(test)))]
    {
        // Bit 7 of DAIF is IRQ mask bit
        if (_saved & (1 << 7)) == 0 {
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
            }
        }
    }
}

/// An interrupt-safe FIFO ticket spinlock.
pub struct TicketSpinLock<T> {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for TicketSpinLock<T> {}
unsafe impl<T: Send> Send for TicketSpinLock<T> {}

impl<T> TicketSpinLock<T> {
    pub const fn new(data: T) -> Self {
        TicketSpinLock {
            next_ticket: AtomicU32::new(0),
            now_serving: AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquires the lock, disabling interrupts on the current CPU while held.
    pub fn lock(&self) -> TicketSpinLockGuard<'_, T> {
        let saved_flags = disable_interrupts();
        let my_ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        while self.now_serving.load(Ordering::Acquire) != my_ticket {
            core::hint::spin_loop();
        }
        TicketSpinLockGuard {
            lock: self,
            saved_flags,
        }
    }

    /// Attempts to acquire the lock without spinning.
    pub fn try_lock(&self) -> Option<TicketSpinLockGuard<'_, T>> {
        let saved_flags = disable_interrupts();
        let curr = self.now_serving.load(Ordering::Relaxed);
        if self
            .next_ticket
            .compare_exchange(curr, curr.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(TicketSpinLockGuard {
                lock: self,
                saved_flags,
            })
        } else {
            restore_interrupts(saved_flags);
            None
        }
    }

    /// Returns mutable reference if holding unique reference to the lock.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

pub struct TicketSpinLockGuard<'a, T> {
    lock: &'a TicketSpinLock<T>,
    saved_flags: u64,
}

impl<T> Deref for TicketSpinLockGuard<'_, T> {
    type Target = T;
    #[inline(always)]
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for TicketSpinLockGuard<'_, T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for TicketSpinLockGuard<'_, T> {
    #[inline(always)]
    fn drop(&mut self) {
        let next = self.lock.now_serving.load(Ordering::Relaxed).wrapping_add(1);
        self.lock.now_serving.store(next, Ordering::Release);
        restore_interrupts(self.saved_flags);
    }
}

/// Convenience alias to replace legacy un-synchronized or interrupt-unsafe SpinLock.
pub type SpinLock<T> = TicketSpinLock<T>;
pub type SpinLockGuard<'a, T> = TicketSpinLockGuard<'a, T>;
