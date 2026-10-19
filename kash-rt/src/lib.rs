//! KashOS Userland Runtime Crate (`kash-rt`).
//!
//! Provides the runtime, CRT0, memory allocator, standard I/O, POSIX C-ABI layer,
//! and `relibc` adaptation interfaces for user-space applications running on KashOS.

#![no_std]

pub mod arch;
pub mod sys;
pub mod posix;
pub mod alloc;
pub mod string;
pub mod stdio;
pub mod crt0;
pub mod relibc;

// Re-exports
pub use alloc::{KashUserAllocator, USER_HEAP};
pub use posix::*;
pub use string::*;
pub use relibc::RelibcSys;

/// Standard panic reporting helper for KashOS user-space applications.
pub fn user_panic(info: &core::panic::PanicInfo) -> ! {
    eprintln!("User Panic: {}", info);
    posix::exit(101);
}
