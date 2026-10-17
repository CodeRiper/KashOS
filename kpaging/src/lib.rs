//! kpaging — 4-level page tables for Kash Kernel.
//!
//! Status: this crate's logic is built and tested (see `tests/`, which runs
//! real `unsafe` pointer-based table walks against host-allocated memory
//! standing in for physical frames — not just type-checked, actually
//! exercised). It is **not yet wired into the live booting kernel**, which
//! still runs on the provisional identity map set up in `boot.S`/`boot.rs`.
//! Doing that swap is the next concrete step (replace the provisional 1 GiB
//! x86-64 identity map and the still-MMU-off AArch64 boot with a real,
//! minimal, W^X-respecting kernel map built from this crate) — rushing it
//! into the same change as writing this crate would mean debugging two new
//! things with real hardware-fault stakes at once, which is exactly the
//! kind of mistake the project's own `TESTING.md` bug log exists to avoid
//! repeating.
//!
//! `unsafe` is used throughout (page tables are raw memory by nature) but
//! confined to `mapper.rs`'s short, SAFETY-commented pointer derefs — the
//! walk logic itself, and all permission-bit encoding, is ordinary safe
//! Rust and is what the tests actually check.
#![no_std]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(test)]
extern crate std;

mod aarch64;
mod allocator;
mod error;
mod mapper;
mod perm;
mod table;
mod x86_64;

pub use aarch64::{AArch64, MAIR_EL1_VALUE};
pub use allocator::{QuotaFrameAllocator, DEFAULT_FRAME_CAPACITY, MAX_DOMAINS};
pub use error::{PageError, PageResult};
pub use mapper::VirtualSpace;
pub use perm::{Arch, Perm};
pub use table::{FrameAllocator, PageTable, PAGE_SIZE};
pub use x86_64::X86_64;
