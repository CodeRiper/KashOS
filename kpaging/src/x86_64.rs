//! x86-64 page table descriptor encoding.
//!
//! IMPORTANT when this is wired into the live kernel (it is not yet — see
//! the crate-level docs): the NX bit here only takes effect if `EFER.NXE`
//! (bit 11) has been set. Without it, bit 63 is architecturally reserved
//! and silently ignored, meaning every page stays executable regardless of
//! what this code writes. `kernel::arch::x86_64::cpuid` already detects
//! `has_nx`; the boot path must check it and set `EFER.NXE` before
//! installing any table built by this module.
use crate::perm::{Arch, Perm};

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const PWT: u64 = 1 << 3; // page write-through
const PCD: u64 = 1 << 4; // page cache-disable
const NX: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

pub struct X86_64;

impl Arch for X86_64 {
    fn table_descriptor(next_table_paddr: u64) -> u64 {
        debug_assert_eq!(next_table_paddr & !ADDR_MASK, 0, "frame must be 4 KiB aligned and <52 bits");
        // Present + writable + user at every intermediate level: x86-64 ANDs
        // permission down the walk, so the *leaf* is always the real,
        // narrowest restriction. Restricting here too would just make the
        // leaf's own bits partially redundant to reason about.
        (next_table_paddr & ADDR_MASK) | PRESENT | WRITABLE | USER
    }

    fn leaf_descriptor(paddr: u64, perm: Perm) -> u64 {
        debug_assert_eq!(paddr & !ADDR_MASK, 0, "frame must be 4 KiB aligned and <52 bits");
        let mut e = (paddr & ADDR_MASK) | PRESENT;
        if perm.writable {
            e |= WRITABLE;
        }
        if perm.user {
            e |= USER;
        }
        if !perm.executable {
            e |= NX;
        }
        if perm.device {
            e |= PWT | PCD; // legacy (non-PAT) encoding for UC — correct for MMIO
        }
        e
    }

    fn is_present(entry: u64) -> bool {
        entry & PRESENT != 0
    }

    fn entry_table_paddr(entry: u64) -> u64 {
        entry & ADDR_MASK
    }

    fn entry_frame_paddr(entry: u64) -> u64 {
        entry & ADDR_MASK
    }

    unsafe fn invalidate(vaddr: u64) {
        // Two reasons this is double-gated, not just `#[cfg(target_arch = "x86_64")]`:
        // (1) `invlpg` doesn't assemble at all while this crate is cross-compiled
        //     as a dependency of the AArch64 kernel build (target_arch="aarch64"),
        //     so the instruction must not exist in that compilation at all.
        // (2) `invlpg` is CPL=0-only — executing it from an ordinary unprivileged
        //     `cargo test` process (ring 3, even on a real x86-64 host) raises
        //     #GP and crashes the test. `not(feature = "host_testing")` keeps it out of test builds
        //     specifically, regardless of which host architecture runs them;
        //     the walk logic this guards (unmap_4k) is what the tests actually
        //     check, not real hardware TLB behaviour, which no host test can
        //     observe anyway.
        #[cfg(all(target_arch = "x86_64", not(feature = "host_testing")))]
        // SAFETY: caller guarantees the MMU is enabled and vaddr is a real address.
        unsafe {
            core::arch::asm!("invlpg [{0}]", in(reg) vaddr, options(nostack, preserves_flags));
        }
        #[cfg(any(not(target_arch = "x86_64"), feature = "host_testing"))]
        {
            let _ = vaddr;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_sets_expected_bits() {
        let e = X86_64::leaf_descriptor(0x1000, Perm::KERNEL_RW);
        assert_eq!(e & PRESENT, PRESENT);
        assert_eq!(e & WRITABLE, WRITABLE);
        assert_eq!(e & USER, 0);
        assert_eq!(e & NX, NX); // not executable -> NX set
        assert_eq!(e & ADDR_MASK, 0x1000);
    }

    #[test]
    fn executable_clears_nx() {
        let e = X86_64::leaf_descriptor(0x2000, Perm::KERNEL_RX);
        assert_eq!(e & NX, 0);
        assert_eq!(e & WRITABLE, 0);
    }

    #[test]
    fn user_sets_user_bit() {
        let e = X86_64::leaf_descriptor(0x3000, Perm::USER_RW);
        assert_eq!(e & USER, USER);
    }

    #[test]
    fn device_sets_uncacheable() {
        let e = X86_64::leaf_descriptor(0x4000, Perm::MMIO);
        assert_eq!(e & (PWT | PCD), PWT | PCD);
    }

    #[test]
    fn table_descriptor_is_always_permissive() {
        // Intermediate entries stay maximally open; the leaf narrows.
        let e = X86_64::table_descriptor(0x5000);
        assert_eq!(e & (PRESENT | WRITABLE | USER), PRESENT | WRITABLE | USER);
    }
}
