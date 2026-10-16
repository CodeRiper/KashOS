//! AArch64 translation-table descriptor encoding (4 KiB granule, 4 levels).
//!
//! This is a genuinely different bit layout from x86-64 — AArch64 has no
//! single "writable" or "NX" bit at fixed positions; permission, memory
//! type and shareability each live in their own field. A reference
//! implementation that reused x86-64-shaped flags (PRESENT=bit0,
//! WRITABLE=bit1, NX=bit63) verbatim on AArch64 would compile but produce
//! structurally wrong descriptors — this module exists specifically so
//! that mistake isn't possible; see `perm::Arch` for how the two
//! architectures share a walk engine without sharing bit layouts.
//!
//! IMPORTANT when this is wired into the live kernel (it is not yet — see
//! the crate-level docs): `MAIR_EL1` must be programmed with
//! [`MAIR_EL1_VALUE`] before any table built here is installed, or
//! `AttrIndx` 0/1 won't mean "Normal" / "Device" as this code assumes.
use crate::perm::{Arch, Perm};

const VALID: u64 = 1 << 0;
const TABLE_OR_PAGE: u64 = 1 << 1; // 1 = table (L0-2) or page (L3); 0 = block (unused here)
const ATTRINDX_NORMAL: u64 = 0b000 << 2;
const ATTRINDX_DEVICE: u64 = 0b001 << 2;
// The descriptor's 2-bit AP[2:1] field spans bits [7:6] (bit7=AP[2], bit6=AP[1]).
// Truth table (ARM ARM): 00=EL1 RW/no EL0, 01=EL1 RW+EL0 RW, 10=EL1 RO/no EL0,
// 11=EL1 RO+EL0 RO — i.e. AP[1] (bit6) alone toggles "EL0 may access it" and
// AP[2] (bit7) alone toggles "read-only", and the two combine independently.
const AP_EL0_ACCESS: u64 = 1 << 6; // AP[1]
const AP_READ_ONLY: u64 = 1 << 7; // AP[2]
const SH_INNER: u64 = 0b11 << 8; // Inner Shareable — Normal memory
const SH_OUTER: u64 = 0b10 << 8; // Outer Shareable — Device memory (ARM ARM: Device is always >= Outer Shareable)
const AF: u64 = 1 << 10; // Access Flag — set up front; we don't implement AF-fault handling
const PXN: u64 = 1 << 53; // Privileged (EL1) execute-never
const UXN: u64 = 1 << 54; // Unprivileged (EL0) execute-never
const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000; // bits [47:12]; LPA2 (>48-bit PA) not handled here

/// Program into `MAIR_EL1` before installing any table from this module.
/// AttrIndx 0 = Normal, Inner/Outer Write-Back, Read/Write-Allocate (`0xFF`).
/// AttrIndx 1 = Device-nGnRnE (`0x00`).
pub const MAIR_EL1_VALUE: u64 = 0x0000_0000_0000_00FF;

pub struct AArch64;

impl Arch for AArch64 {
    fn table_descriptor(next_table_paddr: u64) -> u64 {
        debug_assert_eq!(next_table_paddr & !ADDR_MASK, 0, "frame must be 4 KiB aligned and <48-bit PA");
        // No APTable/PXNTable/UXNTable/NSTable restriction bits set (bits
        // 63/61/60/59 left 0): every real restriction is decided at the
        // leaf, mirroring the x86-64 side's "ANDed-down" design so the two
        // walks read the same way despite the different encoding.
        (next_table_paddr & ADDR_MASK) | VALID | TABLE_OR_PAGE
    }

    fn leaf_descriptor(paddr: u64, perm: Perm) -> u64 {
        debug_assert_eq!(paddr & !ADDR_MASK, 0, "frame must be 4 KiB aligned and <48-bit PA");
        let mut e = (paddr & ADDR_MASK) | VALID | TABLE_OR_PAGE | AF;

        e |= if perm.device { ATTRINDX_DEVICE } else { ATTRINDX_NORMAL };
        e |= if perm.device { SH_OUTER } else { SH_INNER };

        if perm.user {
            e |= AP_EL0_ACCESS;
        }
        if !perm.writable {
            e |= AP_READ_ONLY;
        }

        // Execute-never, split by privilege level the way Linux's arm64 port
        // does: a user-owned page may never be executed from EL1 regardless
        // of its own executable flag (stops the kernel ever being tricked
        // into fetching instructions from user-controlled memory — the same
        // intent as x86's SMEP), and a kernel-owned page may never be
        // executed from EL0 (the AArch64 analogue of SMEP's other half).
        if perm.user {
            e |= PXN;
            if !perm.executable {
                e |= UXN;
            }
        } else {
            e |= UXN;
            if !perm.executable {
                e |= PXN;
            }
        }
        e
    }

    fn is_present(entry: u64) -> bool {
        entry & VALID != 0
    }

    fn entry_table_paddr(entry: u64) -> u64 {
        entry & ADDR_MASK
    }

    fn entry_frame_paddr(entry: u64) -> u64 {
        entry & ADDR_MASK
    }

    unsafe fn invalidate(vaddr: u64) {
        // See the matching comment on X86_64::invalidate: gated on both the
        // real target (this crate is also compiled, unused, into the x86-64
        // kernel build, where `tlbi` simply isn't a valid instruction to
        // assemble at all) and `not(feature = "host_testing")` (`tlbi`/`dsb`/`isb` are EL1+-only
        // and would fault in an ordinary unprivileged host test process).
        #[cfg(all(target_arch = "aarch64", not(feature = "host_testing")))]
        // SAFETY: caller guarantees the MMU is enabled and vaddr is a real address.
        unsafe {
            core::arch::asm!(
                "lsr {0}, {0}, #12",
                "tlbi vaae1is, {0}",
                "dsb ish",
                "isb",
                in(reg) vaddr,
                options(nostack)
            );
        }
        #[cfg(any(not(target_arch = "aarch64"), feature = "host_testing"))]
        {
            let _ = vaddr;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_is_valid_page_type() {
        let e = AArch64::leaf_descriptor(0x1000, Perm::KERNEL_RW);
        assert_eq!(e & (VALID | TABLE_OR_PAGE), VALID | TABLE_OR_PAGE);
        assert_eq!(e & ADDR_MASK, 0x1000);
    }

    #[test]
    fn kernel_rw_is_el1_only_and_writable() {
        let e = AArch64::leaf_descriptor(0x2000, Perm::KERNEL_RW);
        assert_eq!(e & AP_EL0_ACCESS, 0, "kernel-only page must not grant EL0 access");
        assert_eq!(e & AP_READ_ONLY, 0, "writable page must not set the read-only bit");
    }

    #[test]
    fn user_ro_grants_el0_and_blocks_writes() {
        let e = AArch64::leaf_descriptor(0x3000, Perm::USER_RO);
        assert_eq!(e & AP_EL0_ACCESS, AP_EL0_ACCESS);
        assert_eq!(e & AP_READ_ONLY, AP_READ_ONLY);
    }

    #[test]
    fn execute_never_split_by_privilege_mirrors_smep() {
        // A user page: EL1 (kernel) can never execute it (PXN always set);
        // EL0 may, only if explicitly executable.
        let user_rx = AArch64::leaf_descriptor(0x4000, Perm::USER_RX);
        assert_eq!(user_rx & PXN, PXN, "kernel must never execute a user page");
        assert_eq!(user_rx & UXN, 0, "user page marked executable must allow EL0 fetch");

        let user_rw = AArch64::leaf_descriptor(0x5000, Perm::USER_RW);
        assert_eq!(user_rw & UXN, UXN, "non-executable user page must deny EL0 fetch too");

        // A kernel page: EL0 (user) can never execute it (UXN always set);
        // EL1 may, only if explicitly executable.
        let kern_rx = AArch64::leaf_descriptor(0x6000, Perm::KERNEL_RX);
        assert_eq!(kern_rx & UXN, UXN, "user must never execute a kernel page");
        assert_eq!(kern_rx & PXN, 0, "kernel page marked executable must allow EL1 fetch");

        let kern_rw = AArch64::leaf_descriptor(0x7000, Perm::KERNEL_RW);
        assert_eq!(kern_rw & PXN, PXN, "non-executable kernel page must deny EL1 fetch too");
    }

    #[test]
    fn device_memory_uses_device_attrindx_and_outer_shareable() {
        let e = AArch64::leaf_descriptor(0x8000, Perm::MMIO);
        assert_eq!(e & (0b111 << 2), ATTRINDX_DEVICE);
        assert_eq!(e & (0b11 << 8), SH_OUTER);
    }

    #[test]
    fn normal_memory_uses_normal_attrindx_and_inner_shareable() {
        let e = AArch64::leaf_descriptor(0x9000, Perm::KERNEL_RW);
        assert_eq!(e & (0b111 << 2), ATTRINDX_NORMAL);
        assert_eq!(e & (0b11 << 8), SH_INNER);
    }

    #[test]
    fn table_descriptor_sets_no_table_level_restrictions() {
        let e = AArch64::table_descriptor(0xA000);
        assert_eq!(e & (VALID | TABLE_OR_PAGE), VALID | TABLE_OR_PAGE);
        assert_eq!(e >> 59, 0, "no APTable/PXNTable/UXNTable/NSTable bits should be set");
    }
}
