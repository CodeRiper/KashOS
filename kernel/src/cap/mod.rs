//! Capability Subsystem Module (seL4 Architecture)
pub mod sel4_core;

pub use sel4_core::*;
use crate::blockdev::SpinLock;

pub static CAP_CORE: SpinLock<SeL4CapabilityCore<1024>> = SpinLock::new(SeL4CapabilityCore::new());

/// Global helper to invoke seL4 Untyped Retype with automatic CDT registration
pub fn sel4_untyped_retype(untyped_slot: usize, target_type: KernelObjType, dest_slot: usize) -> Result<u64, SeL4Error> {
    CAP_CORE.lock().untyped_retype(untyped_slot, target_type, dest_slot)
}

/// Global helper to invoke seL4 CNode Revoke with automatic physical memory zeroing
pub fn sel4_cnode_revoke(slot_idx: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_revoke(slot_idx, |paddr, size| {
        // Deterministic hardware-level memory wipe
        unsafe {
            let ptr = paddr as *mut u8;
            core::ptr::write_bytes(ptr, 0, size);
            // Flush cache lines to ensure zeroing reaches physical DRAM
            let mut offset = 0;
            while offset < size {
                core::arch::asm!("clflush [{p}]", p = in(reg) ptr.add(offset), options(nostack, preserves_flags));
                offset += 64;
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    })
}
