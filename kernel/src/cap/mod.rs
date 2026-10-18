//! Capability Subsystem Module (seL4 Architecture)
pub mod sel4_core;

extern crate alloc;
use alloc::format;
use alloc::string::String;

pub use sel4_core::*;
use crate::blockdev::SpinLock;

pub static CAP_CORE: SpinLock<SeL4CapabilityCore<1024>> = SpinLock::new(SeL4CapabilityCore::new());

/// Global helper to register initial physical memory Untyped blocks discovered at boot.
pub fn init_root_untyped(paddr: u64, size_bytes: u64, is_device: bool, slot: usize) -> Result<(), SeL4Error> {
    let mut core = CAP_CORE.lock();
    let mut size_bits = 12u8; // 4 KiB minimum
    while (1u64 << (size_bits + 1)) <= size_bytes && size_bits < 30 {
        size_bits += 1;
    }
    core.register_untyped(paddr, size_bits, is_device, slot)
}

/// Global helper to invoke seL4 Untyped Retype with automatic CDT registration
pub fn sel4_untyped_retype(untyped_slot: usize, target_type: KernelObjType, dest_slot: usize) -> Result<u64, SeL4Error> {
    CAP_CORE.lock().untyped_retype(untyped_slot, target_type, dest_slot)
}

/// Global helper to invoke seL4 CNode Mint with rights attenuation and compartment badge
pub fn sel4_mint_endpoint(src_slot: usize, dest_slot: usize, rights_mask: CapRights, badge: u64) -> Result<(), SeL4Error> {
    CAP_CORE.lock().mint_badged_endpoint(src_slot, dest_slot, rights_mask, badge)
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

/// Print all active capabilities and CDT hierarchy for auditing and inspection.
pub fn print_active_caps() {
    let core = CAP_CORE.lock();
    crate::kprintln!("\n╔══════════════════════════════════════════════════════════════════════╗");
    crate::kprintln!("║             seL4 CAPABILITY DERIVATION TREE (CDT) AUDIT              ║");
    crate::kprintln!("╠══════════════════════════════════════════════════════════════════════╣");
    crate::kprintln!("║ Slot │ Type         │ Rights │ Badge / Addr     │ CDT Hierarchy      ║");
    crate::kprintln!("╠──────┼──────────────┼────────┼──────────────────┼────────────────────╣");
    let mut active = 0;
    for (i, slot) in core.slots.iter().enumerate() {
        if !slot.cap.is_null() {
            active += 1;
            let (type_name, badge_str) = match slot.cap.kind {
                CapKind::Untyped { size_bits, watermark, .. } => {
                    (alloc::format!("Untyped({}K)", (1u64 << size_bits) >> 10), alloc::format!("wm:{:#x}", watermark))
                }
                CapKind::Frame { paddr, is_large } => {
                    (alloc::format!("Frame({})", if is_large { "2M" } else { "4K" }), alloc::format!("pa:{:#x}", paddr))
                }
                CapKind::Endpoint { badge, .. } => {
                    (String::from("Endpoint"), if badge > 0 { alloc::format!("badge:{:#x}", badge) } else { String::from("unbadged") })
                }
                CapKind::Notification { badge, .. } => {
                    (String::from("Notification"), if badge > 0 { alloc::format!("badge:{:#x}", badge) } else { String::from("unbadged") })
                }
                CapKind::TCB { tcb_id, priority, .. } => {
                    (alloc::format!("TCB(pri:{})", priority), alloc::format!("id:{:#x}", tcb_id))
                }
                CapKind::CNode { radix, .. } => {
                    (alloc::format!("CNode(2^{})", radix), String::from("guarded"))
                }
                CapKind::SchedContext { budget_us, .. } => {
                    (alloc::format!("SchedCtx({}us)", budget_us), String::from("temporal"))
                }
                CapKind::ASIDPool { pool_id } => {
                    (alloc::format!("ASIDPool({})", pool_id), String::from("vspace"))
                }
                CapKind::IOPort { start_port, end_port } => {
                    (alloc::format!("IOPort({}-{})", start_port, end_port), String::from("hw-port"))
                }
                CapKind::Null => (String::from("Null"), String::from("none")),
            };
            let parent_str = match slot.parent {
                Some(p) => alloc::format!("child of [{}]", p),
                None => String::from("root task"),
            };
            let r_str = alloc::format!("0b{:04b}", slot.cap.rights.bits());
            crate::kprintln!("║ {:<4} │ {:<12} │ {:<6} │ {:<16} │ {:<18} ║",
                             i, type_name, r_str, badge_str, parent_str);
        }
    }
    crate::kprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    crate::kprintln!("[cdt] Total active capability tokens in CSpace: {}\n", active);
}
