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

/// Global helper to invoke seL4 Untyped Retype Batch for N consecutive slots
pub fn sel4_untyped_retype_batch(
    untyped_slot: usize,
    target_type: KernelObjType,
    dest_start_slot: usize,
    num_objects: usize,
) -> Result<u64, SeL4Error> {
    CAP_CORE.lock().untyped_retype_batch(untyped_slot, target_type, dest_start_slot, num_objects)
}

/// Global helper to query untyped capability metadata
pub fn sel4_untyped_query(slot_idx: usize) -> Result<(u64, u64, u64, bool, u64), SeL4Error> {
    CAP_CORE.lock().untyped_query(slot_idx)
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

/// Global helper to invoke seL4 CNode Revoke returning RevocationStats
pub fn sel4_cnode_revoke_with_stats(slot_idx: usize) -> Result<RevocationStats, SeL4Error> {
    CAP_CORE.lock().cnode_revoke_with_stats(slot_idx, |paddr, size| {
        unsafe {
            let ptr = paddr as *mut u8;
            core::ptr::write_bytes(ptr, 0, size);
            let mut offset = 0;
            while offset < size {
                core::arch::asm!("clflush [{p}]", p = in(reg) ptr.add(offset), options(nostack, preserves_flags));
                offset += 64;
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    })
}

/// Global helper to verify that revocation transitively eliminated all descendants
pub fn sel4_verify_revoke_complete(revoked_slot: usize) -> Result<(), &'static str> {
    CAP_CORE.lock().verify_revoke_complete(revoked_slot)
}

// ── B2: CNode Operation Global Helpers ────────────────────────────────────

/// Global helper: seL4_CNode_Copy with rights attenuation and CDT insertion
pub fn sel4_cnode_copy(src_slot: usize, dest_slot: usize, rights_mask: CapRights) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_copy(src_slot, dest_slot, rights_mask)
}

/// Global helper: seL4_CNode_Move with CDT re-parenting
pub fn sel4_cnode_move(src_slot: usize, dest_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_move(src_slot, dest_slot)
}

/// Global helper: seL4_CNode_Mutate (atomic Move + rights attenuate)
pub fn sel4_cnode_mutate(src_slot: usize, dest_slot: usize, rights_mask: CapRights) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_mutate(src_slot, dest_slot, rights_mask)
}

/// Global helper: seL4_CNode_Rotate (atomic 3-way rotation)
pub fn sel4_cnode_rotate(src_slot: usize, pivot_slot: usize, dest_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_rotate(src_slot, pivot_slot, dest_slot)
}

/// Global helper: seL4_CNode_Delete with grandparent adoption
pub fn sel4_cnode_delete(slot_idx: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_delete(slot_idx)
}

/// Global helper: seL4_CNode_SaveCaller (save Reply cap from caller TCB)
pub fn sel4_cnode_save_caller(caller_tcb_slot: usize, dest_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_save_caller(caller_tcb_slot, dest_slot)
}

/// Global helper: Set guard value and size on a CNode capability
pub fn sel4_cnode_set_guard(cnode_slot: usize, guard: u64, guard_size: u8) -> Result<(), SeL4Error> {
    CAP_CORE.lock().cnode_set_guard(cnode_slot, guard, guard_size)
}

/// Global helper: Resolve a CPtr through guarded radix CSpace resolution
pub fn sel4_resolve_cptr(root_cnode_slot: usize, cptr: u64, depth: u8) -> Result<usize, SeL4Error> {
    CAP_CORE.lock().resolve_cptr(root_cnode_slot, cptr, depth)
}

/// Global helper: Verify CDT structural integrity invariants
pub fn sel4_check_cdt_invariants() -> Result<(), &'static str> {
    CAP_CORE.lock().check_cdt_invariants()
}

// ── B4: Synchronous Endpoint & IPC Global Helpers ─────────────────────────

/// Global helper: seL4_Send / seL4_NBSend through an Endpoint
pub fn sel4_endpoint_send(
    ep_slot: usize,
    sender_tcb: u64,
    msg: IpcMessage,
    blocking: bool,
) -> Result<EndpointSendResult, SeL4Error> {
    CAP_CORE.lock().endpoint_send(ep_slot, sender_tcb, msg, blocking)
}

/// Global helper: seL4_Recv / seL4_NBRecv on an Endpoint
pub fn sel4_endpoint_recv(
    ep_slot: usize,
    receiver_tcb: u64,
    transfer_dest_slot: Option<usize>,
    blocking: bool,
) -> Result<EndpointRecvResult, SeL4Error> {
    CAP_CORE.lock().endpoint_recv(ep_slot, receiver_tcb, transfer_dest_slot, blocking)
}

/// Global helper: seL4_Call through an Endpoint
pub fn sel4_endpoint_call(
    ep_slot: usize,
    caller_tcb: u64,
    msg: IpcMessage,
    reply_dest_slot: usize,
) -> Result<EndpointCallResult, SeL4Error> {
    CAP_CORE.lock().endpoint_call(ep_slot, caller_tcb, msg, reply_dest_slot)
}

/// Global helper: seL4_Reply to a caller using a Reply capability
pub fn sel4_endpoint_reply(
    reply_slot: usize,
    msg: IpcMessage,
) -> Result<u64, SeL4Error> {
    CAP_CORE.lock().endpoint_reply(reply_slot, msg)
}

/// Global helper: seL4_ReplyRecv atomically replying and waiting for next request
pub fn sel4_endpoint_reply_recv(
    ep_slot: usize,
    reply_slot: usize,
    caller_tcb: u64,
    reply_msg: IpcMessage,
    transfer_dest_slot: Option<usize>,
    blocking: bool,
) -> Result<(u64, EndpointRecvResult), SeL4Error> {
    CAP_CORE.lock().endpoint_reply_recv(ep_slot, reply_slot, caller_tcb, reply_msg, transfer_dest_slot, blocking)
}

/// Global helper: Query endpoint queue state
pub fn sel4_endpoint_query_state(ep_slot: usize) -> Result<(EndpointQueueMode, usize, usize), SeL4Error> {
    CAP_CORE.lock().endpoint_query_state(ep_slot)
}

// ── B5: Asynchronous Notification Global Helpers ──────────────────────────

/// Global helper: seL4_Signal a notification object
pub fn sel4_notification_signal(ntfn_slot: usize) -> Result<NotificationSignalResult, SeL4Error> {
    CAP_CORE.lock().notification_signal(ntfn_slot)
}

/// Global helper: seL4_Wait on a notification object
pub fn sel4_notification_wait(ntfn_slot: usize, thread_id: u64) -> Result<NotificationWaitResult, SeL4Error> {
    CAP_CORE.lock().notification_wait(ntfn_slot, thread_id)
}

/// Global helper: seL4_Poll a notification object
pub fn sel4_notification_poll(ntfn_slot: usize) -> Result<u64, SeL4Error> {
    CAP_CORE.lock().notification_poll(ntfn_slot)
}

/// Global helper: Query notification state
pub fn sel4_notification_query_state(ntfn_slot: usize) -> Result<(NotificationState, u64, usize), SeL4Error> {
    CAP_CORE.lock().notification_query_state(ntfn_slot)
}

// ── B6: Thread Control Block (TCB) & Fault Global Helpers ─────────────────

/// Global helper: seL4_TCB_Configure a thread
pub fn sel4_tcb_configure(
    tcb_slot: usize,
    fault_ep: Option<usize>,
    cspace_root: Option<usize>,
    vspace_root: Option<usize>,
    ipc_buffer_vaddr: u64,
) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_configure(tcb_slot, fault_ep, cspace_root, vspace_root, ipc_buffer_vaddr)
}

/// Global helper: seL4_TCB_ReadRegisters
pub fn sel4_tcb_read_registers(tcb_slot: usize) -> Result<UserContext, SeL4Error> {
    CAP_CORE.lock().tcb_read_registers(tcb_slot)
}

/// Global helper: seL4_TCB_WriteRegisters
pub fn sel4_tcb_write_registers(tcb_slot: usize, regs: UserContext) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_write_registers(tcb_slot, regs)
}

/// Global helper: seL4_TCB_SetPriority
pub fn sel4_tcb_set_priority(target_tcb_slot: usize, authority_tcb_slot: usize, new_prio: u8) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_set_priority(target_tcb_slot, authority_tcb_slot, new_prio)
}

/// Global helper: seL4_TCB_SetMCPriority
pub fn sel4_tcb_set_mc_priority(target_tcb_slot: usize, authority_tcb_slot: usize, new_mcp: u8) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_set_mc_priority(target_tcb_slot, authority_tcb_slot, new_mcp)
}

/// Global helper: seL4_TCB_Suspend
pub fn sel4_tcb_suspend(tcb_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_suspend(tcb_slot)
}

/// Global helper: seL4_TCB_Resume
pub fn sel4_tcb_resume(tcb_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_resume(tcb_slot)
}

/// Global helper: seL4_TCB_BindNotification
pub fn sel4_tcb_bind_notification(tcb_slot: usize, ntfn_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_bind_notification(tcb_slot, ntfn_slot)
}

/// Global helper: seL4_TCB_UnbindNotification
pub fn sel4_tcb_unbind_notification(tcb_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_unbind_notification(tcb_slot)
}

/// Global helper: Deliver thread fault to configured fault endpoint
pub fn sel4_tcb_deliver_fault(tcb_slot: usize, fault: FaultInfo) -> Result<EndpointSendResult, SeL4Error> {
    CAP_CORE.lock().tcb_deliver_fault(tcb_slot, fault)
}

/// Global helper: Query TCB state
pub fn sel4_tcb_query_state(tcb_slot: usize) -> Result<(ThreadState, u8, u8, Option<usize>), SeL4Error> {
    CAP_CORE.lock().tcb_query_state(tcb_slot)
}

/// Global helper: seL4_SchedContext_Configure
pub fn sel4_sched_context_configure(sc_slot: usize, budget_us: u64, period_us: u64, badge: u64) -> Result<(), SeL4Error> {
    CAP_CORE.lock().sched_context_configure(sc_slot, budget_us, period_us, badge)
}

/// Global helper: seL4_SchedContext_Bind
pub fn sel4_sched_context_bind(sc_slot: usize, tcb_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().sched_context_bind(sc_slot, tcb_slot)
}

/// Global helper: seL4_SchedContext_Unbind
pub fn sel4_sched_context_unbind(sc_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().sched_context_unbind(sc_slot)
}

/// Global helper: Deduct execution time from SchedContext
pub fn sel4_sched_context_charge(sc_slot: usize, elapsed_us: u64) -> Result<(u64, bool), SeL4Error> {
    CAP_CORE.lock().sched_context_charge(sc_slot, elapsed_us)
}

/// Global helper: Replenish SchedContext budget
pub fn sel4_sched_context_replenish(sc_slot: usize, current_time_us: u64) -> Result<u64, SeL4Error> {
    CAP_CORE.lock().sched_context_replenish(sc_slot, current_time_us)
}

/// Global helper: Donate scheduling context during synchronous IPC
pub fn sel4_sched_context_donate(donor_tcb_slot: usize, recipient_tcb_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().sched_context_donate(donor_tcb_slot, recipient_tcb_slot)
}

/// Global helper: Return donated scheduling context
pub fn sel4_sched_context_return(recipient_tcb_slot: usize) -> Result<(), SeL4Error> {
    CAP_CORE.lock().sched_context_return(recipient_tcb_slot)
}

/// Global helper: Query SchedContext parameters
pub fn sel4_sched_context_query(sc_slot: usize) -> Result<(u64, u64, u64, Option<u64>, u64), SeL4Error> {
    CAP_CORE.lock().sched_context_query(sc_slot)
}

/// Global helper: Configure TCB passive flag
pub fn sel4_tcb_set_passive(tcb_slot: usize, is_passive: bool) -> Result<(), SeL4Error> {
    CAP_CORE.lock().tcb_set_passive(tcb_slot, is_passive)
}

/// Global helper: Query TCB MCS state
pub fn sel4_tcb_query_mcs_state(tcb_slot: usize) -> Result<(bool, Option<usize>, Option<usize>), SeL4Error> {
    CAP_CORE.lock().tcb_query_mcs_state(tcb_slot)
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
                CapKind::Reply { tcb_id, is_valid } => {
                    (alloc::format!("Reply({})", if is_valid { "valid" } else { "spent" }), alloc::format!("tcb:{:#x}", tcb_id))
                }
                CapKind::PageTable { paddr, level } => {
                    (alloc::format!("PageTable(L{})", level), alloc::format!("pa:{:#x}", paddr))
                }
                CapKind::VSpace { cr3, asid } => {
                    (alloc::format!("VSpace(asid:{})", asid), alloc::format!("cr3:{:#x}", cr3))
                }
                CapKind::IrqControl => (String::from("IrqControl"), String::from("root-irq")),
                CapKind::IrqHandler { irq } => {
                    (alloc::format!("IrqHandler({})", irq), String::from("hw-irq"))
                }
                CapKind::IoPortControl => (String::from("IoPortCtrl"), String::from("root-io")),
                CapKind::IOSpace { pci_bdf, domain_id } => {
                    (alloc::format!("IOSpace(dom:{})", domain_id), alloc::format!("bdf:{:#x}", pci_bdf))
                }
                CapKind::Vcpu { vcpu_id } => {
                    (alloc::format!("Vcpu({})", vcpu_id), String::from("virt-cpu"))
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
