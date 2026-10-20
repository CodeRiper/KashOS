//! High-Assurance Synchronous IPC Subsystem (kipc integration).
//!
//! Provides seL4-style synchronous rendezvous message passing and capability transfer
//! between processes over badged endpoints.
//!
//! Enforces:
//! - Rendezvous semantics: sender and receiver must meet; whichever arrives first blocks.
//! - Direct register/buffer transfer: payload is transferred under kernel mediation with SMAP safety.
//! - Unforgeable compartment badges: the sender cannot spoof its badge; the kernel extracts it
//!   from the sender's Endpoint capability and delivers it to the receiver.
//! - Capability transfer: capabilities can be attached to IPC messages and securely installed
//!   into the receiver's private CSpace.
#![allow(unsafe_code)]

use crate::arch::x86_64::syscall::SyscallError;
use crate::process::{PROCESS_CSPACES, PROCESS_TABLE, ProcessState};
use crate::sync::TicketSpinLock;
use crate::task::{current_tid, SCHEDULER};
use kcore::{Cap, CapKind, Rights};
pub use kipc::{ChannelError, RingChannel};

pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_IPC_WORDS: usize = 8; // 64 bytes fast payload

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IpcMessage {
    pub sender_badge: u64,
    pub tag: u64,
    pub words: [u64; MAX_IPC_WORDS],
    pub words_len: usize,
    pub transferred_cap: Option<Cap>,
}

impl IpcMessage {
    pub const fn empty() -> Self {
        Self {
            sender_badge: 0,
            tag: 0,
            words: [0; MAX_IPC_WORDS],
            words_len: 0,
            transferred_cap: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointState {
    Idle,
    WaitSend,
    WaitRecv,
}

pub struct Endpoint {
    pub id: u64,
    pub state: EndpointState,
    pub waiting_pid: Option<u32>,
    pub pending_msg: Option<IpcMessage>,
    pub dest_cap_slot: Option<usize>,
    pub in_use: bool,
}

impl Endpoint {
    pub const fn new(id: u64) -> Self {
        Self {
            id,
            state: EndpointState::Idle,
            waiting_pid: None,
            pending_msg: None,
            dest_cap_slot: None,
            in_use: false,
        }
    }
}

pub static ENDPOINTS: TicketSpinLock<[Endpoint; MAX_ENDPOINTS]> =
    TicketSpinLock::new([
        Endpoint::new(0), Endpoint::new(1), Endpoint::new(2), Endpoint::new(3),
        Endpoint::new(4), Endpoint::new(5), Endpoint::new(6), Endpoint::new(7),
        Endpoint::new(8), Endpoint::new(9), Endpoint::new(10), Endpoint::new(11),
        Endpoint::new(12), Endpoint::new(13), Endpoint::new(14), Endpoint::new(15),
        Endpoint::new(16), Endpoint::new(17), Endpoint::new(18), Endpoint::new(19),
        Endpoint::new(20), Endpoint::new(21), Endpoint::new(22), Endpoint::new(23),
        Endpoint::new(24), Endpoint::new(25), Endpoint::new(26), Endpoint::new(27),
        Endpoint::new(28), Endpoint::new(29), Endpoint::new(30), Endpoint::new(31),
        Endpoint::new(32), Endpoint::new(33), Endpoint::new(34), Endpoint::new(35),
        Endpoint::new(36), Endpoint::new(37), Endpoint::new(38), Endpoint::new(39),
        Endpoint::new(40), Endpoint::new(41), Endpoint::new(42), Endpoint::new(43),
        Endpoint::new(44), Endpoint::new(45), Endpoint::new(46), Endpoint::new(47),
        Endpoint::new(48), Endpoint::new(49), Endpoint::new(50), Endpoint::new(51),
        Endpoint::new(52), Endpoint::new(53), Endpoint::new(54), Endpoint::new(55),
        Endpoint::new(56), Endpoint::new(57), Endpoint::new(58), Endpoint::new(59),
        Endpoint::new(60), Endpoint::new(61), Endpoint::new(62), Endpoint::new(63),
    ]);

fn endpoint_slot_for_id(endpoints: &[Endpoint; MAX_ENDPOINTS], id: u64) -> Option<usize> {
    let mut matches = endpoints.iter().enumerate()
        .filter(|(_, endpoint)| endpoint.in_use && endpoint.id == id);
    let slot = matches.next()?.0;
    if matches.next().is_some() { None } else { Some(slot) }
}

/// Synchronous IPC Send: delivers message to a waiting receiver or blocks.
pub fn sys_ipc_send(
    endpoint_cptr: usize,
    tag: u64,
    words: &[u64],
    cap_to_transfer_slot: Option<usize>,
) -> Result<(), SyscallError> {
    let sender_pid = current_tid();
    let sender_slot = crate::process::process_slot_for_pid(sender_pid)
        .ok_or(SyscallError::InvalidCapability)?;
    let (ep_id, badge, cap_to_send) = {
        let mut cspaces = PROCESS_CSPACES.lock();
        let cspace = &mut cspaces[sender_slot];

        // 1. Validate endpoint capability with WRITE rights
        let cap = cspace.lookup(endpoint_cptr, Rights::WRITE)
            .map_err(|_| SyscallError::InvalidCapability)?;

        let (ep_id, badge) = match cap.kind() {
            CapKind::Endpoint { addr } => (addr, cap.badge()),
            _ => return Err(SyscallError::InvalidCapability),
        };

        // 2. Extract capability to transfer if requested (requires GRANT rights)
        let cap_to_send = if let Some(cap_slot) = cap_to_transfer_slot {
            let cap_transfer = cspace.lookup(cap_slot, Rights::GRANT)
                .map_err(|_| SyscallError::InsufficientRights)?;
            Some(*cap_transfer)
        } else {
            None
        };

        (ep_id, badge, cap_to_send)
    };

    let mut words_buf = [0u64; MAX_IPC_WORDS];
    let to_copy = words.len().min(MAX_IPC_WORDS);
    words_buf[..to_copy].copy_from_slice(&words[..to_copy]);

    let msg = IpcMessage {
        sender_badge: badge,
        tag,
        words: words_buf,
        words_len: to_copy,
        transferred_cap: cap_to_send,
    };

    let mut endpoints = ENDPOINTS.lock();
    let ep_idx = endpoint_slot_for_id(&endpoints, ep_id)
        .ok_or(SyscallError::InvalidCapability)?;
    let ep = &mut endpoints[ep_idx];

    // FLASK Mandatory Access Control (MAC) on IPC Channel (Phase 8)
    let sender_sid = crate::process::get_process_sid(sender_pid);
    let target_sid = match ep.state {
        EndpointState::WaitRecv => {
            if let Some(r_pid) = ep.waiting_pid {
                crate::process::get_process_sid(r_pid)
            } else {
                crate::flask::SID_SYSTEM
            }
        }
        _ => {
            if ep_id < 10 {
                crate::flask::SID_SYSTEM
            } else {
                crate::process::get_process_sid(ep_id as u32)
            }
        }
    };

    if let Err(e) = crate::flask::check_ipc(sender_sid, target_sid, crate::flask::perms::IPC_SEND) {
        crate::kprintln!(
            "[ipc] FLASK MAC blocked IPC transmission from PID {} (SID {}) to target SID {}: {}",
            sender_pid, sender_sid, target_sid, e
        );
        return Err(SyscallError::InsufficientRights);
    }

    if cap_to_transfer_slot.is_some() {
        if let Err(e) = crate::flask::check_ipc(sender_sid, target_sid, crate::flask::perms::IPC_TRANSFER_CAP) {
            crate::kprintln!(
                "[ipc] FLASK MAC blocked capability transfer from PID {} (SID {}) to target SID {}: {}",
                sender_pid, sender_sid, target_sid, e
            );
            return Err(SyscallError::InsufficientRights);
        }
    }

    match ep.state {
        EndpointState::WaitRecv => {
            // Rendezvous: receiver is already waiting! Deliver directly.
            let receiver_pid = ep.waiting_pid.ok_or(SyscallError::InvalidCapability)?;
            let rx_task_idx = SCHEDULER.lock().task_index_for_tid(receiver_pid)
                .ok_or(SyscallError::InvalidCapability)?;
            let dest_slot = ep.dest_cap_slot;

            // If capability transfer was requested, install into receiver's CSpace
            if let (Some(cap), Some(dst)) = (msg.transferred_cap, dest_slot) {
                let rx_cspace_idx = crate::process::process_slot_for_pid(receiver_pid)
                    .ok_or(SyscallError::InvalidCapability)?;
                let mut cspaces = PROCESS_CSPACES.lock();
                cspaces[rx_cspace_idx].install_transferred(dst, cap)
                    .map_err(|_| SyscallError::InvalidCapability)?;
            }

            // Store message into pending_msg for receiver to read
            ep.waiting_pid = None;
            ep.dest_cap_slot = None;
            ep.pending_msg = Some(msg);
            ep.state = EndpointState::Idle;

            // Unblock receiver
            {
                let mut pcb_table = PROCESS_TABLE.lock();
                if let Some(pcb) = pcb_table.iter_mut().find(|p| p.in_use && p.pid == receiver_pid) {
                    pcb.state = ProcessState::Ready;
                }
            }
            {
                let mut sched = SCHEDULER.lock();
                sched.enqueue_ready(rx_task_idx)
                    .map_err(|_| SyscallError::InvalidCapability)?;
            }

            Ok(())
        }
        _ => {
            // No receiver waiting: block sender
            ep.state = EndpointState::WaitSend;
            ep.waiting_pid = Some(sender_pid);
            ep.pending_msg = Some(msg);

            {
                let mut pcb_table = PROCESS_TABLE.lock();
                if let Some(pcb) = pcb_table.iter_mut().find(|p| p.in_use && p.pid == sender_pid) {
                    pcb.state = ProcessState::Blocked;
                }
            }

            Ok(())
        }
    }
}

/// Synchronous IPC Receive: receives message from a waiting sender or blocks.
pub fn sys_ipc_recv(
    endpoint_cptr: usize,
    dest_cap_slot: Option<usize>,
) -> Result<IpcMessage, SyscallError> {
    let receiver_pid = current_tid();
    let receiver_slot = crate::process::process_slot_for_pid(receiver_pid)
        .ok_or(SyscallError::InvalidCapability)?;
    let ep_id = {
        let cspaces = PROCESS_CSPACES.lock();
        let cspace = &cspaces[receiver_slot];

        let cap = cspace.lookup(endpoint_cptr, Rights::READ)
            .map_err(|_| SyscallError::InvalidCapability)?;

        match cap.kind() {
            CapKind::Endpoint { addr } => addr,
            _ => return Err(SyscallError::InvalidCapability),
        }
    };

    let mut endpoints = ENDPOINTS.lock();
    let ep_idx = endpoint_slot_for_id(&endpoints, ep_id)
        .ok_or(SyscallError::InvalidCapability)?;
    let ep = &mut endpoints[ep_idx];

    match ep.state {
        EndpointState::WaitSend => {
            // Rendezvous: sender is already waiting! Check FLASK MAC receive permission
            let sender_pid = ep.waiting_pid.ok_or(SyscallError::InvalidCapability)?;
            let tx_task_idx = SCHEDULER.lock().task_index_for_tid(sender_pid)
                .ok_or(SyscallError::InvalidCapability)?;
            let sender_sid = crate::process::get_process_sid(sender_pid);
            let receiver_sid = crate::process::get_process_sid(receiver_pid);
            if let Err(e) = crate::flask::check_ipc(sender_sid, receiver_sid, crate::flask::perms::IPC_RECV) {
                crate::kprintln!("[ipc] FLASK MAC blocked IPC receive for PID {} from PID {}: {}", receiver_pid, sender_pid, e);
                return Err(SyscallError::InsufficientRights);
            }

            let sender_pid = ep.waiting_pid.take().unwrap();
            let msg = ep.pending_msg.take().ok_or(SyscallError::InvalidCapability)?;

            // If capability transfer was attached, install into receiver's CSpace
            if let (Some(cap), Some(dst)) = (msg.transferred_cap, dest_cap_slot) {
                let rx_cspace_idx = crate::process::process_slot_for_pid(receiver_pid)
                    .ok_or(SyscallError::InvalidCapability)?;
                let mut cspaces = PROCESS_CSPACES.lock();
                cspaces[rx_cspace_idx].install_transferred(dst, cap)
                    .map_err(|_| SyscallError::InvalidCapability)?;
            }

            ep.state = EndpointState::Idle;

            // Unblock sender
            {
                let mut pcb_table = PROCESS_TABLE.lock();
                if let Some(pcb) = pcb_table.iter_mut().find(|p| p.in_use && p.pid == sender_pid) {
                    pcb.state = ProcessState::Ready;
                }
            }
            {
                let mut sched = SCHEDULER.lock();
                sched.enqueue_ready(tx_task_idx)
                    .map_err(|_| SyscallError::InvalidCapability)?;
            }

            Ok(msg)
        }
        _ => {
            // No sender waiting: block receiver
            ep.state = EndpointState::WaitRecv;
            ep.waiting_pid = Some(receiver_pid);
            ep.dest_cap_slot = dest_cap_slot;

            {
                let mut pcb_table = PROCESS_TABLE.lock();
                if let Some(pcb) = pcb_table.iter_mut().find(|p| p.in_use && p.pid == receiver_pid) {
                    pcb.state = ProcessState::Blocked;
                }
            }

            // Return empty pending message until woken
            Ok(IpcMessage::empty())
        }
    }
}
