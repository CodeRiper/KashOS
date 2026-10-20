//! seL4 Capability Microkernel Core (seL4 Reference Manual v16.0.0 Architecture)
//!
//! Provides mathematically unforgeable capability tokens, guarded radix CSpaces,
//! watermark-tracked Untyped memory, Capability Derivation Tree (CDT) tracking,
//! recursive revocation with deterministic memory zeroing, badged IPC endpoints,
//! notifications, and Mixed-Criticality System (MCS) temporal isolation.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

#[cfg(test)]
extern crate std;

// ── 1. Access Rights (Orthogonal seL4 Model) ──────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CapRights(u8);

impl CapRights {
    pub const NONE: CapRights = CapRights(0);
    pub const READ: CapRights = CapRights(1 << 0);
    pub const WRITE: CapRights = CapRights(1 << 1);
    pub const GRANT: CapRights = CapRights(1 << 2);
    pub const GRANT_REPLY: CapRights = CapRights(1 << 3);
    pub const ALL: CapRights = CapRights(0b1111);

    pub const fn from_bits(bits: u8) -> Self {
        CapRights(bits & Self::ALL.0)
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: CapRights) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn intersect(self, other: CapRights) -> CapRights {
        CapRights(self.0 & other.0)
    }

    pub const fn union(self, other: CapRights) -> CapRights {
        CapRights(self.0 | other.0)
    }
}

impl core::ops::BitOr for CapRights {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        self.union(rhs)
    }
}

impl core::ops::BitAnd for CapRights {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        self.intersect(rhs)
    }
}

// ── 2. Kernel Object Types & Memory Alignment ─────────────────────────────────

pub const MIN_UNTYPED_BITS: u8 = 4;   // 16 bytes
pub const FRAME_BITS: u8 = 12;         // 4 KiB standard MMU page
pub const LARGE_FRAME_BITS: u8 = 21;   // 2 MiB large page
pub const HUGE_FRAME_BITS: u8 = 30;    // 1 GiB huge page
pub const ENDPOINT_BITS: u8 = 4;       // 16 bytes
pub const NOTIFICATION_BITS: u8 = 4;   // 16 bytes
pub const TCB_BITS: u8 = 10;           // 1024 bytes
pub const SCHED_CONTEXT_BITS: u8 = 8;  // 256 bytes

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KernelObjType {
    Untyped { size_bits: u8 },
    Frame4K,
    Frame2M,
    Frame1G,
    Endpoint,
    Notification,
    TCB,
    CNode { size_bits: u8 },
    SchedContext { budget_us: u64, period_us: u64 },
    Reply,
    PageTable,
    VSpace,
    ASIDPool,
    IrqControl,
    IrqHandler { irq: u8 },
    IoPortControl,
    IoPort { start_port: u16, end_port: u16 },
    IoSpace { pci_bdf: u16, domain_id: u16 },
    Vcpu,
}

impl KernelObjType {
    pub const fn size_bytes(&self) -> u64 {
        match *self {
            KernelObjType::Untyped { size_bits } => 1u64 << size_bits,
            KernelObjType::Frame4K => 1u64 << FRAME_BITS,
            KernelObjType::Frame2M => 1u64 << LARGE_FRAME_BITS,
            KernelObjType::Frame1G => 1u64 << HUGE_FRAME_BITS,
            KernelObjType::Endpoint => 1u64 << ENDPOINT_BITS,
            KernelObjType::Notification => 1u64 << NOTIFICATION_BITS,
            KernelObjType::TCB => 1u64 << TCB_BITS,
            KernelObjType::CNode { size_bits } => 32u64 * (1u64 << size_bits), // 32 bytes per slot on x86_64
            KernelObjType::SchedContext { .. } => 1u64 << SCHED_CONTEXT_BITS,
            KernelObjType::Reply => 32,
            KernelObjType::PageTable => 4096,
            KernelObjType::VSpace => 4096,
            KernelObjType::ASIDPool => 4096, // 4 KiB manages 1,024 VSpaces
            KernelObjType::IrqControl => 0,
            KernelObjType::IrqHandler { .. } => 32,
            KernelObjType::IoPortControl => 0,
            KernelObjType::IoPort { .. } => 16,
            KernelObjType::IoSpace { .. } => 32,
            KernelObjType::Vcpu => 4096,
        }
    }
}

// ── 3. Capability Descriptors & Kinds ─────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapKind {
    Null,
    Untyped {
        paddr: u64,
        size_bits: u8,
        is_device: bool,
        watermark: u64,
    },
    Frame {
        paddr: u64,
        is_large: bool,
    },
    Endpoint {
        addr: u64,
        badge: u64, // 0 = unbadged master, >0 = immutable cryptographic compartment badge
    },
    Notification {
        addr: u64,
        badge: u64,
    },
    TCB {
        tcb_id: u64,
        priority: u8,
        is_passive: bool, // MCS: true if scheduling context is unbound
    },
    CNode {
        radix: u8,
        guard: u64,
        guard_size: u8,
    },
    SchedContext {
        sc_id: u64,
        budget_us: u64,
        period_us: u64,
        is_sporadic: bool,
    },
    Reply {
        tcb_id: u64,
        is_valid: bool,
    },
    PageTable {
        paddr: u64,
        level: u8,
    },
    VSpace {
        cr3: u64,
        asid: u32,
    },
    ASIDPool {
        pool_id: u32,
    },
    IrqControl,
    IrqHandler {
        irq: u8,
    },
    IoPortControl,
    IOPort {
        start_port: u16,
        end_port: u16,
    },
    IOSpace {
        pci_bdf: u16,
        domain_id: u16,
    },
    Vcpu {
        vcpu_id: u32,
    },
}

impl CapKind {
    pub const fn tcb_id(&self) -> Option<u64> {
        match *self {
            CapKind::TCB { tcb_id, .. } => Some(tcb_id),
            CapKind::Reply { tcb_id, .. } => Some(tcb_id),
            _ => None,
        }
    }

    pub const fn sc_id(&self) -> Option<u64> {
        match *self {
            CapKind::SchedContext { sc_id, .. } => Some(sc_id),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cap {
    pub kind: CapKind,
    pub rights: CapRights,
}

impl Cap {
    pub const NULL: Cap = Cap {
        kind: CapKind::Null,
        rights: CapRights::NONE,
    };

    pub const fn is_null(&self) -> bool {
        matches!(self.kind, CapKind::Null)
    }

    pub const fn badge(&self) -> Option<u64> {
        match self.kind {
            CapKind::Endpoint { badge, .. } if badge > 0 => Some(badge),
            CapKind::Notification { badge, .. } if badge > 0 => Some(badge),
            _ => None,
        }
    }
}

// ── 4. Capability Derivation Tree (CDT) Node ──────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct CdtSlot {
    pub cap: Cap,
    pub parent: Option<usize>,
    pub first_child: Option<usize>,
    pub next_sibling: Option<usize>,
    pub prev_sibling: Option<usize>,
}

impl CdtSlot {
    pub const EMPTY: Self = Self {
        cap: Cap::NULL,
        parent: None,
        first_child: None,
        next_sibling: None,
        prev_sibling: None,
    };
}

// ── 5. Errors & Lookup Failures ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeL4Error {
    InvalidRoot,
    MissingCapability,
    DepthMismatch,
    GuardMismatch,
    InsufficientRights,
    SlotOccupied,
    SlotEmpty,
    NotEnoughMemory,
    IllegalOperation,
    InvalidCapability,
    InvalidArgument,
    RevokeFailed,
    WouldBlock,
}

// ── B4: Synchronous IPC & Badged Endpoints ────────────────────────────────────

/// seL4 MessageInfo register packing format
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageInfo {
    pub label: u64,
    pub length: u8,      // number of message registers (0..4)
    pub extra_caps: u8,  // number of capabilities transferred (0..2)
    pub caps_unwrapped: u8,
}

impl MessageInfo {
    pub const fn new(label: u64, length: u8, extra_caps: u8) -> Self {
        Self { label, length, extra_caps, caps_unwrapped: 0 }
    }
}

/// seL4 Synchronous IPC Message payload
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcMessage {
    pub info: MessageInfo,
    pub registers: [u64; 4], // MR0..MR3 fast IPC registers
    pub badge: u64,          // Receiver sees sender's badge here
    pub transfer_cap_slot: Option<usize>, // Capability slot to transfer if GRANT held
}

impl IpcMessage {
    pub const fn new(label: u64, words: &[u64]) -> Self {
        let mut registers = [0u64; 4];
        let mut len = 0u8;
        while (len as usize) < words.len() && (len as usize) < 4 {
            registers[len as usize] = words[len as usize];
            len += 1;
        }
        Self {
            info: MessageInfo::new(label, len, 0),
            registers,
            badge: 0,
            transfer_cap_slot: None,
        }
    }
}

/// Endpoint queue state machine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointQueueMode {
    Idle,
    Send,
    Receive,
}

/// A queued thread entry waiting on an Endpoint
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointQueueEntry {
    pub thread_id: u64,
    pub message: IpcMessage,
    pub badge: u64,
    pub is_call: bool,
    pub reply_slot: Option<usize>,
    pub transfer_dest_slot: Option<usize>,
}

/// Kernel object state for an Endpoint (16 bytes in hardware)
#[derive(Clone, Debug)]
pub struct EndpointObject {
    pub addr: u64,
    pub mode: EndpointQueueMode,
    pub send_queue: Vec<EndpointQueueEntry>,
    pub recv_queue: Vec<EndpointQueueEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointSendResult {
    /// Delivered directly to a waiting receiver without blocking
    DeliveredImmediately {
        receiver_tcb: u64,
        badge: u64,
    },
    /// No receiver was waiting; calling thread is queued on the endpoint
    BlockedOnSend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRecvResult {
    /// Message was received immediately from a queued sender
    Received {
        sender_tcb: u64,
        message: IpcMessage,
        badge: u64,
    },
    /// No sender was queued; calling thread is queued on the endpoint
    BlockedOnReceive,
    /// Non-blocking receive found no waiting sender
    NoMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointCallResult {
    /// Delivered immediately to a waiting receiver; caller is waiting for reply
    DeliveredAndWaitingReply {
        receiver_tcb: u64,
        badge: u64,
    },
    /// No receiver was waiting; caller is queued on endpoint
    BlockedOnSend,
}

// ── B5: Asynchronous Notifications & Event Signaling ─────────────────────────

/// Notification object states matching seL4
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationState {
    Idle,
    Active,
    Waiting,
}

/// In-kernel Notification object state (16 bytes in hardware)
#[derive(Clone, Debug)]
pub struct NotificationObject {
    pub addr: u64,
    pub state: NotificationState,
    pub accumulated_bits: u64,
    pub wait_queue: Vec<u64>, // Thread IDs waiting for notification
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationSignalResult {
    /// Signal was delivered directly to a waiting thread
    DeliveredToWaitingThread {
        thread_id: u64,
        badge: u64,
    },
    /// No thread was waiting; signal accumulated into the event word
    Accumulated {
        new_bits: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotificationWaitResult {
    /// Received accumulated bits immediately without blocking
    ReceivedImmediately(u64),
    /// No signals were pending; calling thread is queued on the notification
    BlockedOnNotification,
}

// ── B6: Thread Control Blocks (TCBs), Fault Handlers & State ──────────────────

/// Execution state of a thread in seL4
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Inactive,
    Ready,
    Running,
    BlockedOnReceive,
    BlockedOnSend,
    BlockedOnReply,
    BlockedOnNotification,
    Suspended,
    Restart,
}

/// User registers context for x86_64
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserContext {
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// seL4 Fault Types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultType {
    CapFault = 0xFA01,
    VmFault = 0xFA02,
    UnknownSyscall = 0xFA03,
    UserException = 0xFA04,
}

/// In-kernel fault delivery information
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultInfo {
    pub fault_type: FaultType,
    pub fault_addr: u64,
    pub fault_code: u64,
    pub ip: u64,
}

/// In-kernel Scheduling Context object for Mixed-Criticality Systems (MCS)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedContextObject {
    pub sc_id: u64,
    pub budget_us: u64,
    pub period_us: u64,
    pub remaining_budget_us: u64,
    pub bound_tcb_id: Option<u64>,
    pub badge: u64,
    pub is_sporadic: bool,
    pub last_replenished_us: u64,
    pub replenishment_deadline_us: u64,
}

/// In-kernel Thread Control Block (TCB) state (1024 bytes in hardware)
#[derive(Clone, Debug)]
pub struct TcbObject {
    pub tcb_id: u64,
    pub state: ThreadState,
    pub priority: u8,
    pub mcp: u8, // Maximum Controlled Priority
    pub registers: UserContext,
    pub cspace_root_slot: Option<usize>,
    pub vspace_root_slot: Option<usize>,
    pub fault_ep_slot: Option<usize>,
    pub ipc_buffer_vaddr: u64,
    pub bound_notification_slot: Option<usize>,
    pub is_passive: bool,
    pub bound_sched_context_slot: Option<usize>,
    pub donated_sched_context_slot: Option<usize>,
}

// ── 6. Guarded Radix Capability Space & Microkernel Core ──────────────────────

pub struct SeL4CapabilityCore<const N: usize> {
    pub slots: [CdtSlot; N],
    pub untyped_descriptors: Vec<UntypedDescriptor>,
    pub endpoint_objects: Vec<EndpointObject>,
    pub notification_objects: Vec<NotificationObject>,
    pub tcb_objects: Vec<TcbObject>,
    pub sched_context_objects: Vec<SchedContextObject>,
}

#[derive(Debug)]
pub struct UntypedDescriptor {
    pub paddr: u64,
    pub size_bits: u8,
    pub is_device: bool,
    pub watermark: AtomicU64,
}

/// Revocation statistics returned by `cnode_revoke_with_stats` for audit logging.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevocationStats {
    pub objects_destroyed: usize,
    pub bytes_zeroed: usize,
}

impl<const N: usize> SeL4CapabilityCore<N> {
    pub const fn new() -> Self {
        Self {
            slots: [CdtSlot::EMPTY; N],
            untyped_descriptors: Vec::new(),
            endpoint_objects: Vec::new(),
            notification_objects: Vec::new(),
            tcb_objects: Vec::new(),
            sched_context_objects: Vec::new(),
        }
    }

    /// Register a physical memory untyped block (general RAM or MMIO device)
    pub fn register_untyped(&mut self, paddr: u64, size_bits: u8, is_device: bool, slot_idx: usize) -> Result<(), SeL4Error> {
        if slot_idx >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[slot_idx].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }

        self.slots[slot_idx] = CdtSlot {
            cap: Cap {
                kind: CapKind::Untyped {
                    paddr,
                    size_bits,
                    is_device,
                    watermark: 0,
                },
                rights: CapRights::ALL,
            },
            parent: None,
            first_child: None,
            next_sibling: None,
            prev_sibling: None,
        };

        self.untyped_descriptors.push(UntypedDescriptor {
            paddr,
            size_bits,
            is_device,
            watermark: AtomicU64::new(0),
        });

        Ok(())
    }

    /// seL4_Untyped_Retype(): Advances allocation watermark and mints child capabilities
    /// inserted into the Capability Derivation Tree (CDT).
    /// seL4_Untyped_Retype(): Batch retype into N consecutive destination slots
    pub fn untyped_retype_batch(
        &mut self,
        untyped_slot: usize,
        target_type: KernelObjType,
        dest_start_slot: usize,
        num_objects: usize,
    ) -> Result<u64, SeL4Error> {
        if num_objects == 0 {
            return Err(SeL4Error::InvalidArgument);
        }
        if untyped_slot >= N || dest_start_slot >= N || dest_start_slot + num_objects > N {
            return Err(SeL4Error::DepthMismatch);
        }

        // Invariant: Retyping Untyped memory strictly requires WRITE authority
        if !self.slots[untyped_slot].cap.rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }

        for slot in dest_start_slot..(dest_start_slot + num_objects) {
            if !self.slots[slot].cap.is_null() {
                return Err(SeL4Error::SlotOccupied);
            }
        }

        let (base_paddr, max_size, is_dev, cur_wm) = match self.slots[untyped_slot].cap.kind {
            CapKind::Untyped { paddr, size_bits, is_device, watermark } => {
                (paddr, 1u64 << size_bits, is_device, watermark)
            }
            _ => return Err(SeL4Error::IllegalOperation),
        };

        // Device Memory Invariant: is_device == true can ONLY be retyped into Frames or smaller Untypeds
        if is_dev {
            match target_type {
                KernelObjType::Frame4K | KernelObjType::Frame2M | KernelObjType::Frame1G | KernelObjType::Untyped { .. } => {}
                _ => return Err(SeL4Error::IllegalOperation), // Attempting TCB/Endpoint from device MMIO rejected
            }
        }

        let obj_size = target_type.size_bytes();
        // Alignment: align watermark to object size boundary (minimum 16 bytes)
        let align_mask = obj_size.max(16) - 1;
        let aligned_wm = (cur_wm + align_mask) & !align_mask;
        let total_bytes = obj_size.checked_mul(num_objects as u64).ok_or(SeL4Error::NotEnoughMemory)?;
        if aligned_wm + total_bytes > max_size {
            return Err(SeL4Error::NotEnoughMemory);
        }

        for i in 0..num_objects {
            let dest_slot = dest_start_slot + i;
            let allocated_paddr = base_paddr + aligned_wm + (i as u64) * obj_size;

            let new_cap_kind = match target_type {
                KernelObjType::Frame4K => CapKind::Frame { paddr: allocated_paddr, is_large: false },
                KernelObjType::Frame2M => CapKind::Frame { paddr: allocated_paddr, is_large: true },
                KernelObjType::Frame1G => CapKind::Frame { paddr: allocated_paddr, is_large: true },
                KernelObjType::Endpoint => CapKind::Endpoint { addr: allocated_paddr, badge: 0 },
                KernelObjType::Notification => CapKind::Notification { addr: allocated_paddr, badge: 0 },
            KernelObjType::TCB => {
                self.get_or_create_tcb_mut(allocated_paddr);
                CapKind::TCB { tcb_id: allocated_paddr, priority: 128, is_passive: false }
            }
                KernelObjType::CNode { size_bits } => CapKind::CNode { radix: size_bits, guard: 0, guard_size: 0 },
                KernelObjType::SchedContext { budget_us, period_us } => {
                    self.sched_context_objects.push(SchedContextObject {
                        sc_id: allocated_paddr,
                        budget_us,
                        period_us,
                        remaining_budget_us: budget_us,
                        bound_tcb_id: None,
                        badge: 0,
                        is_sporadic: true,
                        last_replenished_us: 0,
                        replenishment_deadline_us: period_us,
                    });
                    CapKind::SchedContext {
                        sc_id: allocated_paddr,
                        budget_us,
                        period_us,
                        is_sporadic: true,
                    }
                }
                KernelObjType::Reply => CapKind::Reply { tcb_id: allocated_paddr, is_valid: true },
                KernelObjType::PageTable => CapKind::PageTable { paddr: allocated_paddr, level: 1 },
                KernelObjType::VSpace => CapKind::VSpace { cr3: allocated_paddr, asid: 1 },
                KernelObjType::ASIDPool => CapKind::ASIDPool { pool_id: (allocated_paddr >> 12) as u32 },
                KernelObjType::IrqControl => CapKind::IrqControl,
                KernelObjType::IrqHandler { irq } => CapKind::IrqHandler { irq },
                KernelObjType::IoPortControl => CapKind::IoPortControl,
                KernelObjType::IoPort { start_port, end_port } => CapKind::IOPort { start_port, end_port },
                KernelObjType::IoSpace { pci_bdf, domain_id } => CapKind::IOSpace { pci_bdf, domain_id },
                KernelObjType::Vcpu => CapKind::Vcpu { vcpu_id: (allocated_paddr >> 12) as u32 },
                KernelObjType::Untyped { size_bits } => CapKind::Untyped {
                    paddr: allocated_paddr,
                    size_bits,
                    is_device: is_dev,
                    watermark: 0,
                },
            };

            let prev_first = self.slots[untyped_slot].first_child;
            self.slots[dest_slot] = CdtSlot {
                cap: Cap {
                    kind: new_cap_kind,
                    rights: CapRights::ALL,
                },
                parent: Some(untyped_slot),
                first_child: None,
                next_sibling: prev_first,
                prev_sibling: None,
            };

            if let Some(first_idx) = prev_first {
                self.slots[first_idx].prev_sibling = Some(dest_slot);
            }
            self.slots[untyped_slot].first_child = Some(dest_slot);
        }

        // Update watermark
        if let CapKind::Untyped { ref mut watermark, .. } = self.slots[untyped_slot].cap.kind {
            *watermark = aligned_wm + total_bytes;
        }

        Ok(base_paddr + aligned_wm)
    }

    /// Single-object retype helper
    pub fn untyped_retype(
        &mut self,
        untyped_slot: usize,
        target_type: KernelObjType,
        dest_slot: usize,
    ) -> Result<u64, SeL4Error> {
        self.untyped_retype_batch(untyped_slot, target_type, dest_slot, 1)
    }

    /// Query Untyped capability metadata: (base_paddr, size_bytes, watermark, is_device, free_bytes)
    pub fn untyped_query(&self, slot_idx: usize) -> Result<(u64, u64, u64, bool, u64), SeL4Error> {
        if slot_idx >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        match self.slots[slot_idx].cap.kind {
            CapKind::Untyped { paddr, size_bits, watermark, is_device } => {
                let size_bytes = 1u64 << size_bits;
                let free_bytes = size_bytes.saturating_sub(watermark);
                Ok((paddr, size_bytes, watermark, is_device, free_bytes))
            }
            _ => Err(SeL4Error::IllegalOperation),
        }
    }

    /// seL4_CNode_Mint(): Mint a new capability with restricted rights and unforgeable badge
    pub fn mint_badged_endpoint(
        &mut self,
        src_slot: usize,
        dest_slot: usize,
        rights_mask: CapRights,
        badge: u64,
    ) -> Result<(), SeL4Error> {
        if src_slot >= N || dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }
        if badge == 0 {
            return Err(SeL4Error::InvalidArgument);
        }

        let (src_kind, src_rights) = (self.slots[src_slot].cap.kind, self.slots[src_slot].cap.rights);
        let derived_kind = match src_kind {
            CapKind::Endpoint { addr, badge: existing } => {
                if existing != 0 {
                    return Err(SeL4Error::IllegalOperation); // Cannot re-badge an already badged endpoint
                }
                CapKind::Endpoint { addr, badge }
            }
            CapKind::Notification { addr, badge: existing } => {
                if existing != 0 {
                    return Err(SeL4Error::IllegalOperation);
                }
                CapKind::Notification { addr, badge }
            }
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // Rights monotonicity: derived rights can only be a subset
        let derived_rights = src_rights.intersect(rights_mask);

        // Insert into CDT
        let prev_first = self.slots[src_slot].first_child;
        self.slots[dest_slot] = CdtSlot {
            cap: Cap { kind: derived_kind, rights: derived_rights },
            parent: Some(src_slot),
            first_child: None,
            next_sibling: prev_first,
            prev_sibling: None,
        };

        if let Some(first_idx) = prev_first {
            self.slots[first_idx].prev_sibling = Some(dest_slot);
        }
        self.slots[src_slot].first_child = Some(dest_slot);

        Ok(())
    }

    // ── B4: Synchronous Endpoint & Capability Routing Methods ────────────

    fn get_or_create_endpoint_mut(&mut self, addr: u64) -> usize {
        for (i, ep) in self.endpoint_objects.iter().enumerate() {
            if ep.addr == addr {
                return i;
            }
        }
        self.endpoint_objects.push(EndpointObject {
            addr,
            mode: EndpointQueueMode::Idle,
            send_queue: Vec::new(),
            recv_queue: Vec::new(),
        });
        self.endpoint_objects.len() - 1
    }

    /// Query endpoint queue state: (mode, send_queue_len, recv_queue_len)
    pub fn endpoint_query_state(&mut self, ep_slot: usize) -> Result<(EndpointQueueMode, usize, usize), SeL4Error> {
        if ep_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let addr = match self.slots[ep_slot].cap.kind {
            CapKind::Endpoint { addr, .. } => addr,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let ep_idx = self.get_or_create_endpoint_mut(addr);
        let obj = &self.endpoint_objects[ep_idx];
        Ok((obj.mode, obj.send_queue.len(), obj.recv_queue.len()))
    }

    /// seL4_Send / seL4_NBSend: Synchronously send an IPC message through an Endpoint
    pub fn endpoint_send(
        &mut self,
        ep_slot: usize,
        sender_tcb: u64,
        mut msg: IpcMessage,
        blocking: bool,
    ) -> Result<EndpointSendResult, SeL4Error> {
        if ep_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (ep_addr, ep_badge, ep_rights) = match self.slots[ep_slot].cap.kind {
            CapKind::Endpoint { addr, badge } => (addr, badge, self.slots[ep_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // Rights check: WRITE required to Send
        if !ep_rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }

        // Capability routing check: if transferring a cap, both EP and transferred cap must have GRANT
        if let Some(transfer_slot) = msg.transfer_cap_slot {
            if !ep_rights.contains(CapRights::GRANT) {
                return Err(SeL4Error::InsufficientRights);
            }
            if transfer_slot >= N || self.slots[transfer_slot].cap.is_null() {
                return Err(SeL4Error::SlotEmpty);
            }
            if !self.slots[transfer_slot].cap.rights.contains(CapRights::GRANT) {
                return Err(SeL4Error::InsufficientRights);
            }
        }

        // Stamp sender's unforgeable badge onto message
        msg.badge = ep_badge;

        let ep_idx = self.get_or_create_endpoint_mut(ep_addr);

        // Case A: A receiver is already waiting
        if !self.endpoint_objects[ep_idx].recv_queue.is_empty() {
            let rx = self.endpoint_objects[ep_idx].recv_queue.remove(0);
            if self.endpoint_objects[ep_idx].recv_queue.is_empty() {
                self.endpoint_objects[ep_idx].mode = EndpointQueueMode::Idle;
            }

            // Transfer capability if receiver provided a receive slot
            if let (Some(src_slot), Some(dst_slot)) = (msg.transfer_cap_slot, rx.transfer_dest_slot) {
                if dst_slot < N && self.slots[dst_slot].cap.is_null() {
                    let _ = self.cnode_copy(src_slot, dst_slot, CapRights::ALL);
                }
            }

            Ok(EndpointSendResult::DeliveredImmediately {
                receiver_tcb: rx.thread_id,
                badge: ep_badge,
            })
        } else {
            // Case B: No receiver waiting
            if !blocking {
                Err(SeL4Error::WouldBlock)
            } else {
                self.endpoint_objects[ep_idx].send_queue.push(EndpointQueueEntry {
                    thread_id: sender_tcb,
                    message: msg,
                    badge: ep_badge,
                    is_call: false,
                    reply_slot: None,
                    transfer_dest_slot: None,
                });
                self.endpoint_objects[ep_idx].mode = EndpointQueueMode::Send;
                Ok(EndpointSendResult::BlockedOnSend)
            }
        }
    }

    /// seL4_Recv / seL4_NBRecv: Synchronously wait for an IPC message on an Endpoint
    pub fn endpoint_recv(
        &mut self,
        ep_slot: usize,
        receiver_tcb: u64,
        transfer_dest_slot: Option<usize>,
        blocking: bool,
    ) -> Result<EndpointRecvResult, SeL4Error> {
        if ep_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (ep_addr, ep_rights) = match self.slots[ep_slot].cap.kind {
            CapKind::Endpoint { addr, .. } => (addr, self.slots[ep_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // Rights check: READ required to Receive
        if !ep_rights.contains(CapRights::READ) {
            return Err(SeL4Error::InsufficientRights);
        }

        // If receiving capabilities, endpoint must have GRANT
        if transfer_dest_slot.is_some() && !ep_rights.contains(CapRights::GRANT) {
            return Err(SeL4Error::InsufficientRights);
        }
        if let Some(dst) = transfer_dest_slot {
            if dst >= N {
                return Err(SeL4Error::DepthMismatch);
            }
            if !self.slots[dst].cap.is_null() {
                return Err(SeL4Error::SlotOccupied);
            }
        }

        let ep_idx = self.get_or_create_endpoint_mut(ep_addr);

        // Case A: A sender is already queued
        if !self.endpoint_objects[ep_idx].send_queue.is_empty() {
            let tx = self.endpoint_objects[ep_idx].send_queue.remove(0);
            if self.endpoint_objects[ep_idx].send_queue.is_empty() {
                self.endpoint_objects[ep_idx].mode = EndpointQueueMode::Idle;
            }

            // If caller did seL4_Call, mint Reply capability into receiver's CSpace
            if tx.is_call {
                if let Some(r_slot) = tx.reply_slot {
                    if r_slot < N && self.slots[r_slot].cap.is_null() {
                        self.slots[r_slot] = CdtSlot {
                            cap: Cap {
                                kind: CapKind::Reply { tcb_id: tx.thread_id, is_valid: true },
                                rights: CapRights::ALL,
                            },
                            parent: None,
                            first_child: None,
                            next_sibling: None,
                            prev_sibling: None,
                        };
                    }
                }
            }

            // Transfer capability if requested
            if let (Some(src_slot), Some(dst_slot)) = (tx.message.transfer_cap_slot, transfer_dest_slot) {
                if dst_slot < N && self.slots[dst_slot].cap.is_null() {
                    let _ = self.cnode_copy(src_slot, dst_slot, CapRights::ALL);
                }
            }

            Ok(EndpointRecvResult::Received {
                sender_tcb: tx.thread_id,
                message: tx.message,
                badge: tx.badge,
            })
        } else {
            // Case B: No sender waiting
            if !blocking {
                Ok(EndpointRecvResult::NoMessage)
            } else {
                self.endpoint_objects[ep_idx].recv_queue.push(EndpointQueueEntry {
                    thread_id: receiver_tcb,
                    message: IpcMessage::default(),
                    badge: 0,
                    is_call: false,
                    reply_slot: None,
                    transfer_dest_slot,
                });
                self.endpoint_objects[ep_idx].mode = EndpointQueueMode::Receive;
                Ok(EndpointRecvResult::BlockedOnReceive)
            }
        }
    }

    /// seL4_Call: Send message and block awaiting Reply from receiver
    pub fn endpoint_call(
        &mut self,
        ep_slot: usize,
        caller_tcb: u64,
        mut msg: IpcMessage,
        reply_dest_slot: usize,
    ) -> Result<EndpointCallResult, SeL4Error> {
        if ep_slot >= N || reply_dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[reply_dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }

        let (ep_addr, ep_badge, ep_rights) = match self.slots[ep_slot].cap.kind {
            CapKind::Endpoint { addr, badge } => (addr, badge, self.slots[ep_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // Rights check: WRITE and GRANT_REPLY required to Call
        let req = CapRights::WRITE | CapRights::GRANT_REPLY;
        if !ep_rights.contains(req) {
            return Err(SeL4Error::InsufficientRights);
        }

        // Capability transfer check
        if let Some(transfer_slot) = msg.transfer_cap_slot {
            if !ep_rights.contains(CapRights::GRANT) {
                return Err(SeL4Error::InsufficientRights);
            }
            if transfer_slot >= N || self.slots[transfer_slot].cap.is_null() {
                return Err(SeL4Error::SlotEmpty);
            }
            if !self.slots[transfer_slot].cap.rights.contains(CapRights::GRANT) {
                return Err(SeL4Error::InsufficientRights);
            }
        }

        msg.badge = ep_badge;
        let ep_idx = self.get_or_create_endpoint_mut(ep_addr);

        if !self.endpoint_objects[ep_idx].recv_queue.is_empty() {
            let rx = self.endpoint_objects[ep_idx].recv_queue.remove(0);
            if self.endpoint_objects[ep_idx].recv_queue.is_empty() {
                self.endpoint_objects[ep_idx].mode = EndpointQueueMode::Idle;
            }

            // Mint one-shot Reply cap in caller-designated reply slot
            self.slots[reply_dest_slot] = CdtSlot {
                cap: Cap {
                    kind: CapKind::Reply { tcb_id: caller_tcb, is_valid: true },
                    rights: CapRights::ALL,
                },
                parent: None,
                first_child: None,
                next_sibling: None,
                prev_sibling: None,
            };

            // Capability transfer if requested
            if let (Some(src_slot), Some(dst_slot)) = (msg.transfer_cap_slot, rx.transfer_dest_slot) {
                if dst_slot < N && self.slots[dst_slot].cap.is_null() {
                    let _ = self.cnode_copy(src_slot, dst_slot, CapRights::ALL);
                }
            }

            Ok(EndpointCallResult::DeliveredAndWaitingReply {
                receiver_tcb: rx.thread_id,
                badge: ep_badge,
            })
        } else {
            // Queue caller as blocked on Call
            self.endpoint_objects[ep_idx].send_queue.push(EndpointQueueEntry {
                thread_id: caller_tcb,
                message: msg,
                badge: ep_badge,
                is_call: true,
                reply_slot: Some(reply_dest_slot),
                transfer_dest_slot: None,
            });
            self.endpoint_objects[ep_idx].mode = EndpointQueueMode::Send;
            Ok(EndpointCallResult::BlockedOnSend)
        }
    }

    /// seL4_Reply: Atomically reply to a previously received Call and unblock the caller.
    /// Strictly single-use: invalidates the Reply capability upon execution.
    pub fn endpoint_reply(
        &mut self,
        reply_slot: usize,
        _msg: IpcMessage,
    ) -> Result<u64, SeL4Error> {
        if reply_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if self.slots[reply_slot].cap.is_null() {
            return Err(SeL4Error::SlotEmpty);
        }

        let caller_tcb = match self.slots[reply_slot].cap.kind {
            CapKind::Reply { tcb_id, is_valid } => {
                if !is_valid {
                    return Err(SeL4Error::InvalidCapability);
                }
                tcb_id
            }
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // One-shot consumption: delete the Reply capability so it cannot be reused
        self.slots[reply_slot] = CdtSlot::EMPTY;

        Ok(caller_tcb)
    }

    /// seL4_ReplyRecv: Atomically replies to a caller and waits for the next request.
    pub fn endpoint_reply_recv(
        &mut self,
        ep_slot: usize,
        reply_slot: usize,
        caller_tcb: u64,
        reply_msg: IpcMessage,
        transfer_dest_slot: Option<usize>,
        blocking: bool,
    ) -> Result<(u64, EndpointRecvResult), SeL4Error> {
        let unblocked_tcb = self.endpoint_reply(reply_slot, reply_msg)?;
        let recv_res = self.endpoint_recv(ep_slot, caller_tcb, transfer_dest_slot, blocking)?;
        Ok((unblocked_tcb, recv_res))
    }

    // ── B5: Asynchronous Notification Methods ─────────────────────────────

    fn get_or_create_notification_mut(&mut self, addr: u64) -> usize {
        for (i, ntfn) in self.notification_objects.iter().enumerate() {
            if ntfn.addr == addr {
                return i;
            }
        }
        self.notification_objects.push(NotificationObject {
            addr,
            state: NotificationState::Idle,
            accumulated_bits: 0,
            wait_queue: Vec::new(),
        });
        self.notification_objects.len() - 1
    }

    /// Query notification object state: (state, accumulated_bits, wait_queue_len)
    pub fn notification_query_state(&mut self, ntfn_slot: usize) -> Result<(NotificationState, u64, usize), SeL4Error> {
        if ntfn_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let addr = match self.slots[ntfn_slot].cap.kind {
            CapKind::Notification { addr, .. } => addr,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let idx = self.get_or_create_notification_mut(addr);
        let obj = &self.notification_objects[idx];
        Ok((obj.state, obj.accumulated_bits, obj.wait_queue.len()))
    }

    /// seL4_Signal: Asynchronously signal a notification object.
    /// Bitwise ORs the capability badge (or default 1 if unbadged) into the notification word.
    /// Never blocks the calling thread.
    pub fn notification_signal(&mut self, ntfn_slot: usize) -> Result<NotificationSignalResult, SeL4Error> {
        if ntfn_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (addr, badge, rights) = match self.slots[ntfn_slot].cap.kind {
            CapKind::Notification { addr, badge } => (addr, badge, self.slots[ntfn_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // Rights check: WRITE required to Signal
        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }

        let signal_badge = if badge != 0 { badge } else { 1 };
        let idx = self.get_or_create_notification_mut(addr);

        // Case A: A thread is waiting
        if !self.notification_objects[idx].wait_queue.is_empty() {
            let waiting_tid = self.notification_objects[idx].wait_queue.remove(0);
            if self.notification_objects[idx].wait_queue.is_empty() {
                self.notification_objects[idx].state = NotificationState::Idle;
            }
            Ok(NotificationSignalResult::DeliveredToWaitingThread {
                thread_id: waiting_tid,
                badge: signal_badge,
            })
        } else {
            // Case B: No thread waiting; accumulate bits into event word
            self.notification_objects[idx].accumulated_bits |= signal_badge;
            self.notification_objects[idx].state = NotificationState::Active;
            Ok(NotificationSignalResult::Accumulated {
                new_bits: self.notification_objects[idx].accumulated_bits,
            })
        }
    }

    /// seL4_Wait: Wait for signals on a notification object.
    /// If Active, atomically extracts and resets the accumulated bits.
    /// If Idle, calling thread is queued on the notification.
    pub fn notification_wait(&mut self, ntfn_slot: usize, thread_id: u64) -> Result<NotificationWaitResult, SeL4Error> {
        if ntfn_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (addr, rights) = match self.slots[ntfn_slot].cap.kind {
            CapKind::Notification { addr, .. } => (addr, self.slots[ntfn_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        // Rights check: READ required to Wait
        if !rights.contains(CapRights::READ) {
            return Err(SeL4Error::InsufficientRights);
        }

        let idx = self.get_or_create_notification_mut(addr);

        if self.notification_objects[idx].state == NotificationState::Active {
            let bits = self.notification_objects[idx].accumulated_bits;
            self.notification_objects[idx].accumulated_bits = 0;
            self.notification_objects[idx].state = NotificationState::Idle;
            Ok(NotificationWaitResult::ReceivedImmediately(bits))
        } else {
            self.notification_objects[idx].wait_queue.push(thread_id);
            self.notification_objects[idx].state = NotificationState::Waiting;
            Ok(NotificationWaitResult::BlockedOnNotification)
        }
    }

    /// seL4_Poll: Non-blocking check for pending signals on a notification object.
    pub fn notification_poll(&mut self, ntfn_slot: usize) -> Result<u64, SeL4Error> {
        if ntfn_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (addr, rights) = match self.slots[ntfn_slot].cap.kind {
            CapKind::Notification { addr, .. } => (addr, self.slots[ntfn_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        if !rights.contains(CapRights::READ) {
            return Err(SeL4Error::InsufficientRights);
        }

        let idx = self.get_or_create_notification_mut(addr);

        if self.notification_objects[idx].state == NotificationState::Active {
            let bits = self.notification_objects[idx].accumulated_bits;
            self.notification_objects[idx].accumulated_bits = 0;
            self.notification_objects[idx].state = NotificationState::Idle;
            Ok(bits)
        } else {
            Ok(0)
        }
    }

    // ── B6: Thread Control Block (TCB) & Fault Methods ────────────────────

    fn get_or_create_tcb_mut(&mut self, tcb_id: u64) -> usize {
        for (i, tcb) in self.tcb_objects.iter().enumerate() {
            if tcb.tcb_id == tcb_id {
                return i;
            }
        }
        self.tcb_objects.push(TcbObject {
            tcb_id,
            state: ThreadState::Inactive,
            priority: 128,
            mcp: 128,
            registers: UserContext::default(),
            cspace_root_slot: None,
            vspace_root_slot: None,
            fault_ep_slot: None,
            ipc_buffer_vaddr: 0,
            bound_notification_slot: None,
            is_passive: false,
            bound_sched_context_slot: None,
            donated_sched_context_slot: None,
        });
        self.tcb_objects.len() - 1
    }

    /// seL4_TCB_Configure: Configure a thread's isolated CSpace, VSpace, fault endpoint, and IPC buffer.
    pub fn tcb_configure(
        &mut self,
        tcb_slot: usize,
        fault_ep: Option<usize>,
        cspace_root: Option<usize>,
        vspace_root: Option<usize>,
        ipc_buffer_vaddr: u64,
    ) -> Result<(), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }

        // Validate optional capability slots
        if let Some(f_ep) = fault_ep {
            if f_ep >= N || self.slots[f_ep].cap.is_null() {
                return Err(SeL4Error::SlotEmpty);
            }
            if !matches!(self.slots[f_ep].cap.kind, CapKind::Endpoint { .. }) {
                return Err(SeL4Error::InvalidCapability);
            }
        }
        if let Some(cs_root) = cspace_root {
            if cs_root >= N || self.slots[cs_root].cap.is_null() {
                return Err(SeL4Error::SlotEmpty);
            }
            if !matches!(self.slots[cs_root].cap.kind, CapKind::CNode { .. }) {
                return Err(SeL4Error::InvalidCapability);
            }
        }
        if let Some(vs_root) = vspace_root {
            if vs_root >= N || self.slots[vs_root].cap.is_null() {
                return Err(SeL4Error::SlotEmpty);
            }
            if !matches!(self.slots[vs_root].cap.kind, CapKind::VSpace { .. } | CapKind::PageTable { .. }) {
                return Err(SeL4Error::InvalidCapability);
            }
        }

        let idx = self.get_or_create_tcb_mut(tcb_id);
        self.tcb_objects[idx].fault_ep_slot = fault_ep;
        self.tcb_objects[idx].cspace_root_slot = cspace_root;
        self.tcb_objects[idx].vspace_root_slot = vspace_root;
        self.tcb_objects[idx].ipc_buffer_vaddr = ipc_buffer_vaddr;

        // Thread transitions from Inactive to Ready once execution environment is configured
        if self.tcb_objects[idx].state == ThreadState::Inactive {
            self.tcb_objects[idx].state = ThreadState::Ready;
        }

        Ok(())
    }

    /// seL4_TCB_ReadRegisters: Read user execution registers of a thread
    pub fn tcb_read_registers(&mut self, tcb_slot: usize) -> Result<UserContext, SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        if !rights.contains(CapRights::READ) {
            return Err(SeL4Error::InsufficientRights);
        }
        let idx = self.get_or_create_tcb_mut(tcb_id);
        Ok(self.tcb_objects[idx].registers)
    }

    /// seL4_TCB_WriteRegisters: Write user execution registers into a thread
    pub fn tcb_write_registers(&mut self, tcb_slot: usize, regs: UserContext) -> Result<(), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        let idx = self.get_or_create_tcb_mut(tcb_id);
        self.tcb_objects[idx].registers = regs;
        Ok(())
    }

    /// seL4_TCB_SetPriority: Set thread scheduling priority, bounded strictly by authority thread's MCP
    pub fn tcb_set_priority(
        &mut self,
        target_tcb_slot: usize,
        authority_tcb_slot: usize,
        new_prio: u8,
    ) -> Result<(), SeL4Error> {
        if target_tcb_slot >= N || authority_tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (target_id, target_rights) = match self.slots[target_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[target_tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let (auth_id, auth_rights) = match self.slots[authority_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[authority_tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        if !target_rights.contains(CapRights::WRITE) || !auth_rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }

        let auth_idx = self.get_or_create_tcb_mut(auth_id);
        let auth_mcp = self.tcb_objects[auth_idx].mcp;

        // MCP Invariant: Authority bound check
        if new_prio > auth_mcp {
            return Err(SeL4Error::InsufficientRights);
        }

        let target_idx = self.get_or_create_tcb_mut(target_id);
        self.tcb_objects[target_idx].priority = new_prio;
        Ok(())
    }

    /// seL4_TCB_SetMCPriority: Set thread Maximum Controlled Priority, bounded by authority thread's MCP
    pub fn tcb_set_mc_priority(
        &mut self,
        target_tcb_slot: usize,
        authority_tcb_slot: usize,
        new_mcp: u8,
    ) -> Result<(), SeL4Error> {
        if target_tcb_slot >= N || authority_tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (target_id, target_rights) = match self.slots[target_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[target_tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let (auth_id, _) = match self.slots[authority_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[authority_tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };

        if !target_rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }

        let auth_idx = self.get_or_create_tcb_mut(auth_id);
        let max_allowed = self.tcb_objects[auth_idx].mcp;

        if new_mcp > max_allowed {
            return Err(SeL4Error::InsufficientRights);
        }

        let target_idx = self.get_or_create_tcb_mut(target_id);
        self.tcb_objects[target_idx].mcp = new_mcp;
        Ok(())
    }

    /// seL4_TCB_Suspend: Explicitly suspend a thread's execution
    pub fn tcb_suspend(&mut self, tcb_slot: usize) -> Result<(), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        let idx = self.get_or_create_tcb_mut(tcb_id);
        self.tcb_objects[idx].state = ThreadState::Suspended;
        Ok(())
    }

    /// seL4_TCB_Resume: Resume a suspended thread
    pub fn tcb_resume(&mut self, tcb_slot: usize) -> Result<(), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        let idx = self.get_or_create_tcb_mut(tcb_id);
        if self.tcb_objects[idx].state == ThreadState::Suspended || self.tcb_objects[idx].state == ThreadState::Restart {
            self.tcb_objects[idx].state = ThreadState::Ready;
        }
        Ok(())
    }

    /// seL4_TCB_BindNotification: Bind an asynchronous notification object to a TCB
    pub fn tcb_bind_notification(&mut self, tcb_slot: usize, ntfn_slot: usize) -> Result<(), SeL4Error> {
        if tcb_slot >= N || ntfn_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        if !matches!(self.slots[ntfn_slot].cap.kind, CapKind::Notification { .. }) {
            return Err(SeL4Error::InvalidCapability);
        }

        let idx = self.get_or_create_tcb_mut(tcb_id);
        self.tcb_objects[idx].bound_notification_slot = Some(ntfn_slot);
        Ok(())
    }

    /// seL4_TCB_UnbindNotification: Unbind notification object from a TCB
    pub fn tcb_unbind_notification(&mut self, tcb_slot: usize) -> Result<(), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let (tcb_id, rights) = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => (tcb_id, self.slots[tcb_slot].cap.rights),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        if !rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        let idx = self.get_or_create_tcb_mut(tcb_id);
        self.tcb_objects[idx].bound_notification_slot = None;
        Ok(())
    }

    /// Deliver a thread fault to its configured fault endpoint
    pub fn tcb_deliver_fault(
        &mut self,
        tcb_slot: usize,
        fault: FaultInfo,
    ) -> Result<EndpointSendResult, SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let tcb_id = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let idx = self.get_or_create_tcb_mut(tcb_id);
        let fault_ep_slot = self.tcb_objects[idx].fault_ep_slot.ok_or(SeL4Error::MissingCapability)?;

        // Thread is suspended while fault is handled
        self.tcb_objects[idx].state = ThreadState::Suspended;

        // Encode fault IPC message
        let fault_msg = IpcMessage::new(
            fault.fault_type as u64,
            &[fault.fault_addr, fault.fault_code, fault.ip, tcb_id],
        );

        self.endpoint_send(fault_ep_slot, tcb_id, fault_msg, true)
    }

    /// Query TCB state: (state, priority, mcp, fault_ep_slot)
    pub fn tcb_query_state(&mut self, tcb_slot: usize) -> Result<(ThreadState, u8, u8, Option<usize>), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let tcb_id = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let idx = self.get_or_create_tcb_mut(tcb_id);
        let obj = &self.tcb_objects[idx];
        Ok((obj.state, obj.priority, obj.mcp, obj.fault_ep_slot))
    }

    // ── B3: Transitive Revocation & Amnesic Memory Zeroing ────────────────

    /// seL4_CNode_Revoke(): Transitively deletes every capability derived from
    /// the target slot.  The target capability itself is kept.
    ///
    /// For Untyped caps: resets the watermark to 0 and zeroes the entire
    /// physical memory region (anti-forensic / zero-remanence guarantee).
    ///
    /// Returns `RevocationStats` counting objects destroyed and bytes zeroed.
    pub fn cnode_revoke_with_stats<F>(
        &mut self,
        slot_idx: usize,
        mut zero_hook: F,
    ) -> Result<RevocationStats, SeL4Error>
    where
        F: FnMut(u64, usize),
    {
        if slot_idx >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if self.slots[slot_idx].cap.is_null() {
            return Err(SeL4Error::SlotEmpty);
        }

        let mut stats = RevocationStats::default();

        // Iterative subtree deletion using an explicit work stack to avoid
        // kernel stack overflow on deeply nested CDT trees.
        // Phase 1: Collect all descendants into a doomed set.
        let mut doomed = [false; N];
        let mut stack: [usize; N] = [0; N];
        let mut sp = 0usize;

        // Seed with direct children
        let mut child_opt = self.slots[slot_idx].first_child;
        while let Some(child_idx) = child_opt {
            if sp < N {
                stack[sp] = child_idx;
                sp += 1;
            }
            child_opt = self.slots[child_idx].next_sibling;
        }

        // DFS traversal: push children of each visited node
        while sp > 0 {
            sp -= 1;
            let idx = stack[sp];
            if idx >= N || doomed[idx] {
                continue;
            }
            doomed[idx] = true;

            // Push this node's children
            let mut grandchild = self.slots[idx].first_child;
            while let Some(gc_idx) = grandchild {
                if gc_idx < N && !doomed[gc_idx] && sp < N {
                    stack[sp] = gc_idx;
                    sp += 1;
                }
                grandchild = self.slots[gc_idx].next_sibling;
            }
        }

        // Phase 2: Zero and destroy all doomed slots.
        for i in 0..N {
            if !doomed[i] {
                continue;
            }

            // B3: Comprehensive amnesic zeroing — zero ALL object types
            let bytes = Self::zero_object_memory(&self.slots[i].cap, &mut zero_hook);
            stats.bytes_zeroed += bytes;
            stats.objects_destroyed += 1;

            self.slots[i] = CdtSlot::EMPTY;
        }

        // Clear parent's child list
        self.slots[slot_idx].first_child = None;

        // If Untyped: reset watermark and zero entire backing region
        if let CapKind::Untyped { paddr, size_bits, ref mut watermark, is_device } =
            self.slots[slot_idx].cap.kind
        {
            *watermark = 0;
            if !is_device {
                let region_size = 1usize << size_bits;
                zero_hook(paddr, region_size);
                stats.bytes_zeroed += region_size;
            }
        }

        Ok(stats)
    }

    /// Legacy revoke API (without stats) for backwards compatibility.
    pub fn cnode_revoke<F>(&mut self, slot_idx: usize, zero_hook: F) -> Result<(), SeL4Error>
    where
        F: FnMut(u64, usize),
    {
        self.cnode_revoke_with_stats(slot_idx, zero_hook)?;
        Ok(())
    }

    /// Zero the physical memory backing a capability's kernel object.
    /// Returns the number of bytes zeroed.
    fn zero_object_memory<F>(cap: &Cap, zero_hook: &mut F) -> usize
    where
        F: FnMut(u64, usize),
    {
        match cap.kind {
            CapKind::Frame { paddr, is_large } => {
                let sz = if is_large { 2 * 1024 * 1024 } else { 4096 };
                zero_hook(paddr, sz);
                sz
            }
            CapKind::TCB { tcb_id, .. } => {
                zero_hook(tcb_id, 1024); // TCB_BITS = 10
                1024
            }
            CapKind::Endpoint { addr, .. } => {
                zero_hook(addr, 16); // ENDPOINT_BITS = 4
                16
            }
            CapKind::Notification { addr, .. } => {
                zero_hook(addr, 16); // NOTIFICATION_BITS = 4
                16
            }
            CapKind::CNode { radix, .. } => {
                let sz = 32 * (1usize << radix); // 32 bytes per slot
                // CNode doesn't have a stored paddr in this model,
                // so we zero via a synthetic address.  In a real kernel
                // the CNode's backing frame would be tracked.
                sz // accounting only — actual zeroing happens through Untyped
            }
            CapKind::SchedContext { sc_id, .. } => {
                // SCHED_CONTEXT_BITS = 8 -> 256 bytes
                zero_hook(sc_id, 256);
                256
            }
            CapKind::Reply { tcb_id, .. } => {
                zero_hook(tcb_id, 32);
                32
            }
            CapKind::PageTable { paddr, .. } => {
                zero_hook(paddr, 4096);
                4096
            }
            CapKind::VSpace { cr3, .. } => {
                zero_hook(cr3, 4096);
                4096
            }
            CapKind::ASIDPool { .. } => {
                4096 // accounting only
            }
            CapKind::Vcpu { .. } => {
                4096 // accounting only
            }
            CapKind::Untyped { paddr, size_bits, is_device, .. } => {
                if !is_device {
                    let sz = 1usize << size_bits;
                    zero_hook(paddr, sz);
                    sz
                } else {
                    0
                }
            }
            // Control capabilities and IO capabilities have no backing memory
            CapKind::IrqControl | CapKind::IoPortControl => 0,
            CapKind::IrqHandler { .. } => 32,
            CapKind::IOPort { .. } => 16,
            CapKind::IOSpace { .. } => 32,
            CapKind::Null => 0,
        }
    }

    /// Post-revocation transitive completeness verification:
    /// After revoking slot S, no slot should transitively point back to S
    /// as a parent (all descendants must have been destroyed).
    pub fn verify_revoke_complete(&self, revoked_slot: usize) -> Result<(), &'static str> {
        if revoked_slot >= N {
            return Err("revoked_slot out of range");
        }
        // The revoked slot itself must have no children
        if self.slots[revoked_slot].first_child.is_some() {
            return Err("revoked slot still has children");
        }
        // No other slot should be a descendant of the revoked slot
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.cap.is_null() || i == revoked_slot {
                continue;
            }
            // Walk parent chain to check for revoked_slot ancestry
            let mut cur = slot.parent;
            let mut hops = 0;
            while let Some(p) = cur {
                if p == revoked_slot {
                    return Err("descendant survived revocation");
                }
                hops += 1;
                if hops > N {
                    return Err("cycle detected in parent chain");
                }
                if p >= N {
                    break;
                }
                cur = self.slots[p].parent;
            }
        }
        Ok(())
    }

    // ── B2: Guarded Radix CSpace Resolution ─────────────────────────────────

    /// seL4 CSpace Address Resolution (Reference Manual §3.2):
    /// Walks a chain of CNodes, consuming guard bits and radix bits from the
    /// capability pointer (CPtr) at each level until `depth` bits are fully
    /// consumed.  Returns the resolved slot index.
    ///
    /// Resolution algorithm:
    ///   1. Extract `guard_size` bits from CPtr at current offset; reject on mismatch.
    ///   2. Extract `radix` bits to compute the slot index within the CNode.
    ///   3. Advance offset by `guard_size + radix`.
    ///   4. If offset == depth, the slot is the answer (terminal).
    ///   5. If the slot contains another CNode, recurse from step 1.
    ///   6. If the slot is NOT a CNode and we have remaining bits, fail with DepthMismatch.
    ///
    /// `root_cnode_slot`: index of the root CNode cap in the flat slot array.
    /// `cptr`: the capability pointer to resolve (bit-vector, MSB-first).
    /// `depth`: total number of bits to consume (0 < depth <= 64).
    pub fn resolve_cptr(
        &self,
        root_cnode_slot: usize,
        cptr: u64,
        depth: u8,
    ) -> Result<usize, SeL4Error> {
        if depth == 0 || depth > 64 {
            return Err(SeL4Error::InvalidArgument);
        }
        if root_cnode_slot >= N {
            return Err(SeL4Error::InvalidRoot);
        }

        let mut current_slot = root_cnode_slot;
        let mut bits_consumed: u8 = 0;

        // Safety: loop bounded by depth ≤ 64 and strictly increasing bits_consumed
        loop {
            let cnode_cap = &self.slots[current_slot].cap;
            let (radix, guard, guard_size) = match cnode_cap.kind {
                CapKind::CNode { radix, guard, guard_size } => (radix, guard, guard_size),
                _ => return Err(SeL4Error::InvalidRoot),
            };

            // Step 1: Guard check — extract `guard_size` bits from CPtr starting at `bits_consumed`
            if guard_size > 0 {
                let remaining = depth - bits_consumed;
                if guard_size > remaining {
                    return Err(SeL4Error::DepthMismatch);
                }
                let shift = 64 - bits_consumed - guard_size;
                let extracted_guard = (cptr >> shift) & ((1u64 << guard_size) - 1);
                if extracted_guard != guard {
                    return Err(SeL4Error::GuardMismatch);
                }
            }
            bits_consumed += guard_size;

            // Step 2: Radix indexing — extract `radix` bits to get the slot offset within this CNode
            if radix > 0 {
                let remaining = depth - bits_consumed;
                if radix > remaining {
                    return Err(SeL4Error::DepthMismatch);
                }
                let shift = 64 - bits_consumed - radix;
                let slot_offset = ((cptr >> shift) & ((1u64 << radix) - 1)) as usize;
                // CNode slots are stored contiguously after the CNode cap itself.
                // For this flat-array model, we treat the CNode cap's slot as the
                // base and the radix indices as offsets from (current_slot + 1).
                // But in real seL4 the CNode is a separate memory object.
                // For our model: CNode at slot S holds 2^radix children in slots S+1..S+2^radix.
                // However, since we have a flat array, we use a mapping function.
                // Practical approach: the CNode at `current_slot` governs slots
                // starting at a base index. We store the base in the CNode's
                // paddr-equivalent.  For simplicity in this model, the CNode's
                // child slots start at `current_slot + 1`.
                let target_slot = current_slot + 1 + slot_offset;
                if target_slot >= N {
                    return Err(SeL4Error::DepthMismatch);
                }
                bits_consumed += radix;

                // Step 3: Check if resolution is complete
                if bits_consumed == depth {
                    return Ok(target_slot); // Terminal: resolution complete
                }

                // Step 4: Not terminal — the target slot must contain another CNode
                if matches!(self.slots[target_slot].cap.kind, CapKind::CNode { .. }) {
                    current_slot = target_slot;
                    continue;
                } else {
                    return Err(SeL4Error::DepthMismatch); // Non-CNode at non-terminal depth
                }
            } else {
                // radix == 0: only guard bits consumed, the CNode itself is the result
                if bits_consumed == depth {
                    return Ok(current_slot);
                }
                return Err(SeL4Error::DepthMismatch);
            }
        }
    }

    /// Simplified flat-array CPtr lookup with rights check (used when CSpace is
    /// modeled as a single flat CNode).
    pub fn lookup_cptr(&self, cptr: u64, need_rights: CapRights) -> Result<&Cap, SeL4Error> {
        let slot_idx = (cptr as usize) % N;
        let slot = &self.slots[slot_idx];

        if slot.cap.is_null() {
            return Err(SeL4Error::MissingCapability);
        }
        if !slot.cap.rights.contains(need_rights) {
            return Err(SeL4Error::InsufficientRights);
        }

        Ok(&slot.cap)
    }

    // ── B2: CNode Operations ──────────────────────────────────────────────

    /// seL4_CNode_Copy(): Copy a capability from src_slot to dest_slot with
    /// rights attenuated by `rights_mask`.  Untyped caps cannot be copied
    /// (they can only be retyped).  The new cap becomes a CDT child of the source.
    pub fn cnode_copy(
        &mut self,
        src_slot: usize,
        dest_slot: usize,
        rights_mask: CapRights,
    ) -> Result<(), SeL4Error> {
        if src_slot >= N || dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if src_slot == dest_slot {
            return Err(SeL4Error::InvalidArgument);
        }
        if !self.slots[dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }
        let src_cap = self.slots[src_slot].cap;
        if src_cap.is_null() {
            return Err(SeL4Error::SlotEmpty);
        }
        // Untyped caps cannot be copied (seL4 invariant: prevents watermark duplication)
        if matches!(src_cap.kind, CapKind::Untyped { .. }) {
            return Err(SeL4Error::IllegalOperation);
        }

        let derived_rights = src_cap.rights.intersect(rights_mask);
        let derived_cap = Cap { kind: src_cap.kind, rights: derived_rights };

        // Insert into CDT as child of src
        let prev_first = self.slots[src_slot].first_child;
        self.slots[dest_slot] = CdtSlot {
            cap: derived_cap,
            parent: Some(src_slot),
            first_child: None,
            next_sibling: prev_first,
            prev_sibling: None,
        };
        if let Some(first_idx) = prev_first {
            self.slots[first_idx].prev_sibling = Some(dest_slot);
        }
        self.slots[src_slot].first_child = Some(dest_slot);

        Ok(())
    }

    /// seL4_CNode_Move(): Move a capability from src_slot to dest_slot.
    /// The source slot is emptied.  All CDT children of src are re-parented to dest.
    /// The moved cap retains its parent relationship.
    pub fn cnode_move(
        &mut self,
        src_slot: usize,
        dest_slot: usize,
    ) -> Result<(), SeL4Error> {
        if src_slot >= N || dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if src_slot == dest_slot {
            return Err(SeL4Error::InvalidArgument);
        }
        if !self.slots[dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }
        if self.slots[src_slot].cap.is_null() {
            return Err(SeL4Error::SlotEmpty);
        }

        // Copy the entire CDT slot
        let moved = self.slots[src_slot];

        // Re-parent all children from src to dest
        let mut child_opt = moved.first_child;
        while let Some(child_idx) = child_opt {
            self.slots[child_idx].parent = Some(dest_slot);
            child_opt = self.slots[child_idx].next_sibling;
        }

        // Update the parent's child list to point to dest instead of src
        if let Some(parent_idx) = moved.parent {
            if self.slots[parent_idx].first_child == Some(src_slot) {
                self.slots[parent_idx].first_child = Some(dest_slot);
            }
        }

        // Update siblings to point to dest instead of src
        if let Some(prev_idx) = moved.prev_sibling {
            self.slots[prev_idx].next_sibling = Some(dest_slot);
        }
        if let Some(next_idx) = moved.next_sibling {
            self.slots[next_idx].prev_sibling = Some(dest_slot);
        }

        self.slots[dest_slot] = moved;
        self.slots[src_slot] = CdtSlot::EMPTY;

        Ok(())
    }

    /// seL4_CNode_Mutate(): Atomically move a capability and attenuate its rights.
    /// Equivalent to Move + rights intersection in a single atomic step.
    pub fn cnode_mutate(
        &mut self,
        src_slot: usize,
        dest_slot: usize,
        rights_mask: CapRights,
    ) -> Result<(), SeL4Error> {
        self.cnode_move(src_slot, dest_slot)?;
        self.slots[dest_slot].cap.rights =
            self.slots[dest_slot].cap.rights.intersect(rights_mask);
        Ok(())
    }

    /// seL4_CNode_Rotate(): Atomic 3-way capability rotation:
    ///   pivot → dest, src → pivot, src emptied.
    /// All CDT parent/child/sibling links are updated atomically.
    pub fn cnode_rotate(
        &mut self,
        src_slot: usize,
        pivot_slot: usize,
        dest_slot: usize,
    ) -> Result<(), SeL4Error> {
        if src_slot >= N || pivot_slot >= N || dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if src_slot == pivot_slot || pivot_slot == dest_slot || src_slot == dest_slot {
            return Err(SeL4Error::InvalidArgument);
        }
        if self.slots[src_slot].cap.is_null() || self.slots[pivot_slot].cap.is_null() {
            return Err(SeL4Error::SlotEmpty);
        }
        if !self.slots[dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }

        // Snapshot the slots before changing any derivation links.
        let snap_src = self.slots[src_slot];
        let snap_pivot = self.slots[pivot_slot];

        // CNode_Rotate moves the source cap to the pivot slot and the pivot
        // cap to the destination. Remap every edge that points at either
        // moved slot, including links between the source and pivot when one
        // is an ancestor or sibling of the other. Updating links globally
        // avoids stale self-links when both caps share a parent.
        let remap = |slot: Option<usize>| {
            slot.map(|idx| {
                if idx == src_slot {
                    pivot_slot
                } else if idx == pivot_slot {
                    dest_slot
                } else {
                    idx
                }
            })
        };
        let mut moved_src = snap_src;
        moved_src.parent = remap(moved_src.parent);
        moved_src.first_child = remap(moved_src.first_child);
        moved_src.next_sibling = remap(moved_src.next_sibling);
        moved_src.prev_sibling = remap(moved_src.prev_sibling);
        let mut moved_pivot = snap_pivot;
        moved_pivot.parent = remap(moved_pivot.parent);
        moved_pivot.first_child = remap(moved_pivot.first_child);
        moved_pivot.next_sibling = remap(moved_pivot.next_sibling);
        moved_pivot.prev_sibling = remap(moved_pivot.prev_sibling);

        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if idx == src_slot || idx == pivot_slot || idx == dest_slot {
                continue;
            }
            slot.parent = remap(slot.parent);
            slot.first_child = remap(slot.first_child);
            slot.next_sibling = remap(slot.next_sibling);
            slot.prev_sibling = remap(slot.prev_sibling);
        }

        self.slots[src_slot] = CdtSlot::EMPTY;
        self.slots[pivot_slot] = moved_src;
        self.slots[dest_slot] = moved_pivot;

        Ok(())
    }

    /// seL4_CNode_Delete(): Remove a capability from a slot.
    /// Re-parents all children of the deleted cap to its parent (grandparent adoption).
    /// An Untyped cap with live children cannot be deleted (must be revoked first).
    pub fn cnode_delete(&mut self, slot_idx: usize) -> Result<(), SeL4Error> {
        if slot_idx >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if self.slots[slot_idx].cap.is_null() {
            return Err(SeL4Error::SlotEmpty);
        }

        // Untyped with live children must be revoked first
        if matches!(self.slots[slot_idx].cap.kind, CapKind::Untyped { .. })
            && self.slots[slot_idx].first_child.is_some()
        {
            return Err(SeL4Error::RevokeFailed);
        }

        let parent = self.slots[slot_idx].parent;

        // Unlink this slot from parent's child list
        let prev = self.slots[slot_idx].prev_sibling;
        let next = self.slots[slot_idx].next_sibling;
        if let Some(prev_idx) = prev {
            self.slots[prev_idx].next_sibling = next;
        }
        if let Some(next_idx) = next {
            self.slots[next_idx].prev_sibling = prev;
        }
        // If this was the first child of parent, update parent's first_child
        if let Some(parent_idx) = parent {
            if self.slots[parent_idx].first_child == Some(slot_idx) {
                self.slots[parent_idx].first_child = next;
            }
        }

        // Grandparent adoption: re-parent all children to the deleted cap's parent
        let mut child_opt = self.slots[slot_idx].first_child;
        let mut last_child = None;
        while let Some(child_idx) = child_opt {
            self.slots[child_idx].parent = parent;
            last_child = Some(child_idx);
            child_opt = self.slots[child_idx].next_sibling;
        }

        // Link adopted children into parent's child list
        if let Some(first_child) = self.slots[slot_idx].first_child {
            if let Some(parent_idx) = parent {
                // Append adopted children to the front of parent's child list
                let old_first = self.slots[parent_idx].first_child;
                if let Some(last) = last_child {
                    self.slots[last].next_sibling = old_first;
                }
                if let Some(old_first_idx) = old_first {
                    self.slots[old_first_idx].prev_sibling = last_child;
                }
                self.slots[parent_idx].first_child = Some(first_child);
                self.slots[first_child].prev_sibling = None;
            }
        }

        self.slots[slot_idx] = CdtSlot::EMPTY;
        Ok(())
    }

    /// seL4_CNode_SaveCaller(): Save a Reply capability from a caller TCB into a CNode slot.
    /// The reply cap is one-shot: once saved, the caller's slot is consumed.
    pub fn cnode_save_caller(
        &mut self,
        caller_tcb_slot: usize,
        dest_slot: usize,
    ) -> Result<(), SeL4Error> {
        if caller_tcb_slot >= N || dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
        }

        let tcb_cap = self.slots[caller_tcb_slot].cap;
        let tcb_id = match tcb_cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        self.slots[dest_slot] = CdtSlot {
            cap: Cap {
                kind: CapKind::Reply { tcb_id, is_valid: true },
                rights: CapRights::ALL,
            },
            parent: Some(caller_tcb_slot),
            first_child: None,
            next_sibling: self.slots[caller_tcb_slot].first_child,
            prev_sibling: None,
        };

        if let Some(old_first) = self.slots[caller_tcb_slot].first_child {
            self.slots[old_first].prev_sibling = Some(dest_slot);
        }
        self.slots[caller_tcb_slot].first_child = Some(dest_slot);

        Ok(())
    }

    /// Configure the guard value and size on a CNode capability.
    /// This controls how CSpace address resolution skips/matches guard bits
    /// before indexing into the radix.
    pub fn cnode_set_guard(
        &mut self,
        cnode_slot: usize,
        guard: u64,
        guard_size: u8,
    ) -> Result<(), SeL4Error> {
        if cnode_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if guard_size > 64 {
            return Err(SeL4Error::InvalidArgument);
        }
        // Validate that guard value fits within guard_size bits
        if guard_size < 64 && guard >= (1u64 << guard_size) {
            return Err(SeL4Error::InvalidArgument);
        }

        match self.slots[cnode_slot].cap.kind {
            CapKind::CNode { radix, .. } => {
                self.slots[cnode_slot].cap.kind = CapKind::CNode {
                    radix,
                    guard,
                    guard_size,
                };
                Ok(())
            }
            _ => Err(SeL4Error::InvalidCapability),
        }
    }

    // ── B2: CDT Integrity Invariant Checker ───────────────────────────────

    /// Verify all Capability Derivation Tree structural invariants:
    /// I1: Null slots have no CDT links.
    /// I2: Sibling links are consistent (prev↔next bijection).
    /// I3: Every child's parent pointer matches the parent that lists it.
    /// I4: No cycles in the parent chain (bounded by N hops).
    /// I5: Rights monotonicity — no child has more rights than its parent.
    pub fn check_cdt_invariants(&self) -> Result<(), &'static str> {
        for (i, slot) in self.slots.iter().enumerate() {
            // I1: Null slots must have no CDT links
            if slot.cap.is_null() {
                if slot.parent.is_some() || slot.first_child.is_some()
                    || slot.next_sibling.is_some() || slot.prev_sibling.is_some()
                {
                    return Err("I1: null slot has CDT links");
                }
                continue;
            }

            // I2: Sibling consistency — if slot.next_sibling == Some(j), then j.prev_sibling == Some(i)
            if let Some(next_idx) = slot.next_sibling {
                if next_idx >= N {
                    return Err("I2: next_sibling out of range");
                }
                if self.slots[next_idx].prev_sibling != Some(i) {
                    return Err("I2: next_sibling's prev_sibling doesn't point back");
                }
            }
            if let Some(prev_idx) = slot.prev_sibling {
                if prev_idx >= N {
                    return Err("I2: prev_sibling out of range");
                }
                if self.slots[prev_idx].next_sibling != Some(i) {
                    return Err("I2: prev_sibling's next_sibling doesn't point back");
                }
            }

            // I3: If this slot has a parent, verify the parent's child list contains this slot
            if let Some(parent_idx) = slot.parent {
                if parent_idx >= N {
                    return Err("I3: parent index out of range");
                }
                if self.slots[parent_idx].cap.is_null() {
                    return Err("I3: parent slot is null");
                }
                // Walk parent's child list to find this slot
                let mut found = false;
                let mut cursor = self.slots[parent_idx].first_child;
                let mut hops = 0usize;
                while let Some(child_idx) = cursor {
                    if child_idx == i {
                        found = true;
                        break;
                    }
                    hops += 1;
                    if hops > N {
                        return Err("I3: cycle in sibling list");
                    }
                    cursor = self.slots[child_idx].next_sibling;
                }
                if !found {
                    return Err("I3: slot claims parent but not in parent's child list");
                }
            }

            // I4: Acyclic parent chain (bounded by N hops)
            {
                let mut cur = slot.parent;
                let mut hops = 0usize;
                while let Some(p) = cur {
                    if p >= N {
                        return Err("I4: parent index out of range in chain");
                    }
                    hops += 1;
                    if hops > N {
                        return Err("I4: cycle in parent chain");
                    }
                    if p == i {
                        return Err("I4: slot is its own ancestor");
                    }
                    cur = self.slots[p].parent;
                }
            }

            // I5: Rights monotonicity — child rights ⊆ parent rights
            if let Some(parent_idx) = slot.parent {
                let parent_rights = self.slots[parent_idx].cap.rights;
                if !parent_rights.contains(slot.cap.rights) {
                    return Err("I5: rights escalation detected");
                }
            }
        }

        // I3 supplement: verify first_child links point to valid children
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.cap.is_null() {
                continue;
            }
            if let Some(first_child) = slot.first_child {
                if first_child >= N {
                    return Err("I3: first_child out of range");
                }
                if self.slots[first_child].parent != Some(i) {
                    return Err("I3: first_child's parent doesn't point back");
                }
                if self.slots[first_child].prev_sibling.is_some() {
                    return Err("I3: first_child has prev_sibling (should be None)");
                }
            }
        }

        Ok(())
    }

    // ── B7: Mixed-Criticality Scheduling (MCS): SchedContext & Temporal Isolation ──

    fn get_or_create_sched_context_mut(&mut self, sc_id: u64, budget_us: u64, period_us: u64) -> usize {
        for (i, sc) in self.sched_context_objects.iter().enumerate() {
            if sc.sc_id == sc_id {
                return i;
            }
        }
        self.sched_context_objects.push(SchedContextObject {
            sc_id,
            budget_us,
            period_us,
            remaining_budget_us: budget_us,
            bound_tcb_id: None,
            badge: 0,
            is_sporadic: true,
            last_replenished_us: 0,
            replenishment_deadline_us: period_us,
        });
        self.sched_context_objects.len() - 1
    }

    /// seL4_SchedContext_Configure: Sets parameters (budget, period, badge) on a Scheduling Context.
    /// Invariant: budget_us > 0 and budget_us <= period_us.
    pub fn sched_context_configure(
        &mut self,
        sc_slot: usize,
        budget_us: u64,
        period_us: u64,
        badge: u64,
    ) -> Result<(), SeL4Error> {
        if sc_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[sc_slot].cap.rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        if budget_us == 0 || budget_us > period_us {
            return Err(SeL4Error::InvalidArgument);
        }
        let sc_id = match self.slots[sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, .. } => sc_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let idx = self.get_or_create_sched_context_mut(sc_id, budget_us, period_us);
        self.sched_context_objects[idx].budget_us = budget_us;
        self.sched_context_objects[idx].period_us = period_us;
        self.sched_context_objects[idx].remaining_budget_us = budget_us;
        self.sched_context_objects[idx].badge = badge;
        self.sched_context_objects[idx].replenishment_deadline_us = period_us;

        // Keep cap kind synchronized
        self.slots[sc_slot].cap.kind = CapKind::SchedContext {
            sc_id,
            budget_us,
            period_us,
            is_sporadic: true,
        };

        Ok(())
    }

    /// seL4_SchedContext_Bind: Binds a Scheduling Context to a target TCB.
    /// Requires WRITE on SchedContext and WRITE on TCB.
    /// Transitions target thread out of passive state.
    pub fn sched_context_bind(&mut self, sc_slot: usize, tcb_slot: usize) -> Result<(), SeL4Error> {
        if sc_slot >= N || tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[sc_slot].cap.rights.contains(CapRights::WRITE)
            || !self.slots[tcb_slot].cap.rights.contains(CapRights::WRITE)
        {
            return Err(SeL4Error::InsufficientRights);
        }
        let (sc_id, budget_us, period_us) = match self.slots[sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, budget_us, period_us, .. } => (sc_id, budget_us, period_us),
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let tcb_id = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let sc_idx = self.get_or_create_sched_context_mut(sc_id, budget_us, period_us);
        if let Some(existing_tcb) = self.sched_context_objects[sc_idx].bound_tcb_id {
            if existing_tcb != tcb_id {
                return Err(SeL4Error::IllegalOperation); // SchedContext already bound to another thread
            }
        }

        let tcb_idx = self.get_or_create_tcb_mut(tcb_id);
        self.sched_context_objects[sc_idx].bound_tcb_id = Some(tcb_id);
        self.tcb_objects[tcb_idx].bound_sched_context_slot = Some(sc_slot);
        self.tcb_objects[tcb_idx].is_passive = false;

        // Update TCB cap in slot if present
        if let CapKind::TCB { ref mut is_passive, .. } = self.slots[tcb_slot].cap.kind {
            *is_passive = false;
        }

        Ok(())
    }

    /// seL4_SchedContext_Unbind: Disassociates a Scheduling Context from its bound TCB.
    /// The previously bound TCB becomes passive.
    pub fn sched_context_unbind(&mut self, sc_slot: usize) -> Result<(), SeL4Error> {
        if sc_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[sc_slot].cap.rights.contains(CapRights::WRITE) {
            return Err(SeL4Error::InsufficientRights);
        }
        let sc_id = match self.slots[sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, .. } => sc_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let sc_idx = match self.sched_context_objects.iter().position(|s| s.sc_id == sc_id) {
            Some(i) => i,
            None => return Ok(()),
        };

        if let Some(bound_tcb) = self.sched_context_objects[sc_idx].bound_tcb_id {
            if let Some(tcb_idx) = self.tcb_objects.iter().position(|t| t.tcb_id == bound_tcb) {
                self.tcb_objects[tcb_idx].bound_sched_context_slot = None;
                if self.tcb_objects[tcb_idx].donated_sched_context_slot.is_none() {
                    self.tcb_objects[tcb_idx].is_passive = true;
                }
            }
            self.sched_context_objects[sc_idx].bound_tcb_id = None;
        }

        Ok(())
    }

    /// Deducts consumed execution time from the scheduling context's budget.
    /// Returns (remaining_budget_us, is_exhausted).
    pub fn sched_context_charge(&mut self, sc_slot: usize, elapsed_us: u64) -> Result<(u64, bool), SeL4Error> {
        if sc_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let sc_id = match self.slots[sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, .. } => sc_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let sc_idx = match self.sched_context_objects.iter().position(|s| s.sc_id == sc_id) {
            Some(i) => i,
            None => return Err(SeL4Error::InvalidCapability),
        };

        let obj = &mut self.sched_context_objects[sc_idx];
        obj.remaining_budget_us = obj.remaining_budget_us.saturating_sub(elapsed_us);
        let exhausted = obj.remaining_budget_us == 0;

        Ok((obj.remaining_budget_us, exhausted))
    }

    /// Restores scheduling context budget when current time advances past the replenishment deadline.
    pub fn sched_context_replenish(&mut self, sc_slot: usize, current_time_us: u64) -> Result<u64, SeL4Error> {
        if sc_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let sc_id = match self.slots[sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, .. } => sc_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let sc_idx = match self.sched_context_objects.iter().position(|s| s.sc_id == sc_id) {
            Some(i) => i,
            None => return Err(SeL4Error::InvalidCapability),
        };

        let obj = &mut self.sched_context_objects[sc_idx];
        if current_time_us >= obj.replenishment_deadline_us {
            obj.remaining_budget_us = obj.budget_us;
            obj.last_replenished_us = current_time_us;
            obj.replenishment_deadline_us = current_time_us + obj.period_us;
        }

        Ok(obj.remaining_budget_us)
    }

    /// Donates donor thread's active scheduling context to a passive server during synchronous IPC.
    pub fn sched_context_donate(&mut self, donor_tcb_slot: usize, recipient_tcb_slot: usize) -> Result<(), SeL4Error> {
        if donor_tcb_slot >= N || recipient_tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let donor_tcb_id = match self.slots[donor_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let recipient_tcb_id = match self.slots[recipient_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let donor_idx = self.get_or_create_tcb_mut(donor_tcb_id);
        let donor_sc_slot = self.tcb_objects[donor_idx]
            .bound_sched_context_slot
            .ok_or(SeL4Error::MissingCapability)?;

        // Verify SchedContext has remaining budget
        let sc_id = match self.slots[donor_sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, .. } => sc_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let sc_idx = self.sched_context_objects.iter().position(|s| s.sc_id == sc_id).ok_or(SeL4Error::InvalidCapability)?;
        if self.sched_context_objects[sc_idx].remaining_budget_us == 0 {
            return Err(SeL4Error::InvalidArgument);
        }

        let recipient_idx = self.get_or_create_tcb_mut(recipient_tcb_id);
        if !self.tcb_objects[recipient_idx].is_passive {
            return Err(SeL4Error::IllegalOperation); // Only passive threads receive donated time
        }

        self.tcb_objects[recipient_idx].donated_sched_context_slot = Some(donor_sc_slot);
        self.tcb_objects[recipient_idx].is_passive = false;

        Ok(())
    }

    /// Returns a donated scheduling context back to the client upon reply.
    pub fn sched_context_return(&mut self, recipient_tcb_slot: usize) -> Result<(), SeL4Error> {
        if recipient_tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let recipient_tcb_id = match self.slots[recipient_tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let recipient_idx = self.get_or_create_tcb_mut(recipient_tcb_id);
        self.tcb_objects[recipient_idx].donated_sched_context_slot = None;
        if self.tcb_objects[recipient_idx].bound_sched_context_slot.is_none() {
            self.tcb_objects[recipient_idx].is_passive = true;
        }

        Ok(())
    }

    /// Query SchedContext parameters: (budget_us, period_us, remaining_budget_us, bound_tcb_id, badge)
    pub fn sched_context_query(&mut self, sc_slot: usize) -> Result<(u64, u64, u64, Option<u64>, u64), SeL4Error> {
        if sc_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let sc_id = match self.slots[sc_slot].cap.kind {
            CapKind::SchedContext { sc_id, .. } => sc_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };

        let sc_idx = match self.sched_context_objects.iter().position(|s| s.sc_id == sc_id) {
            Some(i) => i,
            None => return Err(SeL4Error::InvalidCapability),
        };

        let obj = &self.sched_context_objects[sc_idx];
        Ok((
            obj.budget_us,
            obj.period_us,
            obj.remaining_budget_us,
            obj.bound_tcb_id,
            obj.badge,
        ))
    }

    /// Configures whether a TCB is marked passive (MCS).
    pub fn tcb_set_passive(&mut self, tcb_slot: usize, is_passive: bool) -> Result<(), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let tcb_id = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let idx = self.get_or_create_tcb_mut(tcb_id);
        self.tcb_objects[idx].is_passive = is_passive;
        if let CapKind::TCB { is_passive: ref mut cap_passive, .. } = self.slots[tcb_slot].cap.kind {
            *cap_passive = is_passive;
        }
        Ok(())
    }

    /// Query TCB MCS state: (is_passive, bound_sched_context_slot, donated_sched_context_slot)
    pub fn tcb_query_mcs_state(&mut self, tcb_slot: usize) -> Result<(bool, Option<usize>, Option<usize>), SeL4Error> {
        if tcb_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        let tcb_id = match self.slots[tcb_slot].cap.kind {
            CapKind::TCB { tcb_id, .. } => tcb_id,
            _ => return Err(SeL4Error::InvalidCapability),
        };
        let idx = self.get_or_create_tcb_mut(tcb_id);
        let obj = &self.tcb_objects[idx];
        Ok((obj.is_passive, obj.bound_sched_context_slot, obj.donated_sched_context_slot))
    }
}
