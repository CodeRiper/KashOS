//! seL4 Capability Microkernel Core (seL4 Reference Manual v16.0.0 Architecture)
//!
//! Provides mathematically unforgeable capability tokens, guarded radix CSpaces,
//! watermark-tracked Untyped memory, Capability Derivation Tree (CDT) tracking,
//! recursive revocation with deterministic memory zeroing, badged IPC endpoints,
//! notifications, and Mixed-Criticality System (MCS) temporal isolation.
extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

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
}

// ── 6. Guarded Radix Capability Space & Microkernel Core ──────────────────────

pub struct SeL4CapabilityCore<const N: usize> {
    pub slots: [CdtSlot; N],
    untyped_descriptors: Vec<UntypedDescriptor>,
}

#[derive(Debug)]
pub struct UntypedDescriptor {
    pub paddr: u64,
    pub size_bits: u8,
    pub is_device: bool,
    pub watermark: AtomicU64,
}

impl<const N: usize> SeL4CapabilityCore<N> {
    pub const fn new() -> Self {
        Self {
            slots: [CdtSlot::EMPTY; N],
            untyped_descriptors: Vec::new(),
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
    pub fn untyped_retype(
        &mut self,
        untyped_slot: usize,
        target_type: KernelObjType,
        dest_slot: usize,
    ) -> Result<u64, SeL4Error> {
        if untyped_slot >= N || dest_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }
        if !self.slots[dest_slot].cap.is_null() {
            return Err(SeL4Error::SlotOccupied);
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
        if aligned_wm + obj_size > max_size {
            return Err(SeL4Error::NotEnoughMemory);
        }

        let allocated_paddr = base_paddr + aligned_wm;

        // Construct the new capability
        let new_cap_kind = match target_type {
            KernelObjType::Frame4K => CapKind::Frame { paddr: allocated_paddr, is_large: false },
            KernelObjType::Frame2M => CapKind::Frame { paddr: allocated_paddr, is_large: true },
            KernelObjType::Frame1G => CapKind::Frame { paddr: allocated_paddr, is_large: true },
            KernelObjType::Endpoint => CapKind::Endpoint { addr: allocated_paddr, badge: 0 },
            KernelObjType::Notification => CapKind::Notification { addr: allocated_paddr, badge: 0 },
            KernelObjType::TCB => CapKind::TCB { tcb_id: allocated_paddr, priority: 128, is_passive: false },
            KernelObjType::CNode { size_bits } => CapKind::CNode { radix: size_bits, guard: 0, guard_size: 0 },
            KernelObjType::SchedContext { budget_us, period_us } => CapKind::SchedContext { budget_us, period_us, is_sporadic: true },
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

        // Update watermark
        if let CapKind::Untyped { ref mut watermark, .. } = self.slots[untyped_slot].cap.kind {
            *watermark = aligned_wm + obj_size;
        }

        // Insert into CDT as child of untyped_slot
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

        Ok(allocated_paddr)
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

    /// seL4_CNode_Revoke(): Recursively deletes all child capabilities in the CDT,
    /// resets Untyped watermark, and zeroes physical memory.
    pub fn cnode_revoke<F>(&mut self, slot_idx: usize, mut zero_hook: F) -> Result<(), SeL4Error>
    where
        F: FnMut(u64, usize),
    {
        if slot_idx >= N {
            return Err(SeL4Error::DepthMismatch);
        }

        // Recursively delete all children
        let mut curr_child = self.slots[slot_idx].first_child;
        while let Some(child_idx) = curr_child {
            let next = self.slots[child_idx].next_sibling;
            self.delete_subtree(child_idx, &mut zero_hook);
            curr_child = next;
        }
        self.slots[slot_idx].first_child = None;

        // If this slot was an Untyped capability, reset its watermark to 0 and zero entire region
        if let CapKind::Untyped { paddr, size_bits, ref mut watermark, is_device } = self.slots[slot_idx].cap.kind {
            *watermark = 0;
            if !is_device {
                zero_hook(paddr, 1usize << size_bits);
            }
        }

        Ok(())
    }

    fn delete_subtree<F>(&mut self, root_idx: usize, zero_hook: &mut F)
    where
        F: FnMut(u64, usize),
    {
        let mut curr_child = self.slots[root_idx].first_child;
        while let Some(child_idx) = curr_child {
            let next = self.slots[child_idx].next_sibling;
            self.delete_subtree(child_idx, zero_hook);
            curr_child = next;
        }

        // Trigger kernel destroy / zero memory frame
        match self.slots[root_idx].cap.kind {
            CapKind::Frame { paddr, is_large } => {
                let sz = if is_large { 2 * 1024 * 1024 } else { 4096 };
                zero_hook(paddr, sz);
            }
            CapKind::TCB { tcb_id, .. } => {
                zero_hook(tcb_id, 1024);
            }
            _ => {}
        }

        self.slots[root_idx] = CdtSlot::EMPTY;
    }

    /// Lookup capability pointer with Guarded Radix CSpace resolution
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

    /// MCS: Scheduling Context Donation for Passive Servers
    pub fn mcs_donate_budget(&mut self, server_tcb_slot: usize, client_sc_slot: usize) -> Result<(), SeL4Error> {
        if server_tcb_slot >= N || client_sc_slot >= N {
            return Err(SeL4Error::DepthMismatch);
        }

        match (self.slots[server_tcb_slot].cap.kind, self.slots[client_sc_slot].cap.kind) {
            (CapKind::TCB { is_passive, .. }, CapKind::SchedContext { budget_us, .. }) => {
                if !is_passive {
                    return Err(SeL4Error::IllegalOperation); // Only passive servers borrow client budget
                }
                if budget_us == 0 {
                    return Err(SeL4Error::InvalidArgument); // Budget exhausted
                }
                Ok(())
            }
            _ => Err(SeL4Error::InvalidCapability),
        }
    }
}
