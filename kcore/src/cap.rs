use crate::error::{KError, KResult};

/// Access rights. Unknown bits are rejected, never silently truncated.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Rights(u8);

impl Rights {
    pub const NONE: Rights = Rights(0);
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const GRANT: Rights = Rights(1 << 2);
    pub const ALL: Rights = Rights(0b111);

    /// Parse untrusted bits (e.g. from a syscall argument).
    pub const fn from_bits(bits: u8) -> Option<Rights> {
        if bits & !Self::ALL.0 == 0 {
            Some(Rights(bits))
        } else {
            None
        }
    }
    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn contains(self, other: Rights) -> bool {
        self.0 & other.0 == other.0
    }
    pub const fn intersect(self, other: Rights) -> Rights {
        Rights(self.0 & other.0)
    }
}

pub const MIN_UNTYPED_BITS: u8 = 4; // 16 bytes
pub const MAX_UNTYPED_BITS: u8 = 47; // 128 TiB, keeps every shift/add overflow-free
pub const FRAME_BITS: u8 = 12; // 4 KiB
pub const ENDPOINT_BITS: u8 = 4; // 16 bytes
pub const NOTIFICATION_BITS: u8 = 4; // 16 bytes
pub const TCB_BITS: u8 = 10; // 1024 bytes
pub const SCHED_CONTEXT_BITS: u8 = 8; // 256 bytes

/// Kernel object types that can be carved out of Untyped memory (seL4 v16.0 Model).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObjType {
    Untyped { size_bits: u8 },
    Frame,
    Endpoint,
    Notification,
    TCB,
    CNode { size_bits: u8 },
    SchedContext { size_bits: u8 },
}

impl ObjType {
    pub const fn size_bits(self) -> u8 {
        match self {
            ObjType::Untyped { size_bits } => size_bits,
            ObjType::Frame => FRAME_BITS,
            ObjType::Endpoint => ENDPOINT_BITS,
            ObjType::Notification => NOTIFICATION_BITS,
            ObjType::TCB => TCB_BITS,
            ObjType::CNode { size_bits } => size_bits,
            ObjType::SchedContext { size_bits } => size_bits,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CapKind {
    Null,
    /// `free` is the allocation watermark (bytes already handed out from `base`).
    Untyped { base: u64, size_bits: u8, free: u64 },
    Frame { paddr: u64 },
    Endpoint { addr: u64 },
    Notification { addr: u64 },
    TCB { tcb_id: u64 },
    CNode { radix: u8, guard: u64, guard_size: u8 },
    SchedContext { budget_us: u64, period_us: u64 },
    IOSpace { pci_bdf: u16, domain_id: u16 },
    IOPageTable { level: u8 },
    IOPort { start_port: u16, end_port: u16 },
}

impl CapKind {
    /// Physical memory this capability designates, as `(start, len)`.
    pub const fn range(&self) -> Option<(u64, u64)> {
        match *self {
            CapKind::Null => None,
            CapKind::Untyped { base, size_bits, .. } => Some((base, 1u64 << size_bits)),
            CapKind::Frame { paddr } => Some((paddr, 1u64 << FRAME_BITS)),
            CapKind::Endpoint { addr } => Some((addr, 1u64 << ENDPOINT_BITS)),
            CapKind::Notification { addr } => Some((addr, 1u64 << NOTIFICATION_BITS)),
            CapKind::TCB { tcb_id } => Some((tcb_id, 1u64 << TCB_BITS)),
            CapKind::CNode { radix, .. } => Some((0, 1u64 << radix)),
            CapKind::SchedContext { .. } => Some((0, 1u64 << SCHED_CONTEXT_BITS)),
            CapKind::IOSpace { .. } => None,
            CapKind::IOPageTable { .. } => None,
            CapKind::IOPort { .. } => None,
        }
    }
}

/// A capability. Fields are crate-private so no other crate can forge one;
/// the only public constructors are `Cap::NULL` and `Cap::new_untyped` (boot).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cap {
    pub(crate) kind: CapKind,
    pub(crate) rights: Rights,
    /// 0 = unbadged. Only meaningful on Endpoint caps.
    pub(crate) badge: u64,
}

impl Cap {
    pub const NULL: Cap = Cap { kind: CapKind::Null, rights: Rights::NONE, badge: 0 };

    /// Describe a region of RAM as Untyped memory. Boot code only.
    /// The region must be naturally aligned and must not wrap the address space.
    pub fn new_untyped(base: u64, size_bits: u8) -> KResult<Cap> {
        if !(MIN_UNTYPED_BITS..=MAX_UNTYPED_BITS).contains(&size_bits) {
            return Err(KError::InvalidArgument);
        }
        let size = 1u64 << size_bits;
        if base & (size - 1) != 0 || base.checked_add(size).is_none() {
            return Err(KError::InvalidArgument);
        }
        Ok(Cap {
            kind: CapKind::Untyped { base, size_bits, free: 0 },
            rights: Rights::ALL,
            badge: 0,
        })
    }

    pub const fn kind(&self) -> CapKind {
        self.kind
    }
    pub const fn rights(&self) -> Rights {
        self.rights
    }
    pub const fn badge(&self) -> u64 {
        self.badge
    }
    pub const fn is_null(&self) -> bool {
        matches!(self.kind, CapKind::Null)
    }
}

/// Extended Capability Rights bitmasks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CapRights(pub u32);

impl CapRights {
    pub const NONE: u32    = 0;
    pub const READ: u32    = 1 << 0;
    pub const WRITE: u32   = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const GRANT: u32   = 1 << 3; // Derive child capabilities
    pub const REVOKE: u32  = 1 << 4; // Recursively revoke descendants
    pub const ALL: u32     = (1 << 5) - 1;

    pub const fn contains(&self, bit: u32) -> bool {
        (self.0 & bit) == bit
    }
}

/// Capability Derivation Tree (CDT) node tracking explicit parent-child lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityNode {
    pub cap_id: u64,
    pub object_ptr: u64,
    pub rights: Rights,
    pub badge: Option<u64>,
    pub parent_cap_id: Option<u64>,
    pub first_child: Option<u64>,
    pub next_sibling: Option<u64>,
}

impl CapabilityNode {
    pub const EMPTY: Self = CapabilityNode {
        cap_id: 0,
        object_ptr: 0,
        rights: Rights::NONE,
        badge: None,
        parent_cap_id: None,
        first_child: None,
        next_sibling: None,
    };
}

/// OpenBSD-inspired system call restriction flags (pledge).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PledgeFlags(pub u32);

impl PledgeFlags {
    pub const NONE: u32  = 0;
    pub const STDIO: u32 = 1 << 0;
    pub const RPATH: u32 = 1 << 1;
    pub const WPATH: u32 = 1 << 2;
    pub const CPATH: u32 = 1 << 3;
    pub const INET: u32  = 1 << 4;
    pub const PROC: u32  = 1 << 5;
    pub const EXEC: u32  = 1 << 6;
    pub const ALL: u32   = (1 << 7) - 1;

    pub const fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) == flag
    }
}

/// Process security context for microkernel-enforced pledge and unveil sandboxing.
#[derive(Clone, Copy, Debug)]
pub struct ProcessSecurityContext {
    pub active_pledges: PledgeFlags,
    pub is_pledged: bool,
    pub unveiled_namespaces: [(u64, Rights); 16],
    pub unveiled_count: usize,
}

impl ProcessSecurityContext {
    pub const fn unconfined() -> Self {
        ProcessSecurityContext {
            active_pledges: PledgeFlags(PledgeFlags::ALL),
            is_pledged: false,
            unveiled_namespaces: [(0, Rights::NONE); 16],
            unveiled_count: 0,
        }
    }

    /// Pledges a subset of privileges. Privileges can only shrink, never expand.
    pub fn pledge(&mut self, pledges: u32) -> KResult<()> {
        if self.is_pledged && (self.active_pledges.0 & pledges) != pledges {
            return Err(KError::InsufficientRights);
        }
        self.active_pledges.0 &= pledges;
        self.is_pledged = true;
        Ok(())
    }

    /// Unveils a specific VFS node capability to this process with restricted rights.
    pub fn unveil(&mut self, inode_id: u64, rights: Rights) -> KResult<()> {
        if let Some(entry) = self.unveiled_namespaces.iter_mut().find(|(id, _)| *id == inode_id) {
            // Can only restrict or maintain rights
            entry.1 = entry.1.intersect(rights);
            return Ok(());
        }
        if self.unveiled_count >= self.unveiled_namespaces.len() {
            return Err(KError::TableFull);
        }
        self.unveiled_namespaces[self.unveiled_count] = (inode_id, rights);
        self.unveiled_count += 1;
        Ok(())
    }

    /// Verifies access to an unveiled namespace inode.
    pub fn check_unveil(&self, inode_id: u64, required: Rights) -> bool {
        if self.unveiled_count == 0 {
            return true; // No unveil restrictions installed yet
        }
        self.unveiled_namespaces[..self.unveiled_count]
            .iter()
            .any(|(id, rights)| *id == inode_id && rights.contains(required))
    }
}

