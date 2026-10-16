/// What a leaf mapping is allowed to do. Shared across architectures; each
/// `Arch` impl translates this into its own descriptor bit layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perm {
    pub user: bool,
    pub writable: bool,
    pub executable: bool,
    /// Device (MMIO) memory vs normal (cacheable) RAM. Matters a lot on
    /// AArch64 (selects the MAIR attribute index and shareability); on
    /// x86-64 it selects PCD/PWT (cache-disable, write-through) so MMIO
    /// reads/writes aren't silently cached or reordered.
    pub device: bool,
}

impl Perm {
    pub const KERNEL_RW: Perm = Perm { user: false, writable: true, executable: false, device: false };
    pub const KERNEL_RX: Perm = Perm { user: false, writable: false, executable: true, device: false };
    pub const KERNEL_RO: Perm = Perm { user: false, writable: false, executable: false, device: false };
    pub const USER_RW: Perm = Perm { user: true, writable: true, executable: false, device: false };
    pub const USER_RX: Perm = Perm { user: true, writable: false, executable: true, device: false };
    pub const USER_RO: Perm = Perm { user: true, writable: false, executable: false, device: false };
    pub const MMIO: Perm = Perm { user: false, writable: true, executable: false, device: true };
}

/// One architecture's page-table descriptor encoding. The walk logic in
/// `mapper.rs` is written once against this trait; `x86_64.rs` and
/// `aarch64.rs` each provide a correct, architecture-specific
/// implementation — the two encodings are *not* bit-compatible (AArch64
/// descriptors use entirely different bit positions for permission,
/// shareability and memory-type than x86-64's PRESENT/WRITABLE/NX layout),
/// so sharing one "generic flags: u64" between them, as a naive port would,
/// silently produces wrong page tables on whichever architecture wasn't
/// tested — that is specifically what this trait split avoids.
pub trait Arch {
    /// A present, writable pointer to `next_table_paddr`, with no
    /// additional restriction applied at this level (all real permission
    /// checks happen at the leaf — see the trait-level docs above).
    fn table_descriptor(next_table_paddr: u64) -> u64;
    /// A present leaf (4 KiB page) descriptor for `paddr` with `perm`.
    fn leaf_descriptor(paddr: u64, perm: Perm) -> u64;
    /// True if `entry`'s present/valid bit is set.
    fn is_present(entry: u64) -> bool;
    /// The next-level table's physical address encoded in a present,
    /// non-leaf `entry`.
    fn entry_table_paddr(entry: u64) -> u64;
    /// The frame physical address encoded in a present leaf `entry`.
    fn entry_frame_paddr(entry: u64) -> u64;
    /// Invalidate any cached translation for `vaddr` in the local TLB.
    /// # Safety
    /// Must only be called with the MMU enabled and a valid `vaddr`.
    unsafe fn invalidate(vaddr: u64);
}
