#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageError {
    /// Address isn't aligned to the page size the operation requires.
    Misaligned,
    /// A mapping already exists where this one would go.
    AlreadyMapped,
    /// No mapping exists at this address.
    NotMapped,
    /// The frame allocator ran out of physical memory.
    OutOfFrames,
    /// The allocator returned a frame that isn't page-aligned — a bug in the
    /// caller's `FrameAllocator`, not in this crate.
    AllocatorGaveBadFrame,
    /// Rejected: the request asks for a page that is both writable and
    /// executable. This crate enforces W^X by default; there is no
    /// parameter to bypass it, on purpose — a kernel that needs a JIT page
    /// should map it read-only+executable, write through a *different*,
    /// writable-only mapping of the same frame, then drop that mapping.
    WriteExecuteViolation,
    /// The requesting domain has exhausted its allocated frame quota.
    QuotaExceeded,
    /// Physical frame was not allocated or has already been freed.
    FrameNotAllocated,
    /// Domain identifier exceeds maximum supported domain count.
    InvalidDomain,
}

pub type PageResult<T> = Result<T, PageError>;
