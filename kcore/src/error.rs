/// Errors returned to callers. Every failure is an error value, never a panic,
/// and every failing operation leaves the capability table unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KError {
    /// Slot index outside the table.
    InvalidSlot = 1,
    /// Destination slot is already in use.
    SlotOccupied = 2,
    /// Source slot holds no capability.
    SlotEmpty = 3,
    /// The capability lacks a required right.
    InsufficientRights = 4,
    /// Operation is not valid for this kind of capability.
    InvalidCapType = 5,
    /// The untyped region cannot satisfy the request.
    NoMemory = 6,
    /// Malformed argument (bad size, bad badge, unknown rights bits, ...).
    InvalidArgument = 7,
    /// Capability still has derived children; revoke first.
    RevokeFirst = 8,
    /// Namespace table or capacity limit reached.
    TableFull = 9,
}

pub type KResult<T> = Result<T, KError>;
