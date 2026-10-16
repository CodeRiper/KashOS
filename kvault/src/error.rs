/// All failures. `BadPassword` is returned both for "wrong password" and "no such slot",
/// so an attacker learns nothing about how many volumes exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    BadPassword,
    /// Authentication failed or structure is damaged: data was modified, moved or truncated.
    Corrupt,
    Io,
    NoSpace,
    NotFound,
    Exists,
    FolderLocked,
    InvalidName,
    InvalidParams,
    TooMany,
    DeviceTooSmall,
    Kdf,
    /// Cryptographic hash or Merkle tree child digest mismatch (tampering detected).
    IntegrityViolation,
    /// Requested block index or offset exceeds boundary.
    OutOfBounds,
}
pub type VaultResult<T> = Result<T, VaultError>;
