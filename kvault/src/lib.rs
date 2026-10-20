//! kvault: encrypted, tamper-evident storage for capkern (runs as an isolated userspace service).
//!
//! * Key derivation: Argon2id (RFC 9106) from passwords, HKDF-SHA256 for subkeys.
//! * Encryption: XChaCha20-Poly1305 on every 4 KiB block (fast on CPUs without AES instructions,
//!   authenticated, 192-bit random nonces). Block index, volume and file are bound in as AAD, so
//!   blocks cannot be swapped, moved or replayed into another place without detection.
//! * Header: 8 slots that look like random bytes; unused slots are indistinguishable from used ones.
//! * Hidden volume: a second password opens a different region of the same device.
//! * Duress password: opening with it destroys every key slot (cryptographic erase).
//! * Per-folder passwords: a folder key wrapped under its own password; the volume password alone
//!   cannot decrypt a protected folder.
//! * Keyfiles: `Vault::format_with_keyfile` / `open_with_keyfile` pair a password with an optional
//!   file (VeraCrypt-style two-factor unlock) — getting either wrong is a plain `BadPassword`.
//! No `unsafe`. Keys live in `Zeroizing` buffers and are wiped on drop.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod blockdev;
mod codec;
mod crypto;
mod error;
mod vault;
pub mod kvaultfs;
pub mod pool;

pub use blockdev::{BlockDevice, MemDevice, BLOCK_SIZE};
pub use crypto::{
    combine_password_keyfile, derive_key, kdf, kdf_with_memory_limit, random_key, subkey,
    KdfParams, Key, DEFAULT_MAX_KDF_MEMORY_KIB, ABSOLUTE_MAX_KDF_MEMORY_KIB,
    MIN_KDF_MEMORY_KIB,
};
pub use error::{VaultError, VaultResult};
pub use rand_core;
pub use zeroize;
pub use vault::{FileInfo, FolderInfo, FormatOptions, OpenFail, OpenOutcome, Vault};
pub use kvaultfs::{
    AfSplit, CryptoProfile, KfsInode, MerkleBlockHeader, MerkleBlockPointer,
    StealthVolumeManager, AF_SPLIT_SECTORS, KFS_MAGIC,
};
pub use pool::{
    ExtentDescriptor, PoolError, PoolSuperblock, StoragePoolEngine, VaultPool,
    POOL_BLOCK_SIZE, SUBVOL_APPS, SUBVOL_BROWSER, SUBVOL_EXTERNAL, SUBVOL_PERSONAL,
    SUBVOL_SYSTEM,
};

