//! Passphrase-gated KMS key residency and session locking.
//!
//! Boot stays locked until an explicit passphrase is entered. Persistent TPM
//! enrollment/unsealing is not implemented here and is never reported active.
//! The encrypted vault applies its own per-volume Argon2id KDF using its stored
//! salt and parameters; the KMS transform provides domain separation only.


extern crate alloc;
use core::sync::atomic::{AtomicBool, Ordering};
use kvault::zeroize::Zeroizing;
use crate::blockdev::SpinLock;

pub const MASTER_KEY_LEN: usize = 32;

/// Domain-separated KDF salt for sovereign KMS derivation
pub const SYSTEM_KDF_SALT: [u8; 32] = [
    0x4B, 0x61, 0x73, 0x68, 0x4F, 0x53, 0x5F, 0x53,
    0x61, 0x6C, 0x74, 0x5F, 0x32, 0x30, 0x32, 0x36,
    0x9E, 0x37, 0x79, 0xB9, 0x7F, 0x4A, 0x7C, 0x15,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmsError {
    Uninitialized,
    Locked,
    DerivationFailed,
    KeyVerificationFailed,
}

pub struct KeyManagementService {
    master_key: Option<Zeroizing<[u8; MASTER_KEY_LEN]>>,
    session_locked: AtomicBool,
}

impl KeyManagementService {
    pub const fn new() -> Self {
        Self {
            master_key: None,
            session_locked: AtomicBool::new(true),
        }
    }

    /// Unlocks the KMS with a user-supplied passphrase (passphrase first).
    pub fn unlock_with_passphrase(&mut self, passphrase: &[u8]) -> Result<(), KmsError> {
        if passphrase.is_empty() {
            return Err(KmsError::KeyVerificationFailed);
        }
        let key = kvault::derive_key(passphrase, &SYSTEM_KDF_SALT, b"kashos/kms-master-key")
            .map_err(|_| KmsError::DerivationFailed)?;
        self.master_key = Some(key);
        self.session_locked.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Starts the KMS locked. A user credential is required before storage opens.
    pub fn init(&mut self) -> Result<(), KmsError> {
        if self.master_key.is_some() {
            self.lock_session();
        } else {
            self.session_locked.store(true, Ordering::SeqCst);
        }
        crate::kprintln!("[kms] Locked: enter the vault passphrase at the console to unlock storage.");
        crate::kprintln!("[kms] Persistent TPM key provisioning is unavailable; no TPM-backed unlock is claimed.");
        Ok(())
    }

    /// Derives a domain-separated subkey using HKDF-SHA256.
    pub fn derive_subkey(&self, domain: &[u8]) -> Result<Zeroizing<[u8; 32]>, KmsError> {
        if self.is_locked() {
            return Err(KmsError::Locked);
        }
        let master = self.master_key.as_ref().ok_or(KmsError::Uninitialized)?;
        kvault::subkey(master, domain).map_err(|_| KmsError::DerivationFailed)
    }

    /// Returns a reference to the active master vault key.
    pub fn get_master_key(&self) -> Result<&[u8; MASTER_KEY_LEN], KmsError> {
        if self.is_locked() {
            return Err(KmsError::Locked);
        }
        self.master_key.as_ref().map(|k| &**k).ok_or(KmsError::Uninitialized)
    }

    /// Screen lock event: scrub the stored key buffer through the kernel helper.
    pub fn lock_session(&mut self) {
        crate::kprintln!("[kms] Locking session: zeroizing the stored master-key buffer...");
        if let Some(mut key) = self.master_key.take() {
            crate::security::scrub_slice(&mut *key);
        }
        self.session_locked.store(true, Ordering::SeqCst);
        crate::kprintln!("[kms] Stored key buffer scrub completed; other residual copies are not audited.");
    }

    pub fn is_locked(&self) -> bool {
        self.session_locked.load(Ordering::Relaxed)
    }

}

pub static KMS: SpinLock<KeyManagementService> = SpinLock::new(KeyManagementService::new());

/// Initializes the global Key Management Service.
pub fn init() {
    let mut guard = KMS.lock();
    let _ = guard.init();
}

/// Unlocks the global Key Management Service using a user-supplied passphrase.
pub fn unlock_with_passphrase(passphrase: &[u8]) -> Result<(), KmsError> {
    let mut guard = KMS.lock();
    guard.unlock_with_passphrase(passphrase)
}

/// Locks the global KMS session and scrubs key buffers.
pub fn on_screen_lock() {
    let mut guard = KMS.lock();
    guard.lock_session();
}

/// Audits a memory slice to verify that 100% of bytes are zeroized (0x00).
pub fn verify_zeroized(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}
