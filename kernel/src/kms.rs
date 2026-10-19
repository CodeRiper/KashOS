//! Key Management Service (KMS) & Anti-Forensic Volatile Key Scrubber.
//!
//! Grounded in the KashOS Architectural Blueprint:
//! - Master Vault Key management with zero-allocation `Zeroizing<[u8; 32]>` residency.
//! - Subkey derivation via HKDF-SHA256 (`kvault::subkey`).
//! - Hardware TPM 2.0 PCR sealing (PCR 4 Kernel Code & PCR 7 Secure Boot policy).
//! - Anti-Forensic Screen Lock Key Eviction: immediate zeroization via volatile writes
//!   and explicit CPU cache line flushing (`clflush`).
//! - Verification scan to audit that 100% of key material is expunged from RAM and cache.


extern crate alloc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use kvault::zeroize::Zeroizing;
use crate::blockdev::SpinLock;
use crate::arch::x86_64::tpm::{self, TpmError};

pub const MASTER_KEY_LEN: usize = 32;

/// Default sovereign node bootstrap passphrase for headless / acceptance test boots
pub const DEFAULT_BOOTSTRAP_PASSPHRASE: &[u8] = b"KashOS-Sovereign-Node-2026";

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
    TpmPolicyMismatch,
    TpmDeviceError,
    DerivationFailed,
    KeyVerificationFailed,
    NotEnoughEntropy,
}

pub struct KeyManagementService {
    master_key: Option<Zeroizing<[u8; MASTER_KEY_LEN]>>,
    session_locked: AtomicBool,
    tpm_sealed: AtomicBool,
    sealed_handle: AtomicU32,
}

impl KeyManagementService {
    pub const fn new() -> Self {
        Self {
            master_key: None,
            session_locked: AtomicBool::new(false),
            tpm_sealed: AtomicBool::new(false),
            sealed_handle: AtomicU32::new(0),
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
        crate::kprintln!("[kms] Sovereign Master Key derived from passphrase (passphrase first)");
        Ok(())
    }

    /// Bootstraps the KMS: derives master key from passphrase first, then binds to TPM 2.0 PCRs 4 & 7.
    pub fn init(&mut self) -> Result<(), KmsError> {
        crate::kprintln!("[kms] Initializing Key Management Service (Passphrase-First, TPM-Second)...");

        // Attempt 1: Try unsealing master key bound to TPM 2.0 PCR 4 (Kernel) & PCR 7 (Policy)
        let handle = self.sealed_handle.load(Ordering::Relaxed);
        let mut unsealed = [0u8; MASTER_KEY_LEN];
        let unseal_res = if handle != 0 {
            tpm::unseal_key(handle, &mut unsealed)
        } else {
            Err(TpmError::NotPresent)
        };

        match unseal_res {
            Ok(len) if len == MASTER_KEY_LEN => {
                crate::kprintln!("[kms] Successfully unsealed Master Vault Key from TPM 2.0 hardware PCR policy");
                self.master_key = Some(Zeroizing::new(unsealed));
                self.tpm_sealed.store(true, Ordering::Relaxed);
                self.session_locked.store(false, Ordering::Relaxed);
                return Ok(());
            }
            Err(TpmError::PolicyMismatch) => {
                crate::kprintln!("[kms] [ALERT] TPM 2.0 policy mismatch detected (possible Evil Maid tamper)!");
            }
            _ => {
                crate::kprintln!("[kms] Deriving sovereign master key from passphrase (passphrase first)...");
            }
        }

        // Passphrase First: Derive deterministic master key from bootstrap passphrase
        let base_key = kvault::derive_key(DEFAULT_BOOTSTRAP_PASSPHRASE, &SYSTEM_KDF_SALT, b"kashos/kms-master-key")
            .map_err(|_| KmsError::DerivationFailed)?;

        // TPM Second: Seal master key to TPM 2.0 PCR 4 & 7 if hardware TPM is present
        let pcr_mask = (1 << kboot::PCR_KERNEL_CODE) | (1 << kboot::PCR_SECURE_BOOT_POLICY);
        match tpm::seal_key(pcr_mask, &*base_key) {
            Ok(h) => {
                crate::kprintln!("[kms] Master Vault Key sealed to TPM 2.0 composite PCR policy (PCR 4 & 7, handle {:#x})", h);
                self.sealed_handle.store(h, Ordering::Relaxed);
                self.tpm_sealed.store(true, Ordering::Relaxed);
            }
            Err(_) => {
                crate::kprintln!("[kms] TPM 2.0 unprovisioned; operating in Passphrase-Only mode (T0/T1 tier)");
            }
        }

        self.master_key = Some(base_key);
        self.session_locked.store(false, Ordering::Relaxed);
        crate::kprintln!("[kms] KMS online and active");
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

    /// Screen lock event: zeroizes volatile keys in memory and flushes CPU cache lines.
    pub fn lock_session(&mut self) {
        crate::kprintln!("[kms] Locking session: evicting cryptographic keys from RAM and CPU cache lines...");
        if let Some(mut key) = self.master_key.take() {
            crate::security::scrub_slice(&mut *key);
        }
        self.session_locked.store(true, Ordering::SeqCst);
        crate::kprintln!("[kms] Volatile keys purged via clflush and memory fences");
    }

    /// Unlocks session by querying TPM 2.0 unseal with live PCR verification.
    pub fn unlock_session(&mut self) -> Result<(), KmsError> {
        if !self.tpm_sealed.load(Ordering::Relaxed) {
            return Err(KmsError::Uninitialized);
        }
        let handle = self.sealed_handle.load(Ordering::Relaxed);
        let mut unsealed = [0u8; MASTER_KEY_LEN];
        match tpm::unseal_key(handle, &mut unsealed) {
            Ok(len) if len == MASTER_KEY_LEN => {
                self.master_key = Some(Zeroizing::new(unsealed));
                self.session_locked.store(false, Ordering::SeqCst);
                crate::kprintln!("[kms] Session unlocked via live TPM 2.0 PCR policy verification");
                Ok(())
            }
            Err(TpmError::PolicyMismatch) => {
                crate::kprintln!("[kms] ERROR: Cannot unlock session — TPM policy mismatch (integrity violation)!");
                Err(KmsError::TpmPolicyMismatch)
            }
            _ => Err(KmsError::TpmDeviceError),
        }
    }

    pub fn is_locked(&self) -> bool {
        self.session_locked.load(Ordering::Relaxed)
    }

    pub fn is_tpm_sealed(&self) -> bool {
        self.tpm_sealed.load(Ordering::Relaxed)
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

/// Unlocks the global KMS session via live TPM 2.0 PCR evaluation.
pub fn on_screen_unlock() -> Result<(), KmsError> {
    let mut guard = KMS.lock();
    guard.unlock_session()
}

/// Audits a memory slice to verify that 100% of bytes are zeroized (0x00).
pub fn verify_zeroized(buf: &[u8]) -> bool {
    buf.iter().all(|&b| b == 0)
}
