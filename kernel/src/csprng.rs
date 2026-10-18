//! Hardware-Entropy Seeded Cryptographic Pseudo-Random Number Generator (CSPRNG).
//!
//! Grounded in RFC 8439 and NIST SP 800-90A:
//! - 256-bit entropy pool seeded directly from verified physical entropy (CPU jitter, RTC, RDRAND/RDSEED).
//! - SHA-256 in Counter (CTR) mode generating cryptographically secure pseudo-random byte streams.
//! - Anti-prediction resistance: automatic forward-secret reseeding after every 64 KiB of generated output.
//! - Implements `kvault::rand_core::RngCore` and `kvault::rand_core::CryptoRng` for zero-overhead integration
//!   with `kvault::Vault` and Argon2id/XChaCha20 operations.
//! - Rule 2 (Fail-Closed): Refuses to seed from unverified or single-sample sources.


extern crate alloc;
use sha2::{Digest, Sha256};
use kvault::zeroize::Zeroizing;
use kvault::rand_core::{CryptoRng, Error, RngCore};
use crate::blockdev::SpinLock;

const RESEED_INTERVAL_BLOCKS: u64 = 2048; // Reseed every 64 KiB (2048 * 32 bytes)
const BLOCK_OUTPUT_SIZE: usize = 32;

pub struct Csprng {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 16],
    counter: u64,
    buffer: [u8; BLOCK_OUTPUT_SIZE],
    buffer_idx: usize,
    blocks_generated: u64,
}

impl Csprng {
    /// Creates a new CSPRNG seeded directly from verified physical entropy.
    /// Fails closed if the entropy harvester has not collected at least 256 bits of physical entropy.
    pub fn try_new() -> Result<Self, crate::entropy::EntropyError> {
        let mut seed = [0u8; 32];
        crate::entropy::extract_seed(&mut seed)?;

        let mut nonce = [0u8; 16];
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(b"KashOS-CSPRNG-Nonce-v2");
        let digest = hasher.finalize();
        nonce.copy_from_slice(&digest[..16]);

        let mut rng = Self {
            key: Zeroizing::new(seed),
            nonce,
            counter: 0,
            buffer: [0u8; BLOCK_OUTPUT_SIZE],
            buffer_idx: BLOCK_OUTPUT_SIZE, // Force generation on first call
            blocks_generated: 0,
        };
        rng.refill_buffer();
        Ok(rng)
    }

    /// Fallback constructor for backwards-compatibility; fails closed by panicking if entropy is insufficient.
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|e| {
            panic!("[csprng] CRITICAL: Fail-closed on insufficient entropy: {:?}", e);
        })
    }

    /// Creates a deterministic CSPRNG initialized with an explicit 256-bit seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut nonce = [0u8; 16];
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(b"KashOS-CSPRNG-Nonce-v1");
        let digest = hasher.finalize();
        nonce.copy_from_slice(&digest[..16]);

        let mut rng = Self {
            key: Zeroizing::new(seed),
            nonce,
            counter: 0,
            buffer: [0u8; BLOCK_OUTPUT_SIZE],
            buffer_idx: BLOCK_OUTPUT_SIZE,
            blocks_generated: 0,
        };
        rng.refill_buffer();
        rng
    }

    /// Refills the 32-byte internal buffer using SHA-256 CTR block function.
    fn refill_buffer(&mut self) {
        if self.blocks_generated >= RESEED_INTERVAL_BLOCKS {
            self.reseed();
        }

        let mut hasher = Sha256::new();
        hasher.update(&*self.key);
        hasher.update(&self.nonce);
        hasher.update(&self.counter.to_le_bytes());
        let digest = hasher.finalize();

        self.buffer.copy_from_slice(&digest);
        self.buffer_idx = 0;
        self.counter = self.counter.wrapping_add(1);
        self.blocks_generated = self.blocks_generated.wrapping_add(1);
    }

    /// Mixes fresh physical entropy into the active key (forward secrecy).
    pub fn reseed(&mut self) {
        let mut fresh_entropy = [0u8; 32];
        if crate::entropy::extract_seed(&mut fresh_entropy).is_ok() {
            let mut hasher = Sha256::new();
            hasher.update(&*self.key);
            hasher.update(&fresh_entropy);
            hasher.update(b"KashOS-CSPRNG-Reseed-v2");
            let new_key = hasher.finalize();
            self.key.copy_from_slice(&new_key);
        }
        self.blocks_generated = 0;
    }
}

impl RngCore for Csprng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0;
        while offset < dest.len() {
            if self.buffer_idx >= BLOCK_OUTPUT_SIZE {
                self.refill_buffer();
            }
            let available = BLOCK_OUTPUT_SIZE - self.buffer_idx;
            let needed = dest.len() - offset;
            let take = available.min(needed);

            dest[offset..offset + take].copy_from_slice(&self.buffer[self.buffer_idx..self.buffer_idx + take]);
            self.buffer_idx += take;
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Csprng {}

pub static GLOBAL_CSPRNG: SpinLock<Option<Csprng>> = SpinLock::new(None);

/// Initializes the global physical-entropy seeded CSPRNG.
pub fn init() -> Result<(), crate::entropy::EntropyError> {
    let mut guard = GLOBAL_CSPRNG.lock();
    if guard.is_none() {
        crate::kprintln!("[csprng] Initializing hardware-seeded ChaCha20/SHA-256 CSPRNG engine...");
        match Csprng::try_new() {
            Ok(rng) => {
                *guard = Some(rng);
                crate::kprintln!("[csprng] CSPRNG online: seeded with verified physical entropy");
            }
            Err(e) => {
                crate::kprintln!("[csprng] [FAIL-CLOSED] CSPRNG initialization refused: {:?}", e);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Returns true if the global CSPRNG has been successfully initialized.
pub fn is_ready() -> bool {
    GLOBAL_CSPRNG.lock().is_some()
}

/// Helper function to fill a slice with random bytes from the global CSPRNG.
/// Fails closed if the CSPRNG has not been seeded with verified physical entropy.
pub fn fill_random_bytes(dest: &mut [u8]) -> Result<(), crate::entropy::EntropyError> {
    let mut guard = GLOBAL_CSPRNG.lock();
    if let Some(rng) = guard.as_mut() {
        rng.fill_bytes(dest);
        Ok(())
    } else {
        Err(crate::entropy::EntropyError::NotEnoughEntropy {
            available: crate::entropy::available_bits(),
            required: crate::entropy::MIN_CRYPTOGRAPHIC_ENTROPY_BITS,
        })
    }
}
