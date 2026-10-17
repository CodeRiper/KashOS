use crate::blockdev::BLOCK_SIZE;
use crate::error::{VaultError, VaultResult};
use alloc::{vec, vec::Vec};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key as AeadKey, Tag, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type Key = Zeroizing<[u8; 32]>;

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
pub const SEAL_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
/// Usable bytes per 4 KiB sealed block.
pub const PAYLOAD: usize = BLOCK_SIZE - SEAL_OVERHEAD;

/// Argon2id cost. Stored in the clear in the header (it reveals only how expensive unlocking is).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// RFC 9106 first recommended option: 2 GiB, t=1, p=4. Use where RAM allows.
    pub const RFC9106_HIGH_MEMORY: KdfParams = KdfParams { m_kib: 2 * 1024 * 1024, t: 1, p: 4 };
    /// RFC 9106 second recommended option: 64 MiB, t=3, p=4.
    pub const RFC9106_LOW_MEMORY: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 4 };
    /// KashOS 1 GiB Legacy Profile (Pages 10-11 of Architectural Blueprint):
    /// 256 MiB RAM scratchpad, 12 passes, 1 lane. Uses exactly 25% of 1 GiB RAM.
    pub const KASHOS_1GIB_LEGACY: KdfParams = KdfParams { m_kib: 256 * 1024, t: 12, p: 1 };
    /// KashOS Ultra-Low RAM Fallback (for 100 MiB systems):
    /// 64 MiB scratchpad, 32 passes, 1 lane.
    pub const KASHOS_ULTRA_LOW_RAM: KdfParams = KdfParams { m_kib: 64 * 1024, t: 32, p: 1 };
    /// Floor for small devices (OWASP minimum): 19 MiB, t=2, p=1. Pair with a long passphrase.
    pub const LOW_END: KdfParams = KdfParams { m_kib: 19 * 1024, t: 2, p: 1 };
    /// FOR TESTS ONLY: trivially brute-forceable.
    pub const TEST_ONLY_INSECURE_FAST: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };

    /// Reject values that are nonsensical or would let a hostile header exhaust memory/time.
    pub fn validate(&self) -> VaultResult<()> {
        let ok = (1..=16).contains(&self.p)
            && (1..=16).contains(&self.t)
            && self.m_kib >= 8 * self.p
            && self.m_kib <= 4 * 1024 * 1024;
        if ok { Ok(()) } else { Err(VaultError::InvalidParams) }
    }
}

/// Combine a password with an optional keyfile into the byte string that
/// actually goes into Argon2id — VeraCrypt-style two-factor unlock: the
/// password is "something you know", a keyfile is "something you have".
/// Getting either one wrong produces different Argon2id output and so, on
/// `Vault::open`, the ordinary `BadPassword` outcome — there is no separate
/// "wrong keyfile" error, on purpose: distinguishing the two would let an
/// attacker learn which factor they already have right.
///
/// The keyfile's full bytes are hashed (SHA-256) rather than used directly,
/// so an arbitrarily large file works as a keyfile at a fixed, small cost,
/// and so the keyfile's own bytes never sit in the same buffer this
/// function returns (that buffer is `Zeroizing`; cloning the keyfile's
/// bytes into it directly would mean an unbounded amount of the keyfile
/// itself needs zeroizing on every call, for no security benefit — a digest
/// carries the same "must match exactly" property at a fixed 32 bytes).
pub fn combine_password_keyfile(password: &[u8], keyfile: Option<&[u8]>) -> Zeroizing<Vec<u8>> {
    let mut combined = Zeroizing::new(Vec::with_capacity(password.len() + 32));
    combined.extend_from_slice(password);
    if let Some(kf) = keyfile {
        let digest = Sha256::digest(kf);
        combined.extend_from_slice(&digest);
    }
    combined
}

pub fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *k);
    k
}

pub fn kdf(password: &[u8], salt: &[u8; 32], p: &KdfParams) -> VaultResult<Key> {
    p.validate()?;
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|_| VaultError::InvalidParams)?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, &mut *out).map_err(|_| VaultError::Kdf)?;
    Ok(out)
}

/// HKDF-SHA256 subkey with domain separation via `info`.
pub fn subkey(parent: &Key, info: &[u8]) -> VaultResult<Key> {
    let hk = Hkdf::<Sha256>::new(None, &parent[..]);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out).map_err(|_| VaultError::Kdf)?;
    Ok(out)
}

/// Domain-separated additional authenticated data.
pub fn aad(domain: &str, vol: &[u8; 16], a: u64, b: u64, c: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + 16 + 24);
    v.extend_from_slice(domain.as_bytes());
    v.extend_from_slice(vol);
    v.extend_from_slice(&a.to_le_bytes());
    v.extend_from_slice(&b.to_le_bytes());
    v.extend_from_slice(&c.to_le_bytes());
    v
}

/// nonce(24) || ciphertext || tag(16). Fresh random 192-bit nonce per call.
pub fn seal<R: RngCore + CryptoRng>(rng: &mut R, key: &Key, aad: &[u8], pt: &[u8]) -> VaultResult<Vec<u8>> {
    let mut out = vec![0u8; SEAL_OVERHEAD + pt.len()];
    let (nonce, rest) = out.split_at_mut(NONCE_LEN);
    rng.fill_bytes(nonce);
    let (body, tag_out) = rest.split_at_mut(pt.len());
    body.copy_from_slice(pt);
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&key[..]));
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, body)
        .map_err(|_| VaultError::Corrupt)?;
    tag_out.copy_from_slice(&tag);
    Ok(out)
}

pub fn open(key: &Key, aad: &[u8], ct: &[u8]) -> VaultResult<Zeroizing<Vec<u8>>> {
    if ct.len() < SEAL_OVERHEAD {
        return Err(VaultError::Corrupt);
    }
    let (nonce, rest) = ct.split_at(NONCE_LEN);
    let (body, tag) = rest.split_at(rest.len() - TAG_LEN);
    let mut buf = Zeroizing::new(body.to_vec());
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&key[..]));
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut buf, Tag::from_slice(tag))
        .map_err(|_| VaultError::Corrupt)?;
    Ok(buf)
}

/// Seal up to `PAYLOAD` bytes into exactly one 4 KiB block (zero padded before encryption).
pub fn seal_block<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: &Key,
    aad: &[u8],
    payload: &[u8],
) -> VaultResult<[u8; BLOCK_SIZE]> {
    if payload.len() > PAYLOAD {
        return Err(VaultError::Corrupt);
    }
    let mut padded = Zeroizing::new(vec![0u8; PAYLOAD]);
    padded[..payload.len()].copy_from_slice(payload);
    let v = seal(rng, key, aad, &padded)?;
    v.try_into().map_err(|_| VaultError::Corrupt)
}

pub fn open_block(key: &Key, aad: &[u8], block: &[u8; BLOCK_SIZE]) -> VaultResult<Zeroizing<Vec<u8>>> {
    open(key, aad, block)
}
