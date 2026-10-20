use crate::blockdev::{BlockDevice, BLOCK_SIZE};
use crate::codec::{Reader, Writer};
use crate::crypto::{
    aad, combine_password_keyfile, kdf, kdf_with_memory_limit, open, open_block, random_key, seal,
    seal_block, subkey, Key, KdfParams, DEFAULT_MAX_KDF_MEMORY_KIB, ABSOLUTE_MAX_KDF_MEMORY_KIB,
    PAYLOAD, SEAL_OVERHEAD,
};
use crate::error::{VaultError, VaultResult};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

const SLOTS: usize = 8;
const SLOT_PT: usize = 64; // vk(32) kind(1) region_start(8) region_len(8) reserved(15)
const SLOT_CT: usize = SEAL_OVERHEAD + SLOT_PT; // 104
const HDR_FIXED: usize = 12 + 32; // kdf params + salt
const KIND_NORMAL: u8 = 0;
const KIND_DURESS: u8 = 2;

const MAX_FOLDERS: usize = 16;
const MAX_FREE: usize = 32;
const MAX_NAME: usize = 64;
const MAX_INDEX_BLOCKS: u32 = 64;
const MAX_FILES: u32 = 4096;
const ROOT_BLOCKS: u64 = 2; // rel 0 and rel 1: alternating root records
const WRAPPED_LEN: usize = SEAL_OVERHEAD + 32;

pub struct FormatOptions {
    pub params: KdfParams,
    /// Percentage (0..=80) of the device given to the hidden volume. 0 = no hidden volume.
    pub hidden_percent: u8,
}

pub struct FolderInfo {
    pub name: String,
    pub password_protected: bool,
    pub unlocked: bool,
}

pub struct FileInfo {
    pub name: String,
    pub size: u64,
}

pub enum OpenOutcome<D: BlockDevice> {
    Unlocked(Vault<D>),
    /// The duress password was used: every key slot has been destroyed. The data is gone for good.
    Duress(D),
}

/// Failed open: the error plus the device handed back.
pub struct OpenFail<D> {
    pub error: VaultError,
    pub device: D,
}
impl<D> fmt::Debug for OpenFail<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenFail").field("error", &self.error).finish()
    }
}

// ---------------------------------------------------------------------------------------------
// On-disk structures (all sealed under the volume key; nothing here is readable without it)
// ---------------------------------------------------------------------------------------------

#[derive(Clone)]
struct FolderEntry {
    fid: u64,
    name: String,
    has_pw: bool,
    fsalt: [u8; 32],
    wrapped: Vec<u8>, // empty, or nonce||ct(fk)||tag when password protected
    index_start: u64,
    index_blocks: u32,
}

#[derive(Clone)]
struct Root {
    generation: u64,
    next_free: u64,
    free: Vec<(u64, u64)>,
    folders: Vec<FolderEntry>,
}

impl Root {
    fn empty() -> Root {
        Root { generation: 0, next_free: ROOT_BLOCKS, free: Vec::new(), folders: Vec::new() }
    }

    fn encode(&self) -> VaultResult<Vec<u8>> {
        if self.free.len() > MAX_FREE || self.folders.len() > MAX_FOLDERS {
            return Err(VaultError::TooMany);
        }
        let mut w = Writer::default();
        w.u64(self.generation);
        w.u64(self.next_free);
        w.u16(self.free.len() as u16);
        for &(s, l) in &self.free {
            w.u64(s);
            w.u64(l);
        }
        w.u16(self.folders.len() as u16);
        for f in &self.folders {
            w.u64(f.fid);
            w.str8(&f.name);
            w.u8(f.has_pw as u8);
            w.bytes(&f.fsalt);
            w.u8(f.wrapped.len() as u8);
            w.bytes(&f.wrapped);
            w.u64(f.index_start);
            w.u32(f.index_blocks);
        }
        if w.buf.len() > PAYLOAD {
            return Err(VaultError::TooMany);
        }
        Ok(w.buf)
    }

    fn decode(b: &[u8], region_len: u64) -> VaultResult<Root> {
        let mut r = Reader::new(b);
        let generation = r.u64()?;
        let next_free = r.u64()?;
        if next_free < ROOT_BLOCKS || next_free > region_len {
            return Err(VaultError::Corrupt);
        }
        let nfree = r.u16()? as usize;
        if nfree > MAX_FREE {
            return Err(VaultError::Corrupt);
        }
        let mut free = Vec::new();
        for _ in 0..nfree {
            let (s, l) = (r.u64()?, r.u64()?);
            if s < ROOT_BLOCKS || l == 0 || s.checked_add(l).ok_or(VaultError::Corrupt)? > next_free {
                return Err(VaultError::Corrupt);
            }
            free.push((s, l));
        }
        let nfold = r.u16()? as usize;
        if nfold > MAX_FOLDERS {
            return Err(VaultError::Corrupt);
        }
        let mut folders = Vec::new();
        for _ in 0..nfold {
            let fid = r.u64()?;
            let name = r.str8()?;
            let has_pw = r.u8()? != 0;
            let fsalt = r.arr32()?;
            let wl = r.u8()? as usize;
            let wrapped = r.take(wl)?.to_vec();
            if has_pw != (wl == WRAPPED_LEN) || (!has_pw && wl != 0) {
                return Err(VaultError::Corrupt);
            }
            let index_start = r.u64()?;
            let index_blocks = r.u32()?;
            check_extent(index_start, index_blocks as u64, next_free)?;
            if index_blocks > MAX_INDEX_BLOCKS {
                return Err(VaultError::Corrupt);
            }
            folders.push(FolderEntry { fid, name, has_pw, fsalt, wrapped, index_start, index_blocks });
        }
        Ok(Root { generation, next_free, free, folders })
    }

    /// First-fit from the free list, else bump. Does not touch the device.
    fn alloc(&mut self, n: u64, region_len: u64) -> VaultResult<u64> {
        if n == 0 {
            return Ok(0);
        }
        for i in 0..self.free.len() {
            let (s, l) = self.free[i];
            if l >= n {
                if l == n {
                    self.free.remove(i);
                } else {
                    self.free[i] = (s + n, l - n);
                }
                return Ok(s);
            }
        }
        let end = self.next_free.checked_add(n).ok_or(VaultError::NoSpace)?;
        if end > region_len {
            return Err(VaultError::NoSpace);
        }
        let s = self.next_free;
        self.next_free = end;
        Ok(s)
    }

    fn free_extent(&mut self, s: u64, n: u64) {
        if n == 0 {
            return;
        }
        if s + n == self.next_free {
            self.next_free = s;
            while let Some(pos) = self.free.iter().position(|&(fs, fl)| fs + fl == self.next_free) {
                let (fs, _) = self.free.remove(pos);
                self.next_free = fs;
            }
            return;
        }
        self.free.push((s, n));
        self.free.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for &(s, l) in &self.free {
            match merged.last_mut() {
                Some(last) if last.0 + last.1 == s => last.1 += l,
                _ => merged.push((s, l)),
            }
        }
        // If fragmentation exceeds the table, deliberately leak the smallest extent (already erased).
        while merged.len() > MAX_FREE {
            if let Some(i) = (0..merged.len()).min_by_key(|&i| merged[i].1) {
                merged.remove(i);
            }
        }
        self.free = merged;
    }
}

fn check_extent(start: u64, n: u64, next_free: u64) -> VaultResult<()> {
    if n == 0 {
        return if start == 0 { Ok(()) } else { Err(VaultError::Corrupt) };
    }
    let end = start.checked_add(n).ok_or(VaultError::Corrupt)?;
    if start < ROOT_BLOCKS || end > next_free {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}

#[derive(Clone)]
struct FileEntry {
    name: String,
    file_id: u64,
    size: u64,
    start: u64,
    nblocks: u32,
}

fn check_name(n: &str) -> VaultResult<()> {
    let ok = !n.is_empty() && n.len() <= MAX_NAME && !n.chars().any(|c| c.is_control() || c == '/' || c == '\\');
    if ok { Ok(()) } else { Err(VaultError::InvalidName) }
}

fn rand_u64<R: RngCore + CryptoRng>(rng: &mut R) -> u64 {
    rng.next_u64()
}

// ---------------------------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------------------------

pub struct Vault<D: BlockDevice> {
    dev: D,
    vk: Key,
    root_key: Key,
    vol_id: [u8; 16],
    region_start: u64,
    region_len: u64,
    slot: usize,
    salt: [u8; 32],
    params: KdfParams,
    kdf_memory_limit_kib: u32,
    root: Root,
    unlocked: BTreeMap<u64, Key>,
}

fn vol_id_of(vk: &Key) -> VaultResult<[u8; 16]> {
    let k = subkey(vk, b"kvault/vol-id")?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&k[..16]);
    Ok(id)
}

fn slot_aad(i: usize) -> Vec<u8> {
    aad("kvault/slot", &[0u8; 16], i as u64, 0, 0)
}

fn root_aad(vol: &[u8; 16], abs: u64) -> Vec<u8> {
    aad("kvault/root", vol, abs, 0, 0)
}

fn write_root_block<D: BlockDevice, R: RngCore + CryptoRng>(
    dev: &mut D,
    rng: &mut R,
    root_key: &Key,
    vol: &[u8; 16],
    region_start: u64,
    root: &Root,
) -> VaultResult<()> {
    let abs = region_start + (root.generation % 2);
    let blk = seal_block(rng, root_key, &root_aad(vol, abs), &root.encode()?)?;
    dev.write_block(abs, &blk)
}

impl<D: BlockDevice> Vault<D> {
    // -----------------------------------------------------------------------------------------
    // Keyfile-aware wrappers (additive — `format`/`open`/`change_password` below are unchanged
    // and keep working exactly as before; these just pre-combine password+keyfile and delegate).
    // -----------------------------------------------------------------------------------------

    /// Like [`Vault::format`], but each volume's password can be paired with
    /// an optional keyfile (see [`crate::crypto::combine_password_keyfile`]).
    /// A volume formatted this way can only be opened with
    /// [`Vault::open_with_keyfile`] passing the *same* password and keyfile
    /// — [`Vault::open`] with the plain password alone will see it as a
    /// wrong password, not as "missing a keyfile": that is the point.
    #[allow(clippy::too_many_arguments)]
    pub fn format_with_keyfile<R: RngCore + CryptoRng>(
        dev: D,
        rng: &mut R,
        opts: &FormatOptions,
        outer_pw: &[u8],
        outer_keyfile: Option<&[u8]>,
        hidden: Option<(&[u8], Option<&[u8]>)>,
        duress: Option<(&[u8], Option<&[u8]>)>,
    ) -> VaultResult<D> {
        let outer = combine_password_keyfile(outer_pw, outer_keyfile);
        let hidden_combined = hidden.map(|(pw, kf)| combine_password_keyfile(pw, kf));
        let duress_combined = duress.map(|(pw, kf)| combine_password_keyfile(pw, kf));
        // `.as_deref()` only unwraps one `Deref` layer (`Zeroizing<Vec<u8>>`
        // -> `&Vec<u8>`), not all the way to `&[u8]` — `.as_ref().map(...)`
        // goes through the full chain via method-call auto-deref instead.
        Self::format(
            dev,
            rng,
            opts,
            &outer,
            hidden_combined.as_ref().map(|v| v.as_slice()),
            duress_combined.as_ref().map(|v| v.as_slice()),
        )
    }

    /// Like [`Vault::open`], but requires the keyfile used at format time
    /// (if any) in addition to the password. Passing the wrong keyfile, or
    /// none when one was used at format time, is indistinguishable from a
    /// wrong password: both land on the ordinary `BadPassword` outcome.
    pub fn open_with_keyfile<R: RngCore + CryptoRng>(
        dev: D,
        rng: &mut R,
        password: &[u8],
        keyfile: Option<&[u8]>,
    ) -> Result<OpenOutcome<D>, OpenFail<D>> {
        let combined = combine_password_keyfile(password, keyfile);
        Self::open(dev, rng, &combined)
    }

    /// Like [`Vault::change_password`], but for a volume using a keyfile:
    /// `old_keyfile` must match the one the vault currently requires (or be
    /// `None` if it currently requires none), and the volume will
    /// afterwards require `new_keyfile` instead.
    pub fn change_password_with_keyfile<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        new_pw: &[u8],
        new_keyfile: Option<&[u8]>,
    ) -> VaultResult<()> {
        let combined = combine_password_keyfile(new_pw, new_keyfile);
        self.change_password(rng, &combined)
    }

    // -----------------------------------------------------------------------------------------
    // Format / open
    // -----------------------------------------------------------------------------------------

    /// Create a vault. The whole device is first filled with random data, so used and unused
    /// space are indistinguishable. Passwords must all be different.
    pub fn format<R: RngCore + CryptoRng>(
        mut dev: D,
        rng: &mut R,
        opts: &FormatOptions,
        outer_pw: &[u8],
        hidden_pw: Option<&[u8]>,
        duress_pw: Option<&[u8]>,
    ) -> VaultResult<D> {
        opts.params.validate()?;
        let count = dev.block_count();
        if opts.hidden_percent > 80 || outer_pw.is_empty() {
            return Err(VaultError::InvalidParams);
        }
        if (opts.hidden_percent > 0) != hidden_pw.is_some() {
            return Err(VaultError::InvalidParams);
        }
        let mut seen: Vec<&[u8]> = Vec::new();
        for pw in [Some(outer_pw), hidden_pw, duress_pw].into_iter().flatten() {
            if pw.is_empty() || seen.contains(&pw) {
                return Err(VaultError::InvalidParams);
            }
            seen.push(pw);
        }
        if count < 32 {
            return Err(VaultError::DeviceTooSmall);
        }

        // 1. Random-fill everything.
        let mut blk = [0u8; BLOCK_SIZE];
        for i in 0..count {
            rng.fill_bytes(&mut blk);
            dev.write_block(i, &blk)?;
        }

        // 2. Regions.
        let usable = count - 1;
        let hidden_len = usable * opts.hidden_percent as u64 / 100;
        let outer_len = usable - hidden_len;
        if outer_len < 8 || (hidden_pw.is_some() && hidden_len < 8) {
            return Err(VaultError::DeviceTooSmall);
        }
        let outer_start = 1;
        let hidden_start = 1 + outer_len;

        // 3. Header: params | salt | 8 slots (random positions) | random fill.
        let mut salt = [0u8; 32];
        rng.fill_bytes(&mut salt);
        let mut hdr = [0u8; BLOCK_SIZE];
        rng.fill_bytes(&mut hdr);
        hdr[0..4].copy_from_slice(&opts.params.m_kib.to_le_bytes());
        hdr[4..8].copy_from_slice(&opts.params.t.to_le_bytes());
        hdr[8..12].copy_from_slice(&opts.params.p.to_le_bytes());
        hdr[12..44].copy_from_slice(&salt);

        struct Vol<'a> {
            pw: &'a [u8],
            vk: Key,
            kind: u8,
            start: u64,
            len: u64,
        }
        let mut vols: Vec<Vol> = Vec::new();
        vols.push(Vol { pw: outer_pw, vk: random_key(rng), kind: KIND_NORMAL, start: outer_start, len: outer_len });
        if let Some(h) = hidden_pw {
            vols.push(Vol { pw: h, vk: random_key(rng), kind: KIND_NORMAL, start: hidden_start, len: hidden_len });
        }
        if let Some(d) = duress_pw {
            vols.push(Vol { pw: d, vk: random_key(rng), kind: KIND_DURESS, start: outer_start, len: outer_len });
        }

        let mut used: Vec<usize> = Vec::new();
        for v in &vols {
            let mut i = (rand_u64(rng) % SLOTS as u64) as usize;
            while used.contains(&i) {
                i = (rand_u64(rng) % SLOTS as u64) as usize;
            }
            used.push(i);
            let kek = kdf(v.pw, &salt, &opts.params)?;
            let mut pt = Zeroizing::new([0u8; SLOT_PT]);
            pt[..32].copy_from_slice(&v.vk[..]);
            pt[32] = v.kind;
            pt[33..41].copy_from_slice(&v.start.to_le_bytes());
            pt[41..49].copy_from_slice(&v.len.to_le_bytes());
            let ct = seal(rng, &kek, &slot_aad(i), &pt[..])?;
            debug_assert_eq!(ct.len(), SLOT_CT);
            let off = HDR_FIXED + i * SLOT_CT;
            hdr[off..off + SLOT_CT].copy_from_slice(&ct);
        }
        dev.write_block(0, &hdr)?;

        // 4. Empty root for each real (non-duress) volume.
        for v in vols.iter().filter(|v| v.kind == KIND_NORMAL) {
            let root_key = subkey(&v.vk, b"kvault/root-key")?;
            let vol = vol_id_of(&v.vk)?;
            write_root_block(&mut dev, rng, &root_key, &vol, v.start, &Root::empty())?;
        }
        Ok(dev)
    }

    /// Open with a password. Wrong password and "no such volume" are indistinguishable.
    pub fn open<R: RngCore + CryptoRng>(dev: D, rng: &mut R, password: &[u8]) -> Result<OpenOutcome<D>, OpenFail<D>> {
        Self::open_with_memory_limit(dev, rng, password, DEFAULT_MAX_KDF_MEMORY_KIB)
    }

    /// Open a vault only if its stored Argon2 memory cost fits within `max_memory_kib`.
    ///
    /// Use the default [`Vault::open`] for untrusted or unknown storage. This
    /// explicit-budget variant is for callers that have measured available
    /// memory (for example, the kernel heap) or for offline recovery on a host
    /// with sufficient RAM. The limit is capped at the supported Argon2 range.
    pub fn open_with_memory_limit<R: RngCore + CryptoRng>(
        dev: D,
        rng: &mut R,
        password: &[u8],
        max_memory_kib: u32,
    ) -> Result<OpenOutcome<D>, OpenFail<D>> {
        let max_memory_kib = max_memory_kib.min(ABSOLUTE_MAX_KDF_MEMORY_KIB);
        match Self::open_inner(&dev, password, max_memory_kib) {
            Ok(Opened::Duress) => {
                let mut dev = dev;
                let mut blk = [0u8; BLOCK_SIZE];
                rng.fill_bytes(&mut blk);
                // Destroy the header: params, salt and every slot. Without a slot there is no key.
                match dev.write_block(0, &blk) {
                    Ok(()) => Ok(OpenOutcome::Duress(dev)),
                    Err(error) => Err(OpenFail { error, device: dev }),
                }
            }
            Ok(Opened::Normal { vk, region_start, region_len, slot, salt, params }) => {
                match Self::finish_open(&dev, vk, region_start, region_len, slot, salt, params) {
                    Ok(parts) => Ok(OpenOutcome::Unlocked(Vault {
                        dev,
                        vk: parts.vk,
                        root_key: parts.root_key,
                        vol_id: parts.vol_id,
                        region_start,
                        region_len,
                        slot,
                        salt,
                        params,
                        kdf_memory_limit_kib: max_memory_kib,
                        root: parts.root,
                        unlocked: BTreeMap::new(),
                    })),
                    Err(error) => Err(OpenFail { error, device: dev }),
                }
            }
            Err(error) => Err(OpenFail { error, device: dev }),
        }
    }

    fn open_inner(dev: &D, password: &[u8], max_memory_kib: u32) -> VaultResult<Opened> {
        let mut hdr = [0u8; BLOCK_SIZE];
        dev.read_block(0, &mut hdr)?;
        let params = KdfParams {
            m_kib: u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]),
            t: u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
            p: u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
        };
        // A wiped or foreign device has garbage params: report it exactly like a wrong password.
        params.validate_with_memory_limit(max_memory_kib).map_err(|_| VaultError::BadPassword)?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&hdr[12..44]);
        let kek = kdf_with_memory_limit(password, &salt, &params, max_memory_kib)?;
        for i in 0..SLOTS {
            let off = HDR_FIXED + i * SLOT_CT;
            let Ok(pt) = open(&kek, &slot_aad(i), &hdr[off..off + SLOT_CT]) else { continue };
            if pt.len() != SLOT_PT {
                continue;
            }
            let mut vk = Zeroizing::new([0u8; 32]);
            vk.copy_from_slice(&pt[..32]);
            let kind = pt[32];
            let start = u64::from_le_bytes(pt[33..41].try_into().map_err(|_| VaultError::Corrupt)?);
            let len = u64::from_le_bytes(pt[41..49].try_into().map_err(|_| VaultError::Corrupt)?);
            if kind == KIND_DURESS {
                return Ok(Opened::Duress);
            }
            let end = start.checked_add(len).ok_or(VaultError::Corrupt)?;
            if kind != KIND_NORMAL || start < 1 || len < 8 || end > dev.block_count() {
                return Err(VaultError::Corrupt);
            }
            return Ok(Opened::Normal { vk, region_start: start, region_len: len, slot: i, salt, params });
        }
        Err(VaultError::BadPassword)
    }

    fn finish_open(
        dev: &D,
        vk: Key,
        region_start: u64,
        region_len: u64,
        _slot: usize,
        _salt: [u8; 32],
        _params: KdfParams,
    ) -> VaultResult<OpenParts> {
        let root_key = subkey(&vk, b"kvault/root-key")?;
        let vol_id = vol_id_of(&vk)?;
        let mut best: Option<Root> = None;
        for rel in 0..ROOT_BLOCKS {
            let abs = region_start + rel;
            let mut blk = [0u8; BLOCK_SIZE];
            dev.read_block(abs, &mut blk)?;
            let Ok(pt) = open_block(&root_key, &root_aad(&vol_id, abs), &blk) else { continue };
            let Ok(root) = Root::decode(&pt, region_len) else { continue };
            if root.generation % 2 != rel {
                continue;
            }
            if best.as_ref().map_or(true, |b| root.generation > b.generation) {
                best = Some(root);
            }
        }
        let root = best.ok_or(VaultError::Corrupt)?;
        Ok(OpenParts { vk, root_key, vol_id, root })
    }

    pub fn into_device(self) -> D {
        self.dev
    }

    /// Forget all folder keys (they are zeroized on drop).
    pub fn lock_all(&mut self) {
        self.unlocked.clear();
    }

    pub fn free_blocks(&self) -> u64 {
        self.region_len - self.root.next_free + self.root.free.iter().map(|f| f.1).sum::<u64>()
    }

    /// Change the volume password. The new password must not open any other slot.
    pub fn change_password<R: RngCore + CryptoRng>(&mut self, rng: &mut R, new_pw: &[u8]) -> VaultResult<()> {
        if new_pw.is_empty() {
            return Err(VaultError::InvalidParams);
        }
        let kek = kdf_with_memory_limit(new_pw, &self.salt, &self.params, self.kdf_memory_limit_kib)?;
        let mut hdr = [0u8; BLOCK_SIZE];
        self.dev.read_block(0, &mut hdr)?;
        for i in 0..SLOTS {
            let off = HDR_FIXED + i * SLOT_CT;
            if open(&kek, &slot_aad(i), &hdr[off..off + SLOT_CT]).is_ok() {
                return Err(VaultError::InvalidParams); // collides with an existing password
            }
        }
        let mut pt = Zeroizing::new([0u8; SLOT_PT]);
        pt[..32].copy_from_slice(&self.vk[..]);
        pt[32] = KIND_NORMAL;
        pt[33..41].copy_from_slice(&self.region_start.to_le_bytes());
        pt[41..49].copy_from_slice(&self.region_len.to_le_bytes());
        let ct = seal(rng, &kek, &slot_aad(self.slot), &pt[..])?;
        let off = HDR_FIXED + self.slot * SLOT_CT;
        hdr[off..off + SLOT_CT].copy_from_slice(&ct);
        self.dev.write_block(0, &hdr)
    }

    // -----------------------------------------------------------------------------------------
    // Folders
    // -----------------------------------------------------------------------------------------

    fn folder_pos(&self, name: &str) -> VaultResult<usize> {
        self.root.folders.iter().position(|f| f.name == name).ok_or(VaultError::NotFound)
    }

    fn plain_folder_key(&self, fid: u64) -> VaultResult<Key> {
        subkey(&self.vk, &aad("kvault/folder", &self.vol_id, fid, 0, 0))
    }

    fn folder_key(&self, pos: usize) -> VaultResult<Key> {
        let f = &self.root.folders[pos];
        if !f.has_pw {
            return self.plain_folder_key(f.fid);
        }
        match self.unlocked.get(&f.fid) {
            Some(k) => Ok(Zeroizing::new(**k)),
            None => Err(VaultError::FolderLocked),
        }
    }

    pub fn list_folders(&self) -> Vec<FolderInfo> {
        self.root
            .folders
            .iter()
            .map(|f| FolderInfo {
                name: f.name.clone(),
                password_protected: f.has_pw,
                unlocked: !f.has_pw || self.unlocked.contains_key(&f.fid),
            })
            .collect()
    }

    /// Create a folder. With a password, the folder key is random and wrapped under that password,
    /// so even the volume password cannot read the contents.
    pub fn create_folder<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        name: &str,
        password: Option<&[u8]>,
    ) -> VaultResult<()> {
        check_name(name)?;
        if self.root.folders.iter().any(|f| f.name == name) {
            return Err(VaultError::Exists);
        }
        if self.root.folders.len() >= MAX_FOLDERS {
            return Err(VaultError::TooMany);
        }
        let fid = rand_u64(rng);
        let mut fsalt = [0u8; 32];
        rng.fill_bytes(&mut fsalt);
        let (wrapped, new_key) = match password {
            Some(pw) => {
                if pw.is_empty() {
                    return Err(VaultError::InvalidParams);
                }
                let fk = random_key(rng);
                let kek = kdf_with_memory_limit(pw, &fsalt, &self.params, self.kdf_memory_limit_kib)?;
                let w = seal(rng, &kek, &aad("kvault/fkwrap", &self.vol_id, fid, 0, 0), &fk[..])?;
                (w, Some(fk))
            }
            None => (Vec::new(), None),
        };
        let mut root = self.root.clone();
        root.folders.push(FolderEntry {
            fid,
            name: name.into(),
            has_pw: password.is_some(),
            fsalt,
            wrapped,
            index_start: 0,
            index_blocks: 0,
        });
        self.commit(rng, root)?;
        if let Some(k) = new_key {
            self.unlocked.insert(fid, k);
        }
        Ok(())
    }

    pub fn unlock_folder(&mut self, name: &str, password: &[u8]) -> VaultResult<()> {
        let pos = self.folder_pos(name)?;
        let f = &self.root.folders[pos];
        if !f.has_pw {
            return Ok(());
        }
        let kek = kdf_with_memory_limit(password, &f.fsalt, &self.params, self.kdf_memory_limit_kib)?;
        let pt = open(&kek, &aad("kvault/fkwrap", &self.vol_id, f.fid, 0, 0), &f.wrapped)
            .map_err(|_| VaultError::BadPassword)?;
        if pt.len() != 32 {
            return Err(VaultError::Corrupt);
        }
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&pt);
        let fid = f.fid;
        self.unlocked.insert(fid, k);
        Ok(())
    }

    pub fn lock_folder(&mut self, name: &str) -> VaultResult<()> {
        let pos = self.folder_pos(name)?;
        let fid = self.root.folders[pos].fid;
        self.unlocked.remove(&fid);
        Ok(())
    }

    pub fn change_folder_password<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        name: &str,
        old_pw: &[u8],
        new_pw: &[u8],
    ) -> VaultResult<()> {
        if new_pw.is_empty() {
            return Err(VaultError::InvalidParams);
        }
        let pos = self.folder_pos(name)?;
        if !self.root.folders[pos].has_pw {
            return Err(VaultError::InvalidParams);
        }
        self.unlock_folder(name, old_pw)?;
        let fid = self.root.folders[pos].fid;
        let fk = self.folder_key(pos)?;
        let mut fsalt = [0u8; 32];
        rng.fill_bytes(&mut fsalt);
        let kek = kdf_with_memory_limit(new_pw, &fsalt, &self.params, self.kdf_memory_limit_kib)?;
        let wrapped = seal(rng, &kek, &aad("kvault/fkwrap", &self.vol_id, fid, 0, 0), &fk[..])?;
        let mut root = self.root.clone();
        root.folders[pos].fsalt = fsalt;
        root.folders[pos].wrapped = wrapped;
        self.commit(rng, root)
    }

    /// Delete a folder and erase everything in it. The folder must be unlocked.
    pub fn delete_folder<R: RngCore + CryptoRng>(&mut self, rng: &mut R, name: &str) -> VaultResult<()> {
        let pos = self.folder_pos(name)?;
        let fk = self.folder_key(pos)?;
        let entries = self.read_index(pos, &fk)?;
        let mut root = self.root.clone();
        let mut pending: Vec<(u64, u64)> = entries.iter().filter(|e| e.nblocks > 0).map(|e| (e.start, e.nblocks as u64)).collect();
        let f = root.folders.remove(pos);
        if f.index_blocks > 0 {
            pending.push((f.index_start, f.index_blocks as u64));
        }
        for &(s, l) in &pending {
            root.free_extent(s, l);
        }
        self.commit(rng, root)?;
        self.unlocked.remove(&f.fid);
        self.erase(rng, &pending);
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Files
    // -----------------------------------------------------------------------------------------

    pub fn list_files(&self, folder: &str) -> VaultResult<Vec<FileInfo>> {
        let pos = self.folder_pos(folder)?;
        let fk = self.folder_key(pos)?;
        Ok(self.read_index(pos, &fk)?.into_iter().map(|e| FileInfo { name: e.name, size: e.size }).collect())
    }

    pub fn read_file(&self, folder: &str, name: &str) -> VaultResult<Zeroizing<Vec<u8>>> {
        let pos = self.folder_pos(folder)?;
        let fk = self.folder_key(pos)?;
        let entries = self.read_index(pos, &fk)?;
        let e = entries.iter().find(|e| e.name == name).ok_or(VaultError::NotFound)?;
        let file_key = self.file_key(&fk, e.file_id)?;
        let mut out = Zeroizing::new(Vec::with_capacity(e.size as usize));
        for i in 0..e.nblocks as u64 {
            let abs = self.region_start + e.start + i;
            let mut blk = [0u8; BLOCK_SIZE];
            self.dev.read_block(abs, &mut blk)?;
            let pt = open_block(&file_key, &aad("kvault/data", &self.vol_id, abs, e.file_id, i), &blk)?;
            out.extend_from_slice(&pt);
        }
        if (out.len() as u64) < e.size {
            return Err(VaultError::Corrupt);
        }
        out.truncate(e.size as usize);
        Ok(out)
    }

    /// Returns the absolute physical block starting index and block count on the underlying `BlockDevice`.
    pub fn file_block_range(&self, folder: &str, name: &str) -> VaultResult<(u64, u32)> {
        let pos = self.folder_pos(folder)?;
        let fk = self.folder_key(pos)?;
        let entries = self.read_index(pos, &fk)?;
        let e = entries.iter().find(|e| e.name == name).ok_or(VaultError::NotFound)?;
        let abs = self.region_start + e.start;
        Ok((abs, e.nblocks))
    }

    pub fn write_file<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        folder: &str,
        name: &str,
        data: &[u8],
    ) -> VaultResult<()> {
        check_name(name)?;
        let pos = self.folder_pos(folder)?;
        let fid = self.root.folders[pos].fid;
        let fk = self.folder_key(pos)?;
        let mut entries = self.read_index(pos, &fk)?;
        if entries.len() as u32 >= MAX_FILES && !entries.iter().any(|e| e.name == name) {
            return Err(VaultError::TooMany);
        }
        let mut root = self.root.clone();
        let mut pending: Vec<(u64, u64)> = Vec::new();

        let nblocks = data.len().div_ceil(PAYLOAD) as u64;
        if nblocks > u32::MAX as u64 {
            return Err(VaultError::NoSpace);
        }
        let file_id = rand_u64(rng);
        let file_key = self.file_key(&fk, file_id)?;
        let start = root.alloc(nblocks, self.region_len)?;
        for (i, chunk) in data.chunks(PAYLOAD).enumerate() {
            let abs = self.region_start + start + i as u64;
            let blk = seal_block(rng, &file_key, &aad("kvault/data", &self.vol_id, abs, file_id, i as u64), chunk)?;
            self.dev.write_block(abs, &blk)?;
        }
        if let Some(p) = entries.iter().position(|e| e.name == name) {
            let old = entries.remove(p);
            if old.nblocks > 0 {
                pending.push((old.start, old.nblocks as u64));
            }
        }
        entries.push(FileEntry { name: name.into(), file_id, size: data.len() as u64, start, nblocks: nblocks as u32 });
        self.replace_index(rng, &mut root, pos, fid, &fk, &entries, &mut pending)?;
        for &(s, l) in &pending {
            root.free_extent(s, l);
        }
        self.commit(rng, root)?;
        self.erase(rng, &pending);
        Ok(())
    }

    pub fn delete_file<R: RngCore + CryptoRng>(&mut self, rng: &mut R, folder: &str, name: &str) -> VaultResult<()> {
        let pos = self.folder_pos(folder)?;
        let fid = self.root.folders[pos].fid;
        let fk = self.folder_key(pos)?;
        let mut entries = self.read_index(pos, &fk)?;
        let p = entries.iter().position(|e| e.name == name).ok_or(VaultError::NotFound)?;
        let old = entries.remove(p);
        let mut root = self.root.clone();
        let mut pending: Vec<(u64, u64)> = Vec::new();
        if old.nblocks > 0 {
            pending.push((old.start, old.nblocks as u64));
        }
        self.replace_index(rng, &mut root, pos, fid, &fk, &entries, &mut pending)?;
        for &(s, l) in &pending {
            root.free_extent(s, l);
        }
        self.commit(rng, root)?;
        self.erase(rng, &pending);
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------------------------

    fn file_key(&self, fk: &Key, file_id: u64) -> VaultResult<Key> {
        subkey(fk, &aad("kvault/file", &self.vol_id, file_id, 0, 0))
    }

    fn index_key(&self, fk: &Key) -> VaultResult<Key> {
        subkey(fk, b"kvault/index")
    }

    fn read_index(&self, pos: usize, fk: &Key) -> VaultResult<Vec<FileEntry>> {
        let f = &self.root.folders[pos];
        if f.index_blocks == 0 {
            return Ok(Vec::new());
        }
        let ik = self.index_key(fk)?;
        let mut all = Zeroizing::new(Vec::new());
        for i in 0..f.index_blocks as u64 {
            let abs = self.region_start + f.index_start + i;
            let mut blk = [0u8; BLOCK_SIZE];
            self.dev.read_block(abs, &mut blk)?;
            let pt = open_block(&ik, &aad("kvault/index", &self.vol_id, abs, f.fid, i), &blk)?;
            all.extend_from_slice(&pt);
        }
        let mut r = Reader::new(&all);
        let count = r.u32()?;
        if count > MAX_FILES {
            return Err(VaultError::Corrupt);
        }
        let mut out = Vec::new();
        for _ in 0..count {
            let name = r.str8()?;
            let file_id = r.u64()?;
            let size = r.u64()?;
            let start = r.u64()?;
            let nblocks = r.u32()?;
            check_extent(start, nblocks as u64, self.root.next_free)?;
            if size > nblocks as u64 * PAYLOAD as u64 {
                return Err(VaultError::Corrupt);
            }
            out.push(FileEntry { name, file_id, size, start, nblocks });
        }
        Ok(out)
    }

    /// Write a new index extent for folder `pos` into the (uncommitted) `root` and queue the old one.
    #[allow(clippy::too_many_arguments)]
    fn replace_index<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        root: &mut Root,
        pos: usize,
        fid: u64,
        fk: &Key,
        entries: &[FileEntry],
        pending: &mut Vec<(u64, u64)>,
    ) -> VaultResult<()> {
        let old = (root.folders[pos].index_start, root.folders[pos].index_blocks);
        let (start, blocks) = if entries.is_empty() {
            (0, 0)
        } else {
            let mut w = Writer::default();
            w.u32(entries.len() as u32);
            for e in entries {
                w.str8(&e.name);
                w.u64(e.file_id);
                w.u64(e.size);
                w.u64(e.start);
                w.u32(e.nblocks);
            }
            let blocks = w.buf.len().div_ceil(PAYLOAD) as u32;
            if blocks > MAX_INDEX_BLOCKS {
                return Err(VaultError::TooMany);
            }
            let start = root.alloc(blocks as u64, self.region_len)?;
            let ik = self.index_key(fk)?;
            for (i, chunk) in w.buf.chunks(PAYLOAD).enumerate() {
                let abs = self.region_start + start + i as u64;
                let blk = seal_block(rng, &ik, &aad("kvault/index", &self.vol_id, abs, fid, i as u64), chunk)?;
                self.dev.write_block(abs, &blk)?;
            }
            (start, blocks)
        };
        if old.1 > 0 {
            pending.push((old.0, old.1 as u64));
        }
        root.folders[pos].index_start = start;
        root.folders[pos].index_blocks = blocks;
        Ok(())
    }

    /// Atomically publish a new root: generation+1 goes into the *other* of the two root blocks.
    /// A crash before this single block write leaves the previous root fully intact.
    fn commit<R: RngCore + CryptoRng>(&mut self, rng: &mut R, mut new_root: Root) -> VaultResult<()> {
        new_root.generation = self.root.generation + 1;
        write_root_block(&mut self.dev, rng, &self.root_key, &self.vol_id, self.region_start, &new_root)?;
        self.root = new_root;
        Ok(())
    }

    /// Best-effort overwrite of freed extents with random data. (On flash with wear levelling this
    /// is not a guarantee; the real guarantee is that the keys are gone / never recoverable.)
    fn erase<R: RngCore + CryptoRng>(&mut self, rng: &mut R, extents: &[(u64, u64)]) {
        let mut blk = [0u8; BLOCK_SIZE];
        for &(s, l) in extents {
            for i in 0..l {
                rng.fill_bytes(&mut blk);
                let _ = self.dev.write_block(self.region_start + s + i, &blk);
            }
        }
    }
}

enum Opened {
    Duress,
    Normal { vk: Key, region_start: u64, region_len: u64, slot: usize, salt: [u8; 32], params: KdfParams },
}

struct OpenParts {
    vk: Key,
    root_key: Key,
    vol_id: [u8; 16],
    root: Root,
}
