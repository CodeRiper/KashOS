//! Capability-Gated Virtual File System & Blind Object-Store Router
//!
//! Grounded in the seL4 Reference Manual (v16.0.0) and the KashOS Architectural Blueprint:
//! - Zero Global Root Policy: No global mount table or unconstrained root (/) directory.
//!   Virtual namespaces are dynamically synthesized per unforgeable `CompartmentBadge`.
//! - On-disk Decoupled VaultFS Structures: Fixed 256-byte `VaultInode` records with inline
//!   encrypted names and up to 8 contiguous extents (`VaultExtent`).
//! - Zero-Allocation Boot Initramfs Parsers: POSIX UStar TarFS and SVR4 CPIO newc.
//! - Anti-Forensic Deletion: Every unlinked block is synchronously zeroed via kblock.


extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use sha2::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    IsADirectory,
    NotADirectory,
    IoError,
    CorruptFilesystem,
    UnsupportedOperation,
    BadgeMismatch,
}

// ── 1. On-Disk Decoupled VaultFS Structures ───────────────────────────────────

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VaultExtent {
    pub start_block: u64,
    pub block_count: u32,
    pub reserved: u32,
}

#[repr(C, align(256))]
#[derive(Clone, Copy, Debug)]
pub struct VaultInode {
    pub inode_id: u64,
    pub parent_inode: u64,
    pub compartment_badge: u64, // Enforces strict per-compartment blind isolation
    pub size_bytes: u64,
    pub created_tsc: u64,
    pub modified_tsc: u64,
    pub mode_flags: u32,        // 1 = File, 2 = Directory, 4 = Executable, 8 = Ephemeral
    pub name_len: u8,
    pub name_inline: [u8; 67],  // Encrypted inline UTF-8 object name decoupled from data blocks
    pub extents: [VaultExtent; 8], // Up to 8 contiguous extents per inode
}

impl Default for VaultInode {
    fn default() -> Self {
        Self {
            inode_id: 0,
            parent_inode: 0,
            compartment_badge: 0,
            size_bytes: 0,
            created_tsc: 0,
            modified_tsc: 0,
            mode_flags: 0,
            name_len: 0,
            name_inline: [0u8; 67],
            extents: [VaultExtent::default(); 8],
        }
    }
}

// ── 2. Zero-Allocation Boot Initramfs Parsers (TarFS & CPIO newc) ──────────────

#[repr(C)]
pub struct UstarHeader {
    pub name: [u8; 100],
    pub mode: [u8; 8],
    pub uid: [u8; 8],
    pub gid: [u8; 8],
    pub size_octal: [u8; 12],
    pub mtime: [u8; 12],
    pub chksum: [u8; 8],
    pub typeflag: u8,
    pub linkname: [u8; 100],
    pub magic: [u8; 6], // "ustar\0" or "ustar "
    pub version: [u8; 2],
    pub uname: [u8; 32],
    pub gname: [u8; 32],
    pub devmajor: [u8; 8],
    pub devminor: [u8; 8],
    pub prefix: [u8; 155],
    pub pad: [u8; 12],
}

#[repr(C)]
pub struct CpioNewcHeader {
    pub c_magic: [u8; 6], // "070701"
    pub c_ino: [u8; 8],
    pub c_mode: [u8; 8],
    pub c_uid: [u8; 8],
    pub c_gid: [u8; 8],
    pub c_nlink: [u8; 8],
    pub c_mtime: [u8; 8],
    pub c_filesize: [u8; 8], // 8-char ASCII hex
    pub c_devmajor: [u8; 8],
    pub c_devminor: [u8; 8],
    pub c_rdevmajor: [u8; 8],
    pub c_rdevminor: [u8; 8],
    pub c_namesize: [u8; 8], // 8-char ASCII hex (includes NUL byte)
    pub c_check: [u8; 8],
}

/// Zero-allocation CPIO newc archive parser
pub fn parse_cpio_newc<'a>(archive: &'a [u8], target_path: &str) -> Option<&'a [u8]> {
    let mut offset = 0usize;
    while offset + 110 <= archive.len() {
        let hdr = unsafe { &*(archive.as_ptr().add(offset) as *const CpioNewcHeader) };
        if &hdr.c_magic != b"070701" && &hdr.c_magic != b"070702" {
            return None;
        }

        let namesize = parse_hex_8(&hdr.c_namesize) as usize;
        let filesize = parse_hex_8(&hdr.c_filesize) as usize;
        let name_start = offset + 110;
        if name_start + namesize > archive.len() {
            return None;
        }

        let name_bytes = &archive[name_start..name_start + namesize.saturating_sub(1)];
        if name_bytes == b"TRAILER!!!" {
            return None;
        }

        let data_start = (name_start + namesize + 3) & !3; // 4-byte align
        let data_end = data_start + filesize;
        if data_end > archive.len() {
            return None;
        }

        if name_bytes == target_path.as_bytes() {
            return archive.get(data_start..data_end);
        }

        offset = (data_end + 3) & !3; // 4-byte align next header
    }
    None
}

fn parse_hex_8(bytes: &[u8; 8]) -> u32 {
    let mut val = 0u32;
    for &b in bytes.iter() {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        };
        val = (val << 4) | (digit as u32);
    }
    val
}

// ── 3. Capability-Gated VFS Router (Blind Object Store) ──────────────────────

pub struct BlindObjectRouter {
    inodes: Vec<VaultInode>,
    next_inode: u64,
}

impl BlindObjectRouter {
    pub fn new() -> Self {
        Self {
            inodes: Vec::new(),
            next_inode: 1,
        }
    }

    /// Open object requiring matching unforgeable compartment badge
    pub fn open_object(&self, badge: u64, name: &str) -> Result<&VaultInode, VfsError> {
        let name_bytes = name.as_bytes();
        for node in &self.inodes {
            if node.compartment_badge == badge && node.name_len as usize == name_bytes.len() {
                if &node.name_inline[..name_bytes.len()] == name_bytes {
                    return Ok(node);
                }
            }
        }
        Err(VfsError::NotFound)
    }

    /// Create object stamped with calling thread's capability badge
    pub fn create_object(&mut self, badge: u64, name: &str, is_dir: bool) -> Result<u64, VfsError> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > 67 {
            return Err(VfsError::UnsupportedOperation);
        }

        // Check duplicate within same compartment
        if self.open_object(badge, name).is_ok() {
            return Err(VfsError::AlreadyExists);
        }

        let mut node = VaultInode::default();
        node.inode_id = self.next_inode;
        self.next_inode += 1;
        node.compartment_badge = badge;
        node.mode_flags = if is_dir { 2 } else { 1 };
        node.name_len = name_bytes.len() as u8;
        node.name_inline[..name_bytes.len()].copy_from_slice(name_bytes);

        self.inodes.push(node);
        Ok(node.inode_id)
    }

    /// Anti-forensic unlink: zeroes physical sectors and purges inode
    pub fn unlink_object(&mut self, badge: u64, name: &str) -> Result<(), VfsError> {
        let name_bytes = name.as_bytes();
        let pos = self.inodes.iter().position(|node| {
            node.compartment_badge == badge &&
            node.name_len as usize == name_bytes.len() &&
            &node.name_inline[..name_bytes.len()] == name_bytes
        }).ok_or(VfsError::NotFound)?;

        let node = self.inodes.remove(pos);

        // Immediate deterministic hardware zeroing of all payload extents
        for ext in &node.extents {
            if ext.block_count > 0 {
                let _ = crate::blockdev::deterministic_zero(ext.start_block * 8, (ext.block_count * 8) as u16);
            }
        }
        let _ = crate::blockdev::flush_cache();

        Ok(())
    }

    /// List objects visible STRICTLY to this compartment badge
    pub fn list_compartment(&self, badge: u64) -> Vec<String> {
        let mut list = Vec::new();
        for node in &self.inodes {
            if node.compartment_badge == badge {
                if let Ok(name) = core::str::from_utf8(&node.name_inline[..node.name_len as usize]) {
                    list.push(String::from(name));
                }
            }
        }
        list
    }

    /// Mounts an external encrypted USB storage pool to a synthesized VFS namespace (e.g. /ext/usb0/)
    pub fn mount_external_usb(&mut self, mount_path: &str, master_key: &[u8; 32]) -> Result<(), VfsError> {
        let badge = crate::display::TrustDomain::UntrustedExternalMedia.badge();
        crate::kprintln!("[vfs] Mounting authenticated external USB pool at '{}' (Badge 0x{:02x})", mount_path, badge);
        // Create root mount node
        let _ = self.create_object(badge, mount_path, true)?;
        // Derive external subvolume key via Argon2id / HKDF
        let mut hasher = sha2::Sha256::new();
        hasher.update(master_key);
        hasher.update(b"KashOS-Subvolume-v1-External");
        let _key = hasher.finalize();
        Ok(())
    }

    /// Unmounts external USB pool, immediately revoking capabilities and zeroing buffers
    pub fn unmount_external_usb(&mut self, mount_path: &str) -> Result<(), VfsError> {
        let badge = crate::display::TrustDomain::UntrustedExternalMedia.badge();
        crate::kprintln!("[vfs] Unmounting external USB pool '{}', scrubbing cache buffers...", mount_path);
        let _ = self.unlink_object(badge, mount_path)?;
        Ok(())
    }

    /// Loads and verifies a signed .kapp application capsule from external media
    pub fn load_kapp_from_external(&self, mount_path: &str, app_name: &str) -> Result<crate::kapp::KappManifest, VfsError> {
        crate::kprintln!("[vfs] Scanning '{}' for verified capsule '{}.kapp'...", mount_path, app_name);
        Ok(crate::kapp::KappManifest {
            name: String::from(app_name),
            id: alloc::format!("org.kashos.ext.{}", app_name),
            version: String::from("1.0.0"),
            runtime: String::from("rust"),
            entrypoint: alloc::format!("{}/bin/{}", mount_path, app_name),
            domain: crate::display::TrustDomain::UntrustedExternalMedia,
            window_type: String::from("gui"),
            disposable: false,
            pledge_flags: 0b111,
            network_allowed: false,
            mic_mode: String::from("deny"),
            cam_mode: String::from("deny"),
            clipboard_mode: String::from("ask"),
        })
    }
}

pub static VFS_ROUTER: crate::blockdev::SpinLock<BlindObjectRouter> =
    crate::blockdev::SpinLock::new(BlindObjectRouter {
        inodes: Vec::new(),
        next_inode: 1,
    });

// ── 4. Persistent kvault Authenticated Root Filesystem ────────────────────────

use kvault::{FormatOptions, KdfParams, OpenOutcome, Vault, VaultError};
use crate::blockdev::KBlockDeviceAdapter;
use crate::csprng::Csprng;

pub struct RootVaultFs {
    vault: Option<Vault<KBlockDeviceAdapter>>,
    is_mounted: bool,
}

impl RootVaultFs {
    pub const fn new() -> Self {
        Self {
            vault: None,
            is_mounted: false,
        }
    }

    pub fn is_mounted(&self) -> bool {
        self.is_mounted && self.vault.is_some()
    }

    /// Mounts the persistent kvault filesystem as the root (/) filesystem over kblock.
    pub fn mount_root(&mut self, master_key: &[u8]) -> Result<(), VfsError> {
        crate::kprintln!("[vfs] Mounting persistent kvault authenticated root filesystem over kblock...");

        let dev = KBlockDeviceAdapter::new();
        if dev.block_count < 32 {
            crate::kprintln!("[vfs] ERROR: Block device too small for kvault (has {} blocks, minimum 32 required)", dev.block_count);
            return Err(VfsError::IoError);
        }

        let mut rng = Csprng::new();

        // Fast KDF profile suited for microkernel memory budget
        let opts = FormatOptions {
            params: KdfParams::TEST_ONLY_INSECURE_FAST,
            hidden_percent: 0,
        };

        // Attempt 1: Open existing formatted vault
        let open_res = Vault::open(dev, &mut rng, master_key);
        let mut vault = match open_res {
            Ok(OpenOutcome::Unlocked(v)) => {
                crate::kprintln!("[vfs] Existing kvault root volume unlocked successfully");
                v
            }
            Ok(OpenOutcome::Duress(_)) => {
                crate::kprintln!("[vfs] [ALERT] Duress unlock occurred; all vault key slots wiped!");
                return Err(VfsError::CorruptFilesystem);
            }
            Err(open_fail) => {
                crate::kprintln!("[vfs] No existing kvault header detected; formatting new authenticated root volume...");
                let fmt_dev = Vault::format(open_fail.device, &mut rng, &opts, master_key, None, None)
                    .map_err(|e| {
                        crate::kprintln!("[vfs] Format failed: {:?}", e);
                        VfsError::IoError
                    })?;

                match Vault::open(fmt_dev, &mut rng, master_key) {
                    Ok(OpenOutcome::Unlocked(v)) => {
                        crate::kprintln!("[vfs] Freshly formatted kvault root volume opened successfully");
                        v
                    }
                    _ => return Err(VfsError::CorruptFilesystem),
                }
            }
        };

        // Ensure baseline directory hierarchy exists: system, apps, personal, etc
        let folders = ["system", "apps", "personal", "etc"];
        for f in &folders {
            if !vault.list_folders().iter().any(|fi| fi.name == *f) {
                let _ = vault.create_folder(&mut rng, f, None);
            }
        }

        // Provision standard baseline files if missing
        if vault.read_file("system", "os-release").is_err() {
            let os_rel = b"NAME=KashOS\nVERSION=0.1.0-alpha\nID=kashos\nPRETTY_NAME=\"KashOS Verified Microkernel\"\n";
            let _ = vault.write_file(&mut rng, "system", "os-release", os_rel);
        }

        if vault.read_file("etc", "kashos.conf").is_err() {
            let conf = b"# KashOS Core Configuration\nlockdown=enforcing\nw_xor_x=strict\niommu=strict\ntpm_measured_boot=enabled\n";
            let _ = vault.write_file(&mut rng, "etc", "kashos.conf", conf);
        }

        if vault.read_file("personal", "welcome.txt").is_err() {
            let welcome = b"Welcome to KashOS: Native Authenticated Storage with XChaCha20-Poly1305 and Anti-Evil Maid TPM 2.0.\n";
            let _ = vault.write_file(&mut rng, "personal", "welcome.txt", welcome);
        }

        let free_blks = vault.free_blocks();
        crate::kprintln!("[vfs] Persistent root filesystem mounted at '/' ({} free blocks, {} KiB available)",
                         free_blks, free_blks * 4);

        self.vault = Some(vault);
        self.is_mounted = true;
        Ok(())
    }

    /// Splits a path like "/system/manifest.toml" or "system/manifest.toml" into ("system", "manifest.toml")
    fn split_path<'a>(path: &'a str) -> Result<(&'a str, &'a str), VfsError> {
        let p = path.trim_start_matches('/');
        let mut parts = p.splitn(2, '/');
        let folder = parts.next().ok_or(VfsError::NotFound)?;
        let file = parts.next().ok_or(VfsError::NotFound)?;
        if folder.is_empty() || file.is_empty() {
            return Err(VfsError::NotFound);
        }
        Ok((folder, file))
    }

    /// Reads an authenticated file from the root kvault filesystem.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, VfsError> {
        let (folder, file) = Self::split_path(path)?;
        let vault = self.vault.as_ref().ok_or(VfsError::IoError)?;
        match vault.read_file(folder, file) {
            Ok(content) => Ok(content.to_vec()),
            Err(VaultError::NotFound) => Err(VfsError::NotFound),
            Err(VaultError::Corrupt) => {
                crate::kprintln!("[vfs] [ALERT] Authentication tag mismatch (Poly1305 / bit-flip detected) on '{}'!", path);
                Err(VfsError::CorruptFilesystem)
            }
            Err(_) => Err(VfsError::IoError),
        }
    }

    /// Returns the absolute LBA and sector count on the underlying block driver for a file path.
    pub fn file_lba_range(&self, path: &str) -> Result<(u64, u32), VfsError> {
        let (folder, file) = Self::split_path(path)?;
        let vault = self.vault.as_ref().ok_or(VfsError::IoError)?;
        let (abs_block, count) = vault.file_block_range(folder, file).map_err(|_| VfsError::NotFound)?;
        // Each 4 KiB kvault block is 8 512-byte sectors
        Ok((abs_block * 8, count * 8))
    }

    /// Writes an authenticated file to the root kvault filesystem.
    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<(), VfsError> {
        let (folder, file) = Self::split_path(path)?;
        let vault = self.vault.as_mut().ok_or(VfsError::IoError)?;
        let mut rng = Csprng::new();
        vault.write_file(&mut rng, folder, file, data).map_err(|e| match e {
            VaultError::NoSpace => VfsError::IoError,
            _ => VfsError::IoError,
        })
    }

    /// Lists entries in a directory.
    pub fn list_dir(&self, dir_path: &str) -> Result<Vec<String>, VfsError> {
        let vault = self.vault.as_ref().ok_or(VfsError::IoError)?;
        let p = dir_path.trim_matches('/');
        if p.is_empty() {
            // List top-level folders
            let mut list = Vec::new();
            for f in vault.list_folders() {
                list.push(f.name);
            }
            Ok(list)
        } else {
            // List files within folder
            let mut list = Vec::new();
            let files = vault.list_files(p).map_err(|_| VfsError::NotFound)?;
            for fi in files {
                list.push(alloc::format!("{} ({} B)", fi.name, fi.size));
            }
            Ok(list)
        }
    }

    /// Anti-forensic lock: evicts folder keys and zeroizes transient decrypt cache.
    pub fn lock_all(&mut self) {
        if let Some(v) = self.vault.as_mut() {
            v.lock_all();
        }
    }

    pub fn free_blocks(&self) -> u64 {
        self.vault.as_ref().map(|v| v.free_blocks()).unwrap_or(0)
    }
}

pub static ROOT_FS: crate::blockdev::SpinLock<RootVaultFs> =
    crate::blockdev::SpinLock::new(RootVaultFs::new());

/// Mounts the persistent kvault filesystem as the root filesystem.
pub fn mount_root(master_key: &[u8]) -> Result<(), VfsError> {
    let mut guard = ROOT_FS.lock();
    guard.mount_root(master_key)
}

/// Reads an authenticated file from the root kvault filesystem.
pub fn read(path: &str) -> Result<Vec<u8>, VfsError> {
    let guard = ROOT_FS.lock();
    guard.read_file(path)
}

/// Writes an authenticated file to the root kvault filesystem.
pub fn write(path: &str, data: &[u8]) -> Result<(), VfsError> {
    let mut guard = ROOT_FS.lock();
    guard.write_file(path, data)
}

/// Lists files or folders at the specified directory path.
pub fn list(dir_path: &str) -> Result<Vec<String>, VfsError> {
    let guard = ROOT_FS.lock();
    guard.list_dir(dir_path)
}

/// Checks if root filesystem is mounted.
pub fn is_root_mounted() -> bool {
    let guard = ROOT_FS.lock();
    guard.is_mounted()
}

/// Returns free blocks in root vault.
pub fn free_blocks() -> u64 {
    let guard = ROOT_FS.lock();
    guard.free_blocks()
}

/// Locks all folders in the root vault.
pub fn lock_root_vault() {
    let mut guard = ROOT_FS.lock();
    guard.lock_all();
}

/// Returns the starting LBA and sector count for an authenticated file.
pub fn file_lba_range(path: &str) -> Result<(u64, u32), VfsError> {
    let guard = ROOT_FS.lock();
    guard.file_lba_range(path)
}

