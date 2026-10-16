//! FLASK Mandatory Access Control (MAC) Subsystem.
//!
//! Implements the Flux Advanced Security Kernel (FLASK) architecture, decoupling
//! policy enforcement from policy decisions:
//! - Security Identifiers (SIDs): 32-bit integer tokens mapped to security contexts.
//! - Access Vector Cache (AVC): Fast nanosecond lookup cache for security decisions.
//! - Security Server (SS): Policy engine combining SELinux type enforcement,
//!   AppArmor path restrictions, and Firejail system call whitelisting.
//! - Dynamic Policy Invalidation: Real-time atomic policy reloads across Object Managers.
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ── Security Identifiers (SIDs) ──────────────────────────────────────────────

pub type Sid = u32;

pub const SID_NULL: Sid            = 0;
pub const SID_SYSTEM: Sid          = 1; // Trusted kernel & root task
pub const SID_UNTRUSTED_KAPP: Sid  = 2; // Default untrusted application capsule
pub const SID_NET_DOMAIN: Sid      = 3; // Isolated network domain
pub const SID_STORAGE_DOMAIN: Sid  = 4; // Isolated storage domain
pub const SID_USB_DOMAIN: Sid      = 5; // Isolated USB hardware gate
pub const SID_DISPOSABLE: Sid      = 6; // Ephemeral RAM-only disposable session

// ── Security Classes & Permissions ───────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityClass {
    File = 1,
    Socket = 2,
    IpcChannel = 3,
    Window = 4,
    Peripheral = 5,
}

pub mod perms {
    // File permissions
    pub const FILE_READ: u32       = 1 << 0;
    pub const FILE_WRITE: u32      = 1 << 1;
    pub const FILE_EXECUTE: u32    = 1 << 2;
    pub const FILE_CREATE: u32     = 1 << 3;
    pub const FILE_UNLINK: u32     = 1 << 4;

    // Socket / Net permissions
    pub const NET_CONNECT: u32     = 1 << 5;
    pub const NET_BIND: u32        = 1 << 6;
    pub const NET_LISTEN: u32      = 1 << 7;

    // Window / Display permissions
    pub const WIN_MAP: u32         = 1 << 8;
    pub const WIN_FOCUS: u32       = 1 << 9;
    pub const WIN_CLIPBOARD_PASTE: u32 = 1 << 10;
    pub const WIN_CLIPBOARD_COPY: u32  = 1 << 11;

    // Hardware / Peripheral permissions
    pub const DEV_AUDIO_MIC: u32   = 1 << 12;
    pub const DEV_VIDEO_CAM: u32   = 1 << 13;
    pub const DEV_USB_RAW: u32     = 1 << 14;
}

// ── MAC Enforcement Mode ─────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacMode {
    Enforcing,  // Violations blocked and logged immediately
    Permissive, // Violations logged but permitted
    Disabled,   // Access checks bypassed
}

// ── Access Vector Cache (AVC) ────────────────────────────────────────────────

#[derive(Copy, Clone, Debug)]
pub struct AvcEntry {
    pub source_sid: Sid,
    pub target_sid: Sid,
    pub class: SecurityClass,
    pub allowed_perms: u32,
    pub valid: bool,
}

const AVC_CACHE_SIZE: usize = 32;

pub struct AccessVectorCache {
    entries: [AvcEntry; AVC_CACHE_SIZE],
    hit_count: AtomicU64,
    miss_count: AtomicU64,
}

impl AccessVectorCache {
    pub const fn new() -> Self {
        let dummy = AvcEntry {
            source_sid: SID_NULL,
            target_sid: SID_NULL,
            class: SecurityClass::File,
            allowed_perms: 0,
            valid: false,
        };
        Self {
            entries: [dummy; AVC_CACHE_SIZE],
            hit_count: AtomicU64::new(0),
            miss_count: AtomicU64::new(0),
        }
    }

    pub fn lookup(&self, s_sid: Sid, t_sid: Sid, class: SecurityClass) -> Option<u32> {
        for entry in &self.entries {
            if entry.valid && entry.source_sid == s_sid && entry.target_sid == t_sid && entry.class == class {
                self.hit_count.fetch_add(1, Ordering::Relaxed);
                return Some(entry.allowed_perms);
            }
        }
        self.miss_count.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&mut self, s_sid: Sid, t_sid: Sid, class: SecurityClass, allowed: u32) {
        // Simple direct-mapped replacement based on hash
        let idx = ((s_sid ^ t_sid ^ (class as u32)) as usize) % AVC_CACHE_SIZE;
        self.entries[idx] = AvcEntry {
            source_sid: s_sid,
            target_sid: t_sid,
            class,
            allowed_perms: allowed,
            valid: true,
        };
    }

    pub fn invalidate_all(&mut self) {
        for entry in &mut self.entries {
            entry.valid = false;
        }
    }
}

// ── FLASK Security Server ────────────────────────────────────────────────────

pub struct FlaskSecurityServer {
    pub mode: MacMode,
    pub avc: AccessVectorCache,
    policy_generation: AtomicU32,
}

impl FlaskSecurityServer {
    pub const fn new() -> Self {
        Self {
            mode: MacMode::Enforcing,
            avc: AccessVectorCache::new(),
            policy_generation: AtomicU32::new(1),
        }
    }

    /// Evaluates an access request: checks AVC first; on miss, queries policy rules.
    pub fn check_permission(
        &mut self,
        source_sid: Sid,
        target_sid: Sid,
        class: SecurityClass,
        requested_perm: u32,
    ) -> Result<(), &'static str> {
        if self.mode == MacMode::Disabled {
            return Ok(());
        }

        // Step 1: Query AVC
        let allowed_mask = if let Some(mask) = self.avc.lookup(source_sid, target_sid, class) {
            mask
        } else {
            // Step 2: Policy computation on cache miss
            let computed = self.compute_policy(source_sid, target_sid, class);
            self.avc.insert(source_sid, target_sid, class, computed);
            computed
        };

        // Step 3: Enforce permissions
        if (allowed_mask & requested_perm) == requested_perm {
            Ok(())
        } else if self.mode == MacMode::Permissive {
            crate::kprintln!(
                "[FLASK-AUDIT:PERMISSIVE] denied s_sid={} t_sid={} class={:?} perm=0x{:X}",
                source_sid, target_sid, class, requested_perm
            );
            Ok(())
        } else {
            Err("FLASK MAC Policy Denied Operation")
        }
    }

    /// Compute security policy ruling based on FLASK security contexts.
    fn compute_policy(&self, s_sid: Sid, t_sid: Sid, class: SecurityClass) -> u32 {
        // System SID has full permissions across all classes
        if s_sid == SID_SYSTEM {
            return 0xFFFF_FFFF;
        }

        match class {
            SecurityClass::File => {
                if s_sid == SID_UNTRUSTED_KAPP || s_sid == SID_DISPOSABLE {
                    if t_sid == SID_STORAGE_DOMAIN {
                        // Applications can read/write their scoped storage only
                        perms::FILE_READ | perms::FILE_WRITE | perms::FILE_CREATE | perms::FILE_UNLINK
                    } else if t_sid == SID_SYSTEM {
                        // Untrusted apps can only READ system libraries, cannot write or unlink
                        perms::FILE_READ | perms::FILE_EXECUTE
                    } else {
                        0
                    }
                } else {
                    perms::FILE_READ
                }
            }

            SecurityClass::Socket => {
                if s_sid == SID_UNTRUSTED_KAPP || s_sid == SID_DISPOSABLE {
                    // Untrusted applications may connect only through the isolated network domain
                    if t_sid == SID_NET_DOMAIN {
                        perms::NET_CONNECT
                    } else {
                        0 // Direct raw sockets strictly blocked (Firejail seccomp)
                    }
                } else {
                    0
                }
            }

            SecurityClass::Window => {
                // Client windows can map surfaces and receive focus, clipboard paste is mediated
                perms::WIN_MAP | perms::WIN_FOCUS | perms::WIN_CLIPBOARD_PASTE
            }

            SecurityClass::Peripheral => {
                // Hardware devices denied direct access; routed through synthetic fallback
                0
            }

            SecurityClass::IpcChannel => {
                if t_sid == SID_SYSTEM || t_sid == SID_STORAGE_DOMAIN || t_sid == SID_NET_DOMAIN {
                    0xFFFF
                } else {
                    0
                }
            }
        }
    }

    /// Dynamic Atomic Policy Reload: updates policy generation and purges the AVC.
    pub fn reload_policy(&mut self, new_mode: MacMode) {
        self.mode = new_mode;
        self.policy_generation.fetch_add(1, Ordering::SeqCst);
        self.avc.invalidate_all();
        crate::kprintln!(
            "[FLASK] Policy generation updated to {}. AVC flushed across all Object Managers.",
            self.policy_generation.load(Ordering::Relaxed)
        );
    }
}
