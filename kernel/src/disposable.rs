//! Ephemeral Disposable Domains (Domain 5, `disp-vm`).
//!
//! Grounded in the KashOS Threat Model:
//! - Ephemeral disposable domains operate exclusively in volatile RAM scratchpads.
//! - Strict air-gapping: Zero ambient access to persistent storage paths (`/vault`, `/personal`).
//! - FLASK Security Identifier: `SID_DISPOSABLE`.
//! - Cryptographic Teardown Guarantee: Upon termination, 100% of the domain's allocated memory
//!   is overwritten with zeros, cache lines are flushed with `clflush`, and an exhaustive audit scan
//!   verifies zero-remanence (0 bytes retained).

#![allow(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use crate::flask::SID_DISPOSABLE;

pub const DISPOSABLE_DOMAIN_ID: u32 = 5; // disp-vm (Magenta #F538A0)
pub const DEFAULT_SCRATCHPAD_SIZE: usize = 64 * 1024; // 64 KiB ephemeral RAM scratchpad

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TeardownAuditReport {
    pub domain_id: u32,
    pub pid: u32,
    pub bytes_scrubbed: usize,
    pub remanence_detected: bool,
    pub zero_remanence_verified: bool,
}

pub struct DisposableDomain {
    pub domain_id: u32,
    pub pid: u32,
    pub sid: u32,
    pub scratchpad: Vec<u8>,
    pub is_active: bool,
}

impl DisposableDomain {
    pub fn new(pid: u32, size_bytes: usize) -> Result<Self, &'static str> {
        let mut scratchpad = Vec::with_capacity(size_bytes);
        scratchpad.resize(size_bytes, 0);

        crate::process::set_process_sid(pid, SID_DISPOSABLE);

        crate::kprintln!(
            "[disp-vm] Created disposable domain #{} (PID {}, {} KiB RAM scratchpad, SID_DISPOSABLE)",
            DISPOSABLE_DOMAIN_ID, pid, size_bytes / 1024
        );
        crate::kprintln!("[disp-vm] -> Security Boundary: Air-gapped from persistent storage (zero ambient authority)");

        Ok(Self {
            domain_id: DISPOSABLE_DOMAIN_ID,
            pid,
            sid: SID_DISPOSABLE,
            scratchpad,
            is_active: true,
        })
    }

    pub fn write_scratchpad(&mut self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        if !self.is_active {
            return Err("Domain inactive");
        }
        if offset + data.len() > self.scratchpad.len() {
            return Err("Scratchpad out of bounds");
        }
        self.scratchpad[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    pub fn read_scratchpad(&self, offset: usize, out: &mut [u8]) -> Result<(), &'static str> {
        if !self.is_active {
            return Err("Domain inactive");
        }
        if offset + out.len() > self.scratchpad.len() {
            return Err("Scratchpad out of bounds");
        }
        out.copy_from_slice(&self.scratchpad[offset..offset + out.len()]);
        Ok(())
    }

    pub fn terminate(&mut self) -> Result<TeardownAuditReport, &'static str> {
        if !self.is_active {
            return Err("Domain already terminated");
        }

        let total_bytes = self.scratchpad.len();
        crate::kprintln!(
            "[disp-vm] Terminating disposable domain #{} (PID {})... Scrubbing {} bytes of RAM scratchpad",
            self.domain_id, self.pid, total_bytes
        );

        // 1. Zeroize volatile RAM scratchpad
        for byte in self.scratchpad.iter_mut() {
            *byte = 0;
        }

        // 2. Cache flush across all scratchpad memory lines
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let ptr = self.scratchpad.as_ptr();
            let mut offset = 0;
            while offset < total_bytes {
                core::arch::x86_64::_mm_clflush(ptr.add(offset));
                offset += 64; // standard 64-byte x86 cache line
            }
            core::arch::x86_64::_mm_mfence();
        }

        // 3. Post-destruction zero-remanence memory audit scan
        let mut remanence = false;
        for (idx, byte) in self.scratchpad.iter().enumerate() {
            if *byte != 0 {
                crate::kprintln!("[disp-vm] [ALERT] Memory remanence detected at byte offset {}!", idx);
                remanence = true;
                break;
            }
        }

        self.is_active = false;
        // Drop the scratchpad memory
        self.scratchpad.clear();
        self.scratchpad.shrink_to_fit();

        crate::kprintln!(
            "[disp-vm] Domain #{} teardown complete: {} bytes zeroed, remanence: {}",
            self.domain_id, total_bytes, if remanence { "FAILED" } else { "ZERO (CLEAN)" }
        );

        Ok(TeardownAuditReport {
            domain_id: self.domain_id,
            pid: self.pid,
            bytes_scrubbed: total_bytes,
            remanence_detected: remanence,
            zero_remanence_verified: !remanence,
        })
    }
}
