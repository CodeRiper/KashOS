//! TPM 2.0 experimental driver and software state model.
//!
//! The production transport is intentionally disabled. ACPI TPM2 table
//! parsing, TIS/CRB discovery, command marshaling, and response validation
//! have not been validated against hardware or swtpm. `Tpm2Device`'s local
//! PCR/sealing helpers exist only for deterministic self-tests and are not
//! hardware TPM operations. Do not use them to protect persistent keys.

use sha2::{Digest, Sha256};
use crate::sync::TicketSpinLock;

/// Standard TIS MMIO Base Address for Locality 0.
pub const TPM_TIS_BASE_PADDR: u64 = 0xFED4_0000;

// TIS Locality 0 Register Offsets
pub const TPM_ACCESS: usize = 0x0000;
pub const TPM_INT_ENABLE: usize = 0x0008;
pub const TPM_INT_STATUS: usize = 0x0010;
pub const TPM_STS: usize = 0x0018;
pub const TPM_DATA_FIFO: usize = 0x0024;
pub const TPM_INTERFACE_ID: usize = 0x0030;
pub const TPM_DID_VID: usize = 0x0F00;
pub const TPM_RID: usize = 0x0F04;

// TPM_ACCESS Flags
pub const TPM_ACCESS_ESTABLISHMENT: u8 = 0x01;
pub const TPM_ACCESS_REQUEST_USE: u8 = 0x02;
pub const TPM_ACCESS_ACTIVE_LOCALITY: u8 = 0x20;
pub const TPM_ACCESS_VALID: u8 = 0x80;

// TPM_STS Flags
pub const TPM_STS_EXPECT: u8 = 0x08;
pub const TPM_STS_DATA_AVAIL: u8 = 0x10;
pub const TPM_STS_GO: u8 = 0x20;
pub const TPM_STS_COMMAND_READY: u8 = 0x40;
pub const TPM_STS_VALID: u8 = 0x80;

// TPM 2.0 Command Codes and Algorithms
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
pub const TPM_CC_CREATE: u32 = 0x0000_0153;
pub const TPM_CC_UNSEAL: u32 = 0x0000_015E;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_SU_CLEAR: u16 = 0x0000;

// Return Codes
pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM_RC_POLICY_FAIL: u32 = 0x0000_099D;

/// Errors returned by TPM 2.0 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmError {
    NotPresent,
    IoTimeout,
    InvalidParameter,
    BufferTooSmall,
    PcrOutOfBounds,
    PolicyMismatch,
    CommandFailed(u32),
    CapacityExceeded,
}

/// Interface type for TPM 2.0 controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmInterface {
    Tis,
    Crb,
    None,
}

/// Record of a sealed cryptographic item bound to a PCR policy.
#[derive(Clone, Copy)]
pub struct SealedItem {
    pub handle: u32,
    pub pcr_mask: u32,
    pub policy_digest: [u8; 32],
    pub data: [u8; 64],
    pub data_len: usize,
}

impl SealedItem {
    pub const fn empty() -> Self {
        Self {
            handle: 0,
            pcr_mask: 0,
            policy_digest: [0u8; 32],
            data: [0u8; 64],
            data_len: 0,
        }
    }
}

/// Zero-heap TPM test model. Production transport is disabled by `probe`.
pub struct Tpm2Device {
    pub hardware_present: bool,
    pub interface: TpmInterface,
    pub mmio_base: u64,
    pub is_started: bool,
    pub measurement_log: [[u8; 32]; kboot::PCR_COUNT],
    pub sealed_items: [Option<SealedItem>; 8],
    pub next_handle: u32,
    pub event_log: [kboot::TcgEventLogEntry; 32],
    pub event_count: usize,
    pub monotonic_counter: u64,
}

/// TPM discovery is disabled pending validated ACPI and transport support.
pub fn early_init() {
}

impl Tpm2Device {
    pub const fn new() -> Self {
        Self {
            hardware_present: false,
            interface: TpmInterface::None,
            mmio_base: TPM_TIS_BASE_PADDR,
            is_started: false,
            measurement_log: [[0u8; 32]; kboot::PCR_COUNT],
            sealed_items: [None; 8],
            next_handle: 0x8000_0001,
            event_log: [kboot::TcgEventLogEntry::empty(); 32],
            event_count: 0,
            monotonic_counter: kboot::KASH_SECURITY_EPOCH,
        }
    }

    /// Requests Locality 0 access over TIS MMIO.
    pub fn tis_request_locality(&self) -> Result<(), TpmError> {
        let _ = self;
        Err(TpmError::NotPresent)
    }

    /// Releases Locality 0 access.
    pub fn tis_release_locality(&self) {
        let _ = self;
    }

    /// Executes a raw TCG command packet across TIS MMIO FIFO.
    pub fn tis_execute_command(&self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, TpmError> {
        let _ = (self, cmd, resp);
        Err(TpmError::NotPresent)
    }

    /// Executes a command packet using the active hardware interface.
    pub fn execute_command(&self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, TpmError> {
        match self.interface {
            TpmInterface::Tis => self.tis_execute_command(cmd, resp),
            TpmInterface::Crb => Err(TpmError::NotPresent),
            TpmInterface::None => Err(TpmError::NotPresent),
        }
    }

    /// TPM transport is disabled until ACPI discovery and command handling
    /// pass hardware/swtpm conformance tests. Never probe guessed MMIO here.
    pub fn probe(&mut self) -> bool {
        self.interface = TpmInterface::None;
        self.hardware_present = false;
        self.is_started = false;
        crate::kprintln!("[tpm2] NOT AVAILABLE: hardware transport is disabled pending ACPI/TIS/CRB conformance tests");
        false
    }

    /// Issues TPM2_Startup.
    pub fn startup(&mut self, su_type: u16) -> Result<(), TpmError> {
        let su_bytes = su_type.to_be_bytes();
        let cmd = [
            0x80, 0x01,             // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0C, // Total length = 12
            0x00, 0x00, 0x01, 0x44, // TPM_CC_STARTUP
            su_bytes[0], su_bytes[1],
        ];
        let mut resp = [0u8; 32];
        if self.hardware_present {
            let _ = self.execute_command(&cmd, &mut resp);
        }
        self.is_started = true;
        Ok(())
    }

    /// Extends a PCR in the SHA-256 bank:
    /// Sends `TPM2_PCR_Extend` over hardware bus if present, and updates CRTM event log.
    pub fn pcr_extend(&mut self, pcr_idx: usize, digest: &[u8; 32]) -> Result<[u8; 32], TpmError> {
        if pcr_idx >= kboot::PCR_COUNT {
            return Err(TpmError::PcrOutOfBounds);
        }

        if self.hardware_present {
            let mut cmd = [0u8; 46];
            cmd[0..2].copy_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
            cmd[2..6].copy_from_slice(&(46u32).to_be_bytes());
            cmd[6..10].copy_from_slice(&TPM_CC_PCR_EXTEND.to_be_bytes());
            cmd[10..14].copy_from_slice(&(pcr_idx as u32).to_be_bytes());
            cmd[14..46].copy_from_slice(digest);
            let mut resp = [0u8; 32];
            let _ = self.execute_command(&cmd, &mut resp);
        }

        let mut hasher = Sha256::new();
        hasher.update(&self.measurement_log[pcr_idx]);
        hasher.update(digest);
        let res = hasher.finalize();

        self.measurement_log[pcr_idx].copy_from_slice(&res);
        Ok(self.measurement_log[pcr_idx])
    }

    /// Reads the current 32-byte digest of a PCR.
    pub fn pcr_read(&self, pcr_idx: usize) -> Result<[u8; 32], TpmError> {
        if pcr_idx >= kboot::PCR_COUNT {
            return Err(TpmError::PcrOutOfBounds);
        }

        if self.hardware_present {
            let mut cmd = [0u8; 20];
            cmd[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
            cmd[2..6].copy_from_slice(&(20u32).to_be_bytes());
            cmd[6..10].copy_from_slice(&TPM_CC_PCR_READ.to_be_bytes());
            let mut resp = [0u8; 64];
            if let Ok(len) = self.execute_command(&cmd, &mut resp) {
                if len >= 42 {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&resp[len - 32..len]);
                    return Ok(out);
                }
            }
        }

        Ok(self.measurement_log[pcr_idx])
    }

    /// Resets a PCR log entry back to zero.
    pub fn pcr_reset(&mut self, pcr_idx: usize) -> Result<(), TpmError> {
        if pcr_idx >= kboot::PCR_COUNT {
            return Err(TpmError::PcrOutOfBounds);
        }
        self.measurement_log[pcr_idx] = [0u8; 32];
        Ok(())
    }

    /// Computes composite policy digest across selected PCRs.
    pub fn compute_policy_digest(&self, pcr_mask: u32) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for i in 0..kboot::PCR_COUNT {
            if (pcr_mask & (1 << i)) != 0 {
                hasher.update(&self.measurement_log[i]);
            }
        }
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }

    /// Seals a secret to a specific PCR policy mask.
    pub fn seal(&mut self, pcr_mask: u32, secret: &[u8]) -> Result<u32, TpmError> {
        if secret.len() > 64 {
            return Err(TpmError::InvalidParameter);
        }

        let policy_digest = self.compute_policy_digest(pcr_mask);
        let handle = self.next_handle;

        let slot = self.sealed_items.iter_mut().find(|s| s.is_none());
        let slot_ref = match slot {
            Some(s) => s,
            None => return Err(TpmError::CapacityExceeded),
        };

        self.next_handle += 1;

        let mut data = [0u8; 64];
        data[..secret.len()].copy_from_slice(secret);

        *slot_ref = Some(SealedItem {
            handle,
            pcr_mask,
            policy_digest,
            data,
            data_len: secret.len(),
        });

        Ok(handle)
    }

    /// Unseals a secret bound to a PCR policy.
    /// Fails closed with `TpmError::PolicyMismatch` if any measured PCR has changed!
    pub fn unseal(&self, handle: u32, out_buffer: &mut [u8]) -> Result<usize, TpmError> {
        let item = self.sealed_items
            .iter()
            .filter_map(|s| *s)
            .find(|s| s.handle == handle)
            .ok_or(TpmError::InvalidParameter)?;

        if out_buffer.len() < item.data_len {
            return Err(TpmError::BufferTooSmall);
        }

        let live_policy = self.compute_policy_digest(item.pcr_mask);

        if !kboot::verify_measured_boot_hash(&live_policy, &item.policy_digest) {
            crate::kprintln!("[tpm2-fail-closed] Tamper detected! Live PCR policy does not match sealed credential.");
            return Err(TpmError::PolicyMismatch);
        }

        out_buffer[..item.data_len].copy_from_slice(&item.data[..item.data_len]);
        Ok(item.data_len)
    }

    /// Records a structured event into the TCG Event Log.
    pub fn log_event(&mut self, pcr_index: u32, event_type: u32, digest: [u8; 32], desc: &[u8]) {
        if self.event_count < self.event_log.len() {
            self.event_log[self.event_count] = kboot::TcgEventLogEntry::new(pcr_index, event_type, digest, desc);
            self.event_count += 1;
        }
    }

    /// Measures an arbitrary boot stage payload and extends the corresponding PCR, logging into the TCG Event Log.
    pub fn measure_boot_stage(&mut self, pcr_idx: usize, stage_data: &[u8]) -> Result<[u8; 32], TpmError> {
        let digest = kboot::compute_sha256(stage_data);
        let desc: &[u8] = match pcr_idx {
            kboot::PCR_CRTM_FIRMWARE => b"CRTM Platform Firmware",
            kboot::PCR_HARDWARE_CONFIG => b"Hardware Config / ACPI Tables",
            kboot::PCR_BOOTLOADER => b"kboot Bootloader Executable",
            kboot::PCR_BOOT_OPTIONS => b"Bootloader Parameter Options",
            kboot::PCR_KERNEL_CODE => b"KashOS Microkernel Code",
            kboot::PCR_IPL_PARTITION => b"IPL Partition Metadata",
            kboot::PCR_STATE_TRANSITION => b"Platform State Transitions",
            kboot::PCR_SECURE_BOOT_POLICY => b"Secure Boot Policy / DB State",
            kboot::PCR_COMMAND_LINE => b"Kernel Command Line Args",
            kboot::PCR_MANIFEST_INITRD => b"Initrd / Manifest Payload",
            _ => b"Platform Measured Stage",
        };
        self.log_event(pcr_idx as u32, kboot::EV_S_CRTM_CONTENTS, digest, desc);
        self.pcr_extend(pcr_idx, &digest)
    }

    /// Verifies candidate epoch against monotonic anti-rollback counter.
    pub fn check_anti_rollback(&self, candidate_epoch: u64) -> Result<(), kboot::RollbackError> {
        kboot::verify_anti_rollback(self.monotonic_counter, candidate_epoch)
    }

    /// Ratifies a new monotonic anti-rollback security epoch.
    pub fn ratify_anti_rollback(&mut self, new_epoch: u64) -> Result<(), kboot::RollbackError> {
        self.check_anti_rollback(new_epoch)?;
        if self.hardware_present {
            let cmd = [
                0x80, 0x02,
                0x00, 0x00, 0x00, 0x1E,
                0x00, 0x00, 0x01, 0x36,
                (kboot::TPM2_NV_INDEX_ANTI_ROLLBACK >> 24) as u8,
                (kboot::TPM2_NV_INDEX_ANTI_ROLLBACK >> 16) as u8,
                (kboot::TPM2_NV_INDEX_ANTI_ROLLBACK >> 8) as u8,
                kboot::TPM2_NV_INDEX_ANTI_ROLLBACK as u8,
            ];
            let mut resp = [0u8; 32];
            let _ = self.execute_command(&cmd, &mut resp);
        }
        self.monotonic_counter = new_epoch;
        Ok(())
    }

    /// Queries physical random bytes from the hardware TPM 2.0 TRNG.
    pub fn tpm2_get_random(&self, num_bytes: u16, out: &mut [u8]) -> Result<usize, TpmError> {
        if !self.hardware_present {
            return Err(TpmError::NotPresent);
        }
        let num_b = num_bytes.to_be_bytes();
        let cmd = [
            0x80, 0x01,             // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x0C, // length = 12
            0x00, 0x00, 0x01, 0x7B, // TPM_CC_GET_RANDOM
            num_b[0], num_b[1],
        ];
        let mut resp = [0u8; 128];
        let len = self.execute_command(&cmd, &mut resp)?;
        if len > 14 {
            let data_len = (len - 14).min(out.len());
            out[..data_len].copy_from_slice(&resp[14..14 + data_len]);
            Ok(data_len)
        } else {
            Err(TpmError::InvalidParameter)
        }
    }
}

static TPM_DEVICE: TicketSpinLock<Tpm2Device> = TicketSpinLock::new(Tpm2Device::new());

/// Initialize the TPM 2.0 subsystem.
pub fn init() -> bool {
    let mut dev = TPM_DEVICE.lock();
    let found = dev.probe();
    if found {
        crate::status::update(|s| s.tpm2_crtm = crate::status::ComponentStatus::Real);
    } else {
        crate::status::update(|s| s.tpm2_crtm = crate::status::ComponentStatus::NotAvailable);
    }
    found
}

/// Extends a PCR.
pub fn pcr_extend(pcr_idx: usize, digest: &[u8; 32]) -> Result<[u8; 32], TpmError> {
    let _ = (pcr_idx, digest);
    Err(TpmError::NotPresent)
}

/// Reads a PCR.
pub fn pcr_read(pcr_idx: usize) -> Result<[u8; 32], TpmError> {
    let _ = pcr_idx;
    Err(TpmError::NotPresent)
}

/// Resets a PCR.
pub fn pcr_reset(pcr_idx: usize) -> Result<(), TpmError> {
    let _ = pcr_idx;
    Err(TpmError::NotPresent)
}

/// Seals a secret to a set of PCRs.
pub fn seal_key(pcr_mask: u32, secret: &[u8]) -> Result<u32, TpmError> {
    let _ = (pcr_mask, secret);
    Err(TpmError::NotPresent)
}

/// Unseals a secret, failing closed on PCR mismatch.
pub fn unseal_key(handle: u32, out_buf: &mut [u8]) -> Result<usize, TpmError> {
    let _ = (handle, out_buf);
    Err(TpmError::NotPresent)
}

/// Measures arbitrary stage data into a PCR.
pub fn measure_stage(pcr_idx: usize, data: &[u8]) -> Result<[u8; 32], TpmError> {
    let _ = (pcr_idx, data);
    Err(TpmError::NotPresent)
}

/// Returns a human-readable status string for the TPM 2.0 device.
pub fn get_tpm_status() -> &'static str {
    "NOT AVAILABLE (TPM transport disabled; software model is test-only)"
}

/// Verifies and commits an anti-rollback epoch update.
pub fn verify_and_ratify_epoch(candidate: u64) -> Result<(), kboot::RollbackError> {
    let _ = candidate;
    Err(kboot::RollbackError::NvStorageError)
}

/// Prints live Platform Configuration Register (PCR) values.
pub fn print_pcr_report() {
    crate::kprintln!("[tpm2] PCR report unavailable: hardware transport is disabled.");
    crate::kprintln!("[tpm2] Self-test PCR values are software-model state and are not boot measurements.");
}

/// Dumps all recorded TCG event log entries.
pub fn print_tcg_event_log() {
    crate::kprintln!("[tpm2] TCG event log unavailable: no hardware measurements are collected.");
}

/// Prints anti-rollback status.
pub fn print_anti_rollback_status() {
    crate::kprintln!("[tpm2] TPM-backed anti-rollback is unavailable: NV counter transport is not implemented.");
}
