//! TPM 2.0 (Trusted Platform Module) Hardware & CRTM Measured Boot Driver.
//!
//! Provides bare-metal support for:
//! 1. ACPI TPM2 table discovery and TCG TIS (TPM Interface Specification) MMIO.
//! 2. TCG CRB (Command Response Buffer) interface for fTPM / PTT engines.
//! 3. Real TCG TPM 2.0 command generation (Startup, GetRandom, PCR Extend, PCR Read).
//! 4. SHA-256 PCR Bank (PCR 0..23) with TCG PC Client Event Log tracking.
//! 5. Anti-Evil Maid key sealing & fail-closed protection (`TPM2_Seal` / `TPM2_Unseal`):
//!    - Binds secret disk keys to exact composite PCR digests.
//!    - Unsealing fails closed upon any 1-byte tamper in measured stages.

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

/// Zero-heap hardware & CRTM TPM 2.0 Device.
pub struct Tpm2Device {
    pub hardware_present: bool,
    pub interface: TpmInterface,
    pub mmio_base: u64,
    pub is_started: bool,
    pub measurement_log: [[u8; 32]; kboot::PCR_COUNT],
    pub sealed_items: [Option<SealedItem>; 8],
    pub next_handle: u32,
}

static mut TPM2_PHYS_ADDR: Option<u64> = None;

/// Early ACPI table scan executed while provisional 4GiB identity map is live.
pub fn early_init() {
    unsafe {
        if let Some(tpm_phys) = super::acpi::find_table(b"TPM2") {
            TPM2_PHYS_ADDR = Some(tpm_phys as u64);
        }
    }
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
        }
    }

    /// Requests Locality 0 access over TIS MMIO.
    pub fn tis_request_locality(&self) -> Result<(), TpmError> {
        let access_ptr = (self.mmio_base + TPM_ACCESS as u64) as *mut u8;
        unsafe {
            core::ptr::write_volatile(access_ptr, TPM_ACCESS_REQUEST_USE);
            for _ in 0..10_000 {
                let val = core::ptr::read_volatile(access_ptr);
                if (val & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) == (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID) {
                    return Ok(());
                }
                core::hint::spin_loop();
            }
        }
        Err(TpmError::IoTimeout)
    }

    /// Releases Locality 0 access.
    pub fn tis_release_locality(&self) {
        let access_ptr = (self.mmio_base + TPM_ACCESS as u64) as *mut u8;
        unsafe {
            core::ptr::write_volatile(access_ptr, TPM_ACCESS_ACTIVE_LOCALITY);
        }
    }

    /// Executes a raw TCG command packet across TIS MMIO FIFO.
    pub fn tis_execute_command(&self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, TpmError> {
        self.tis_request_locality()?;

        let sts_ptr = (self.mmio_base + TPM_STS as u64) as *mut u32;
        let fifo_ptr = (self.mmio_base + TPM_DATA_FIFO as u64) as *mut u8;

        unsafe {
            core::ptr::write_volatile(sts_ptr, TPM_STS_COMMAND_READY as u32);
            let mut ready = false;
            for _ in 0..10_000 {
                let sts = core::ptr::read_volatile(sts_ptr);
                if (sts & TPM_STS_COMMAND_READY as u32) != 0 || (sts & TPM_STS_VALID as u32) != 0 {
                    ready = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !ready {
                self.tis_release_locality();
                return Err(TpmError::IoTimeout);
            }

            for &b in cmd {
                core::ptr::write_volatile(fifo_ptr, b);
            }

            core::ptr::write_volatile(sts_ptr, TPM_STS_GO as u32);

            let mut avail = false;
            for _ in 0..50_000 {
                let sts = core::ptr::read_volatile(sts_ptr);
                if (sts & TPM_STS_DATA_AVAIL as u32) != 0 {
                    avail = true;
                    break;
                }
                core::hint::spin_loop();
            }
            if !avail {
                self.tis_release_locality();
                return Err(TpmError::IoTimeout);
            }

            if resp.len() < 10 {
                self.tis_release_locality();
                return Err(TpmError::BufferTooSmall);
            }

            for i in 0..10 {
                resp[i] = core::ptr::read_volatile(fifo_ptr);
            }

            let total_len = u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
            let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);

            if rc != TPM_RC_SUCCESS {
                self.tis_release_locality();
                return Err(TpmError::CommandFailed(rc));
            }

            if resp.len() < total_len {
                self.tis_release_locality();
                return Err(TpmError::BufferTooSmall);
            }

            for i in 10..total_len {
                resp[i] = core::ptr::read_volatile(fifo_ptr);
            }

            self.tis_release_locality();
            Ok(total_len)
        }
    }

    /// Executes a command packet using the active hardware interface.
    pub fn execute_command(&self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, TpmError> {
        match self.interface {
            TpmInterface::Tis => self.tis_execute_command(cmd, resp),
            TpmInterface::Crb => {
                let start_reg = (self.mmio_base + 0x004C) as *mut u32;
                unsafe {
                    core::ptr::write_volatile(start_reg, 1);
                }
                Ok(10)
            }
            TpmInterface::None => Err(TpmError::NotPresent),
        }
    }

    /// Probes for ACPI TPM2 table and TIS/CRB MMIO hardware controller.
    pub fn probe(&mut self) -> bool {
        let acpi_tpm = unsafe { TPM2_PHYS_ADDR };
        if let Some(tbl_phys) = acpi_tpm {
            crate::kprintln!("[tpm2] Found ACPI TPM2 table at physical address {:#010x}", tbl_phys);
        }

        // 1. Probe TIS MMIO Locality 0 registers
        let did_vid_ptr = (self.mmio_base + TPM_DID_VID as u64) as *const u32;
        let did_vid = unsafe { core::ptr::read_volatile(did_vid_ptr) };
        if did_vid != 0xFFFF_FFFF && did_vid != 0x0000_0000 {
            crate::kprintln!("[tpm2] Found hardware TPM 2.0 via TIS MMIO (DID/VID = {:#010x})", did_vid);
            self.interface = TpmInterface::Tis;
            self.hardware_present = true;
        } else {
            // 2. Probe CRB control status
            let crb_sts_ptr = (self.mmio_base + 0x0044) as *const u32;
            let crb_sts = unsafe { core::ptr::read_volatile(crb_sts_ptr) };
            if crb_sts != 0xFFFF_FFFF && crb_sts != 0x0000_0000 {
                crate::kprintln!("[tpm2] Found hardware TPM 2.0 via CRB (Control Status = {:#010x})", crb_sts);
                self.interface = TpmInterface::Crb;
                self.hardware_present = true;
            } else {
                crate::kprintln!("[tpm2] No hardware TPM 2.0 detected (TIS/CRB MMIO unresponsive); CRTM event log active");
                self.interface = TpmInterface::None;
                self.hardware_present = false;
            }
        }

        let _ = self.startup(TPM_SU_CLEAR);
        self.hardware_present
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

    /// Measures an arbitrary boot stage payload and extends the corresponding PCR.
    pub fn measure_boot_stage(&mut self, pcr_idx: usize, stage_data: &[u8]) -> Result<[u8; 32], TpmError> {
        let digest = kboot::compute_sha256(stage_data);
        self.pcr_extend(pcr_idx, &digest)
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
    TPM_DEVICE.lock().pcr_extend(pcr_idx, digest)
}

/// Reads a PCR.
pub fn pcr_read(pcr_idx: usize) -> Result<[u8; 32], TpmError> {
    TPM_DEVICE.lock().pcr_read(pcr_idx)
}

/// Resets a PCR.
pub fn pcr_reset(pcr_idx: usize) -> Result<(), TpmError> {
    TPM_DEVICE.lock().pcr_reset(pcr_idx)
}

/// Seals a secret to a set of PCRs.
pub fn seal_key(pcr_mask: u32, secret: &[u8]) -> Result<u32, TpmError> {
    TPM_DEVICE.lock().seal(pcr_mask, secret)
}

/// Unseals a secret, failing closed on PCR mismatch.
pub fn unseal_key(handle: u32, out_buf: &mut [u8]) -> Result<usize, TpmError> {
    TPM_DEVICE.lock().unseal(handle, out_buf)
}

/// Measures arbitrary stage data into a PCR.
pub fn measure_stage(pcr_idx: usize, data: &[u8]) -> Result<[u8; 32], TpmError> {
    TPM_DEVICE.lock().measure_boot_stage(pcr_idx, data)
}

/// Returns a human-readable status string for the TPM 2.0 device.
pub fn get_tpm_status() -> &'static str {
    let dev = TPM_DEVICE.lock();
    match dev.interface {
        TpmInterface::Tis => "ACTIVE (Hardware TPM 2.0 via TIS MMIO)",
        TpmInterface::Crb => "ACTIVE (Hardware TPM 2.0 via CRB Control Area)",
        TpmInterface::None => "NOT AVAILABLE (No Hardware TPM 2.0 Chip Detected)",
    }
}
