//! Intel VT-d (Virtualization Technology for Directed I/O) & PCIe ACS Subsystem.
//!
//! Provides ACPI DMAR discovery and an in-memory VT-d policy model.
//! Hardware translation and PCIe ACS verification are unavailable; activation
//! remains disabled until hardware-visible tables, mappings, and invalidation
//! are implemented and tested.

#![allow(unsafe_code)]

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use khal::{IommuController, PciBdf, PcieAcsFlags};
pub use khal::vtd::*;

// ── VT-d Register Offsets ───────────────────────────────────────────────────

pub const VTD_REG_VERSION: usize      = 0x00; // 32-bit: Architecture version
pub const VTD_REG_CAP: usize          = 0x08; // 64-bit: Capability register
pub const VTD_REG_EXT_CAP: usize      = 0x10; // 64-bit: Extended capability register
pub const VTD_REG_GCMD: usize         = 0x18; // 32-bit: Global command register
pub const VTD_REG_GSTS: usize         = 0x1C; // 32-bit: Global status register
pub const VTD_REG_RTADDR: usize       = 0x20; // 64-bit: Root table address register
pub const VTD_REG_CCMD: usize         = 0x28; // 64-bit: Context command register
pub const VTD_REG_FSTS: usize         = 0x34; // 32-bit: Fault status register
pub const VTD_REG_FECTL: usize        = 0x38; // 32-bit: Fault event control register
pub const VTD_REG_FEDATA: usize       = 0x3C; // 32-bit: Fault event data register
pub const VTD_REG_FEADDR: usize       = 0x40; // 32-bit: Fault event address register
pub const VTD_REG_FEUADDR: usize      = 0x44; // 32-bit: Fault event upper address register
pub const VTD_REG_IQH: usize          = 0x80; // 64-bit: Invalidation queue head register
pub const VTD_REG_IQT: usize          = 0x88; // 64-bit: Invalidation queue tail register
pub const VTD_REG_IQA: usize          = 0x90; // 64-bit: Invalidation queue address register

// Global Command & Status bits
pub const VTD_GCMD_TE: u32            = 1 << 31; // Translation Enable
pub const VTD_GCMD_SRTP: u32          = 1 << 30; // Set Root Table Pointer
pub const VTD_GSTS_TES: u32           = 1 << 31; // Translation Enable Status
pub const VTD_GSTS_RTPS: u32          = 1 << 30; // Root Table Pointer Status

// ── PCIe Access Control Services (ACS) Verifier ─────────────────────────────

pub struct PcieAcsVerifier;

impl PcieAcsVerifier {
    /// ACS is unavailable until ECAM access and ACS extended-capability parsing exist.
    pub fn probe_acs(bdf: PciBdf) -> (bool, PcieAcsFlags) {
        let _ = bdf;
        (
            false,
            PcieAcsFlags {
                source_validation: false,
                translation_blocking: false,
                p2p_request_redirect: false,
                p2p_completion_redirect: false,
                upstream_forwarding: false,
                p2p_egress_control: false,
                direct_translated_p2p: false,
            },
        )
    }
}

use crate::sync::TicketSpinLock;
use core::sync::atomic::{AtomicU32, Ordering};
// ── Intel VT-d Hardware Unit Controller ─────────────────────────────────────

pub struct IntelVtdUnit {
    pub mmio_base: u64,
    pub version: u32,
    is_enabled: bool,
    pub root_table: [VtdRootEntry; 256],
    pub active_domains: u16,
    pub fault_count: AtomicU32,
    pub fault_status: AtomicU32,
    pub last_fault: TicketSpinLock<Option<VtdFaultRecord>>,
    pub slpt: TicketSpinLock<SlptPageTable>,
}

impl IntelVtdUnit {
    pub fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            version: 0x10, // VT-d Architecture 1.0+
            is_enabled: false,
            root_table: [VtdRootEntry { lower: 0, upper: 0 }; 256],
            active_domains: 0,
            fault_count: AtomicU32::new(0),
            fault_status: AtomicU32::new(0),
            last_fault: TicketSpinLock::new(None),
            slpt: TicketSpinLock::new(SlptPageTable::new()),
        }
    }

    /// Attempt hardware activation. Currently returns unavailable before MMIO access.
    pub fn init_hardware(&mut self) -> Result<(), &'static str> {
        self.is_enabled = false;
        Err("VT-d activation is disabled until physical DMA tables, MMIO mapping, invalidation, and device context programming are verified")
    }

    /// Bind a device in the in-memory policy model only; this is not hardware isolation.
    pub fn isolate_device(&mut self, bdf: PciBdf, domain_id: u16) {
        let bus_idx = bdf.bus as usize;
        let context_base = (self.root_table.as_ptr() as usize as u64).wrapping_add(0x1000 * (bus_idx as u64 + 1));
        self.root_table[bus_idx].set_context_table(context_base);
        self.active_domains = self.active_domains.max(domain_id);
        self.slpt.lock().bind_device(bdf, domain_id);
    }

    /// Map a DMA range only after a future verified hardware initialization.
    pub fn map_device_dma(
        &self,
        bdf: PciBdf,
        domain_id: u16,
        guest_phys: u64,
        host_phys: u64,
        size: usize,
        read: bool,
        write: bool,
    ) -> Result<(), ()> {
        if !self.is_enabled {
            return Err(());
        }
        self.slpt
            .lock()
            .map_dma(bdf, domain_id, guest_phys, host_phys, size, read, write)
            .map_err(|_| ())
    }

    /// Unmap peripheral device DMA region.
    pub fn unmap_device_dma(&self, bdf: PciBdf, guest_phys: u64, size: usize) -> Result<(), ()> {
        if !self.is_enabled {
            return Err(());
        }
        self.slpt.lock().unmap_dma(bdf, guest_phys, size).map_err(|_| ())
    }

    /// Exercise the in-memory translation model. This does not observe or block hardware DMA.
    pub fn translate_dma(
        &self,
        bdf: PciBdf,
        domain_id: u16,
        guest_phys: u64,
        is_write: bool,
    ) -> Result<u64, VtdFaultReason> {
        match self.slpt.lock().translate_dma(bdf, domain_id, guest_phys, is_write) {
            Ok(translated) => Ok(translated),
            Err(reason) => {
                let record = VtdFaultRecord {
                    fault_addr: guest_phys,
                    bdf,
                    domain_id,
                    is_write,
                    reason,
                };
                self.fault_count.fetch_add(1, Ordering::Relaxed);
                self.fault_status.fetch_or(1 << 1, Ordering::Relaxed); // Primary Pending Fault (PPF)
                *self.last_fault.lock() = Some(record);
                crate::kprintln!(
                    "[iommu-model] rejected simulated DMA translation from PCI {:02x}:{:02x}.{} to {:#018x} (Domain {}, Reason: {:?})",
                    bdf.bus, bdf.dev, bdf.func, guest_phys, domain_id, reason
                );
                Err(reason)
            }
        }
    }

    pub fn last_fault(&self) -> Option<VtdFaultRecord> {
        *self.last_fault.lock()
    }

    pub fn fault_count(&self) -> u32 {
        self.fault_count.load(Ordering::Relaxed)
    }

    pub fn fault_status(&self) -> u32 {
        self.fault_status.load(Ordering::Relaxed)
    }
}

impl IommuController for IntelVtdUnit {
    fn enable_dma_remapping(&self) -> Result<(), ()> {
        Err(())
    }

    fn disable_dma_remapping(&self) {}

    fn check_pcie_acs(&self, bdf: PciBdf) -> bool {
        let _ = bdf;
        false
    }

    fn map_device_dma(
        &self,
        bdf: PciBdf,
        domain_id: u16,
        guest_phys: u64,
        host_phys: u64,
        size: usize,
        read: bool,
        write: bool,
    ) -> Result<(), ()> {
        if !self.is_enabled {
            return Err(());
        }
        self.map_device_dma(bdf, domain_id, guest_phys, host_phys, size, read, write)
    }

    fn unmap_device_dma(&self, bdf: PciBdf, guest_phys: u64, size: usize) -> Result<(), ()> {
        if !self.is_enabled {
            return Err(());
        }
        self.unmap_device_dma(bdf, guest_phys, size)
    }
}

// ── Global IOMMU State & Prober ─────────────────────────────────────────────

pub struct VtdSystemState {
    pub units: Vec<IntelVtdUnit>,
    pub dmar_found: bool,
    pub total_isolated_devices: usize,
}

static mut VTD_STATE: Option<VtdSystemState> = None;

/// ACPI DMAR discovery is disabled until firmware tables have a bounded mapper.
pub fn early_init() {
}

pub fn init() {
    unsafe {
        VTD_STATE = Some(VtdSystemState {
            units: Vec::new(),
            dmar_found: false,
            total_isolated_devices: 0,
        });
    }
    crate::status::update(|s| s.vtd_iommu = crate::status::ComponentStatus::Stub);
    crate::kprintln!("[iommu] VT-d unavailable: DMAR probing and translation are disabled pending bounded ACPI mapping, physical tables, MMIO mapping, invalidation, device contexts, and ACS verification");
}

pub fn get_iommu_status() -> (bool, usize, usize) {
    unsafe {
        if let Some(ref state) = VTD_STATE {
            (state.dmar_found, state.units.len(), state.total_isolated_devices)
        } else {
            (false, 0, 0)
        }
    }
}
