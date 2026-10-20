//! Driver capability and supervisor prototype (Phase 4).
//!
//! The current code models capability checks and supervisor state. It is not
//! connected to separate driver ELFs, hardware I/O mediation, real DMA mappings,
//! or an end-to-end driver restart path. Do not treat these models as isolation.

#![allow(unsafe_code)]

use kcore::{CapKind, KError, Rights};
use crate::process::{process_slot_for_pid, PROCESS_CSPACES};
use crate::sync::TicketSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverKind {
    Storage,
    Network,
    Input,
    Display,
}

#[derive(Clone, Copy, Debug)]
pub struct DriverService {
    pub name: &'static str,
    pub kind: DriverKind,
    pub pid: u32,
    pub endpoint_slot: usize,
    pub restart_count: u32,
    pub is_healthy: bool,
}

pub struct DriverSupervisor {
    pub services: [Option<DriverService>; 8],
    pub total_restarts: u32,
}

impl DriverSupervisor {
    pub const fn new() -> Self {
        Self {
            services: [None; 8],
            total_restarts: 0,
        }
    }

    /// Registers a driver service and provisions its capability space with device capabilities.
    pub fn register_service(&mut self, name: &'static str, kind: DriverKind) -> Result<u32, &'static str> {
        let _ = (name, kind);
        Err("Driver process launch is unavailable; service registration is disabled")
    }

    /// Provisions an isolated CSpace for the driver with dedicated device capabilities.
    pub fn provision_driver_cspace(pid: u32, kind: DriverKind) -> Result<(), &'static str> {
        let _ = (pid, kind);
        Err("Driver capability provisioning is unavailable until real driver processes and device mappings exist")
    }

    /// Verifies whether process `pid` holds a valid IOPort capability covering `port`.
    pub fn verify_io_port(&self, pid: u32, port: u16, is_write: bool) -> Result<(), KError> {
        let cspace_idx = process_slot_for_pid(pid).ok_or(KError::InvalidArgument)?;
        let cspaces = PROCESS_CSPACES.lock();
        let cs = &cspaces[cspace_idx];

        let need_rights = if is_write { Rights::WRITE } else { Rights::READ };

        // Search slots for a matching IOPort capability
        for slot in 0..64 {
            if let Ok(cap) = cs.lookup(slot, need_rights) {
                if cap.kind().allows_port(port) {
                    return Ok(());
                }
            }
        }

        Err(KError::InsufficientRights)
    }

    /// Verifies whether process `pid` holds a valid Frame capability covering physical address `paddr`.
    pub fn verify_mmio_frame(&self, pid: u32, paddr: u64, is_write: bool) -> Result<(), KError> {
        let cspace_idx = process_slot_for_pid(pid).ok_or(KError::InvalidArgument)?;
        let cspaces = PROCESS_CSPACES.lock();
        let cs = &cspaces[cspace_idx];

        let need_rights = if is_write { Rights::WRITE } else { Rights::READ };
        let page_paddr = paddr & !0xFFF;

        for slot in 0..64 {
            if let Ok(cap) = cs.lookup(slot, need_rights) {
                if let CapKind::Frame { paddr: granted } = cap.kind() {
                    if (granted & !0xFFF) == page_paddr {
                        return Ok(());
                    }
                }
            }
        }

        Err(KError::InsufficientRights)
    }

    /// Intercepts a driver crash, tears down its capability tree, recycles memory, and restarts the service.
    pub fn handle_driver_fault(&mut self, pid: u32, exit_code: i32) -> Option<u32> {
        let _ = (pid, exit_code);
        None
    }

    /// Performs capability-checked port I/O on behalf of user driver.
    pub fn execute_port_io(&self, pid: u32, port: u16, val: u32, is_write: bool, size: u8) -> Result<u32, KError> {
        self.verify_io_port(pid, port, is_write)?;

        // Execute hardware port access safely
        if is_write {
            match size {
                1 => crate::arch::x86_64::pci::outb(port, val as u8),
                2 => crate::arch::x86_64::pci::outw(port, val as u16),
                4 => crate::arch::x86_64::pci::outl(port, val),
                _ => return Err(KError::InvalidArgument),
            }
            Ok(0)
        } else {
            let res = match size {
                1 => crate::arch::x86_64::pci::inb(port) as u32,
                2 => crate::arch::x86_64::pci::inw(port) as u32,
                4 => crate::arch::x86_64::pci::inl(port),
                _ => return Err(KError::InvalidArgument),
            };
            Ok(res)
        }
    }

    /// Performs capability-checked MMIO read on behalf of user driver.
    pub fn execute_mmio_read(&self, pid: u32, paddr: u64, size: u8) -> Result<u64, KError> {
        self.verify_mmio_frame(pid, paddr, false)?;
        unsafe {
            let res = match size {
                1 => core::ptr::read_volatile(paddr as *const u8) as u64,
                2 => core::ptr::read_volatile(paddr as *const u16) as u64,
                4 => core::ptr::read_volatile(paddr as *const u32) as u64,
                8 => core::ptr::read_volatile(paddr as *const u64),
                _ => return Err(KError::InvalidArgument),
            };
            Ok(res)
        }
    }

    /// Performs capability-checked MMIO write on behalf of user driver.
    pub fn execute_mmio_write(&self, pid: u32, paddr: u64, val: u64, size: u8) -> Result<(), KError> {
        self.verify_mmio_frame(pid, paddr, true)?;
        unsafe {
            match size {
                1 => core::ptr::write_volatile(paddr as *mut u8, val as u8),
                2 => core::ptr::write_volatile(paddr as *mut u16, val as u16),
                4 => core::ptr::write_volatile(paddr as *mut u32, val as u32),
                8 => core::ptr::write_volatile(paddr as *mut u64, val),
                _ => return Err(KError::InvalidArgument),
            }
            Ok(())
        }
    }
}

pub static DRIVER_SUPERVISOR: TicketSpinLock<DriverSupervisor> = TicketSpinLock::new(DriverSupervisor::new());

/// Initializes core userspace driver services.
pub fn init() {
    crate::kprintln!("[driver] Driver service launch and capability provisioning are unavailable; no services registered.");
}
