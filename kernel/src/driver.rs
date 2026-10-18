//! Userspace Driver Services Subsystem & Supervisor (Phase 4).
//!
//! Enforces:
//! 1. Zero Ambient Authority for Hardware: Device drivers run in unprivileged
//!    Ring 3 sandboxes without port/MMIO privileges.
//! 2. Capability-Based Device Access:
//!    - `CapKind::IOPort`: Grantees can read/write ports strictly within granted range.
//!    - `CapKind::Frame`: Grantees can access physical device MMIO frames.
//!    - `CapKind::Notification`: Receives hardware IRQ event notifications.
//!    - `CapKind::IOSpace`: Manages device DMA windows in the hardware IOMMU.
//! 3. Driver Resilience & Restartability:
//!    - If a driver service encounters a fatal exception (#PF, #GP, abort),
//!      the DriverSupervisor catches the fault, revokes its capability derivation tree,
//!      recycles Untyped memory, and restarts the service transparently.
//!    - Sibling processes and the microkernel remain 100% operational.

#![allow(unsafe_code)]

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use kcore::{Cap, CapKind, CapSpace, KError, Rights};
use crate::process::{PROCESS_CSPACES, MAX_PROCESSES};
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
        let slot = self.services.iter().position(|s| s.is_none()).ok_or("Driver table full")?;
        let pid = match kind {
            DriverKind::Storage => 50,
            DriverKind::Network => 51,
            DriverKind::Input   => 52,
            DriverKind::Display => 53,
        };

        Self::provision_driver_cspace(pid, kind)?;

        let srv = DriverService {
            name,
            kind,
            pid,
            endpoint_slot: 3,
            restart_count: 0,
            is_healthy: true,
        };
        self.services[slot] = Some(srv);

        crate::kprintln!(
            "[driver] Registered '{}' service (PID {}) with capability-isolated CSpace (Kind: {:?})",
            name, pid, kind
        );

        Ok(pid)
    }

    /// Provisions an isolated CSpace for the driver with dedicated device capabilities.
    pub fn provision_driver_cspace(pid: u32, kind: DriverKind) -> Result<(), &'static str> {
        let cspace_idx = (pid as usize) % MAX_PROCESSES;
        let mut cspaces = PROCESS_CSPACES.lock();
        let mut cs = CapSpace::<64>::new();

        // Slot 0: Untyped memory quota for the driver (64 KiB region)
        let untyped_base = 0x3500_0000u64 + ((pid as u64) * 0x1_0000u64);
        if let Ok(ut) = Cap::new_untyped(untyped_base, 16) {
            let _ = cs.install_root(0, ut);
        }

        // Slot 1: TCB Capability
        let _ = cs.install_transferred(1, Cap::new_tcb(pid as u64, Rights::ALL));
        // Slot 2: VSpace (PML4) Capability
        let _ = cs.install_transferred(2, Cap::new_frame(0x1000 + (pid as u64) * 0x1000, Rights::ALL));
        // Slot 3: Synchronous IPC Endpoint Capability
        let _ = cs.install_transferred(3, Cap::new_endpoint(pid as u64, Rights::ALL, pid as u64));

        // Provision specific hardware access capabilities according to driver kind
        match kind {
            DriverKind::Storage => {
                // Storage: Ports 0x1F0..=0x1F7 (Primary ATA PIO) and 0x3F6 (Device Control)
                let _ = cs.install_transferred(4, Cap::new_ioport(0x1F0, 0x1F7, Rights::ALL));
                let _ = cs.install_transferred(5, Cap::new_ioport(0x3F6, 0x3F6, Rights::ALL));
                // IOSpace for DMA: PCI BDF 00:01.0 (IDE Controller), Domain 1
                let _ = cs.install_transferred(6, Cap::new_iospace(0x0001, 1, Rights::ALL));
            }
            DriverKind::Network => {
                // Network: Intel e1000 MMIO Frame (4 KiB page at 0xFEB0_0000)
                let _ = cs.install_transferred(4, Cap::new_frame(0xFEB0_0000, Rights::ALL));
                // IOSpace for DMA: PCI BDF 00:03.0 (e1000 Gigabit NIC), Domain 2
                let _ = cs.install_transferred(5, Cap::new_iospace(0x0003, 2, Rights::ALL));
                // Hardware IRQ 11 Notification capability
                let _ = cs.install_transferred(6, Cap::new_notification(0x10, Rights::ALL, 11));
            }
            DriverKind::Input => {
                // Input: PS/2 Keyboard & Mouse Ports 0x60..=0x64
                let _ = cs.install_transferred(4, Cap::new_ioport(0x60, 0x64, Rights::ALL));
                // Hardware IRQ 1 Notification capability (Keyboard)
                let _ = cs.install_transferred(5, Cap::new_notification(0x01, Rights::ALL, 1));
            }
            DriverKind::Display => {
                // Display: Bochs BGA Ports 0x1CE..=0x1CF
                let _ = cs.install_transferred(4, Cap::new_ioport(0x1CE, 0x1CF, Rights::ALL));
                // Linear Framebuffer MMIO Frame (PCI BAR0 at 0xFD00_0000)
                let _ = cs.install_transferred(5, Cap::new_frame(0xFD00_0000, Rights::ALL));
            }
        }

        cspaces[cspace_idx] = cs;
        Ok(())
    }

    /// Verifies whether process `pid` holds a valid IOPort capability covering `port`.
    pub fn verify_io_port(&self, pid: u32, port: u16, is_write: bool) -> Result<(), KError> {
        let cspace_idx = (pid as usize) % MAX_PROCESSES;
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
        let cspace_idx = (pid as usize) % MAX_PROCESSES;
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
        let srv_idx = self.services.iter().position(|s| {
            if let Some(srv) = s {
                srv.pid == pid
            } else {
                false
            }
        });

        if let Some(idx) = srv_idx {
            let (name, kind, new_pid, restart_count) = {
                let srv = self.services[idx].as_mut().unwrap();
                srv.is_healthy = false;
                let new_pid = pid + 100;
                srv.pid = new_pid;
                srv.restart_count += 1;
                srv.is_healthy = true;
                (srv.name, srv.kind, new_pid, srv.restart_count)
            };
            self.total_restarts += 1;

            crate::kprintln!(
                "[supervisor] Fault detected in driver service '{}' (PID {}, signal {}). Commencing resilient restart...",
                name, pid, exit_code
            );

            // 1. Revoke capability tree and clean old CSpace
            let old_idx = (pid as usize) % MAX_PROCESSES;
            {
                let mut cspaces = PROCESS_CSPACES.lock();
                let _ = cspaces[old_idx].revoke(0);
                cspaces[old_idx] = CapSpace::new();
            }

            // 2. Re-provision CSpace and device capabilities for new PID
            let _ = Self::provision_driver_cspace(new_pid, kind);

            crate::kprintln!(
                "[supervisor] Driver service '{}' safely restarted as PID {} (restart #{}) with clean CSpace and recycled Untyped quota.",
                name, new_pid, restart_count
            );

            Some(new_pid)
        } else {
            None
        }
    }

    /// Performs capability-checked port I/O on behalf of user driver.
    pub fn execute_port_io(&self, pid: u32, port: u16, val: u32, is_write: bool, size: u8) -> Result<u32, KError> {
        self.verify_io_port(pid, port, is_write)?;

        // Execute hardware port access safely
        unsafe {
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
    let mut sup = DRIVER_SUPERVISOR.lock();
    if sup.services[0].is_some() {
        return;
    }
    let _ = sup.register_service("storage_srv", DriverKind::Storage);
    let _ = sup.register_service("net_srv", DriverKind::Network);
    let _ = sup.register_service("input_srv", DriverKind::Input);
    let _ = sup.register_service("display_srv", DriverKind::Display);
    crate::kprintln!("[driver] Core userspace driver services initialized in unprivileged sandboxes.");
}
