//! Symmetric Multiprocessing (SMP) and ACPI MADT Parser for x86-64.
//!
//! Features:
//! 1. Parses the ACPI MADT ("APIC") table to discover all hardware cores and APIC IDs.
//! 2. Maintains `PerCpuData` structures tracking per-core status, current PID, and stacks.
//! 3. Implements Inter-Processor Interrupts (IPIs) for TLB shootdown and multicore synchronization.
#![allow(unsafe_code)]

use crate::arch::x86_64::acpi;
use crate::arch::x86_64::apic;
use crate::kprintln;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_CPUS: usize = 64;
pub const TLB_SHOOTDOWN_VECTOR: u8 = 251;

#[derive(Clone, Copy, Debug)]
pub struct PerCpuData {
    pub cpu_id: usize,
    pub apic_id: u8,
    pub online: bool,
    pub current_pid: u32,
    pub kernel_stack_top: u64,
}

impl PerCpuData {
    pub const fn empty() -> Self {
        PerCpuData {
            cpu_id: 0,
            apic_id: 0,
            online: false,
            current_pid: 0,
            kernel_stack_top: 0,
        }
    }
}

pub static mut PER_CPU: [PerCpuData; MAX_CPUS] = [PerCpuData::empty(); MAX_CPUS];
static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// Returns the total number of hardware CPU cores discovered via ACPI MADT.
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

/// Discover CPU cores from ACPI MADT and initialize BSP PerCpuData.
pub fn init(bsp_apic_id: u8) -> usize {
    let mut detected_cpus = 0usize;

    if let Some(madt_phys) = acpi::find_table(b"APIC") {
        let len = unsafe { core::ptr::read_volatile((madt_phys + 4) as *const u32) } as usize;
        let mut offset = 44usize; // Entry array begins at offset 44 (after header + local APIC address + flags)

        while offset + 2 <= len {
            let entry_type = unsafe { core::ptr::read_volatile((madt_phys + offset) as *const u8) };
            let entry_len = unsafe { core::ptr::read_volatile((madt_phys + offset + 1) as *const u8) } as usize;

            if entry_len < 2 {
                break;
            }

            // Type 0: Processor Local APIC
            if entry_type == 0 && offset + 8 <= len {
                let apic_id = unsafe { core::ptr::read_volatile((madt_phys + offset + 3) as *const u8) };
                let flags = unsafe { core::ptr::read_volatile((madt_phys + offset + 4) as *const u32) };

                // Bit 0 = Enabled; Bit 1 = Online Capable
                if (flags & 0x01 != 0) || (flags & 0x02 != 0) {
                    if detected_cpus < MAX_CPUS {
                        let is_bsp = apic_id == bsp_apic_id;
                        unsafe {
                            PER_CPU[detected_cpus] = PerCpuData {
                                cpu_id: detected_cpus,
                                apic_id,
                                online: is_bsp,
                                current_pid: if is_bsp { 1 } else { 0 },
                                kernel_stack_top: 0,
                            };
                        }
                        detected_cpus += 1;
                    }
                }
            }

            offset += entry_len;
        }
    }

    if detected_cpus == 0 {
        // Fallback for systems without ACPI MADT: 1 core (BSP)
        unsafe {
            PER_CPU[0] = PerCpuData {
                cpu_id: 0,
                apic_id: bsp_apic_id,
                online: true,
                current_pid: 1,
                kernel_stack_top: 0,
            };
        }
        detected_cpus = 1;
    }

    CPU_COUNT.store(detected_cpus, Ordering::Release);
    kprintln!("[smp] ACPI MADT: {} CPU core(s) detected (BSP APIC ID {})", detected_cpus, bsp_apic_id);
    for i in 0..detected_cpus {
        unsafe {
            kprintln!("[smp]   Core #{}: APIC ID {} (online={})", i, PER_CPU[i].apic_id, PER_CPU[i].online);
        }
    }

    detected_cpus
}

/// Send a TLB shootdown Inter-Processor Interrupt (IPI) to all other online CPUs.
pub fn broadcast_tlb_shootdown() {
    apic::send_broadcast_ipi(TLB_SHOOTDOWN_VECTOR);
}

/// Handle incoming TLB shootdown IPI on the current CPU by flushing the TLB.
pub fn handle_tlb_shootdown() {
    unsafe {
        let mut cr3: u64;
        core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nostack));
        core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack));
    }
    apic::eoi();
}
