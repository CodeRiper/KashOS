//! Symmetric Multiprocessing (SMP) and ACPI MADT Parser for x86-64.
//!
//! Features:
//! 1. Parses the ACPI MADT ("APIC") table to discover all hardware cores and APIC IDs.
//! 2. Maintains `PerCpuData` structures tracking per-core status, current PID, and stacks.
//! 3. Implements standard INIT-SIPI-SIPI multi-core bootstrap protocol for Application Processors (APs).
//! 4. Sets up 16-bit to 64-bit trampoline page at physical 0x8000.
//! 5. Implements Inter-Processor Interrupts (IPIs) for TLB shootdown and multicore synchronization.
#![allow(unsafe_code)]

use crate::arch::x86_64::acpi;
use crate::arch::x86_64::apic;
use crate::kprintln;
use core::sync::atomic::{AtomicUsize, Ordering};

pub const MAX_CPUS: usize = 64;
pub const TLB_SHOOTDOWN_VECTOR: u8 = 251;
pub const AP_TRAMPOLINE_PHYS: u64 = 0x8000;
pub const AP_TRAMPOLINE_PAGE: u8 = 0x08;
pub const AP_HANDOFF_ADDR: u64 = 0x8F00;

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

#[repr(C, align(4096))]
struct ApStack([u8; 16384]);
static mut AP_STACK_POOL: [ApStack; MAX_CPUS] = [const { ApStack([0u8; 16384]) }; MAX_CPUS];

/// Hand-off structure between BSP and AP at 0x8F00.
#[repr(C)]
pub struct ApBootHandoff {
    pub cr3: u64,
    pub stack_top: u64,
    pub cpu_id: u32,
    pub online_flag: u32,
}

/// Returns the total number of hardware CPU cores discovered via ACPI MADT.
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

/// Resolve a firmware-discovered CPU slot by its local APIC ID.
pub fn cpu_index_for_apic_id(apic_id: u8) -> Option<usize> {
    (0..cpu_count().min(MAX_CPUS))
        .find(|&index| unsafe { PER_CPU[index].apic_id == apic_id })
}

/// Helper to delay by approximately `us` microseconds using RDTSC.
fn delay_us(us: u64) {
    let tsc_hz = crate::arch::tsc_frequency_hz().max(1_000_000);
    let cycles = (tsc_hz / 1_000_000) * us;
    let start = crate::arch::rdtsc();
    while crate::arch::rdtsc().saturating_sub(start) < cycles {
        core::hint::spin_loop();
    }
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

/// Write the AP bootstrap trampoline code at physical 0x8000.
pub fn prepare_ap_trampoline() {
    unsafe {
        // Zero the 4 KiB trampoline page
        core::ptr::write_bytes(AP_TRAMPOLINE_PHYS as *mut u8, 0, 4096);

        let code_dst = AP_TRAMPOLINE_PHYS as *mut u8;

        // 16-bit real mode entry:
        // cli                    FA
        // cld                    FC
        // xor ax, ax             31 C0
        // mov ds, ax             8E D8
        // mov es, ax             8E C0
        // mov ss, ax             8E D0
        // lgdt [0x8050]          0F 01 16 50 80
        // mov eax, cr0           0F 20 C0
        // or al, 1               0C 01
        // mov cr0, eax           0F 22 C0
        // jmp 0x08:0x8070        EA 70 80 00 00 08 00
        let real_code: [u8; 30] = [
            0xFA, 0xFC,
            0x31, 0xC0,
            0x8E, 0xD8,
            0x8E, 0xC0,
            0x8E, 0xD0,
            0x0F, 0x01, 0x16, 0x50, 0x80,
            0x0F, 0x20, 0xC0,
            0x0C, 0x01,
            0x0F, 0x22, 0xC0,
            0xEA, 0x70, 0x80, 0x00, 0x00, 0x08, 0x00,
        ];
        core::ptr::copy_nonoverlapping(real_code.as_ptr(), code_dst, real_code.len());

        // GDT at 0x8050 (offset 0x50):
        // 0x00: Null descriptor (8 bytes)
        // 0x08: 32-bit Code (0x00CF9A000000FFFF)
        // 0x10: 32-bit Data (0x00CF92000000FFFF)
        // 0x18: 64-bit Code (0x00AF9A000000FFFF)
        // 0x20: GDT descriptor: limit=31 (0x001F), base=0x8050 (0x00008050)
        let gdt_dst = (AP_TRAMPOLINE_PHYS + 0x50) as *mut u8;
        let gdt_data: [u8; 38] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xAF, 0x00,
            0x1F, 0x00, 0x50, 0x80, 0x00, 0x00,
        ];
        core::ptr::copy_nonoverlapping(gdt_data.as_ptr(), gdt_dst, gdt_data.len());

        // 32-bit Protected Mode code at 0x8070 (offset 0x70):
        // mov ax, 0x10           66 B8 10 00
        // mov ds, ax             8E D8
        // mov es, ax             8E C0
        // mov ss, ax             8E D0
        // mov eax, [0x8F00]      A1 00 8F 00 00
        // mov cr3, eax           0F 22 D8
        // mov eax, cr4           0F 20 E0
        // or eax, 0x20           83 C8 20
        // mov cr4, eax           0F 22 E0
        // mov ecx, 0xC0000080    B9 80 00 00 C0
        // rdmsr                  0F 32
        // or eax, 0x100          0D 00 01 00 00
        // wrmsr                  0F 30
        // mov eax, cr0           0F 20 C0
        // or eax, 0x80000001     0D 01 00 00 80
        // mov cr0, eax           0F 22 C0
        // jmp 0x18:0x80C0        EA C0 80 00 00 18 00
        let pm_dst = (AP_TRAMPOLINE_PHYS + 0x70) as *mut u8;
        let pm_code: [u8; 59] = [
            0x66, 0xB8, 0x10, 0x00,
            0x8E, 0xD8,
            0x8E, 0xC0,
            0x8E, 0xD0,
            0xA1, 0x00, 0x8F, 0x00, 0x00,
            0x0F, 0x22, 0xD8,
            0x0F, 0x20, 0xE0,
            0x83, 0xC8, 0x20,
            0x0F, 0x22, 0xE0,
            0xB9, 0x80, 0x00, 0x00, 0xC0,
            0x0F, 0x32,
            0x0D, 0x00, 0x01, 0x00, 0x00,
            0x0F, 0x30,
            0x0F, 0x20, 0xC0,
            0x0D, 0x01, 0x00, 0x00, 0x80,
            0x0F, 0x22, 0xC0,
            0xEA, 0xC0, 0x80, 0x00, 0x00, 0x18, 0x00,
        ];
        core::ptr::copy_nonoverlapping(pm_code.as_ptr(), pm_dst, pm_code.len());

        // 64-bit Long Mode code at 0x80C0 (offset 0xC0):
        // mov rsp, [0x8F08]      48 8B 24 25 08 8F 00 00
        // mov edi, [0x8F10]      8B 3C 25 10 8F 00 00
        // mov rax, <ap_entry>    48 B8 <8 bytes>
        // call rax               FF D0
        // cli; hlt; jmp $-2      FA F4 EB FC
        let lm_dst = (AP_TRAMPOLINE_PHYS + 0xC0) as *mut u8;
        let mut lm_code = [0u8; 29];
        lm_code[0..8].copy_from_slice(&[0x48, 0x8B, 0x24, 0x25, 0x08, 0x8F, 0x00, 0x00]);
        lm_code[8..15].copy_from_slice(&[0x8B, 0x3C, 0x25, 0x10, 0x8F, 0x00, 0x00]);
        lm_code[15..17].copy_from_slice(&[0x48, 0xB8]);
        let entry_fn_addr = ap_entry as *const () as usize as u64;
        lm_code[17..25].copy_from_slice(&entry_fn_addr.to_le_bytes());
        lm_code[25..29].copy_from_slice(&[0xFF, 0xD0, 0xFA, 0xF4]);
        core::ptr::copy_nonoverlapping(lm_code.as_ptr(), lm_dst, lm_code.len());
    }
}

/// Boot all discovered secondary cores (APs) using the standard INIT-SIPI-SIPI sequence.
pub fn boot_secondary_cores(kernel_cr3: u64) -> usize {
    let count = CPU_COUNT.load(Ordering::Acquire);
    if count <= 1 {
        kprintln!("[smp] Single core detected (profile T0); skipping AP bootstrap.");
        return 1;
    }

    kprintln!("[smp] Bootstrapping {} secondary core(s) via INIT-SIPI-SIPI sequence...", count - 1);
    prepare_ap_trampoline();

    let mut online_count = 1usize; // BSP is core 0
    let handoff = AP_HANDOFF_ADDR as *mut ApBootHandoff;

    for i in 1..count {
        let apic_id = unsafe { PER_CPU[i].apic_id };
        kprintln!("[smp] Starting AP core #{} (APIC ID {})...", i, apic_id);

        let stack_top = unsafe {
            (AP_STACK_POOL[i].0.as_ptr() as u64) + 16384
        };

        unsafe {
            PER_CPU[i].kernel_stack_top = stack_top;
            core::ptr::write_volatile(&mut (*handoff).cr3, kernel_cr3);
            core::ptr::write_volatile(&mut (*handoff).stack_top, stack_top);
            core::ptr::write_volatile(&mut (*handoff).cpu_id, i as u32);
            core::ptr::write_volatile(&mut (*handoff).online_flag, 0);
        }

        // 1. Send INIT IPI
        apic::send_init_ipi(apic_id);
        delay_us(10_000); // 10 ms delay

        // 2. Send 1st SIPI with vector 0x08
        apic::send_sipi(apic_id, AP_TRAMPOLINE_PAGE);
        delay_us(200); // 200 us delay

        // 3. Send 2nd SIPI with vector 0x08
        apic::send_sipi(apic_id, AP_TRAMPOLINE_PAGE);

        // 4. Poll for AP to set online_flag with timeout
        let mut spins = 0;
        let mut online = false;
        while spins < 100_000 {
            if unsafe { core::ptr::read_volatile(&(*handoff).online_flag) } == 1 {
                online = true;
                break;
            }
            core::hint::spin_loop();
            spins += 1;
        }

        if online {
            unsafe { PER_CPU[i].online = true; }
            kprintln!("[smp]   Core #{} (APIC ID {}) is ONLINE", i, apic_id);
            online_count += 1;
        } else {
            kprintln!("[smp]   Core #{} (APIC ID {}) timed out (single-core profile or offline socket)", i, apic_id);
        }
    }

    kprintln!("[smp] SMP bootstrap complete: {}/{} core(s) active", online_count, count);
    online_count
}

/// Entry point for Application Processors once in 64-bit Long Mode.
#[no_mangle]
pub extern "C" fn ap_entry(cpu_id: u32) -> ! {
    let id = cpu_id as usize;
    crate::arch::x86_64::fpu::enable_sse();
    crate::arch::x86_64::apic::init_ap();

    let handoff = AP_HANDOFF_ADDR as *mut ApBootHandoff;
    unsafe {
        core::ptr::write_volatile(&mut (*handoff).online_flag, 1);
        if id < MAX_CPUS {
            PER_CPU[id].online = true;
        }
    }

    crate::kprintln!("[smp] AP core #{} online and entered idle loop", id);

    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }

    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
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
