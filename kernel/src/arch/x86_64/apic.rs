//! x86-64 Local APIC (xAPIC, MMIO at 0xFEE00000 by default).
//! Provides: BSP identification, timer calibration, EOI, and IPI (later).
//! The APIC timer drives the future scheduler tick.
#![allow(unsafe_code)]

/// Default APIC base (may be relocated via IA32_APIC_BASE MSR).
const APIC_BASE: u64 = 0xFEE0_0000;

// Register offsets (relative to APIC base, all 32-bit aligned).
const APIC_ID:        usize = 0x020;
const APIC_VERSION:   usize = 0x030;
const APIC_TPR:       usize = 0x080;   // Task Priority Register
const APIC_EOI:       usize = 0x0B0;
const APIC_SVR:       usize = 0x0F0;   // Spurious Vector Register
const APIC_LVT_TIMER: usize = 0x320;
const APIC_TIMER_ICR: usize = 0x380;   // Initial Count Register
const APIC_TIMER_CCR: usize = 0x390;   // Current Count Register
const APIC_TIMER_DCR: usize = 0x3E0;   // Divide Configuration Register

const TIMER_VECTOR: u32 = 32;
const TIMER_PERIODIC: u32 = 1 << 17;
const APIC_ENABLE: u32 = 1 << 8;       // SVR enable bit

#[inline]
unsafe fn read32(off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((APIC_BASE as usize + off) as *const u32) }
}
#[inline]
unsafe fn write32(off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((APIC_BASE as usize + off) as *mut u32, val) };
}

/// Enable the Local APIC and set up a periodic timer at ~100 Hz.
pub fn init() {
    unsafe {
        // Enable APIC via SVR: set bit 8 and spurious vector (0xFF).
        write32(APIC_SVR, APIC_ENABLE | 0xFF);

        // Zero task priority — allow all interrupts.
        write32(APIC_TPR, 0);

        // Timer: divide by 16, periodic mode, vector 32.
        write32(APIC_TIMER_DCR, 0x3);    // divide by 16
        write32(APIC_LVT_TIMER, TIMER_PERIODIC | TIMER_VECTOR);

        // Calibration: set initial count so the timer fires ~100 times/sec.
        // On QEMU the APIC bus runs at 1 GHz; 1_000_000_000 / 16 / 100 = 625_000.
        // On real hardware this should be calibrated against the PIT, but for
        // the boot milestone a fixed count is good enough.
        write32(APIC_TIMER_ICR, 625_000);

        let id  = (read32(APIC_ID) >> 24) & 0xFF;
        let ver = read32(APIC_VERSION) & 0xFF;
        kprintln!("[apic] id={} version={:#x} timer vector={}  (~100 Hz)",
                  id, ver, TIMER_VECTOR);
    }
}

/// Signal end-of-interrupt to the APIC (call at end of every IRQ handler).
#[inline]
pub fn eoi() {
    unsafe { write32(APIC_EOI, 0); }
}

/// Retrieve the current APIC timer count (counts down from ICR to 0).
pub fn timer_count() -> u32 {
    unsafe { read32(APIC_TIMER_CCR) }
}

/// Read the APIC ID of the current CPU.
pub fn bsp_id() -> u8 {
    unsafe { ((read32(APIC_ID) >> 24) & 0xFF) as u8 }
}

// ── ACPI / QEMU shutdown ──────────────────────────────────────────────────────

/// Power off via the QEMU ACPI controller (I/O port 0x604 = QEMU ACPI shutdown).
/// On real hardware you would walk the ACPI S5 path; for QEMU this is much simpler.
pub fn shutdown_qemu(failure: bool) -> ! {
    let code: u16 = if failure { 0x0001 } else { 0x0000 };
    unsafe {
        // QEMU i440FX / Q35 debug exit device: write 0x0604 to port 0x604
        core::arch::asm!(
            "out dx, ax",
            in("dx") 0x604u16,
            in("ax") (0x2000u16 | code),
            options(nostack, nomem)
        );
        // Fallback: triple-fault by loading a zero-size IDT and INT3.
        core::arch::asm!(
            "lidt [{0}]",
            "int3",
            in(reg) &[0u64; 0],
            options(nostack)
        );
    }
    loop { unsafe { core::arch::asm!("hlt", options(nomem, nostack)); } }
}
