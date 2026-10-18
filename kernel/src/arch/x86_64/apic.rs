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
const APIC_ICR_LOW:  usize = 0x300;   // Interrupt Command Register Low
const APIC_ICR_HIGH: usize = 0x310;   // Interrupt Command Register High
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

/// Send an IPI to all other CPU cores excluding self (e.g. for TLB shootdown).
pub fn send_broadcast_ipi(vector: u8) {
    unsafe {
        // Destination shorthand 0b11 = All Including Self / 0b10 = All Excluding Self
        // Delivery mode 000 (Fixed), Edge triggered (0), Assert (1 << 14)
        let icr_low = (vector as u32) | (0b10 << 18) | (1 << 14);
        write32(APIC_ICR_LOW, icr_low);
        while (read32(APIC_ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Send an INIT IPI to a target CPU core by APIC ID.
pub fn send_init_ipi(target_apic_id: u8) {
    unsafe {
        write32(APIC_ICR_HIGH, (target_apic_id as u32) << 24);
        // Delivery mode 101 (INIT = 0x500), Assert (1 << 14)
        write32(APIC_ICR_LOW, 0x0000_4500);
        while (read32(APIC_ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }
}

/// Send a Start-up IPI (SIPI) to a target CPU core, pointing to trampoline page frame.
pub fn send_sipi(target_apic_id: u8, page_frame: u8) {
    unsafe {
        write32(APIC_ICR_HIGH, (target_apic_id as u32) << 24);
        // Delivery mode 110 (Start-up = 0x600), Assert (1 << 14), vector = page_frame
        write32(APIC_ICR_LOW, 0x0000_4600 | (page_frame as u32));
        while (read32(APIC_ICR_LOW) & (1 << 12)) != 0 {
            core::hint::spin_loop();
        }
    }
}

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static APIC_BUS_MHZ: AtomicU32 = AtomicU32::new(0);
static APIC_INITIAL_COUNT: AtomicU32 = AtomicU32::new(625_000);
static APIC_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PIT_FALLBACK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Calibrate the Local APIC timer against 8254 PIT Channel 2 over a precise 10 ms window.
///
/// Returns `(initial_count_for_100hz, apic_bus_mhz)`.
/// Conforms to Build Guide Stage B / Task F-03 (V-13, V-14).
pub fn calibrate_apic_timer() -> (u32, u32) {
    unsafe {
        // 1. Divide configuration: divide by 16
        write32(APIC_TIMER_DCR, 0x3);

        // 2. Set LVT Timer to masked one-shot mode
        write32(APIC_LVT_TIMER, (1 << 16) | TIMER_VECTOR);

        // 3. Load maximum initial count
        write32(APIC_TIMER_ICR, 0xFFFF_FFFF);

        // 4. Program 8254 PIT Channel 2 for 10 ms countdown (11,932 ticks at 1,193,182 Hz)
        let mut p61: u8;
        core::arch::asm!("in al, 0x61", out("al") p61, options(nomem, nostack, preserves_flags));

        // Disable speaker & gate low
        core::arch::asm!("out 0x61, al", in("al") (p61 & !0x03), options(nomem, nostack, preserves_flags));

        // Mode 0 (interrupt on terminal count), binary, low/high byte
        core::arch::asm!("out 0x43, al", in("al") 0xB0u8, options(nomem, nostack, preserves_flags));
        core::arch::asm!("out 0x42, al", in("al") 0x9Cu8, options(nomem, nostack, preserves_flags));
        core::arch::asm!("out 0x42, al", in("al") 0x2Eu8, options(nomem, nostack, preserves_flags));

        // Gate high to start counting
        core::arch::asm!("out 0x61, al", in("al") ((p61 & !0x02) | 0x01), options(nomem, nostack, preserves_flags));

        // Poll until OUT2 (bit 5 of port 0x61) goes high or timeout
        let mut loops = 0;
        loop {
            core::arch::asm!("in al, 0x61", out("al") p61, options(nomem, nostack, preserves_flags));
            if (p61 & 0x20) != 0 || loops > 10_000_000 {
                break;
            }
            loops += 1;
        }

        // Gate low to reset
        core::arch::asm!("out 0x61, al", in("al") (p61 & !0x03), options(nomem, nostack, preserves_flags));

        let ccr = read32(APIC_TIMER_CCR);
        let ticks_10ms = 0xFFFF_FFFF_u32.saturating_sub(ccr);

        if ticks_10ms > 100 && loops < 10_000_000 {
            // Bus MHz = (ticks_10ms * 16 * 100) / 1_000_000
            let bus_mhz = ((ticks_10ms as u64 * 16 * 100) / 1_000_000) as u32;
            (ticks_10ms, bus_mhz)
        } else {
            // Fallback default: 625,000 ticks (~1.0 GHz APIC bus clock)
            (625_000, 1000)
        }
    }
}

/// Configures legacy 8254 PIT Channel 0 at 100 Hz as fallback timer when APIC is absent.
pub fn init_pit_fallback_100hz() {
    unsafe {
        // PIT Channel 0, lobyte/hibyte, Mode 2 (Rate Generator), binary
        core::arch::asm!("out 0x43, al", in("al") 0x34u8, options(nomem, nostack, preserves_flags));
        // Divisor 11,932 (0x2E9C) for 100 Hz (1,193,182 / 100)
        core::arch::asm!("out 0x40, al", in("al") 0x9Cu8, options(nomem, nostack, preserves_flags));
        core::arch::asm!("out 0x40, al", in("al") 0x2Eu8, options(nomem, nostack, preserves_flags));

        // Unmask IRQ0 on 8259 master PIC (port 0x21 bit 0)
        let mut master_mask: u8;
        core::arch::asm!("in al, 0x21", out("al") master_mask, options(nomem, nostack, preserves_flags));
        core::arch::asm!("out 0x21, al", in("al") (master_mask & !0x01), options(nomem, nostack, preserves_flags));

        PIT_FALLBACK_ACTIVE.store(true, Ordering::SeqCst);
        kprintln!("[pit] Configured 8254 PIT Channel 0 fallback timer at 100 Hz (divisor 11,932)");
    }
}

/// Enable the Local APIC and set up a calibrated periodic timer at 100 Hz.
pub fn init() {
    let cpu = crate::arch::x86_64::cpuid::detect();
    if !cpu.has_apic {
        kprintln!("[apic] No Local APIC detected via CPUID. Falling back to 8254 PIT Channel 0.");
        init_pit_fallback_100hz();
        return;
    }

    unsafe {
        // SAFETY: Mask all IRQs on legacy 8259 dual-PICs (master port 0x21, slave port 0xA1)
        // so legacy PIC interrupts cannot collide with CPU exceptions 0x00..0x1F (e.g. vector 8 #DF).
        core::arch::asm!("out 0x21, al", in("al") 0xFFu8, options(nomem, nostack));
        core::arch::asm!("out 0xA1, al", in("al") 0xFFu8, options(nomem, nostack));

        // Enable APIC via SVR: set bit 8 and spurious vector (0xFF).
        write32(APIC_SVR, APIC_ENABLE | 0xFF);

        // Zero task priority — allow all interrupts.
        write32(APIC_TPR, 0);

        // Dynamically calibrate APIC timer against PIT Channel 2
        let (icr_100hz, bus_mhz) = calibrate_apic_timer();
        APIC_BUS_MHZ.store(bus_mhz, Ordering::SeqCst);
        APIC_INITIAL_COUNT.store(icr_100hz, Ordering::SeqCst);

        // Timer: divide by 16, periodic mode, vector 32.
        write32(APIC_TIMER_DCR, 0x3);    // divide by 16
        write32(APIC_LVT_TIMER, TIMER_PERIODIC | TIMER_VECTOR);
        write32(APIC_TIMER_ICR, icr_100hz);

        APIC_INITIALIZED.store(true, Ordering::SeqCst);

        let id  = (read32(APIC_ID) >> 24) & 0xFF;
        let ver = read32(APIC_VERSION) & 0xFF;
        kprintln!("[apic] id={} version={:#x} bus={} MHz timer vector={} icr={} (100 Hz calibrated)",
                  id, ver, bus_mhz, TIMER_VECTOR, icr_100hz);
    }
}

/// Signal end-of-interrupt to the APIC or legacy PIC (call at end of every IRQ handler).
#[inline]
pub fn eoi() {
    if PIT_FALLBACK_ACTIVE.load(Ordering::Relaxed) {
        unsafe {
            core::arch::asm!("out 0x20, al", in("al") 0x20u8, options(nomem, nostack));
        }
    } else {
        unsafe { write32(APIC_EOI, 0); }
    }
}

/// Retrieve the current APIC timer count (counts down from ICR to 0).
pub fn timer_count() -> u32 {
    unsafe { read32(APIC_TIMER_CCR) }
}

/// Returns the calibrated Local APIC bus frequency in MHz.
pub fn bus_frequency_mhz() -> u32 {
    APIC_BUS_MHZ.load(Ordering::Relaxed)
}

/// Returns the calibrated initial count register (ICR) for 100 Hz.
pub fn initial_count() -> u32 {
    APIC_INITIAL_COUNT.load(Ordering::Relaxed)
}

/// Returns whether legacy 8254 PIT fallback is active.
pub fn is_pit_fallback() -> bool {
    PIT_FALLBACK_ACTIVE.load(Ordering::Relaxed)
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
