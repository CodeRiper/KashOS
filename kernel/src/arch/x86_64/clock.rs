//! Calibrated Monotonic TSC Clock & CMOS RTC (Real-Time Clock) Reader.
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

const CMOS_ADDR: u16 = 0x70;
const CMOS_DATA: u16 = 0x71;

static TSC_HZ: AtomicU64 = AtomicU64::new(1_000_000_000); // Default 1.0 GHz
static LAST_TSC: AtomicU64 = AtomicU64::new(0);

#[inline]
unsafe fn cmos_read(reg: u8) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!("out dx, al", in("dx") CMOS_ADDR, in("al") (reg & 0x7F), options(nomem, nostack, preserves_flags));
        core::arch::asm!("in al, dx", in("dx") CMOS_DATA, out("al") val, options(nomem, nostack, preserves_flags));
    }
    val
}

fn is_rtc_updating() -> bool {
    unsafe { (cmos_read(0x0A) & 0x80) != 0 }
}

fn bcd_to_bin(val: u8) -> u8 {
    (val & 0x0F) + ((val >> 4) * 10)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Reads the real-time clock from CMOS registers and returns seconds since Unix Epoch (1970-01-01 00:00:00 UTC).
pub fn read_rtc_unix_seconds() -> u64 {
    // Wait until RTC update is not in progress (timeout to prevent hanging if CMOS is broken)
    for _ in 0..100_000 {
        if !is_rtc_updating() {
            break;
        }
    }

    let mut sec = unsafe { cmos_read(0x00) };
    let mut min = unsafe { cmos_read(0x02) };
    let mut hour = unsafe { cmos_read(0x04) };
    let mut day = unsafe { cmos_read(0x07) };
    let mut month = unsafe { cmos_read(0x08) };
    let mut year = unsafe { cmos_read(0x09) } as u64;

    let reg_b = unsafe { cmos_read(0x0B) };
    let is_bcd = (reg_b & 0x04) == 0;

    if is_bcd {
        sec = bcd_to_bin(sec);
        min = bcd_to_bin(min);
        hour = bcd_to_bin(hour & 0x7F);
        day = bcd_to_bin(day);
        month = bcd_to_bin(month);
        year = bcd_to_bin(year as u8) as u64;
    }

    // Convert 12-hour mode to 24-hour mode if needed
    if (reg_b & 0x02) == 0 && (hour & 0x80) != 0 {
        hour = ((hour & 0x7F) + 12) % 24;
    }

    let full_year = if year < 70 { 2000 + year } else { 1900 + year };

    let mut days: u64 = 0;
    for y in 1970..full_year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    let month_days = [31, if is_leap_year(full_year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let m_idx = if month >= 1 && month <= 12 { (month - 1) as usize } else { 0 };
    for m in 0..m_idx {
        days += month_days[m];
    }
    days += (day.saturating_sub(1)) as u64;

    days * 86400 + (hour as u64) * 3600 + (min as u64) * 60 + (sec as u64)
}

/// Calibrates the CPU TSC (Time Stamp Counter) using PIT Channel 2 over a 10 ms window.
pub fn calibrate_tsc() {
    unsafe {
        // Read current port 0x61 status
        let mut p61: u8;
        core::arch::asm!("in al, 0x61", out("al") p61, options(nomem, nostack, preserves_flags));

        // Disable speaker & gate low
        core::arch::asm!("out 0x61, al", in("al") (p61 & !0x03), options(nomem, nostack, preserves_flags));

        // Program PIT Channel 2: Mode 0 (interrupt on terminal count), binary, low/high byte
        core::arch::asm!("out 0x43, al", in("al") 0xB0u8, options(nomem, nostack, preserves_flags));

        // 10 ms at 1,193,182 Hz = 11,932 cycles (0x2E9C)
        core::arch::asm!("out 0x42, al", in("al") 0x9Cu8, options(nomem, nostack, preserves_flags));
        core::arch::asm!("out 0x42, al", in("al") 0x2Eu8, options(nomem, nostack, preserves_flags));

        // Gate high to start counting
        core::arch::asm!("out 0x61, al", in("al") ((p61 & !0x02) | 0x01), options(nomem, nostack, preserves_flags));

        let tsc_start = crate::arch::rdtsc();

        // Wait until OUT2 (bit 5 of port 0x61) goes high
        let mut loops = 0;
        loop {
            core::arch::asm!("in al, 0x61", out("al") p61, options(nomem, nostack, preserves_flags));
            if (p61 & 0x20) != 0 || loops > 10_000_000 {
                break;
            }
            loops += 1;
        }
        let tsc_end = crate::arch::rdtsc();

        // Reset gate low
        core::arch::asm!("out 0x61, al", in("al") (p61 & !0x03), options(nomem, nostack, preserves_flags));

        let delta = tsc_end.saturating_sub(tsc_start);
        let hz = if delta > 100_000 && loops < 10_000_000 {
            delta * 100 // 10 ms * 100 = 1 sec
        } else {
            // Fallback: estimate 2.0 GHz
            2_000_000_000
        };

        TSC_HZ.store(hz, Ordering::SeqCst);
        LAST_TSC.store(crate::arch::rdtsc(), Ordering::SeqCst);
        crate::kprintln!("[clock] TSC calibrated against PIT: {} MHz ({} Hz)", hz / 1_000_000, hz);
    }
}

/// Returns the elapsed time in seconds (`dt`) since the last invocation of `elapsed_seconds()`.
pub fn elapsed_seconds() -> f32 {
    let now = crate::arch::rdtsc();
    let prev = LAST_TSC.swap(now, Ordering::SeqCst);
    let delta = now.saturating_sub(prev);
    let hz = TSC_HZ.load(Ordering::Relaxed) as f32;
    if hz > 0.0 {
        let dt = (delta as f32) / hz;
        // Clamp to avoid extreme animation jumps
        if dt < 0.0001 { 0.001 } else if dt > 0.1 { 0.1 } else { dt }
    } else {
        0.016 // ~60 fps default
    }
}

/// Returns the calibrated TSC frequency in Hertz
pub fn tsc_frequency_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}
