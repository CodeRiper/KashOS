//! ARM PL011 UART driver.
//! QEMU virt: 0x09000000 (default; confirmed by device tree).
//! Raspberry Pi 3/4: also PL011 (at 0xFE201000 for Pi 4).
//! No MMIO mapping needed before paging is on — physical == virtual at boot.
#![allow(unsafe_code)]
use core::fmt;

const PL011_BASE: u64 = 0x0900_0000; // QEMU virt default

// Registers (byte offsets from base)
const UARTDR:   u64 = 0x00;  // Data Register
const UARTFR:   u64 = 0x18;  // Flag Register
const UARTIBRD: u64 = 0x24;  // Integer Baud Rate Divisor
const UARTFBRD: u64 = 0x28;  // Fractional Baud Rate Divisor
const UARTLCR:  u64 = 0x2C;  // Line Control Register
const UARTCR:   u64 = 0x30;  // Control Register
const UARTIMSC: u64 = 0x38;  // Interrupt Mask Set/Clear

const FR_TXFF: u32 = 1 << 5;  // TX FIFO full
const FR_RXFE: u32 = 1 << 4;  // RX FIFO empty
const CR_UARTEN: u32 = 1 << 0;
const CR_TXE:    u32 = 1 << 8;
const CR_RXE:    u32 = 1 << 9;
const LCR_FEN:   u32 = 1 << 4;   // FIFO enable
const LCR_WLEN8: u32 = 0b11 << 5; // 8 data bits

static mut UART_BASE: u64 = PL011_BASE;

#[inline]
unsafe fn read32(off: u64) -> u32 {
    unsafe { core::ptr::read_volatile((UART_BASE + off) as *const u32) }
}
#[inline]
unsafe fn write32(off: u64, val: u32) {
    unsafe { core::ptr::write_volatile((UART_BASE + off) as *mut u32, val) };
}

/// Initialise PL011 at `base` (or the default if `base` is 0).
/// Baud rate is irrelevant on QEMU (host terminal handles it).
/// On real hardware use 115200: ibrd=1, fbrd=40 for a 24 MHz refclk.
pub fn init(base: Option<u64>) {
    unsafe {
        if let Some(b) = base {
            UART_BASE = b;
        }
        // Disable UART, wait for any tx to finish
        write32(UARTCR, 0);
        // 115200 baud at 24 MHz refclk: ibrd=13, fbrd=1
        write32(UARTIBRD, 13);
        write32(UARTFBRD, 1);
        // 8-bit words, FIFOs enabled
        write32(UARTLCR, LCR_WLEN8 | LCR_FEN);
        // Mask all interrupts (polling mode)
        write32(UARTIMSC, 0);
        // Enable TX + RX + UART
        write32(UARTCR, CR_UARTEN | CR_TXE | CR_RXE);
    }
}

fn tx_full() -> bool {
    unsafe { read32(UARTFR) & FR_TXFF != 0 }
}

fn put_byte(b: u8) {
    while tx_full() {}
    unsafe { write32(UARTDR, b as u32); }
}

fn write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' { put_byte(b'\r'); }
        put_byte(b);
    }
}

pub fn read_byte() -> Option<u8> {
    unsafe {
        if read32(UARTFR) & FR_RXFE == 0 {
            Some((read32(UARTDR) & 0xFF) as u8)
        } else {
            None
        }
    }
}

pub fn clear_screen() {
    write_str("\x1B[2J\x1B[H");
}

pub fn get_char() -> Option<u8> {
    read_byte()
}

pub struct Uart;

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_str(s);
        Ok(())
    }
}

impl khal::Console for Uart {
    fn put_byte(&self, b: u8) {
        put_byte(b);
    }
}
