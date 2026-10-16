//! x86-64 COM1 / 16550 UART driver. Works on QEMU q35 and VirtualBox.
//! I/O-port based — no MMIO mapping needed at boot.
use core::fmt;

const COM1: u16 = 0x3F8;
const DLAB: u8 = 0x80;
const IER:  u16 = COM1 + 1;
const FCR:  u16 = COM1 + 2;
const LCR:  u16 = COM1 + 3;
const MCR:  u16 = COM1 + 4;
const LSR:  u16 = COM1 + 5;

// Line status bits
const LSR_TX_READY: u8 = 1 << 5;   // transmitter holding register empty
const LSR_DATA_RDY: u8 = 1 << 0;   // data ready (receiver)

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: COM1 is a standard, always-present PC I/O port; writing to it
    // only affects the UART's own shift register.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: same port, just reading status.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}

static mut VGA_COL: usize = 0;
static mut VGA_ROW: usize = 0;
const VGA_BUFFER: *mut u8 = 0xB8000 as *mut u8;

unsafe fn vga_put_byte(b: u8) {
    if b >= 0x80 {
        return; // Ignore non-ASCII / multi-byte UTF-8 bytes on standard 8-bit VGA hardware font
    }
    unsafe {
        if b == b'\n' {
            VGA_COL = 0;
            VGA_ROW += 1;
        } else if b == b'\r' {
            VGA_COL = 0;
        } else if b == 0x08 {
            if VGA_COL > 0 {
                VGA_COL -= 1;
                let offset = (VGA_ROW * 80 + VGA_COL) * 2;
                VGA_BUFFER.add(offset).write_volatile(b' ');
                VGA_BUFFER.add(offset + 1).write_volatile(0x07);
            }
        } else {
            if VGA_COL >= 80 {
                VGA_COL = 0;
                VGA_ROW += 1;
            }
            if VGA_ROW >= 25 {
                // Scroll up 1 line
                core::ptr::copy(VGA_BUFFER.add(160), VGA_BUFFER, 80 * 24 * 2);
                for i in 0..80 {
                    let cell = VGA_BUFFER.add((24 * 80 + i) * 2);
                    cell.write_volatile(b' ');
                    cell.add(1).write_volatile(0x07);
                }
                VGA_ROW = 24;
            }
            let offset = (VGA_ROW * 80 + VGA_COL) * 2;
            let color = if b == b'[' || b == b']' || b == b'{' || b == b'}' {
                0x0B // Bright Cyan
            } else if b == b'#' || b == b'=' || b == b'*' {
                0x0A // Bright Green
            } else {
                0x0F // Bright White on Black
            };
            VGA_BUFFER.add(offset).write_volatile(b);
            VGA_BUFFER.add(offset + 1).write_volatile(color);
            VGA_COL += 1;
        }
    }
}

/// Initialise COM1 at 115200 baud, 8-N-1, and clear VGA text buffer.
pub fn init() {
    unsafe {
        outb(IER, 0x00);                // disable interrupts
        outb(LCR, DLAB);               // enable Divisor Latch Access Bit
        outb(COM1, 0x01);              // divisor low  (115200 baud: divisor=1)
        outb(IER, 0x00);               // divisor high
        outb(LCR, 0x03);               // 8-bit, no parity, 1 stop bit (DLAB cleared)
        outb(FCR, 0xC7);               // enable + clear FIFOs, 14-byte threshold
        outb(MCR, 0x0B);               // RTS + DTR + IRQ-on-loopback-off

        clear_screen();
    }
}

pub fn clear_screen() {
    unsafe {
        for i in 0..(80 * 25) {
            let cell = VGA_BUFFER.add(i * 2);
            cell.write_volatile(b' ');
            cell.add(1).write_volatile(0x07);
        }
        VGA_COL = 0;
        VGA_ROW = 0;
    }
    write_str("\x1B[2J\x1B[H");
}

pub fn busy_delay(cycles: u64) {
    for _ in 0..cycles {
        unsafe {
            let _ = inb(0x80);
        }
    }
}

fn tx_ready() -> bool {
    unsafe { inb(LSR) & LSR_TX_READY != 0 }
}

fn put_byte(b: u8) {
    // Spin until TX holding register is empty. On QEMU this is near-instant.
    while !tx_ready() {}
    unsafe { 
        outb(COM1, b);
        vga_put_byte(b);
    };
}

fn write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            put_byte(b'\r');
        }
        put_byte(b);
    }
}

pub fn read_byte() -> Option<u8> {
    unsafe {
        if inb(LSR) & LSR_DATA_RDY != 0 {
            Some(inb(COM1))
        } else {
            None
        }
    }
}

static mut SHIFT_DOWN: bool = false;

fn scancode_to_ascii(scancode: u8, shifted: bool) -> Option<u8> {
    match scancode {
        0x02 => Some(if shifted { b'!' } else { b'1' }),
        0x03 => Some(if shifted { b'@' } else { b'2' }),
        0x04 => Some(if shifted { b'#' } else { b'3' }),
        0x05 => Some(if shifted { b'$' } else { b'4' }),
        0x06 => Some(if shifted { b'%' } else { b'5' }),
        0x07 => Some(if shifted { b'^' } else { b'6' }),
        0x08 => Some(if shifted { b'&' } else { b'7' }),
        0x09 => Some(if shifted { b'*' } else { b'8' }),
        0x0A => Some(if shifted { b'(' } else { b'9' }),
        0x0B => Some(if shifted { b')' } else { b'0' }),
        0x0C => Some(if shifted { b'_' } else { b'-' }),
        0x0D => Some(if shifted { b'+' } else { b'=' }),
        0x0E => Some(0x08), // Backspace
        0x0F => Some(b'\t'),
        0x10 => Some(if shifted { b'Q' } else { b'q' }),
        0x11 => Some(if shifted { b'W' } else { b'w' }),
        0x12 => Some(if shifted { b'E' } else { b'e' }),
        0x13 => Some(if shifted { b'R' } else { b'r' }),
        0x14 => Some(if shifted { b'T' } else { b't' }),
        0x15 => Some(if shifted { b'Y' } else { b'y' }),
        0x16 => Some(if shifted { b'U' } else { b'u' }),
        0x17 => Some(if shifted { b'I' } else { b'i' }),
        0x18 => Some(if shifted { b'O' } else { b'o' }),
        0x19 => Some(if shifted { b'P' } else { b'p' }),
        0x1A => Some(if shifted { b'{' } else { b'[' }),
        0x1B => Some(if shifted { b'}' } else { b']' }),
        0x1C => Some(b'\n'), // Enter
        0x1E => Some(if shifted { b'A' } else { b'a' }),
        0x1F => Some(if shifted { b'S' } else { b's' }),
        0x20 => Some(if shifted { b'D' } else { b'd' }),
        0x21 => Some(if shifted { b'F' } else { b'f' }),
        0x22 => Some(if shifted { b'G' } else { b'g' }),
        0x23 => Some(if shifted { b'H' } else { b'h' }),
        0x24 => Some(if shifted { b'J' } else { b'j' }),
        0x25 => Some(if shifted { b'K' } else { b'k' }),
        0x26 => Some(if shifted { b'L' } else { b'l' }),
        0x27 => Some(if shifted { b':' } else { b';' }),
        0x28 => Some(if shifted { b'"' } else { b'\'' }),
        0x29 => Some(if shifted { b'~' } else { b'`' }),
        0x2B => Some(if shifted { b'|' } else { b'\\' }),
        0x2C => Some(if shifted { b'Z' } else { b'z' }),
        0x2D => Some(if shifted { b'X' } else { b'x' }),
        0x2E => Some(if shifted { b'C' } else { b'c' }),
        0x2F => Some(if shifted { b'V' } else { b'v' }),
        0x30 => Some(if shifted { b'B' } else { b'b' }),
        0x31 => Some(if shifted { b'N' } else { b'n' }),
        0x32 => Some(if shifted { b'M' } else { b'm' }),
        0x33 => Some(if shifted { b'<' } else { b',' }),
        0x34 => Some(if shifted { b'>' } else { b'.' }),
        0x35 => Some(if shifted { b'?' } else { b'/' }),
        0x39 => Some(b' '), // Space
        _ => None,
    }
}

pub fn poll_ps2_keyboard() -> Option<u8> {
    unsafe {
        let status = inb(0x64);
        if status & 0x01 != 0 {
            let scancode = inb(0x60);
            if scancode == 0x2A || scancode == 0x36 {
                SHIFT_DOWN = true;
                return None;
            } else if scancode == 0xAA || scancode == 0xB6 {
                SHIFT_DOWN = false;
                return None;
            }
            if scancode & 0x80 != 0 {
                return None; // Key release
            }
            let shifted = SHIFT_DOWN;
            scancode_to_ascii(scancode, shifted)
        } else {
            None
        }
    }
}

pub fn get_char() -> Option<u8> {
    if let Some(c) = read_byte() {
        return Some(c);
    }
    poll_ps2_keyboard()
}

/// Writer implements `core::fmt::Write` for the `kprint!` macro.
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
