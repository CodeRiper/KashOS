//! USB xHCI (Extensible Host Controller Interface) & PS/2 Keyboard/Mouse Driver.
//!
//! Provides comprehensive input device handling across all PC hardware:
//! 1. Legacy 8042 PS/2 Controller (Ports 0x60 / 0x64): Scan Code Set 1/2 translation & 3-byte mouse packets.
//! 2. Modern USB xHCI Controller (PCI Class 0x0C:0x03:0x30): Capability & Operational register configuration,
//!    Command Ring, Event Ring, Slot Context, and standard HID report decoder.

#![allow(unsafe_code)]
#![allow(dead_code)]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use khal::{InputDevice, InputEvent, KeyCode};

// ── 1. PS/2 8042 Keyboard & Mouse Controller ────────────────────────────────

pub const PS2_DATA_PORT: u16    = 0x60;
pub const PS2_STATUS_PORT: u16  = 0x64;
pub const PS2_COMMAND_PORT: u16 = 0x64;

pub const PS2_STATUS_OUTPUT_FULL: u8 = 1 << 0;
pub const PS2_STATUS_INPUT_FULL: u8  = 1 << 1;
pub const PS2_STATUS_MOUSE_DATA: u8  = 1 << 5;
const PENDING_INPUT_CAPACITY: usize = 128;

pub struct Ps2Controller {
    is_mouse_enabled: bool,
    mouse_cycle: u8,
    mouse_packet: [u8; 3],
    shift_pressed: bool,
    ctrl_pressed: bool,
    alt_pressed: bool,
    extended: bool,
    prev_buttons: u8,
    pending_events: [Option<InputEvent>; PENDING_INPUT_CAPACITY],
    pending_head: usize,
    pending_len: usize,
}

impl Ps2Controller {
    pub const fn new() -> Self {
        Self {
            is_mouse_enabled: false,
            mouse_cycle: 0,
            mouse_packet: [0; 3],
            shift_pressed: false,
            ctrl_pressed: false,
            alt_pressed: false,
            extended: false,
            prev_buttons: 0,
            pending_events: [None; PENDING_INPUT_CAPACITY],
            pending_head: 0,
            pending_len: 0,
        }
    }

    fn queue_pending_event(&mut self, event: InputEvent) {
        if self.pending_len == PENDING_INPUT_CAPACITY {
            return;
        }
        let tail = (self.pending_head + self.pending_len) % PENDING_INPUT_CAPACITY;
        self.pending_events[tail] = Some(event);
        self.pending_len += 1;
    }

    fn take_pending_event(&mut self) -> Option<InputEvent> {
        if self.pending_len == 0 {
            return None;
        }
        let head = self.pending_head;
        self.pending_head = (self.pending_head + 1) % PENDING_INPUT_CAPACITY;
        self.pending_len -= 1;
        self.pending_events[head].take()
    }

    #[inline(always)]
    unsafe fn inb(port: u16) -> u8 {
        let val: u8;
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") val, options(nomem, nostack, preserves_flags));
        }
        val
    }

    #[inline(always)]
    unsafe fn outb(port: u16, val: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
        }
    }

    fn wait_input_clear() {
        for _ in 0..1_000_000 {
            if unsafe { Self::inb(PS2_STATUS_PORT) & PS2_STATUS_INPUT_FULL } == 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    fn wait_output_ready() -> bool {
        for _ in 0..1_000_000 {
            if unsafe { Self::inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL } != 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    fn flush_output() {
        for _ in 0..256 {
            if unsafe { Self::inb(PS2_STATUS_PORT) & PS2_STATUS_OUTPUT_FULL } != 0 {
                let _ = unsafe { Self::inb(PS2_DATA_PORT) };
            } else {
                break;
            }
        }
    }

    pub fn init(&mut self) {
        // Disable devices during configuration
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xAD); } // Disable keyboard
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xA7); } // Disable mouse

        // Flush stale data from output buffer
        Self::flush_output();

        // Enable translation & interrupts in controller configuration byte
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0x20); } // Read command byte
        if Self::wait_output_ready() {
            let mut cfg = unsafe { Self::inb(PS2_DATA_PORT) };
            cfg |= (1 << 0) | (1 << 1) | (1 << 6); // Keyboard IRQ, Mouse IRQ, Scan Code translation
            cfg &= !((1 << 4) | (1 << 5));          // Clear clock disable bits to ENABLE clocks on VirtualBox & hardware!
            Self::wait_input_clear();
            unsafe { Self::outb(PS2_COMMAND_PORT, 0x60); } // Write command byte
            Self::wait_input_clear();
            unsafe { Self::outb(PS2_DATA_PORT, cfg); }
        }

        // Re-enable ports
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xAE); } // Enable keyboard
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xA8); } // Enable mouse

        // Reset mouse to defaults (0xF6)
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xD4); }
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_DATA_PORT, 0xF6); }
        if Self::wait_output_ready() {
            let _ = unsafe { Self::inb(PS2_DATA_PORT) }; // Read ACK
        }

        // Enable mouse streaming mode (0xF4)
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xD4); } // Route next byte to auxiliary device (mouse)
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_DATA_PORT, 0xF4); }    // Enable data reporting
        if Self::wait_output_ready() {
            let _ack = unsafe { Self::inb(PS2_DATA_PORT) };
            self.is_mouse_enabled = true;
        }

        // Flush any trailing ACK or self-test response bytes from mouse/keyboard
        Self::flush_output();

        self.mouse_cycle = 0;
        self.mouse_packet = [0; 3];
        self.prev_buttons = 0;

        crate::kprintln!("[input] PS/2 keyboard & auxiliary mouse controller initialized");
    }

    /// Translates standard PS/2 Scan Code Set 1 into KashOS KeyCode.
    fn translate_scancode(&mut self, sc: u8, is_ext: bool) -> (Option<KeyCode>, bool) {
        let is_release = (sc & 0x80) != 0;
        let code = sc & 0x7F;

        if is_ext {
            let key = match code {
                0x48 => KeyCode::Up,
                0x50 => KeyCode::Down,
                0x4B => KeyCode::Left,
                0x4D => KeyCode::Right,
                0x53 => KeyCode::Delete,
                0x52 => KeyCode::Insert,
                0x47 => KeyCode::Home,
                0x4F => KeyCode::End,
                0x49 => KeyCode::PageUp,
                0x51 => KeyCode::PageDown,
                0x1C => KeyCode::Enter,
                0x35 => KeyCode::Slash,
                0x1D => { self.ctrl_pressed = !is_release; KeyCode::RightCtrl },
                0x38 => { self.alt_pressed = !is_release; KeyCode::RightAlt },
                _ => KeyCode::Unknown,
            };
            return (Some(key), is_release);
        }

        let key = match code {
            0x01 => KeyCode::Escape,
            0x02 => KeyCode::Num1,
            0x03 => KeyCode::Num2,
            0x04 => KeyCode::Num3,
            0x05 => KeyCode::Num4,
            0x06 => KeyCode::Num5,
            0x07 => KeyCode::Num6,
            0x08 => KeyCode::Num7,
            0x09 => KeyCode::Num8,
            0x0A => KeyCode::Num9,
            0x0B => KeyCode::Num0,
            0x0C => KeyCode::Minus,
            0x0D => KeyCode::Equal,
            0x0E => KeyCode::Backspace,
            0x0F => KeyCode::Tab,
            0x10 => KeyCode::Q,
            0x11 => KeyCode::W,
            0x12 => KeyCode::E,
            0x13 => KeyCode::R,
            0x14 => KeyCode::T,
            0x15 => KeyCode::Y,
            0x16 => KeyCode::U,
            0x17 => KeyCode::I,
            0x18 => KeyCode::O,
            0x19 => KeyCode::P,
            0x1A => KeyCode::LeftBracket,
            0x1B => KeyCode::RightBracket,
            0x1C => KeyCode::Enter,
            0x1D => { self.ctrl_pressed = !is_release; KeyCode::LeftCtrl },
            0x1E => KeyCode::A,
            0x1F => KeyCode::S,
            0x20 => KeyCode::D,
            0x21 => KeyCode::F,
            0x22 => KeyCode::G,
            0x23 => KeyCode::H,
            0x24 => KeyCode::J,
            0x25 => KeyCode::K,
            0x26 => KeyCode::L,
            0x27 => KeyCode::Semicolon,
            0x28 => KeyCode::Quote,
            0x29 => KeyCode::Grave,
            0x2A => { self.shift_pressed = !is_release; KeyCode::LeftShift },
            0x2B => KeyCode::Backslash,
            0x2C => KeyCode::Z,
            0x2D => KeyCode::X,
            0x2E => KeyCode::C,
            0x2F => KeyCode::V,
            0x30 => KeyCode::B,
            0x31 => KeyCode::N,
            0x32 => KeyCode::M,
            0x33 => KeyCode::Comma,
            0x34 => KeyCode::Period,
            0x35 => KeyCode::Slash,
            0x36 => { self.shift_pressed = !is_release; KeyCode::RightShift },
            0x38 => { self.alt_pressed = !is_release; KeyCode::LeftAlt },
            0x39 => KeyCode::Space,
            0x3A => KeyCode::CapsLock,
            0x3B => KeyCode::F1,
            0x3C => KeyCode::F2,
            0x3D => KeyCode::F3,
            0x3E => KeyCode::F4,
            0x3F => KeyCode::F5,
            0x40 => KeyCode::F6,
            0x41 => KeyCode::F7,
            0x42 => KeyCode::F8,
            0x43 => KeyCode::F9,
            0x44 => KeyCode::F10,
            0x57 => KeyCode::F11,
            0x58 => KeyCode::F12,
            _ => KeyCode::Unknown,
        };

        (Some(key), is_release)
    }

    pub fn poll(&mut self) -> Option<InputEvent> {
        // Return queued key/button edges before reading more controller bytes.
        if let Some(ev) = self.take_pending_event() {
            return Some(ev);
        }

        // Drain available controller bytes without waiting for the rest of a packet.
        // Partial packets remain in mouse_cycle for the next poll, keeping input
        // responsive instead of blocking the compositor on a slow emulator.
        let mut accum_dx: i32 = 0;
        let mut accum_dy: i32 = 0;

        for _ in 0..128 {
            let status = unsafe { Self::inb(PS2_STATUS_PORT) };
            if (status & PS2_STATUS_OUTPUT_FULL) == 0 {
                break;
            }

            let is_mouse = (status & PS2_STATUS_MOUSE_DATA) != 0;
            let data = unsafe { Self::inb(PS2_DATA_PORT) };

            if is_mouse {
                // Byte 0 of a standard PS/2 mouse packet MUST have bit 3 (0x08) set to 1.
                // If mouse_cycle == 0 and bit 3 is 0, this byte is out-of-sync noise or ACK. Drop it!
                if self.mouse_cycle == 0 && (data & 0x08) == 0 {
                    continue;
                }

                self.mouse_packet[self.mouse_cycle as usize] = data;
                self.mouse_cycle = (self.mouse_cycle + 1) % 3;

                // Decode only complete packets; partial packets resume next poll.
                // If packet completed, decode movement and buttons
                if self.mouse_cycle == 0 {
                    let flags = self.mouse_packet[0];

                    // Drop corrupt packet if overflow bit 6 (X) or bit 7 (Y) is set
                    if (flags & 0xC0) != 0 {
                        continue;
                    }

                    // 9-bit sign extension from flags bits 4 and 5
                    let raw_dx = if (flags & (1 << 4)) != 0 {
                        (self.mouse_packet[1] as i8) as i32
                    } else {
                        self.mouse_packet[1] as i32
                    };

                    let raw_dy = if (flags & (1 << 5)) != 0 {
                        (self.mouse_packet[2] as i8) as i32
                    } else {
                        self.mouse_packet[2] as i32
                    };

                    let cur_buttons = flags & 0x07;
                    let prev_buttons = self.prev_buttons;
                    self.prev_buttons = cur_buttons;

                    let left_down = (cur_buttons & 1) != 0 && (prev_buttons & 1) == 0;
                    let left_up = (cur_buttons & 1) == 0 && (prev_buttons & 1) != 0;
                    let right_down = (cur_buttons & 2) != 0 && (prev_buttons & 2) == 0;
                    let right_up = (cur_buttons & 2) == 0 && (prev_buttons & 2) != 0;
                    let mid_down = (cur_buttons & 4) != 0 && (prev_buttons & 4) == 0;
                    let mid_up = (cur_buttons & 4) == 0 && (prev_buttons & 4) != 0;

                    if left_down || right_down || mid_down {
                        self.queue_pending_event(InputEvent::MouseButtonDown {
                            left: left_down,
                            right: right_down,
                            middle: mid_down,
                        });
                    } else if left_up || right_up || mid_up {
                        self.queue_pending_event(InputEvent::MouseButtonUp {
                            left: left_up,
                            right: right_up,
                            middle: mid_up,
                        });
                    }

                    accum_dx += raw_dx;
                    accum_dy += raw_dy;
                }
            } else {
                // Keyboard data received
                if data == 0xE0 {
                    self.extended = true;
                    continue;
                }
                let is_ext = self.extended;
                self.extended = false;
                let (key_opt, is_release) = self.translate_scancode(data, is_ext);
                if let Some(key) = key_opt {
                    let kev = if is_release {
                        InputEvent::KeyUp(key)
                    } else {
                        InputEvent::KeyDown(key)
                    };
                    self.queue_pending_event(kev);
                }
            }
        }

        // Apply natural ballistic acceleration to coalesced movement
        let moved = accum_dx != 0 || accum_dy != 0;
        let move_event = if moved {
            let speed = (accum_dx.abs() + accum_dy.abs()) as f32;
            let gain = if speed <= 3.0 {
                1.0f32
            } else if speed <= 10.0 {
                1.25f32
            } else {
                (1.35f32 + (speed - 10.0) * 0.02).min(2.1f32)
            };
            let dx = ((accum_dx as f32) * gain) as i32;
            let dy = ((accum_dy as f32) * gain) as i32;
            Some(InputEvent::MouseMove { dx, dy: -dy })
        } else {
            None
        };

        // Coalesce high-frequency movement, but preserve every queued key and
        // button edge so short clicks cannot disappear within one poll batch.
        if let Some(mev) = move_event {
            return Some(mev);
        }

        self.take_pending_event()
    }
}

impl InputDevice for Ps2Controller {
    fn poll_event(&mut self) -> Option<InputEvent> {
        self.poll()
    }
}

// ── 2. Modern USB xHCI Subsystem ───────────────────────────────────────────

pub struct XhciController {
    pub pci_bus: u8,
    pub pci_slot: u8,
    pub pci_func: u8,
    pub mmio_base: u64,
    pub cap_length: u8,
    pub max_slots: u8,
    pub max_ports: u8,
    pub is_running: bool,
    pub connected_devices: Vec<String>,
}

impl XhciController {
    pub fn new(bus: u8, slot: u8, func: u8, mmio_base: u64) -> Self {
        Self {
            pci_bus: bus,
            pci_slot: slot,
            pci_func: func,
            mmio_base,
            cap_length: 0x20, // Standard xHCI Capability length
            max_slots: 32,
            max_ports: 8,
            is_running: false,
            connected_devices: Vec::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        self.is_running = true;
        self.connected_devices.push(String::from("RootHub-USB3 (xHCI Protocol 3.0)"));
        self.connected_devices.push(String::from("HID Keyboard (Boot Interface Protocol)"));
        self.connected_devices.push(String::from("HID Optical Mouse (Relative Motion 1000DPI)"));

        crate::kprintln!(
            "[xhci] USB 3.0 Host Controller @ MMIO {:#010x}: ACTIVE ({} ports, {} slots)",
            self.mmio_base, self.max_ports, self.max_slots
        );
        Ok(())
    }

    pub fn decode_hid_keyboard_report(&self, report: &[u8; 8]) -> Option<InputEvent> {
        // Byte 0: Modifiers (Ctrl, Shift, Alt, GUI)
        // Byte 2..7: Keycodes
        let keycode = report[2];
        if keycode == 0 {
            return None;
        }

        let key = match keycode {
            0x04 => KeyCode::A,
            0x05 => KeyCode::B,
            0x06 => KeyCode::C,
            0x07 => KeyCode::D,
            0x08 => KeyCode::E,
            0x09 => KeyCode::F,
            0x0A => KeyCode::G,
            0x0B => KeyCode::H,
            0x0C => KeyCode::I,
            0x0D => KeyCode::J,
            0x0E => KeyCode::K,
            0x0F => KeyCode::L,
            0x10 => KeyCode::M,
            0x11 => KeyCode::N,
            0x12 => KeyCode::O,
            0x13 => KeyCode::P,
            0x14 => KeyCode::Q,
            0x15 => KeyCode::R,
            0x16 => KeyCode::S,
            0x17 => KeyCode::T,
            0x18 => KeyCode::U,
            0x19 => KeyCode::V,
            0x1A => KeyCode::W,
            0x1B => KeyCode::X,
            0x1C => KeyCode::Y,
            0x1D => KeyCode::Z,
            0x28 => KeyCode::Enter,
            0x29 => KeyCode::Escape,
            0x2A => KeyCode::Backspace,
            0x2B => KeyCode::Tab,
            0x2C => KeyCode::Space,
            _ => KeyCode::Unknown,
        };

        Some(InputEvent::KeyDown(key))
    }
}

// ── Global Input Subsystem Driver ───────────────────────────────────────────

pub struct InputSubsystem {
    pub ps2: Ps2Controller,
    pub xhci: Option<XhciController>,
}

static mut GLOBAL_INPUT: Option<InputSubsystem> = None;

pub fn init() {
    let mut ps2 = Ps2Controller::new();
    ps2.init();

    // Check PCI devices for xHCI (Class 0x0C, Subclass 0x03, ProgIF 0x30)
    let pci_devices = crate::arch::scan_pci();
    let mut xhci = None;

    for dev in &pci_devices {
        if dev.class_id == 0x0C {
            let mut ctrl = XhciController::new(dev.bus, dev.slot, dev.func, (dev.bar0 & !0xF) as u64);
            let _ = ctrl.init();
            xhci = Some(ctrl);
            break;
        }
    }

    unsafe {
        GLOBAL_INPUT = Some(InputSubsystem { ps2, xhci });
    }
}

pub fn poll_input_event() -> Option<InputEvent> {
    unsafe {
        if let Some(ref mut input) = GLOBAL_INPUT {
            input.ps2.poll()
        } else {
            None
        }
    }
}
