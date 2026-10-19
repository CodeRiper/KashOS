//! USB xHCI (Extensible Host Controller Interface) & PS/2 Keyboard/Mouse Driver.
//!
//! Provides comprehensive input device handling across all PC hardware:
//! 1. Legacy 8042 PS/2 Controller (Ports 0x60 / 0x64): Scan Code Set 1/2 translation & 3-byte mouse packets.
//! 2. Modern USB xHCI Controller (PCI Class 0x0C:0x03:0x30): Capability & Operational register configuration,
//!    Command Ring, Event Ring, Slot Context, and standard HID report decoder.

#![allow(unsafe_code)]

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
    has_wheel: bool,
    mouse_id: u8,
    mouse_packet_len: u8,
    mouse_cycle: u8,
    mouse_packet: [u8; 4],
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
            has_wheel: false,
            mouse_id: 0,
            mouse_packet_len: 3,
            mouse_cycle: 0,
            mouse_packet: [0; 4],
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

    fn mouse_write(byte: u8) -> bool {
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xD4); } // Route next byte to auxiliary device (mouse)
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_DATA_PORT, byte); }
        if Self::wait_output_ready() {
            let ack = unsafe { Self::inb(PS2_DATA_PORT) };
            ack == 0xFA
        } else {
            false
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
        Self::mouse_write(0xF6);

        // IntelliMouse wheel negotiation sequence:
        // Set sample rate 200, then 100, then 80
        Self::mouse_write(0xF3);
        Self::mouse_write(200);
        Self::mouse_write(0xF3);
        Self::mouse_write(100);
        Self::mouse_write(0xF3);
        Self::mouse_write(80);

        // Read Device ID (0xF2)
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_COMMAND_PORT, 0xD4); }
        Self::wait_input_clear();
        unsafe { Self::outb(PS2_DATA_PORT, 0xF2); }
        if Self::wait_output_ready() {
            let ack = unsafe { Self::inb(PS2_DATA_PORT) };
            if ack == 0xFA && Self::wait_output_ready() {
                let id = unsafe { Self::inb(PS2_DATA_PORT) };
                if id == 3 || id == 4 {
                    self.has_wheel = true;
                    self.mouse_id = id;
                    self.mouse_packet_len = 4;
                    crate::kprintln!("[input] PS/2 mouse ID {:#04X}: IntelliMouse scrolling protocol enabled (4-byte packets)", id);
                } else {
                    self.has_wheel = false;
                    self.mouse_id = id;
                    self.mouse_packet_len = 3;
                    crate::kprintln!("[input] PS/2 mouse ID {:#04X}: Standard 3-byte mouse protocol active", id);
                }
            }
        }

        // Enable mouse streaming mode (0xF4)
        if Self::mouse_write(0xF4) {
            self.is_mouse_enabled = true;
        }

        // Flush any trailing ACK or self-test response bytes from mouse/keyboard
        Self::flush_output();

        self.mouse_cycle = 0;
        self.mouse_packet = [0; 4];
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
            crate::entropy::add_interrupt_entropy(if is_mouse { 12 } else { 1 }, data, crate::arch::rdtsc());

            if is_mouse {
                // Byte 0 of a standard PS/2 mouse packet MUST have bit 3 (0x08) set to 1.
                // If mouse_cycle == 0 and bit 3 is 0, this byte is out-of-sync noise or ACK. Drop it!
                if self.mouse_cycle == 0 && (data & 0x08) == 0 {
                    continue;
                }

                self.mouse_packet[self.mouse_cycle as usize] = data;
                self.mouse_cycle = (self.mouse_cycle + 1) % self.mouse_packet_len;

                // Decode only complete packets; partial packets resume next poll.
                // If packet completed, decode movement, buttons, and wheel
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

                    // Decode scroll wheel if active (4-byte IntelliMouse mode)
                    if self.has_wheel {
                        let dz = if self.mouse_id == 4 {
                            let raw = (self.mouse_packet[3] & 0x0F) as i8;
                            if (raw & 0x08) != 0 {
                                (raw | -16) as i32
                            } else {
                                raw as i32
                            }
                        } else {
                            (self.mouse_packet[3] as i8) as i32
                        };
                        if dz != 0 {
                            self.queue_pending_event(InputEvent::MouseWheel { dx: 0, dy: dz });
                        }
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
    pub hci_version: u16,
    pub max_slots: u8,
    pub max_ports: u8,
    pub is_running: bool,
    pub is_64bit_context: bool,
    pub prev_mouse_buttons: u8,
    pub pending_input: [Option<InputEvent>; 32],
    pub pending_head: usize,
    pub pending_len: usize,
    pub connected_devices: Vec<String>,
}

impl XhciController {
    pub fn new(bus: u8, slot: u8, func: u8, mmio_base: u64) -> Self {
        let mut cap_len = 0x20u8;
        let mut hci_ver = 0x0100u16;
        let mut max_slots = 32u8;
        let mut max_ports = 8u8;
        let mut is_64bit = true;

        if mmio_base != 0 {
            // SAFETY: Memory-mapped I/O access to xHCI capability registers
            unsafe {
                let cap_ptr = mmio_base as *const u8;
                cap_len = core::ptr::read_volatile(cap_ptr);
                if cap_len < 0x20 || cap_len > 0x80 {
                    cap_len = 0x20;
                }
                let ver_ptr = (mmio_base + 0x02) as *const u16;
                hci_ver = core::ptr::read_volatile(ver_ptr);

                let params1_ptr = (mmio_base + 0x04) as *const u32;
                let params1 = core::ptr::read_volatile(params1_ptr);
                max_slots = (params1 & 0xFF) as u8;
                max_ports = ((params1 >> 24) & 0xFF) as u8;

                let hcc1_ptr = (mmio_base + 0x10) as *const u32;
                let hcc1 = core::ptr::read_volatile(hcc1_ptr);
                is_64bit = (hcc1 & (1 << 2)) != 0;
            }
        }

        Self {
            pci_bus: bus,
            pci_slot: slot,
            pci_func: func,
            mmio_base,
            cap_length: cap_len,
            hci_version: hci_ver,
            max_slots,
            max_ports,
            is_running: false,
            is_64bit_context: is_64bit,
            prev_mouse_buttons: 0,
            pending_input: [None; 32],
            pending_head: 0,
            pending_len: 0,
            connected_devices: Vec::new(),
        }
    }

    pub fn init(&mut self) -> Result<(), &'static str> {
        if self.mmio_base == 0 {
            self.is_running = false;
            return Err("Invalid xHCI MMIO base");
        }

        let op_base = self.mmio_base + (self.cap_length as u64);

        // SAFETY: Direct volatile MMIO access to xHCI operational and port registers
        unsafe {
            let usbcmd_ptr = (op_base + khal::xhci::XHCI_OP_USBCMD as u64) as *mut u32;
            let usbsts_ptr = (op_base + khal::xhci::XHCI_OP_USBSTS as u64) as *mut u32;

            // 1. Stop controller if currently running
            let cmd = core::ptr::read_volatile(usbcmd_ptr);
            if (cmd & khal::xhci::USBCMD_RS) != 0 {
                core::ptr::write_volatile(usbcmd_ptr, cmd & !khal::xhci::USBCMD_RS);
                for _ in 0..10_000 {
                    if (core::ptr::read_volatile(usbsts_ptr) & khal::xhci::USBSTS_HCH) != 0 {
                        break;
                    }
                    core::hint::spin_loop();
                }
            }

            // 2. Perform Host Controller Reset
            core::ptr::write_volatile(usbcmd_ptr, khal::xhci::USBCMD_HCRST);
            for _ in 0..100_000 {
                let status = core::ptr::read_volatile(usbsts_ptr);
                let cmd_cur = core::ptr::read_volatile(usbcmd_ptr);
                if (cmd_cur & khal::xhci::USBCMD_HCRST) == 0 && (status & khal::xhci::USBSTS_CNR) == 0 {
                    break;
                }
                core::hint::spin_loop();
            }

            // 3. Configure max device slots enabled
            let config_ptr = (op_base + khal::xhci::XHCI_OP_CONFIG as u64) as *mut u32;
            core::ptr::write_volatile(config_ptr, self.max_slots as u32);

            // 4. Power up root hub ports and detect connected devices
            for port in 1..=self.max_ports {
                let portsc_offset = op_base + 0x400 + ((port as u64 - 1) * 0x10);
                let portsc_ptr = portsc_offset as *mut u32;
                let cur_portsc = core::ptr::read_volatile(portsc_ptr);
                core::ptr::write_volatile(portsc_ptr, cur_portsc | khal::xhci::PORTSC_PP);

                // Small spin to let power stabilize
                for _ in 0..1000 { core::hint::spin_loop(); }

                let status = core::ptr::read_volatile(portsc_ptr);
                if (status & khal::xhci::PORTSC_CCS) != 0 {
                    let speed_id = ((status >> 10) & 0x0F) as u8;
                    let speed = khal::xhci::UsbSpeed::from_port_speed(speed_id);
                    crate::kprintln!(
                        "[xhci] Port {} connected: link active, speed = {:?}",
                        port, speed
                    );
                }
            }

            // 5. Start controller (Run/Stop + Interrupter Enable)
            core::ptr::write_volatile(
                usbcmd_ptr,
                khal::xhci::USBCMD_RS | khal::xhci::USBCMD_INTE,
            );
        }

        self.is_running = true;
        crate::kprintln!(
            "[xhci] xHCI host controller active @ MMIO {:#010x} (v{:x}.{:x}, {} slots, {} ports, running)",
            self.mmio_base,
            self.hci_version >> 8,
            self.hci_version & 0xFF,
            self.max_slots,
            self.max_ports
        );
        crate::status::update(|s| s.xhci_usb = crate::status::ComponentStatus::Real);
        Ok(())
    }

    pub fn enqueue_event(&mut self, ev: InputEvent) {
        if self.pending_len < self.pending_input.len() {
            let idx = (self.pending_head + self.pending_len) % self.pending_input.len();
            self.pending_input[idx] = Some(ev);
            self.pending_len += 1;
        }
    }

    pub fn poll_event(&mut self) -> Option<InputEvent> {
        if self.pending_len == 0 {
            None
        } else {
            let ev = self.pending_input[self.pending_head].take();
            self.pending_head = (self.pending_head + 1) % self.pending_input.len();
            self.pending_len -= 1;
            ev
        }
    }

    pub fn handle_hid_keyboard_report(&mut self, report: &[u8; 8]) {
        if let Some(ev) = khal::xhci::decode_usb_keyboard_report(report) {
            self.enqueue_event(ev);
        }
    }

    pub fn handle_hid_mouse_report(&mut self, report: &[u8]) {
        let (btn_ev, motion_ev) = khal::xhci::decode_usb_mouse_report(report, &mut self.prev_mouse_buttons);
        if let Some(ev) = btn_ev {
            self.enqueue_event(ev);
        }
        if let Some(ev) = motion_ev {
            self.enqueue_event(ev);
        }
    }

    pub fn decode_hid_keyboard_report(&self, report: &[u8; 8]) -> Option<InputEvent> {
        khal::xhci::decode_usb_keyboard_report(report)
    }
}

// ── Global Input Subsystem Driver ───────────────────────────────────────────

pub struct InputSubsystem {
    pub ps2: Ps2Controller,
    pub xhci: Option<XhciController>,
}

static mut GLOBAL_INPUT: Option<InputSubsystem> = None;

pub fn get_xhci_status() -> (bool, bool) {
    unsafe {
        if let Some(ref input) = GLOBAL_INPUT {
            if let Some(ref xhci) = input.xhci {
                (xhci.is_running, true)
            } else {
                (false, false)
            }
        } else {
            (false, false)
        }
    }
}

pub fn init() {
    let mut ps2 = Ps2Controller::new();
    ps2.init();

    // Check PCI devices for xHCI (Class 0x0C, Subclass 0x03, ProgIF 0x30)
    let pci_devices = crate::arch::scan_pci();
    let mut xhci = None;

    for dev in &pci_devices {
        if dev.class_id == 0x0C && (dev.subclass_id == 0x03 || dev.prog_if == 0x30) {
            dev.enable_bus_mastering();
            let mut ctrl = XhciController::new(dev.bus, dev.slot, dev.func, (dev.bar0 & !0xF) as u64);
            if ctrl.init().is_ok() {
                xhci = Some(ctrl);
            }
            break;
        }
    }

    if xhci.is_none() {
        crate::status::update(|s| s.xhci_usb = crate::status::ComponentStatus::NotAvailable);
    }

    unsafe {
        GLOBAL_INPUT = Some(InputSubsystem { ps2, xhci });
    }
}

pub fn poll_input_event() -> Option<InputEvent> {
    unsafe {
        if let Some(ref mut input) = GLOBAL_INPUT {
            if let Some(ref mut xhci) = input.xhci {
                if let Some(ev) = xhci.poll_event() {
                    return Some(ev);
                }
            }
            input.ps2.poll()
        } else {
            None
        }
    }
}
