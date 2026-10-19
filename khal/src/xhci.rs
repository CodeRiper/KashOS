//! xHCI (Extensible Host Controller Interface) & USB HID Specification Data Structures
//!
//! Grounded in the official xHCI Specification (v1.1) and USB HID 1.11 Boot Protocol:
//! - TRB (Transfer Request Block) encoding/decoding for Command, Event, and Transfer Rings.
//! - Capability and Operational register bitfields and MMIO offsets.
//! - Standard USB Boot Keyboard (8-byte) & Boot Mouse (3/4-byte) HID report decoders.

use crate::{InputEvent, KeyCode};

// ── TRB (Transfer Request Block) ─────────────────────────────────────────────

pub const TRB_TYPE_NORMAL: u8                     = 1;
pub const TRB_TYPE_SETUP_STAGE: u8                = 2;
pub const TRB_TYPE_DATA_STAGE: u8                 = 3;
pub const TRB_TYPE_STATUS_STAGE: u8               = 4;
pub const TRB_TYPE_LINK: u8                       = 6;
pub const TRB_TYPE_ENABLE_SLOT: u8                = 9;
pub const TRB_TYPE_DISABLE_SLOT: u8               = 10;
pub const TRB_TYPE_ADDRESS_DEVICE: u8             = 11;
pub const TRB_TYPE_CONFIGURE_ENDPOINT: u8         = 12;
pub const TRB_TYPE_TRANSFER_EVENT: u8             = 32;
pub const TRB_TYPE_COMMAND_COMPLETION: u8         = 33;
pub const TRB_TYPE_PORT_STATUS_CHANGE: u8         = 34;
pub const TRB_TYPE_HOST_CONTROLLER_EVENT: u8      = 37;

pub const TRB_COMP_SUCCESS: u8                    = 1;
pub const TRB_COMP_DATA_BUFFER_ERROR: u8          = 2;
pub const TRB_COMP_BABBLE_DETECTED: u8            = 3;
pub const TRB_COMP_TRANSACTION_ERROR: u8          = 4;
pub const TRB_COMP_TRB_ERROR: u8                  = 5;
pub const TRB_COMP_STALL_ERROR: u8                = 6;

/// 16-byte aligned xHCI Transfer Request Block (TRB)
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub const fn new(parameter: u64, status: u32, control: u32) -> Self {
        Self { parameter, status, control }
    }

    pub fn build(trb_type: u8, parameter: u64, status: u32, cycle: bool) -> Self {
        let control = ((trb_type as u32) << 10) | if cycle { 1 } else { 0 };
        Self { parameter, status, control }
    }

    pub fn trb_type(&self) -> u8 {
        ((self.control >> 10) & 0x3F) as u8
    }

    pub fn cycle_bit(&self) -> bool {
        (self.control & 1) != 0
    }

    pub fn completion_code(&self) -> u8 {
        ((self.status >> 24) & 0xFF) as u8
    }

    pub fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }

    pub fn endpoint_id(&self) -> u8 {
        ((self.control >> 16) & 0x1F) as u8
    }
}

// ── Register Definitions ─────────────────────────────────────────────────────

pub const XHCI_CAP_CAPLENGTH: usize = 0x00;
pub const XHCI_CAP_HCIVERSION: usize = 0x02;
pub const XHCI_CAP_HCSPARAMS1: usize = 0x04;
pub const XHCI_CAP_HCSPARAMS2: usize = 0x08;
pub const XHCI_CAP_HCCPARAMS1: usize = 0x10;
pub const XHCI_CAP_DBOFF: usize      = 0x14;
pub const XHCI_CAP_RTSOFF: usize     = 0x18;

pub const XHCI_OP_USBCMD: usize   = 0x00;
pub const XHCI_OP_USBSTS: usize   = 0x04;
pub const XHCI_OP_PAGESIZE: usize = 0x08;
pub const XHCI_OP_DNCTRL: usize   = 0x14;
pub const XHCI_OP_CRCR: usize     = 0x18;
pub const XHCI_OP_DCBAAP: usize   = 0x30;
pub const XHCI_OP_CONFIG: usize   = 0x38;

pub const USBCMD_RS: u32    = 1 << 0; // Run / Stop
pub const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
pub const USBCMD_INTE: u32  = 1 << 2; // Interrupter Enable
pub const USBCMD_HSEE: u32  = 1 << 3; // Host System Error Enable

pub const USBSTS_HCH: u32  = 1 << 0;  // Host Controller Halted
pub const USBSTS_HSE: u32  = 1 << 2;  // Host System Error
pub const USBSTS_EINT: u32 = 1 << 3;  // Event Interrupt
pub const USBSTS_PCD: u32  = 1 << 4;  // Port Change Detect
pub const USBSTS_CNR: u32  = 1 << 11; // Controller Not Ready

pub const PORTSC_CCS: u32        = 1 << 0;  // Current Connect Status
pub const PORTSC_PED: u32        = 1 << 1;  // Port Enabled/Disabled
pub const PORTSC_PR: u32         = 1 << 4;  // Port Reset
pub const PORTSC_PP: u32         = 1 << 9;  // Port Power
pub const PORTSC_SPEED_MASK: u32 = 0x0F << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsbSpeed {
    FullSpeed,  // 12 Mb/s (USB 1.1/2.0)
    LowSpeed,   // 1.5 Mb/s (USB 1.0/1.1)
    HighSpeed,  // 480 Mb/s (USB 2.0)
    SuperSpeed, // 5 Gb/s (USB 3.0)
    Unknown,
}

impl UsbSpeed {
    pub fn from_port_speed(speed: u8) -> Self {
        match speed {
            1 => UsbSpeed::FullSpeed,
            2 => UsbSpeed::LowSpeed,
            3 => UsbSpeed::HighSpeed,
            4 => UsbSpeed::SuperSpeed,
            _ => UsbSpeed::Unknown,
        }
    }
}

// ── Standard USB HID Decoders ────────────────────────────────────────────────

/// Decodes an 8-byte USB boot keyboard report into KeyCode and InputEvent
pub fn decode_usb_keyboard_report(report: &[u8; 8]) -> Option<InputEvent> {
    // Byte 0: Modifier bits
    // Byte 2..7: Up to 6 simultaneous keycodes
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
        0x1E => KeyCode::Num1,
        0x1F => KeyCode::Num2,
        0x20 => KeyCode::Num3,
        0x21 => KeyCode::Num4,
        0x22 => KeyCode::Num5,
        0x23 => KeyCode::Num6,
        0x24 => KeyCode::Num7,
        0x25 => KeyCode::Num8,
        0x26 => KeyCode::Num9,
        0x27 => KeyCode::Num0,
        0x28 => KeyCode::Enter,
        0x29 => KeyCode::Escape,
        0x2A => KeyCode::Backspace,
        0x2B => KeyCode::Tab,
        0x2C => KeyCode::Space,
        0x2D => KeyCode::Minus,
        0x2E => KeyCode::Equal,
        0x2F => KeyCode::LeftBracket,
        0x30 => KeyCode::RightBracket,
        0x31 => KeyCode::Backslash,
        0x33 => KeyCode::Semicolon,
        0x34 => KeyCode::Quote,
        0x35 => KeyCode::Grave,
        0x36 => KeyCode::Comma,
        0x37 => KeyCode::Period,
        0x38 => KeyCode::Slash,
        0x39 => KeyCode::CapsLock,
        0x3A => KeyCode::F1,
        0x3B => KeyCode::F2,
        0x3C => KeyCode::F3,
        0x3D => KeyCode::F4,
        0x3E => KeyCode::F5,
        0x3F => KeyCode::F6,
        0x40 => KeyCode::F7,
        0x41 => KeyCode::F8,
        0x42 => KeyCode::F9,
        0x43 => KeyCode::F10,
        0x44 => KeyCode::F11,
        0x45 => KeyCode::F12,
        0x49 => KeyCode::Insert,
        0x4A => KeyCode::Home,
        0x4B => KeyCode::PageUp,
        0x4C => KeyCode::Delete,
        0x4D => KeyCode::End,
        0x4E => KeyCode::PageDown,
        0x4F => KeyCode::Right,
        0x50 => KeyCode::Left,
        0x51 => KeyCode::Down,
        0x52 => KeyCode::Up,
        _ => KeyCode::Unknown,
    };

    Some(InputEvent::KeyDown(key))
}

/// Decodes standard USB boot mouse report (buttons, dx, dy, optional wheel)
pub fn decode_usb_mouse_report(
    report: &[u8],
    prev_buttons: &mut u8,
) -> (Option<InputEvent>, Option<InputEvent>) {
    if report.len() < 3 {
        return (None, None);
    }

    let buttons = report[0];
    let dx = (report[1] as i8) as i32;
    let dy = (report[2] as i8) as i32;

    let button_event = if buttons != *prev_buttons {
        let released = *prev_buttons & !buttons;
        let pressed = buttons & !*prev_buttons;
        *prev_buttons = buttons;
        if pressed != 0 {
            Some(InputEvent::MouseButtonDown {
                left: (pressed & 1) != 0,
                right: (pressed & 2) != 0,
                middle: (pressed & 4) != 0,
            })
        } else if released != 0 {
            Some(InputEvent::MouseButtonUp {
                left: (released & 1) != 0,
                right: (released & 2) != 0,
                middle: (released & 4) != 0,
            })
        } else {
            None
        }
    } else {
        None
    };

    let motion_event = if dx != 0 || dy != 0 {
        Some(InputEvent::MouseMove { dx, dy })
    } else if report.len() >= 4 && report[3] != 0 {
        let wheel = (report[3] as i8) as i32;
        Some(InputEvent::MouseWheel { dx: 0, dy: wheel })
    } else {
        None
    };

    (button_event, motion_event)
}
