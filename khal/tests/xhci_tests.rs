//! Tests for xHCI Specification Structures and USB HID Boot Report Decoders

use khal::xhci::{
    decode_usb_keyboard_report, decode_usb_mouse_report, Trb, UsbSpeed,
    TRB_COMP_SUCCESS, TRB_TYPE_COMMAND_COMPLETION, TRB_TYPE_NORMAL, TRB_TYPE_SETUP_STAGE,
    USBCMD_HCRST, USBCMD_INTE, USBCMD_RS, USBSTS_CNR, USBSTS_HCH,
};
use khal::{InputEvent, KeyCode};

#[test]
fn test_trb_serialization_and_fields() {
    let trb = Trb::build(TRB_TYPE_NORMAL, 0x1000_2000, 4096, true);
    assert_eq!(trb.parameter, 0x1000_2000);
    assert_eq!(trb.status, 4096);
    assert_eq!(trb.trb_type(), TRB_TYPE_NORMAL);
    assert!(trb.cycle_bit());

    let setup = Trb::build(TRB_TYPE_SETUP_STAGE, 0x8000_0000, 8, false);
    assert_eq!(setup.trb_type(), TRB_TYPE_SETUP_STAGE);
    assert!(!setup.cycle_bit());

    // Event TRB completion code and slot ID
    let event = Trb {
        parameter: 0,
        status: (TRB_COMP_SUCCESS as u32) << 24,
        control: ((TRB_TYPE_COMMAND_COMPLETION as u32) << 10) | (5 << 24) | 1,
    };
    assert_eq!(event.completion_code(), TRB_COMP_SUCCESS);
    assert_eq!(event.slot_id(), 5);
    assert_eq!(event.trb_type(), TRB_TYPE_COMMAND_COMPLETION);
    assert!(event.cycle_bit());
}

#[test]
fn test_usb_speed_conversion() {
    assert_eq!(UsbSpeed::from_port_speed(1), UsbSpeed::FullSpeed);
    assert_eq!(UsbSpeed::from_port_speed(2), UsbSpeed::LowSpeed);
    assert_eq!(UsbSpeed::from_port_speed(3), UsbSpeed::HighSpeed);
    assert_eq!(UsbSpeed::from_port_speed(4), UsbSpeed::SuperSpeed);
    assert_eq!(UsbSpeed::from_port_speed(99), UsbSpeed::Unknown);
}

#[test]
fn test_xhci_register_constants() {
    assert_eq!(USBCMD_RS, 1);
    assert_eq!(USBCMD_HCRST, 2);
    assert_eq!(USBCMD_INTE, 4);
    assert_eq!(USBSTS_HCH, 1);
    assert_eq!(USBSTS_CNR, 1 << 11);
}

#[test]
fn test_decode_usb_keyboard_report() {
    // Report: [Modifiers, Reserved, Key1, Key2, ...]
    let mut report = [0u8; 8];
    report[2] = 0x04; // Key 'A'
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::A)));

    report[2] = 0x1D; // Key 'Z'
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::Z)));

    report[2] = 0x1E; // Key '1'
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::Num1)));

    report[2] = 0x28; // Enter
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::Enter)));

    report[2] = 0x29; // Escape
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::Escape)));

    report[2] = 0x2A; // Backspace
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::Backspace)));

    report[2] = 0x2C; // Space
    assert_eq!(decode_usb_keyboard_report(&report), Some(InputEvent::KeyDown(KeyCode::Space)));

    report[2] = 0x00; // No key pressed
    assert_eq!(decode_usb_keyboard_report(&report), None);
}

#[test]
fn test_decode_usb_mouse_report() {
    let mut prev_buttons = 0u8;

    // Movement without buttons: dx = 5, dy = -10
    let report1 = [0x00, 5, (-10i8) as u8, 0];
    let (btn, mov) = decode_usb_mouse_report(&report1, &mut prev_buttons);
    assert_eq!(btn, None);
    assert_eq!(mov, Some(InputEvent::MouseMove { dx: 5, dy: -10 }));

    // Left Button Down: button byte = 1
    let report2 = [0x01, 0, 0, 0];
    let (btn, mov) = decode_usb_mouse_report(&report2, &mut prev_buttons);
    assert_eq!(btn, Some(InputEvent::MouseButtonDown { left: true, right: false, middle: false }));
    assert_eq!(mov, None);

    // Left Button Up: button byte = 0
    let report3 = [0x00, 0, 0, 0];
    let (btn, _) = decode_usb_mouse_report(&report3, &mut prev_buttons);
    assert_eq!(btn, Some(InputEvent::MouseButtonUp { left: true, right: false, middle: false }));

    // Scroll Wheel Up: dx=0, dy=0, wheel=1
    let report4 = [0x00, 0, 0, 1];
    let (_, mov) = decode_usb_mouse_report(&report4, &mut prev_buttons);
    assert_eq!(mov, Some(InputEvent::MouseWheel { dx: 0, dy: 1 }));
}
