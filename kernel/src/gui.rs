//! Kash UI Desktop Shell Integration (Ring 0 Kernel GUI Driver).
//!
//! Wires the `kash-ui` software-rendered Liquid-Glass desktop compositor
//! to the hardware linear framebuffer and architecture input streams.

#![allow(unsafe_code)]

extern crate alloc;
use alloc::vec::Vec;
use kboot::FramebufferInfo;
use khal::{InputEvent, KeyCode};
use kash_ui::desktop::{Desktop, Input};
use kash_ui::geom::Pt;
use kash_ui::ui::{Key, KeyEv};

/// Helper to convert a KashOS HAL KeyCode + shift state into a char and kash_ui::ui::Key.
fn map_keycode(kc: KeyCode, shift: bool, ctrl: bool, alt: bool) -> Option<KeyEv> {
    let (key, ch) = match kc {
        KeyCode::A => (Key::Char, if shift { 'A' } else { 'a' }),
        KeyCode::B => (Key::Char, if shift { 'B' } else { 'b' }),
        KeyCode::C => (Key::Char, if shift { 'C' } else { 'c' }),
        KeyCode::D => (Key::Char, if shift { 'D' } else { 'd' }),
        KeyCode::E => (Key::Char, if shift { 'E' } else { 'e' }),
        KeyCode::F => (Key::Char, if shift { 'F' } else { 'f' }),
        KeyCode::G => (Key::Char, if shift { 'G' } else { 'g' }),
        KeyCode::H => (Key::Char, if shift { 'H' } else { 'h' }),
        KeyCode::I => (Key::Char, if shift { 'I' } else { 'i' }),
        KeyCode::J => (Key::Char, if shift { 'J' } else { 'j' }),
        KeyCode::K => (Key::Char, if shift { 'K' } else { 'k' }),
        KeyCode::L => (Key::Char, if shift { 'L' } else { 'l' }),
        KeyCode::M => (Key::Char, if shift { 'M' } else { 'm' }),
        KeyCode::N => (Key::Char, if shift { 'N' } else { 'n' }),
        KeyCode::O => (Key::Char, if shift { 'O' } else { 'o' }),
        KeyCode::P => (Key::Char, if shift { 'P' } else { 'p' }),
        KeyCode::Q => (Key::Char, if shift { 'Q' } else { 'q' }),
        KeyCode::R => (Key::Char, if shift { 'R' } else { 'r' }),
        KeyCode::S => (Key::Char, if shift { 'S' } else { 's' }),
        KeyCode::T => (Key::Char, if shift { 'T' } else { 't' }),
        KeyCode::U => (Key::Char, if shift { 'U' } else { 'u' }),
        KeyCode::V => (Key::Char, if shift { 'V' } else { 'v' }),
        KeyCode::W => (Key::Char, if shift { 'W' } else { 'w' }),
        KeyCode::X => (Key::Char, if shift { 'X' } else { 'x' }),
        KeyCode::Y => (Key::Char, if shift { 'Y' } else { 'y' }),
        KeyCode::Z => (Key::Char, if shift { 'Z' } else { 'z' }),
        KeyCode::Num1 => (Key::Char, if shift { '!' } else { '1' }),
        KeyCode::Num2 => (Key::Char, if shift { '@' } else { '2' }),
        KeyCode::Num3 => (Key::Char, if shift { '#' } else { '3' }),
        KeyCode::Num4 => (Key::Char, if shift { '$' } else { '4' }),
        KeyCode::Num5 => (Key::Char, if shift { '%' } else { '5' }),
        KeyCode::Num6 => (Key::Char, if shift { '^' } else { '6' }),
        KeyCode::Num7 => (Key::Char, if shift { '&' } else { '7' }),
        KeyCode::Num8 => (Key::Char, if shift { '*' } else { '8' }),
        KeyCode::Num9 => (Key::Char, if shift { '(' } else { '9' }),
        KeyCode::Num0 => (Key::Char, if shift { ')' } else { '0' }),
        KeyCode::Enter => (Key::Enter, '\n'),
        KeyCode::Escape => (Key::Escape, '\x1b'),
        KeyCode::Backspace => (Key::Backspace, '\x08'),
        KeyCode::Tab => (Key::Tab, '\t'),
        KeyCode::Space => (Key::Space, ' '),
        KeyCode::Minus => (Key::Char, if shift { '_' } else { '-' }),
        KeyCode::Equal => (Key::Char, if shift { '+' } else { '=' }),
        KeyCode::LeftBracket => (Key::Char, if shift { '{' } else { '[' }),
        KeyCode::RightBracket => (Key::Char, if shift { '}' } else { ']' }),
        KeyCode::Backslash => (Key::Char, if shift { '|' } else { '\\' }),
        KeyCode::Semicolon => (Key::Char, if shift { ':' } else { ';' }),
        KeyCode::Quote => (Key::Char, if shift { '"' } else { '\'' }),
        KeyCode::Grave => (Key::Char, if shift { '~' } else { '`' }),
        KeyCode::Comma => (Key::Char, if shift { '<' } else { ',' }),
        KeyCode::Period => (Key::Char, if shift { '>' } else { '.' }),
        KeyCode::Slash => (Key::Char, if shift { '?' } else { '/' }),
        KeyCode::Up => (Key::Up, '\0'),
        KeyCode::Down => (Key::Down, '\0'),
        KeyCode::Left => (Key::Left, '\0'),
        KeyCode::Right => (Key::Right, '\0'),
        _ => return None,
    };

    Some(KeyEv { key, ch, ctrl, shift, alt })
}

/// Blits the Desktop screen canvas (32-bit ARGB/XRGB) to the hardware linear framebuffer.
#[inline]
fn blit_canvas_to_fb(px: &[u32], fb: &FramebufferInfo) {
    let width = fb.width as usize;
    let height = fb.height as usize;
    let pitch_u32 = (fb.pitch / 4) as usize;
    let fb_ptr = fb.base_paddr as *mut u32;

    if pitch_u32 == width {
        // Fast contiguous copy
        unsafe {
            core::ptr::copy_nonoverlapping(px.as_ptr(), fb_ptr, width * height);
        }
    } else {
        // Stride / pitch adaptation: line-by-line copy
        for y in 0..height {
            let src_offset = y * width;
            let dst_offset = y * pitch_u32;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    px.as_ptr().add(src_offset),
                    fb_ptr.add(dst_offset),
                    width,
                );
            }
        }
    }
}

/// Enters the interactive Kash UI desktop event & render loop.
/// This function never returns.
pub fn run(fb: FramebufferInfo) -> ! {
    crate::kprintln!("[gui] Initializing Kash UI Desktop ({}x{} @ {:#x})...",
                     fb.width, fb.height, fb.base_paddr);

    let (free_b, count_b, max_b) = crate::heap::dump_stats();
    crate::kprintln!("[gui] Heap before Desktop::new: total_free={} bytes ({} MiB), blocks={}, max_block={} bytes ({} MiB)",
                     free_b, free_b / (1024 * 1024), count_b, max_b, max_b / (1024 * 1024));

    let free_before = crate::heap::free_bytes();
    let mut desktop = Desktop::new(fb.width as i32, fb.height as i32, /* boot = */ true);
    let free_after = crate::heap::free_bytes();
    let allocated_bytes = free_before.saturating_sub(free_after);

    crate::kprintln!("[gui] Desktop::new allocated: {} KiB ({:.2} MiB)",
                     allocated_bytes / 1024,
                     (allocated_bytes as f32) / (1024.0 * 1024.0));
    crate::kprintln!("[gui] Remaining heap headroom: {} MiB",
                     free_after / (1024 * 1024));

    // Seed desktop wall clock with real hardware RTC unix timestamp
    let unix_secs = crate::arch::read_rtc_unix_seconds();
    desktop.sys.unix_secs = unix_secs as i64;
    crate::kprintln!("[gui] Desktop synchronized with hardware RTC: {} s UTC", unix_secs);

    let mut mouse_x = (fb.width as f32) * 0.5;
    let mut mouse_y = (fb.height as f32) * 0.5;
    let mut left_button = false;
    let mut right_button = false;
    let mut shift_held = false;
    let mut ctrl_held = false;
    let mut alt_held = false;

    let mut frame_count: u64 = 0;
    let mut fps_timer: f32 = 0.0;
    let mut fps_frames: u32 = 0;

    crate::kprintln!("[gui] Entering Liquid-Glass compositor main render loop...");

    loop {
        let dt = crate::arch::elapsed_seconds().clamp(0.001, 0.05);

        fps_timer += dt;
        fps_frames += 1;
        if fps_timer >= 2.0 {
            let fps = (fps_frames as f32) / fps_timer;
            crate::kprintln!("[gui] frame: {} | FPS: {:.1} | Heap free: {} MiB",
                             frame_count, fps, crate::heap::free_bytes() / (1024 * 1024));
            fps_timer = 0.0;
            fps_frames = 0;
        }

        // Drain pending hardware input events
        let mut key_events: Vec<KeyEv> = Vec::new();
        let wheel = Pt::new(0.0, 0.0);

        while let Some(ev) = crate::arch::poll_input_event() {
            match ev {
                InputEvent::MouseMove { dx, dy } => {
                    mouse_x = (mouse_x + dx as f32).clamp(0.0, (fb.width - 1) as f32);
                    mouse_y = (mouse_y + dy as f32).clamp(0.0, (fb.height - 1) as f32);
                }
                InputEvent::MouseButtonDown { left, right, .. } => {
                    if left { left_button = true; }
                    if right { right_button = true; }
                }
                InputEvent::MouseButtonUp { left, right, .. } => {
                    if left { left_button = false; }
                    if right { right_button = false; }
                }
                InputEvent::KeyDown(kc) => {
                    match kc {
                        KeyCode::LeftShift | KeyCode::RightShift => shift_held = true,
                        KeyCode::LeftCtrl | KeyCode::RightCtrl => ctrl_held = true,
                        KeyCode::LeftAlt | KeyCode::RightAlt => alt_held = true,
                        _ => {
                            if let Some(kev) = map_keycode(kc, shift_held, ctrl_held, alt_held) {
                                key_events.push(kev);
                            }
                        }
                    }
                }
                InputEvent::KeyUp(kc) => {
                    match kc {
                        KeyCode::LeftShift | KeyCode::RightShift => shift_held = false,
                        KeyCode::LeftCtrl | KeyCode::RightCtrl => ctrl_held = false,
                        KeyCode::LeftAlt | KeyCode::RightAlt => alt_held = false,
                        _ => {}
                    }
                }
            }
        }

        let input = Input {
            mouse: Pt::new(mouse_x, mouse_y),
            left: left_button,
            right: right_button,
            wheel,
            keys: key_events,
            dt,
        };

        // Render one complete desktop frame
        desktop.frame(&input);

        // Blit composite canvas to physical display memory
        blit_canvas_to_fb(&desktop.screen.px, &fb);

        frame_count += 1;

        if desktop.exit_requested {
            crate::kprintln!("[gui] Desktop shutdown requested. Powering off system...");
            crate::arch::shutdown(false);
        }

        if desktop.restart_requested {
            crate::kprintln!("[gui] Desktop reboot requested. Resetting CPU...");
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("out 0x64, al", in("al") 0xFEu8, options(nomem, nostack));
            }
            crate::arch::shutdown(false);
        }
    }
}
