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
        KeyCode::Delete => (Key::Delete, '\x7f'),
        KeyCode::Home => (Key::Home, '\0'),
        KeyCode::End => (Key::End, '\0'),
        KeyCode::PageUp => (Key::PageUp, '\0'),
        KeyCode::PageDown => (Key::PageDown, '\0'),
        _ => return None,
    };

    Some(KeyEv { key, ch, ctrl, shift, alt })
}

/// Keeps a requested logical renderer size inside the detected output bounds.
fn fit_render_size(output_width: u32, output_height: u32, max_width: u32, max_height: u32) -> (u32, u32) {
    let output_width = output_width.max(1);
    let output_height = output_height.max(1);
    let scale = (max_width as f32 / output_width as f32)
        .min(max_height as f32 / output_height as f32)
        .min(1.0);
    (
        ((output_width as f32 * scale) as u32).max(1),
        ((output_height as f32 * scale) as u32).max(1),
    )
}

/// Blits the Desktop screen canvas (32-bit ARGB/XRGB) to the hardware linear framebuffer.
#[inline]
fn blit_canvas_to_fb(px: &[u32], src_width: usize, src_height: usize, fb: &FramebufferInfo) {
    let width = fb.width as usize;
    let height = fb.height as usize;
    let pitch_u32 = (fb.pitch / 4) as usize;
    let fb_ptr = fb.base_paddr as *mut u32;

    if src_width == width && src_height == height && pitch_u32 == width {
        // Fast contiguous copy
        unsafe {
            core::ptr::copy_nonoverlapping(px.as_ptr(), fb_ptr, width * height);
        }
    } else if src_width != width || src_height != height {
        // Nearest-neighbour upscale for the low-memory compositor mode.
        for y in 0..height {
            let sy = y * src_height / height;
            for x in 0..width {
                let sx = x * src_width / width;
                unsafe { fb_ptr.add(y * pitch_u32 + x).write(*px.get_unchecked(sy * src_width + sx)); }
            }
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

/// Present a localized dirty rectangle to hardware VRAM.
#[inline]
fn blit_rect_to_fb(
    px: &[u32],
    src_width: usize,
    src_height: usize,
    fb: &FramebufferInfo,
    x0: usize,
    y0: usize,
    x1: usize,
    y1: usize,
) {
    let width = fb.width as usize;
    let height = fb.height as usize;
    let pitch_u32 = (fb.pitch / 4) as usize;
    let fb_ptr = fb.base_paddr as *mut u32;

    if src_width == 0 || src_height == 0 || width == 0 || height == 0 {
        return;
    }
    // The dirty rectangle is in compositor coordinates. Convert it to the
    // framebuffer's pixel grid before sampling so low-memory mode never reads
    // beyond its smaller source canvas.
    let x0 = (x0.min(src_width) * width / src_width).min(width);
    let x1 = ((x1.min(src_width) * width + src_width - 1) / src_width).min(width);
    let y0 = (y0.min(src_height) * height / src_height).min(height);
    let y1 = ((y1.min(src_height) * height + src_height - 1) / src_height).min(height);

    if x0 >= x1 || y0 >= y1 {
        return;
    }

    for y in y0..y1 {
        let sy = y * src_height / height;
        for x in x0..x1 {
            let sx = x * src_width / width;
            unsafe {
                fb_ptr.add(y * pitch_u32 + x)
                    .write(*px.get_unchecked(sy * src_width + sx));
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
    // Full-resolution software canvases multiply the framebuffer size several
    // times (desktop, wallpaper, scene, lock layer and window caches). Keep
    // 100 MiB machines usable by rendering at 640x480 when the heap is small.
    let (initial_render_width, initial_render_height) = if free_before < 32 * 1024 * 1024 {
        let scale = (640.0 / fb.width as f32).min(480.0 / fb.height as f32).min(1.0);
        (((fb.width as f32 * scale) as u32).max(1), ((fb.height as f32 * scale) as u32).max(1))
    } else {
        (fb.width, fb.height)
    };
    let mut render_width = initial_render_width;
    let mut render_height = initial_render_height;
    crate::kprintln!("[gui] compositor resolution: {}x{}{}", render_width, render_height,
                     if render_width != fb.width || render_height != fb.height { " (low-memory mode)" } else { "" });
    let mut desktop = Desktop::new(render_width as i32, render_height as i32, /* boot = */ false);
    desktop.sys.display_output = kash_ui::geom::Rect::new(0.0, 0.0, fb.width as f32, fb.height as f32);
    if render_width != fb.width || render_height != fb.height { desktop.set_low_memory_mode(); }
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

    let mut active_display_scale = desktop.sys.display_scale;
    let mut mouse_x = (render_width as f32) * 0.5;
    let mut mouse_y = (render_height as f32) * 0.5;
    let mut prev_cursor_x = mouse_x;
    let mut prev_cursor_y = mouse_y;
    let mut left_button = false;
    let mut right_button = false;
    let mut prev_left_button = false;
    let mut prev_right_button = false;
    let mut shift_held = false;
    let mut ctrl_held = false;
    let mut alt_held = false;

    let mut frame_count: u64 = 0;
    let mut fps_timer: f32 = 0.0;
    let mut fps_frames: u32 = 0;

    crate::kprintln!("[gui] Entering Liquid-Glass compositor main render loop...");

    loop {
        let frame_start_tsc = crate::arch::rdtsc();
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
        let mut mouse_moved = false;

        while let Some(ev) = crate::arch::poll_input_event() {
            match ev {
                InputEvent::MouseMove { dx, dy } => {
                    let pointer_speed = desktop.sys.pointer_speed.clamp(0.5, 2.0);
                    // PS/2 reports relative device motion, not absolute framebuffer
                    // coordinates. Applying the render-to-output scale here made
                    // pointers sluggish whenever low-memory rendering was enabled.
                    mouse_x = (mouse_x + dx as f32 * pointer_speed).clamp(0.0, (render_width - 1) as f32);
                    mouse_y = (mouse_y + dy as f32 * pointer_speed).clamp(0.0, (render_height - 1) as f32);
                    mouse_moved = true;
                }
                InputEvent::MouseButtonDown { left, right, .. } => {
                    if left { left_button = true; }
                    if right { right_button = true; }
                    // Deliver this edge in its own desktop frame. Draining a
                    // press and release together would collapse both into the
                    // final button state before widgets can observe the click.
                    break;
                }
                InputEvent::MouseButtonUp { left, right, .. } => {
                    if left { left_button = false; }
                    if right { right_button = false; }
                    break;
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
            keys: key_events.clone(),
            dt,
        };

        let has_keys = !key_events.is_empty();
        let button_changed = left_button != prev_left_button || right_button != prev_right_button;
        prev_left_button = left_button;
        prev_right_button = right_button;

        // Render one complete desktop frame
        if frame_count < 3 {
            crate::kprintln!("[gui] rendering frame {} (dt={:.3}s)...", frame_count, dt);
        }
        let full_scene_before = desktop.stats_full;
        desktop.frame(&input);
        let scene_redrawn = desktop.stats_full != full_scene_before;

        // Apply the renderer scale only after the Settings frame has finished,
        // so its current canvas cannot be resized while it is being drawn.
        let mut resized = false;
        if desktop.sys.display_scale != active_display_scale {
            let requested = desktop.sys.display_scale;
            let (next_width, next_height) = match requested {
                0 => (initial_render_width, initial_render_height),
                1 => fit_render_size(fb.width, fb.height, 640, 480),
                2 => fit_render_size(fb.width, fb.height, 800, 600),
                // Larger compositor mode follows detected output aspect ratio and
                // caps software-canvas allocation for low-memory machines.
                _ => fit_render_size(fb.width, fb.height, 1280, 800),
            };
            let grows = (next_width as u64) * (next_height as u64) > (render_width as u64) * (render_height as u64);
            if !grows || crate::heap::free_bytes() >= 7 * 1024 * 1024 {
                let old_width = render_width as f32;
                let old_height = render_height as f32;
                desktop.resize(next_width as i32, next_height as i32);
                mouse_x = (mouse_x * next_width as f32 / old_width).clamp(0.0, (next_width - 1) as f32);
                mouse_y = (mouse_y * next_height as f32 / old_height).clamp(0.0, (next_height - 1) as f32);
                prev_cursor_x = mouse_x;
                prev_cursor_y = mouse_y;
                render_width = next_width;
                render_height = next_height;
                active_display_scale = requested;
                resized = true;
                crate::kprintln!("[gui] display renderer changed to {}x{} ({} MiB free)", render_width, render_height, crate::heap::free_bytes() / (1024 * 1024));
            } else {
                desktop.sys.display_scale = active_display_scale;
                crate::kprintln!("[gui] display renderer change refused: less than 7 MiB free");
            }
        }
        if frame_count < 3 {
            crate::kprintln!("[gui] frame {} rendered, blitting to fb...", frame_count);
        }

        // Ultra-High-Performance Adaptive VRAM Blitter:
        // When only the cursor moved, blit ONLY the dirty bounding box around the cursor
        // (48x48 px = 9 KB instead of 3.14 MB), reducing emulated bus writes by 99.7%!
        // Full-screen presents follow a real scene redraw. In low-memory mode
        // the logical canvas is smaller than VRAM; treating that dimension
        // difference as a reason to blit every frame made pointer-only motion
        // copy the entire physical display at 20 FPS.
        let needs_full_blit = frame_count < 10
            || has_keys
            || button_changed
            || left_button
            || right_button
            || desktop.lock.visible()
            || scene_redrawn
            || (frame_count % 60 == 0);

        if resized {
            // Keep the existing complete framebuffer visible until the first
            // frame has been drawn at the newly selected logical resolution.
        } else if needs_full_blit {
            blit_canvas_to_fb(&desktop.screen.px, render_width as usize, render_height as usize, &fb);
            prev_cursor_x = mouse_x;
            prev_cursor_y = mouse_y;
        } else if mouse_moved {
            let min_x = (prev_cursor_x.min(mouse_x) - 48.0).max(0.0) as usize;
            let min_y = (prev_cursor_y.min(mouse_y) - 48.0).max(0.0) as usize;
            // x1/y1 are exclusive bounds, so allow the rectangle to reach the
            // full logical width/height when the pointer is near the right or
            // bottom edge.
            let max_x = (prev_cursor_x.max(mouse_x) + 48.0).min(render_width as f32) as usize;
            let max_y = (prev_cursor_y.max(mouse_y) + 48.0).min(render_height as f32) as usize;
            blit_rect_to_fb(
                &desktop.screen.px,
                render_width as usize,
                render_height as usize,
                &fb,
                min_x,
                min_y,
                max_x,
                max_y,
            );
            prev_cursor_x = mouse_x;
            prev_cursor_y = mouse_y;
        }

        if frame_count < 3 {
            crate::kprintln!("[gui] frame {} blit complete! screen.px[0]={:#x}", frame_count, desktop.screen.px.first().copied().unwrap_or(0));
        }

        frame_count += 1;

        // Cap rendering at 60 FPS and yield the single guest CPU between frames.
        // The existing periodic APIC timer wakes HLT; the next iteration polls
        // PS/2 input, limiting pointer latency to roughly one timer interval.
        let tsc_hz = crate::arch::tsc_frequency_hz().max(1_000_000);
        let frame_target_cycles = tsc_hz / 60; // 60 FPS (~16.6ms per frame)
        #[cfg(target_arch = "x86_64")]
        let start_timer_tick = crate::arch::x86_64::idt::timer_ticks();
        while crate::arch::rdtsc().saturating_sub(frame_start_tsc) < frame_target_cycles {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                // The APIC tick is also a fallback bound in case a platform's
                // TSC stops while halted. Two 100 Hz ticks cap the idle wait.
                if crate::arch::x86_64::idt::timer_ticks().wrapping_sub(start_timer_tick) >= 2 {
                    break;
                }
                core::arch::asm!("hlt", options(nomem, nostack));
            }
            #[cfg(not(target_arch = "x86_64"))]
            core::hint::spin_loop();
        }

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
