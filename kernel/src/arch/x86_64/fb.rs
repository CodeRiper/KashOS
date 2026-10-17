//! Linear 32-bit Framebuffer Detection, Acquisition & Video Output.
#![allow(unsafe_code)]

use kboot::FramebufferInfo;
use crate::arch::x86_64::{pci, vbox::VBoxBgaDisplay};

static mut ACTIVE_FRAMEBUFFER: Option<FramebufferInfo> = None;

/// Sets the active framebuffer information discovered from boot or hardware fallback.
pub fn set_framebuffer(fb: FramebufferInfo) {
    unsafe {
        ACTIVE_FRAMEBUFFER = Some(fb);
    }
}

/// Returns the currently active framebuffer descriptor, if present.
pub fn get_framebuffer() -> Option<FramebufferInfo> {
    unsafe { ACTIVE_FRAMEBUFFER }
}

/// Attempts to acquire a hardware linear framebuffer via Bochs/VirtualBox BGA and PCI BAR0.
/// Used as a transparent fallback on QEMU and VirtualBox when the bootloader didn't provide video.
pub fn acquire_bga_fallback(width: u32, height: u32) -> Option<FramebufferInfo> {
    if !VBoxBgaDisplay::is_available() {
        return None;
    }

    // Find display controller BAR0 without heap allocation
    let bar0_paddr = match pci::find_display_bar0() {
        Some(addr) => addr,
        None => return None,
    };

    // Program BGA hardware registers for 32 bpp linear framebuffer
    if VBoxBgaDisplay::set_resolution(width as u16, height as u16, 32).is_err() {
        return None;
    }

    let pitch = width * 4;
    let size_bytes = (pitch as u64) * (height as u64);

    let fb = FramebufferInfo {
        base_paddr: bar0_paddr,
        size_bytes,
        width,
        height,
        pitch,
        bits_per_pixel: 32,
        red_mask_size: 8,
        green_mask_size: 8,
        blue_mask_size: 8,
    };

    set_framebuffer(fb);
    Some(fb)
}

/// Fills the entire framebuffer with a smooth RGB gradient test pattern to verify pixel blitting.
pub fn fill_gradient_test(fb: &FramebufferInfo) {
    if fb.base_paddr == 0 || fb.width == 0 || fb.height == 0 {
        return;
    }

    let ptr = fb.base_paddr as *mut u32;
    let pitch_u32 = (fb.pitch / 4) as usize;

    for y in 0..fb.height {
        let r = ((y * 255) / fb.height) as u32;
        let row_offset = (y as usize) * pitch_u32;
        for x in 0..fb.width {
            let b = ((x * 255) / fb.width) as u32;
            let g = ((x + y) * 128 / (fb.width + fb.height)) as u32;
            let color = (r << 16) | (g << 8) | b;
            unsafe {
                core::ptr::write_volatile(ptr.add(row_offset + (x as usize)), color);
            }
        }
    }
}

/// Clears the linear framebuffer to a solid 32-bit color.
pub fn clear_framebuffer(fb: &FramebufferInfo, color: u32) {
    if fb.base_paddr == 0 || fb.width == 0 || fb.height == 0 {
        return;
    }

    let ptr = fb.base_paddr as *mut u32;
    let pitch_u32 = (fb.pitch / 4) as usize;

    for y in 0..fb.height {
        let row_offset = (y as usize) * pitch_u32;
        for x in 0..fb.width {
            unsafe {
                core::ptr::write_volatile(ptr.add(row_offset + (x as usize)), color);
            }
        }
    }
}
