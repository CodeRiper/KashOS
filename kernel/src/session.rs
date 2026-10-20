//! Kernel-resident desktop and console entry points.
//!
//! These paths keep the interactive shell and compositor in Ring 0. They are
//! retained for the prototype boot flow, but are not isolated user services.
//! A real user session requires loading and scheduling a user ELF process with
//! a verified address space and capability set; that integration is not wired
//! into the normal boot path yet.

use kboot::FramebufferInfo;

/// Start the current prototype UI path. The desktop and console execute in
/// the kernel address space until real user-mode service integration exists.
pub fn launch_kernel_resident_session(fb_opt: Option<FramebufferInfo>) -> ! {
    let storage_unlocked = crate::vfs::is_root_mounted();

    match (fb_opt, storage_unlocked) {
        (Some(fb), true) => {
            crate::kprintln!(
                "[session] Starting kernel-resident desktop ({}x{}); Ring 3 service isolation is unavailable",
                fb.width, fb.height
            );
            crate::gui::run_desktop_session(fb);
        }
        (fb, _) => {
            if fb.is_some() {
                crate::kprintln!("[session] Storage is locked; starting kernel-resident unlock console");
            } else {
                crate::kprintln!("[session] Starting kernel-resident console; user-mode shell is unavailable");
            }
            let mut shell = crate::shell::KashShell::with_framebuffer(fb);
            shell.run_interactive_terminal();
        }
    }
}
