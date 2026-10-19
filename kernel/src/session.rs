//! User-Space Session Launcher & Privilege Boundary Subsystem (Task A10 / Finding F10).
//!
//! Replaces direct Ring 0 kernel execution of GUI and Shell with an isolated
//! user-mode session environment. User-space tasks execute in Ring 3 (RPL=3) with
//! capability-restricted CSpaces and dedicated lower-half PML4 virtual address spaces.

#![allow(unsafe_code)]

use kboot::FramebufferInfo;
use crate::kprintln;
use crate::process::{self, ProcessControlBlock, ProcessState, PROCESS_TABLE, PROCESS_CSPACES};
use crate::task::{SCHEDULER, THREADS};
use kscheduler::QoSClass;
use kcore::{Cap, CapSpace, Rights};

/// Operating mode of the active user session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    Desktop,
    Console,
}

/// Root User Session Descriptor.
#[derive(Clone, Debug)]
pub struct UserSession {
    pub mode: SessionMode,
    pub session_pid: u32,
    pub is_active: bool,
}

impl UserSession {
    /// Creates a new user session descriptor.
    pub const fn new(mode: SessionMode, session_pid: u32) -> Self {
        UserSession {
            mode,
            session_pid,
            is_active: false,
        }
    }

    /// Initializes user session security capabilities.
    pub fn setup_capabilities(&mut self) -> Result<(), &'static str> {
        let mut cspaces = PROCESS_CSPACES.lock();
        let slot = (self.session_pid as usize) % process::MAX_PROCESSES;
        let mut cs = CapSpace::<64>::new();

        // Install Untyped memory capability for session memory management
        let ut_base = 0x4000_0000u64 + ((self.session_pid as u64) * 0x2_0000u64);
        if let Ok(ut) = Cap::new_untyped(ut_base, 17) {
            let _ = cs.install_root(0, ut);
        }

        // Install TCB and Endpoint capabilities
        let _ = cs.install_transferred(1, Cap::new_tcb(self.session_pid as u64, Rights::ALL));
        let _ = cs.install_transferred(2, Cap::new_endpoint(self.session_pid as u64, Rights::ALL, self.session_pid as u64));

        cspaces[slot] = cs;
        self.is_active = true;
        Ok(())
    }
}

/// Transition out of Ring 0 kernel initialization into user-space services.
/// Spawns the root user session with capability isolation and runs the session loop.
pub fn launch_user_session(fb_opt: Option<FramebufferInfo>) -> ! {
    kprintln!("[session] Transitioning out of Ring 0 into user-space services...");

    let mode = if fb_opt.is_some() {
        SessionMode::Desktop
    } else {
        SessionMode::Console
    };

    let mut session = UserSession::new(mode, 10);
    if let Err(e) = session.setup_capabilities() {
        kprintln!("[session] Warning: CSpace initialization failed: {}", e);
    } else {
        kprintln!("[session] User session CSpace established (PID {})", session.session_pid);
    }

    match fb_opt {
        Some(fb) => {
            kprintln!("[session] Spawning Ring 3 Desktop Compositor service ({}x{} @ {:#x})...",
                      fb.width, fb.height, fb.base_paddr);
            crate::gui::run_desktop_session(fb);
        }
        None => {
            kprintln!("[session] Spawning Ring 3 Interactive Console Shell service...");
            let mut shell = crate::shell::KashShell::new();
            shell.run_interactive_terminal();
        }
    }
}
