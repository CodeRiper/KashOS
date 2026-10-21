//! x86-64 FPU / SSE / SSE2 Hardware Control & Register State.
#![allow(unsafe_code)]

/// Enables SSE and SSE2 support in the CPU control registers.
/// Sets CR0: EM=0, MP=1, NE=1.
/// Sets CR4: OSFXSR=1 (bit 9), OSXMMEXCPT=1 (bit 10).
pub fn enable_sse() {
    unsafe {
        // 1. CR0: Clear EM (bit 2), Set MP (bit 1), Set NE (bit 5)
        let mut cr0: u64;
        core::arch::asm!("mov {0}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        cr0 &= !(1 << 2); // EM = 0 (no emulation)
        cr0 |= 1 << 1;   // MP = 1 (monitor coprocessor)
        cr0 |= 1 << 5;   // NE = 1 (native x87 exception handling)
        core::arch::asm!("mov cr0, {0}", in(reg) cr0, options(nostack, preserves_flags));

        // 2. CR4: Set OSFXSR (bit 9) and OSXMMEXCPT (bit 10)
        let mut cr4: u64;
        core::arch::asm!("mov {0}, cr4", out(reg) cr4, options(nostack, preserves_flags));
        cr4 |= 1 << 9;   // OSFXSR: enable SSE instructions & fxsave/fxrstor
        cr4 |= 1 << 10;  // OSXMMEXCPT: enable unmasked SIMD floating-point exceptions
        core::arch::asm!("mov cr4, {0}", in(reg) cr4, options(nostack, preserves_flags));

        // 3. Initialize FPU unit
        core::arch::asm!("fninit", options(nostack));
    }
}

/// Self-test validating that SSE2 floating-point arithmetic works
/// without generating an Invalid Opcode (#UD) or Device Not Available (#NM) fault.
pub fn selftest() {
    enable_sse();
    let a: f32 = 3.5;
    let b: f32 = 2.0;
    let c: f32 = a * b + 1.5;
    if (c - 8.5).abs() > 0.001 {
        panic!("FPU/SSE self-test failed: computation mismatch");
    }
    timer_interrupt_preserves_sse_state();
    crate::kprintln!("[fpu] SSE/SSE2 enabled: CR0(EM=0,MP=1) CR4(OSFXSR=1,OSXMMEXCPT=1)");
}

/// Exercise the timer ISR's no-switch path with a live XMM register value.
fn timer_interrupt_preserves_sse_state() {
    let sentinel = [
        0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0, 0x31, 0x75, 0xb9, 0xfd, 0x42, 0x86,
        0xca, 0x0e,
    ];
    let mut observed = [0u8; 16];
    // SAFETY: Called after IDT, task, and APIC setup on the BSP. Vector 32 is
    // the initialized kernel timer gate; the single registered boot task means
    // this checks the same-task restore path without waiting for hardware time.
    unsafe {
        core::arch::asm!(
            "movdqu xmm15, xmmword ptr [{sentinel}]",
            "int 0x20",
            "movdqu xmmword ptr [{observed}], xmm15",
            sentinel = in(reg) sentinel.as_ptr(),
            observed = in(reg) observed.as_mut_ptr(),
            lateout("xmm15") _,
        );
    }
    if observed != sentinel {
        panic!("FPU/SSE timer interrupt preservation test failed");
    }
    crate::kprintln!("[fpu] timer ISR preserved live XMM state on same-task path");
}

/// 512-byte aligned buffer for saving/restoring FPU/MMX/SSE/XMM state via `fxsave64`/`fxrstor64`.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FpuState {
    pub buffer: [u8; 512],
}

impl FpuState {
    /// Build the x87/SSE reset image used before a thread has saved its own state.
    ///
    /// FXSAVE stores FCW at bytes 0..2 and MXCSR at bytes 24..28.  A zeroed
    /// image changes the normal exception masks and rounding mode, so it is not
    /// a safe initial state for a thread that will be restored with FXRSTOR.
    pub const fn initial() -> Self {
        let mut buffer = [0u8; 512];
        // FNINIT default x87 control word: all exceptions masked, round-to-nearest.
        buffer[0] = 0x7f;
        buffer[1] = 0x03;
        // Architectural default MXCSR: exceptions masked, round-to-nearest.
        buffer[24] = 0x80;
        buffer[25] = 0x1f;
        FpuState { buffer }
    }

}
