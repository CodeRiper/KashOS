//! ARM GICv3 driver (Generic Interrupt Controller v3).
//! Used on QEMU virt, Raspberry Pi 4, and most modern ARM64 SoCs.
//! QEMU virt GICv3 defaults: Distributor @ 0x08000000, Redistributor @ 0x080A0000.
#![allow(unsafe_code)]

// GICv3 Distributor (GICD) register offsets
const GICD_CTLR:       u64 = 0x000;
const GICD_TYPER:      u64 = 0x004;
const GICD_ISENABLER:  u64 = 0x100; // interrupt set-enable (1 bit per IRQ)
const GICD_ICENABLER:  u64 = 0x180; // interrupt clear-enable
const GICD_ICPENDR:    u64 = 0x280; // interrupt clear-pending
const GICD_IPRIORITYR: u64 = 0x400; // priority (1 byte per IRQ)
const GICD_ITARGETSR:  u64 = 0x800; // target CPU (legacy; GICv3 uses affinity)
const GICD_ICFGR:      u64 = 0xC00; // configuration (level/edge)

// GICv3 CPU Interface (ICC system registers, accessed via MSR/MRS)
// Redistributor base (per-CPU, stride 0x20000)
const GICR_BASE:       u64 = 0x0808_0000;
const GICR_TYPER:      u64 = 0x08;
const GICR_WAKER:      u64 = 0x14;
const GICR_SGI_BASE:   u64 = 0x10000; // SGI/PPI register bank offset

const GICD_BASE:       u64 = 0x0800_0000; // QEMU virt default

const GICD_CTLR_ARE_NS: u32 = 1 << 4; // affinity routing enable (non-secure)
const GICD_CTLR_ENGRP1: u32 = 1 << 1; // enable group 1 interrupts
const GICR_WAKER_PS:    u32 = 1 << 1; // ProcessorSleep
const GICR_WAKER_CA:    u32 = 1 << 2; // ChildrenAsleep

#[inline]
unsafe fn gicd_read(off: u64) -> u32 {
    unsafe { core::ptr::read_volatile((GICD_BASE + off) as *const u32) }
}
#[inline]
unsafe fn gicd_write(off: u64, val: u32) {
    unsafe { core::ptr::write_volatile((GICD_BASE + off) as *mut u32, val) };
}
#[inline]
unsafe fn gicr_read(off: u64) -> u32 {
    unsafe { core::ptr::read_volatile((GICR_BASE + off) as *const u32) }
}
#[inline]
unsafe fn gicr_write(off: u64, val: u32) {
    unsafe { core::ptr::write_volatile((GICR_BASE + off) as *mut u32, val) };
}

/// Initialise GICv3 Distributor and Redistributor for CPU 0.
pub fn init() {
    unsafe {
        // ── Distributor ───────────────────────────────────────────────────
        // Disable Distributor while configuring.
        gicd_write(GICD_CTLR, 0);
        // Read number of supported IRQs (ITLinesNumber field × 32 + 32).
        let typer    = gicd_read(GICD_TYPER);
        let num_irqs = ((typer & 0x1F) + 1) * 32;
        // Set all SPIs to lowest priority (0xFF = lowest in GIC priority model).
        for i in (32..num_irqs).step_by(4) {
            gicd_write(GICD_IPRIORITYR + i as u64, 0xA0A0_A0A0);
        }
        // Disable all SPI interrupts.
        for i in (1..num_irqs / 32).map(|x| x * 4) {
            gicd_write(GICD_ICENABLER + i as u64, 0xFFFF_FFFF);
        }
        // Enable Distributor with affinity routing (GICv3 mode) + Group 1.
        gicd_write(GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENGRP1);
        kprintln!("[gic] distributor: {} IRQs supported", num_irqs);

        // ── Redistributor for CPU 0 ──────────────────────────────────────
        // Wake the Redistributor (clear ProcessorSleep).
        let waker = gicr_read(GICR_WAKER);
        gicr_write(GICR_WAKER, waker & !GICR_WAKER_PS);
        // Spin until ChildrenAsleep is clear.
        let mut tries = 0u32;
        while gicr_read(GICR_WAKER) & GICR_WAKER_CA != 0 && tries < 10_000 {
            tries += 1;
        }
        // SGI/PPI bank: set all PPIs to lowest priority.
        gicr_write(GICR_SGI_BASE + 0x400, 0xA0A0_A0A0); // IPRIORITYR SGI 0-3
        gicr_write(GICR_SGI_BASE + 0x404, 0xA0A0_A0A0);
        // Disable all SGI/PPI for now. The generic timer (PPI 30) is left
        // disabled too: nothing has programmed CNTP_CVAL/CNTP_TVAL yet, and
        // enabling an unprogrammed timer comparator risks an immediate,
        // unhandled IRQ before a scheduler exists to service it. Milestone 4
        // (scheduler) is what turns this on, after CNTP_CTL_EL0 is set up.
        gicr_write(GICR_SGI_BASE + 0x180, 0xFFFF_FFFF); // ICENABLER: all off

        // ── CPU interface (System Register Interface, GICv3) ─────────────
        // Enable System Register Interface.
        core::arch::asm!("msr icc_sre_el1, {0}",  in(reg) 1u64, options(nomem));
        // Priority Mask: accept interrupts at priority 0xF0 and above (all).
        core::arch::asm!("msr icc_pmr_el1,  {0}", in(reg) 0xF0u64, options(nomem));
        // Binary Point 0 (no pre-emption subgroups).
        core::arch::asm!("msr icc_bpr1_el1, {0}", in(reg) 0u64, options(nomem));
        // Enable Group 1 interrupts on this CPU.
        core::arch::asm!("msr icc_igrpen1_el1, {0}", in(reg) 1u64, options(nomem));
        core::arch::asm!("isb");
        kprintln!("[gic] redistributor CPU0 woken after {} poll(s)", tries);
    }
}

/// Enable a Shared Peripheral Interrupt by IRQ number.
pub fn enable_irq(irq: u32) {
    if irq < 32 { return; } // SGI/PPI handled above
    let off = GICD_ISENABLER + (irq / 32 * 4) as u64;
    unsafe { gicd_write(off, 1 << (irq % 32)); }
}

/// Disable a Shared Peripheral Interrupt.
pub fn disable_irq(irq: u32) {
    if irq < 32 { return; }
    let off = GICD_ICENABLER + (irq / 32 * 4) as u64;
    unsafe { gicd_write(off, 1 << (irq % 32)); }
}

/// Acknowledge and return the pending interrupt number (ICC_IAR1_EL1).
pub fn ack_irq() -> u32 {
    let iar: u64;
    unsafe {
        core::arch::asm!("mrs {0}, icc_iar1_el1", out(reg) iar, options(nomem));
        core::arch::asm!("isb");
    }
    (iar & 0xFFFFFF) as u32
}

/// Signal end-of-interrupt (ICC_EOIR1_EL1).
pub fn eoi(irq: u32) {
    unsafe {
        core::arch::asm!("msr icc_eoir1_el1, {0}", in(reg) irq as u64, options(nomem));
        core::arch::asm!("isb");
    }
}

/// ARM64 generic exception vector table (EL1).
/// Installed by init_vectors(); all unexpected exceptions are fatal.
pub mod vectors {
    use core::arch::global_asm;

    global_asm!(r#"
    .section .text, "ax"
    .balign 2048                // Vector table must be 2KiB aligned
    .global _el1_vectors
    _el1_vectors:

    // ── Current EL with SP0 ─────────────────────────────────────────────
    .balign 128; b _exc_sync_el1sp0
    .balign 128; b _exc_irq_el1sp0
    .balign 128; b _exc_fiq_el1sp0
    .balign 128; b _exc_serr_el1sp0

    // ── Current EL with SPx ─────────────────────────────────────────────
    .balign 128; b _exc_sync_el1spx
    .balign 128; b _exc_irq_el1spx
    .balign 128; b _exc_fiq_el1spx
    .balign 128; b _exc_serr_el1spx

    // ── Lower EL (AArch64) ──────────────────────────────────────────────
    .balign 128; b _exc_sync_lower64
    .balign 128; b _exc_irq_lower64
    .balign 128; b _exc_fiq_lower64
    .balign 128; b _exc_serr_lower64

    // ── Lower EL (AArch32) ──────────────────────────────────────────────
    .balign 128; b _exc_sync_lower32
    .balign 128; b _exc_irq_lower32
    .balign 128; b _exc_fiq_lower32
    .balign 128; b _exc_serr_lower32

    /* Fatal: all exceptions jump here with x0 = exception class string ptr */
    .macro exc_fatal label, name
    \label:
        stp  x0, x1,   [sp, #-16]!
        stp  x2, x3,   [sp, #-16]!
        stp  x29, x30, [sp, #-16]!
        mrs  x0, esr_el1
        mrs  x1, far_el1
        mrs  x2, elr_el1
        bl   aarch64_exception_handler
    1:  wfe ; b 1b
    .endm

    exc_fatal _exc_sync_el1sp0,  "sync-el1sp0"
    exc_fatal _exc_irq_el1sp0,   "irq-el1sp0"
    exc_fatal _exc_fiq_el1sp0,   "fiq-el1sp0"
    exc_fatal _exc_serr_el1sp0,  "serr-el1sp0"
    exc_fatal _exc_sync_el1spx,  "sync-el1spx"

    /* IRQ from current EL with SPx — this is the normal kernel IRQ path */
    _exc_irq_el1spx:
        stp  x0, x1,   [sp, #-16]!
        bl   aarch64_irq_handler
        ldp  x0, x1,   [sp], #16
        eret

    exc_fatal _exc_fiq_el1spx,   "fiq-el1spx"
    exc_fatal _exc_serr_el1spx,  "serr-el1spx"
    exc_fatal _exc_sync_lower64, "sync-lower64"
    exc_fatal _exc_irq_lower64,  "irq-lower64"
    exc_fatal _exc_fiq_lower64,  "fiq-lower64"
    exc_fatal _exc_serr_lower64, "serr-lower64"
    exc_fatal _exc_sync_lower32, "sync-lower32"
    exc_fatal _exc_irq_lower32,  "irq-lower32"
    exc_fatal _exc_fiq_lower32,  "fiq-lower32"
    exc_fatal _exc_serr_lower32, "serr-lower32"
    "#);

    #[no_mangle]
    pub extern "C" fn aarch64_exception_handler(esr: u64, far: u64, elr: u64) -> ! {
        kprintln!("\n[EXCEPTION] AArch64 fatal exception (fail-closed)");
        kprintln!("  ESR_EL1={:#018x}  FAR_EL1={:#018x}  ELR_EL1={:#018x}",
                  esr, far, elr);
        kprintln!("  EC={:#x}  ISS={:#x}", (esr >> 26) & 0x3F, esr & 0x1FF_FFFF);
        crate::arch::shutdown(true)
    }

    #[no_mangle]
    pub extern "C" fn aarch64_irq_handler() {
        let irq = super::ack_irq();
        if irq == 1023 { return; } // spurious
        // In milestone 1 all IRQs are unexpected.
        kprintln!("[irq] unexpected IRQ {} — ignoring", irq);
        super::eoi(irq);
    }

    pub fn install() {
        extern "C" { fn _el1_vectors(); }
        let vbar = _el1_vectors as *const () as u64;
        debug_assert!(vbar & 0x7FF == 0, "VBAR must be 2KiB aligned");
        unsafe {
            core::arch::asm!("msr vbar_el1, {0}", in(reg) vbar, options(nomem));
            core::arch::asm!("isb");
        }
        kprintln!("[gic] EL1 vector table installed @ {:#018x}", vbar);
    }
}
