//! AArch64 boot: entry from QEMU virt (EL2 or EL1), drop to EL1, set stack, clear BSS.
//! QEMU passes the DTB address in x0, consistent with the Linux boot protocol for ARM64.
#![allow(unsafe_code)]
use core::arch::global_asm;

global_asm!(r#"
    .section .text.entry, "ax"
    .global _start
_start:
    // x0 = DTB physical address supplied by the boot protocol. On QEMU virt,
    // the ELF is linked above the reserved start-of-RAM area so QEMU can place
    // its DTB there and pass its address through the generated entry stub.
    // A missing pointer is rejected by hardware discovery; the kernel must
    // never invent RAM size or device locations.
    mov  x20, x0

    // ── Determine current exception level ────────────────────────────────
    mrs  x0, CurrentEL
    lsr  x0, x0, #2
    and  x0, x0, #3
    cmp  x0, #2
    b.eq .Lel2_init
    b    .Lel1_init

    // ── EL2 → EL1 drop ───────────────────────────────────────────────────
.Lel2_init:
    // Disable EL2 traps for FP/SIMD (we won't use them in the kernel anyway)
    msr  hcr_el2, xzr
    // Set EL1 execution state to AArch64
    mov  x0, #(1 << 31)       // HCR_EL2.RW = 1 → EL1 is AArch64
    msr  hcr_el2, x0
    // Initialize EL1 system registers
    msr  sctlr_el1, xzr
    msr  mair_el1, xzr
    // SPSR_EL2: return to EL1h (EL1 with dedicated SP), all interrupts masked
    mov  x0, #(0b00101)       // DAIF masked, EL1h
    orr  x0, x0, #(0b1111 << 6)  // D+A+I+F bits set (all masked)
    msr  spsr_el2, x0
    // ELR_EL2 → el1_init
    adr  x0, .Lel1_init
    msr  elr_el2, x0
    eret

    // ── EL1 initialisation ────────────────────────────────────────────────
.Lel1_init:
    // Mask all interrupts until we initialise the GIC.
    msr  daifset, #0xf

    // Explicitly select the dedicated per-EL stack pointer (SP_EL1, "EL1h"
    // mode), SPSel=1. QEMU's virt machine starts the primary CPU directly
    // at EL1 by default (no `virtualization=on`), so the EL2 path above
    // that sets SPSR_EL2's mode bits to EL1h is skipped entirely — without
    // this, PSTATE.SP is left at its EL1t reset state, "sp" below silently
    // targets SP_EL0 instead of SP_EL1, and every exception is delivered to
    // the "Current EL with SP0" vector slots (the fatal ones) instead of
    // the dedicated SPx slots this kernel actually handles.
    msr  SPSel, #1
    isb

    // Set up boot stack (defined in linker script).
    adrp x0, __stack_top
    add  sp, x0, :lo12:__stack_top

    // Zero BSS.
    adrp x0, __bss_start
    add  x0, x0, :lo12:__bss_start
    adrp x1, __bss_end
    add  x1, x1, :lo12:__bss_end
.Lbss_loop:
    cmp  x0, x1
    b.ge .Lbss_done
    str  xzr, [x0], #8
    b    .Lbss_loop
.Lbss_done:

    // rust_entry(hartid=0, dtb_addr=x20)
    mov  x0, xzr
    mov  x1, x20
    bl   rust_entry

.Lhang:
    wfe
    b    .Lhang
"#);

#[no_mangle]
pub extern "C" fn rust_entry(hartid: usize, dtb: u64) -> ! {
    crate::kmain(hartid, dtb as usize)
}
