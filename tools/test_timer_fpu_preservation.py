#!/usr/bin/env python3
"""Guard save-before-Rust and restore-at-ISR-exit FPU preservation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    idt = (ROOT / "kernel/src/arch/x86_64/idt.rs").read_text(encoding="utf-8")
    task = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")
    fpu = (ROOT / "kernel/src/arch/x86_64/fpu.rs").read_text(encoding="utf-8")
    entry = idt.split("_isr32:", 1)[1].split("/* TLB Shootdown", 1)[0]

    save = entry.index("fxsave64")
    call = entry.index("call x86_timer_handler")
    restore = entry.index("fxrstor64")
    assert save < call < restore, "timer ISR must save before Rust and restore after Rust"
    assert "and rsp, -16" in entry, "FXSAVE scratch must be 16-byte aligned"
    assert "sub rsp, 528" in entry, "ISR scratch must hold 512-byte image and restore pointer"
    assert "lea rdx, [rsp + 512]" in entry and "mov [rsp + 512], rsi" in entry, (
        "handler must choose the FPU image restored by the assembly epilogue"
    )
    assert "incoming_fpu: *const FpuState" in idt
    assert "next_fpu_out: *mut *const FpuState" in idt
    assert "incoming_fpu: &FpuState" in task
    assert "prev_thread.fpu = *incoming_fpu" in task
    assert "*next_fpu_out = &next_thread.fpu" in task
    assert "timer_interrupt_preserves_sse_state();" in fpu
    assert '"int 0x20"' in fpu and 'lateout("xmm15")' in fpu
    assert "observed != sentinel" in fpu
    print("PASS: timer ISR saves outgoing FPU before Rust and restores selected state at exit")


if __name__ == "__main__":
    main()
