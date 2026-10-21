#!/usr/bin/env python3
"""Guard the x86 FXSAVE image used when a thread first runs."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    fpu = (ROOT / "kernel/src/arch/x86_64/fpu.rs").read_text(encoding="utf-8")
    task = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")
    process = (ROOT / "kernel/src/process.rs").read_text(encoding="utf-8")

    assert "pub const fn initial() -> Self" in fpu, "FPU state needs a valid initial image"
    assert "buffer[0] = 0x7f" in fpu and "buffer[1] = 0x03" in fpu, (
        "initial x87 control word must be 0x037f (masked exceptions, nearest rounding)"
    )
    assert "buffer[24] = 0x80" in fpu and "buffer[25] = 0x1f" in fpu, (
        "initial MXCSR must be 0x1f80"
    )
    assert "fpu: FpuState::initial()" in task, "kernel threads must receive initialized FP state"
    assert "fpu: FpuState::initial()" in process, "user processes must receive initialized FP state"
    assert "fpu: FpuState::empty()" not in task + process, (
        "new execution contexts must not restore the all-zero FXSAVE image"
    )
    print("PASS: new thread and process FPU images use architectural defaults")


if __name__ == "__main__":
    main()
