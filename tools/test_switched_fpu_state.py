#!/usr/bin/env python3
"""Guard an actual timer-preempted task switch with per-thread XMM sentinels."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    source = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")
    qemu = (ROOT / "tests/test_qemu_boot.py").read_text(encoding="utf-8")

    assert "extern \"C\" fn fpu_switch_worker" in source
    assert '"movdqu xmm15, xmmword ptr [{sentinel}]"' in source
    assert '"xchg byte ptr [{started}], al"' in source
    assert 'out("rax") _' in source, "XMM probe must not alias pointer inputs with AL"
    assert '"cmp byte ptr [{stop}], 0"' in source
    assert '"movdqu xmmword ptr [{observed}], xmm15"' in source
    assert "lateout(\"xmm15\") _" in source
    assert "!FPU_SWITCH_STARTED.load" in source
    assert "FPU_SWITCH_STOP.store(true" in source
    assert "while !FPU_SWITCH_DONE.load" in source
    assert "FPU_SWITCH_OK.load" in source
    assert "switched_fpu_preserved" in qemu
    print("PASS: scheduler self-test holds and checks XMM15 across a real task handoff")


if __name__ == "__main__":
    main()
