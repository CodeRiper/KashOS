#!/usr/bin/env python3
"""Guard fast syscall entry against sharing a live syscall stack across tasks."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSCALL = (ROOT / "kernel/src/arch/x86_64/syscall.rs").read_text(encoding="utf-8")
TASK = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")
QEMU = (ROOT / "tests/test_qemu_boot.py").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


assert "pub fn set_current_kernel_stack_top" in SYSCALL
assert "kernel_stack_top: AtomicU64" in SYSCALL
assert "offset_of!(SyscallCpuState, kernel_stack_top) == 8" in SYSCALL
assert 'mov rsp, gs:[8]' in SYSCALL
assert "set_current_kernel_stack_top(initial_rsp)" in function_body(TASK, "pub fn init(")
assert "set_current_kernel_stack_top(next_thread.stack_top)" in function_body(TASK, "pub fn on_timer_tick(")
assert "set_current_kernel_stack_top(idle_stack_top)" in function_body(TASK, "fn switch_to_idle(")
assert "current_thread_stack_contains" in function_body(SYSCALL, "pub extern \"sysv64\" fn kash_rust_syscall_dispatcher(")
assert '"syscall_thread_stack": False' in QEMU
assert 'required_markers["syscall_thread_stack"] = True' in QEMU
print("PASS: fast syscall entry uses the current task's guarded kernel stack")
