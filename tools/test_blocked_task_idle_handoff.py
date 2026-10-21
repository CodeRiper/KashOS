#!/usr/bin/env python3
"""Guard the scheduler-to-idle handoff for a blocked last runnable task."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEDULER = (ROOT / "kscheduler/src/lib.rs").read_text(encoding="utf-8")
TASK = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")
ARCH = (ROOT / "kernel/src/arch/x86_64/mod.rs").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")
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


assert "pub enum ContextSwitchTarget" in SCHEDULER
assert "ContextSwitchTarget::Idle" in SCHEDULER
assert "None if prev.is_some()" in SCHEDULER
assert "static IDLE_STACKS" in TASK
assert "initialize_idle_context(cpu_index)" in function_body(TASK, "pub fn init(")
assert "test_blocked_task_idle_handoff()" in SELFTEST
assert '"blocked_idle_handoff": False' in QEMU
assert 'required_markers["blocked_idle_handoff"] = True' in QEMU
assert "switch_to_idle(cpu_index)" in function_body(TASK, "pub fn on_timer_tick(")
idle_switch = function_body(TASK, "fn switch_to_idle(")
assert "CPU_IDLE_RSP[cpu_index].load" in idle_switch
assert "set_tss_rsp0(idle_stack_top)" in idle_switch
assert "CPU_CURRENT_TID[cpu_index].store(0" in idle_switch
idle_entry = function_body(TASK, "extern \"C\" fn idle_entry(")
assert "IDLE_WAKE_PROBE_TID.swap(0" in idle_entry
assert "wake_task_by_tid(wake_tid)" in idle_entry
timer = function_body(TASK, "pub fn on_timer_tick(")
assert "ContextSwitchTarget::Idle" in timer
assert "crate::arch::shutdown(true)" in timer, "invalid task context must fail closed"
assert "crate::task::stack_guard_page_addresses()" in ARCH
print("PASS: blocked last runnable task switches to guarded per-CPU idle context")
