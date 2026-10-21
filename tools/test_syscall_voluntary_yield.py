#!/usr/bin/env python3
"""Guard the voluntary syscall yield path and its supervisor reschedule gate."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHED = (ROOT / "kscheduler/src/lib.rs").read_text(encoding="utf-8")
SCHED_TESTS = (ROOT / "kscheduler/tests/scheduler_tests.rs").read_text(encoding="utf-8")
TASK = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")
SYSCALL = (ROOT / "kernel/src/arch/x86_64/syscall.rs").read_text(encoding="utf-8")
IDT = (ROOT / "kernel/src/arch/x86_64/idt.rs").read_text(encoding="utf-8")
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


planner = function_body(SCHED, "pub fn plan_voluntary_yield_on_cpu(")
assert "task.state != ThreadState::Running" in planner
assert "self.enqueue_ready(prev_idx)?" in planner
assert "self.schedule_on_cpu(core_id)" in planner
assert "system_ticks_us.fetch_add" not in planner
assert "voluntary_yield_rotates_same_band_tasks_without_charging_timer_time" in SCHED_TESTS
assert "voluntary_yield_with_only_current_task_does_not_switch_or_duplicate_queue_entry" in SCHED_TESTS
assert 'nr::SYS_YIELD => {' in SYSCALL
assert 'asm!("int 0xf0"' in SYSCALL
assert "on_voluntary_yield" in TASK
assert "fn _isr240();" in IDT
assert "(*idt).0[240] = IdtGate::interrupt_gate(_isr240" in IDT
assert "attr: 0x8E" in IDT, "reschedule gate must remain supervisor-only"
assert "_isr240:" in IDT and "call x86_yield_handler" in IDT and "fxsave64 [rsp]" in IDT
assert "[user] SYS_YIELD resumed Ring 3" in SELFTEST
assert '"syscall_yield_resumed": False' in QEMU
assert 'required_markers["syscall_yield_resumed"] = True' in QEMU
print("PASS: SYS_YIELD forces a supervisor reschedule and resumes its Ring 3 syscall")
