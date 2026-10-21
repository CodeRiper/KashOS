#!/usr/bin/env python3
"""Guard the supervisor handoff used to suspend a blocked syscall frame."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
task = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")
idt = (ROOT / "kernel/src/arch/x86_64/idt.rs").read_text(encoding="utf-8")
scheduler = (ROOT / "kscheduler/src/lib.rs").read_text(encoding="utf-8")
selftest = (ROOT / "kernel/src/task.rs").read_text(encoding="utf-8")

assert "pub fn block_current_task()" in task
assert "sched.block_task(task_idx)" in task
assert 'asm!("int 0xf1"' in task
assert "pub fn on_blocked_current_handoff(" in task
assert "plan_blocked_current_handoff_on_cpu(cpu_index)" in task
assert "pub fn plan_blocked_current_handoff_on_cpu(" in scheduler
assert "ThreadState::Blocked" in scheduler
assert ".global _isr241" in idt
assert "call x86_block_handoff_handler" in idt
assert "(*idt).0[241] = IdtGate::interrupt_gate(_isr241 as *const () as usize as u64, 0)" in idt
assert "let block_result = block_current_task();" in selftest
assert "handoff_blocked_current();" in selftest

print("PASS: blocked syscall context uses a supervisor-only saved-frame handoff")
