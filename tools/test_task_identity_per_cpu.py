#!/usr/bin/env python3
"""Guard current-task identity against cross-CPU aliasing and root fallback."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TASK_PATH = "kernel/src/task.rs"
SMP_PATH = "kernel/src/arch/x86_64/smp.rs"
SYSCALL_PATH = "kernel/src/arch/x86_64/syscall.rs"


def check(task: str, smp: str, syscall: str) -> None:
    required_task = (
        "static CPU_CURRENT_TID: [AtomicU32; smp::MAX_CPUS]",
        "fn current_cpu_index() -> Option<usize>",
        "smp::cpu_index_for_apic_id(crate::arch::x86_64::apic::current_id())",
        "pub fn current_tid() -> u32",
        "CPU_CURRENT_TID[cpu_index].load(Ordering::Acquire)",
        "pub fn set_current_tid(tid: u32)",
        "CPU_CURRENT_TID[cpu_index].store(tid, Ordering::Release)",
        "CPU_CURRENT_TID[cpu_index].store(1, Ordering::Release)",
    )
    for fragment in required_task:
        assert fragment in task, f"per-CPU task identity invariant missing: {fragment}"
    assert "static CURRENT_TID: AtomicU32" not in task, "global current TID remains"
    assert "current_pid: u32" not in smp, "duplicate non-atomic current task state remains in PerCpuData"
    assert "CURRENT_TID.store(next_thread.tid" not in task, "scheduler still writes a global task ID"
    assert "CPU_CURRENT_TID[cpu_index].store(next_thread.tid, Ordering::Release)" in task
    assert "crate::task::current_tid().max(1)" not in syscall, (
        "unknown CPU identity must not be converted to root task ID 1"
    )
    assert "if current_pid == 0" in syscall, "syscall dispatcher must reject unresolved CPU identity"


def main() -> None:
    task = (ROOT / TASK_PATH).read_text(encoding="utf-8")
    smp = (ROOT / SMP_PATH).read_text(encoding="utf-8")
    syscall = (ROOT / SYSCALL_PATH).read_text(encoding="utf-8")
    check(task, smp, syscall)
    print("PASS: task identity is CPU-local and unresolved syscall identity fails closed")

    if "--verify-baseline" in sys.argv:
        baseline_task = subprocess.run(
            ["git", "show", f"main:{TASK_PATH}"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout
        baseline_smp = subprocess.run(
            ["git", "show", f"main:{SMP_PATH}"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout
        baseline_syscall = subprocess.run(
            ["git", "show", f"main:{SYSCALL_PATH}"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout
        try:
            check(baseline_task, baseline_smp, baseline_syscall)
        except AssertionError:
            print("PASS: regression guard rejects the shared-TID baseline")
        else:
            raise AssertionError("regression guard accepted the shared-TID baseline")


if __name__ == "__main__":
    main()
