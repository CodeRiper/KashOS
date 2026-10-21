#!/usr/bin/env python3
"""Guard real per-thread stack guard mappings and their QEMU fault check."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TASK_PATH = "kernel/src/task.rs"
ARCH_PATH = "kernel/src/arch/x86_64/mod.rs"
IDT_PATH = "kernel/src/arch/x86_64/idt.rs"
SELFTEST_PATH = "kernel/src/selftest.rs"
QEMU_PATH = "tests/test_qemu_boot.py"


def check(task: str, arch: str, idt: str, selftest: str, qemu: str) -> None:
    assert "pub fn stack_guard_page_addresses() -> [u64; MAX_TASKS + smp::MAX_CPUS]" in task
    assert "thread_stacks[index].guard_page.as_ptr() as u64" in task
    assert "idle_stacks[index - MAX_TASKS].guard_page.as_ptr() as u64" in task
    assert "crate::task::stack_guard_page_addresses()" in arch
    assert "unmap_4k(guard_va)" in arch
    assert "unmap_4k(guard_paddr)" in arch, "boot stack guard must remain unmapped"
    assert "expected_fault_error: AtomicU64" in idt
    assert "pub fn set_expected_page_fault(" in idt
    assert "frame.error == state.expected_fault_error.load(Ordering::SeqCst)" in idt
    assert "test_thread_stack_guard()" in selftest
    assert "[stack] PASS: thread and CPU idle stack guards are non-present" in selftest
    assert '"stack_guard_unmapped": False' in qemu
    assert 'required_markers["stack_guard_unmapped"] = True' in qemu


def read_sources() -> tuple[str, str, str, str, str]:
    return tuple((ROOT / path).read_text(encoding="utf-8") for path in (
        TASK_PATH, ARCH_PATH, IDT_PATH, SELFTEST_PATH, QEMU_PATH
    ))  # type: ignore[return-value]


def main() -> None:
    check(*read_sources())
    print("PASS: thread and idle stack guards are unmapped and checked by exact page fault")

    if "--verify-baseline" in sys.argv:
        paths = (TASK_PATH, ARCH_PATH, IDT_PATH, SELFTEST_PATH, QEMU_PATH)
        old = [subprocess.run(
            ["git", "show", f"HEAD:{path}"], cwd=ROOT, check=True,
            capture_output=True, text=True,
        ).stdout for path in paths]
        try:
            check(*old)
        except AssertionError:
            print("PASS: regression guard rejects the existing mapped-guard implementation")
        else:
            raise AssertionError("regression guard accepted the existing mapped guards")


if __name__ == "__main__":
    main()
