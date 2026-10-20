#!/usr/bin/env python3
"""Guard CPU-local x86-64 GDT/TSS state and APIC-indexed stack updates."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
GDT_PATH = "kernel/src/arch/x86_64/gdt.rs"
TASK_PATH = "kernel/src/task.rs"


def check(gdt: str, task: str) -> None:
    required_gdt = (
        "struct CpuGdtState",
        "static mut CPU_GDT: [CpuGdtState;",
        "double_fault_stack: IstStack",
        "nmi_stack: IstStack",
        "machine_check_stack: IstStack",
        "pub fn init(kernel_stack_top: u64, cpu_index: usize) -> bool",
        "CPU_GDT_READY[cpu_index].store(true, Ordering::Release)",
        "CPU_GDT[cpu_index].tss.rsp0 = rsp0",
        "cpu_index_for_apic_id(apic_id)",
    )
    for fragment in required_gdt:
        assert fragment in gdt, f"GDT/TSS CPU-local invariant missing: {fragment}"
    assert "pub static mut TSS:" not in gdt, "a shared singleton TSS remains"
    assert "pub static mut GDT:" not in gdt, "a shared singleton GDT remains"
    assert "PER_CPU[0].current_pid" not in task, "scheduler still writes CPU slot zero"
    assert "cpu_index_for_apic_id(" in task, "scheduler must resolve its current CPU slot"


def main() -> None:
    gdt = (ROOT / GDT_PATH).read_text(encoding="utf-8")
    task = (ROOT / TASK_PATH).read_text(encoding="utf-8")
    check(gdt, task)
    print("PASS: CPU-local GDT/TSS/IST state and APIC-indexed scheduler updates")

    if "--verify-baseline" in __import__("sys").argv:
        old_gdt = subprocess.run(
            ["git", "show", f"HEAD:{GDT_PATH}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        old_task = subprocess.run(
            ["git", "show", f"HEAD:{TASK_PATH}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        try:
            check(old_gdt, old_task)
        except AssertionError:
            print("PASS: regression guard rejects the pre-change singleton implementation")
        else:
            raise AssertionError("regression guard accepted the pre-change implementation")


if __name__ == "__main__":
    main()
