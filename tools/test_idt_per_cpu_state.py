#!/usr/bin/env python3
"""Guard CPU-local x86 IDT, fault recovery, and timer accounting state."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
IDT_PATH = "kernel/src/arch/x86_64/idt.rs"
ARCH_PATH = "kernel/src/arch/x86_64/mod.rs"


def check(idt: str, arch: str) -> None:
    required = (
        "struct CpuInterruptState",
        "idt: Idt",
        "expected_fault: AtomicBool",
        "expected_fault_rip: AtomicU64",
        "expected_fault_error: AtomicU64",
        "fault_caught: AtomicBool",
        "fault_recovery_rip: AtomicU64",
        "user_fault_recovery_rip: AtomicU64",
        "timer_ticks: AtomicU64",
        "static mut CPU_INTERRUPT_STATE: [CpuInterruptState; super::smp::MAX_CPUS]",
        "static CPU_IDT_READY: [AtomicBool; super::smp::MAX_CPUS]",
        "pub fn init(cpu_index: usize) -> bool",
        "CPU_IDT_READY[cpu_index].load(Ordering::Acquire)",
        "addr_of_mut!(CPU_INTERRUPT_STATE[cpu_index].idt)",
        "CPU_IDT_READY[cpu_index].store(true, Ordering::Release)",
        "cpu_index_for_apic_id(apic_id)",
        "state.expected_fault.store(false, Ordering::SeqCst)",
        "pub fn set_expected_fault(fault_rip: u64, recovery_rip: u64)",
        "pub fn set_expected_page_fault(fault_rip: u64, recovery_rip: u64, error_code: u64)",
        "if vec == 14",
        "frame.rip == state.expected_fault_rip.load(Ordering::SeqCst)",
        "frame.error == state.expected_fault_error.load(Ordering::SeqCst)",
        "pub fn clear_expected_fault()",
        "state.timer_ticks.fetch_add(1, Ordering::Relaxed)",
    )
    for fragment in required:
        assert fragment in idt, f"per-CPU IDT/fault state invariant missing: {fragment}"
    for shared in (
        "static mut IDT:",
        "static EXPECTED_FAULT:",
        "static FAULT_CAUGHT:",
        "static FAULT_RECOVERY_RIP:",
        "static USER_FAULT_RECOVERY_RIP:",
        "static TIMER_TICKS:",
    ):
        assert shared not in idt, f"shared interrupt state remains: {shared}"
    assert "idt::init(cpu_index)" in arch, "BSP must load its discovered CPU's IDT"
    selftest = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")
    assert '"3:"' in selftest and '"lea rdi, [rip + 3f]"' in selftest
    assert "idt::clear_expected_fault();" in selftest
    fault_test = selftest.split("pub fn test_nx_smep_fault()", 1)[1].split("#[repr(align", 1)[0]
    assert "options(nomem)" not in fault_test, (
        "fault self-test calls a state-mutating function and must keep asm memory effects visible"
    )


def main() -> None:
    idt = (ROOT / IDT_PATH).read_text(encoding="utf-8")
    arch = (ROOT / ARCH_PATH).read_text(encoding="utf-8")
    check(idt, arch)
    print("PASS: per-CPU IDT, fault recovery, and timer state")

    if "--verify-baseline" in sys.argv:
        old_idt = subprocess.run(
            ["git", "show", f"HEAD^:{IDT_PATH}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        old_arch = subprocess.run(
            ["git", "show", f"HEAD^:{ARCH_PATH}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        try:
            check(old_idt, old_arch)
        except AssertionError:
            print("PASS: regression guard rejects the pre-change shared interrupt state")
        else:
            raise AssertionError("regression guard accepted the old shared interrupt state")


if __name__ == "__main__":
    main()
