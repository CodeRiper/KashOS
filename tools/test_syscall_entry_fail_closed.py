#!/usr/bin/env python3
"""Guard x86-64 syscall entry against shared state and user-stack use in kernel."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


syscall = read("kernel/src/arch/x86_64/syscall.rs")
arch = read("kernel/src/arch/x86_64/mod.rs")
entry = syscall.split('core::arch::global_asm!(', 1)[1].split('extern "C"', 1)[0]

require(not re.search(r"\bSYSCALL_KERNEL_STACK\b", syscall)
        and not re.search(r"\bUSER_RSP_SCRATCH\b", syscall),
        "syscall entry has no single global stack or user-RSP scratch")
require("SYSCALL_KERNEL_STACKS" in syscall and "SYSCALL_CPU_STATE" in syscall,
        "kernel syscall stack and scratch state are allocated per CPU")
require("gs:[0]" in entry and "gs:[8]" in entry,
        "entry switches using the CPU-local GS state before stack memory access")
require(entry.index("swapgs") < entry.index("mov gs:[0], rsp")
        < entry.index("mov rsp, gs:[8]"),
        "entry swaps GS, saves user RSP, then loads the trusted stack in order")
require("pop rsp" not in entry.lower(),
        "untrusted user RSP is not installed while still executing in Ring 0")
require(entry.index("cmp rcx") < entry.index("mov rsp, r10"),
        "return RIP is checked before restoring user RSP for SYSRET")
require("push r10" in entry and entry.index("push r10") < entry.index("iretq"),
        "fallback IRET frame is built on the trusted kernel stack")
require(arch.index("smp::init(apic::bsp_id())") < arch.index("syscall::init()"),
        "CPU discovery precedes current-CPU syscall state installation")
require("cpu_index_for_apic_id" in syscall,
        "syscall CPU state selects the slot matching the current APIC ID")
require("wrmsr(IA32_GS_BASE, 0)" in syscall
        and "wrmsr(IA32_KERNEL_GS_BASE, cpu_state as u64)" in syscall,
        "current CPU's GS-base MSRs point at its initialized entry state")

print("All syscall-entry regression checks passed.")
