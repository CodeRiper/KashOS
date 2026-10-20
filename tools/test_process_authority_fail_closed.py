#!/usr/bin/env python3
"""Guard user-process CSpace indexing and default authority."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


process = read("kernel/src/process.rs")
syscalls = read("kernel/src/arch/x86_64/syscall.rs")
selftest = read("kernel/src/selftest.rs")

require("cspaces[slot] = CapSpace::<64>::new()" in process,
        "new user process starts with an empty CSpace")
require("Cap::new_untyped" not in process and "Cap::new_frame" not in process and "Rights::ALL" not in process,
        "process setup grants no fabricated memory objects or broad ambient rights")
require("pub fn process_slot_for_pid(pid: u32) -> Option<usize>" in process,
        "process IDs resolve through the process table")
require("process_slot != (pid1 as usize % crate::process::MAX_PROCESSES)" in selftest
        and "PROCESS_CSPACES.lock()[process_slot]" in selftest,
        "T13 exercises a PID whose CSpace slot differs from its modulo index and checks it starts empty")
require("process_slot_for_pid(current_pid as u32)" in syscalls,
        "capability syscalls resolve the process slot before CSpace access")
require("(current_pid as usize) % crate::process::MAX_PROCESSES" not in syscalls,
        "syscall CSpace lookup does not treat a PID as an array index")
require(syscalls.count("None => return SyscallError::InvalidArgument as i64") >= 2,
        "invalid capability rights masks fail instead of defaulting to full rights")

print("All process authority regression checks passed.")
