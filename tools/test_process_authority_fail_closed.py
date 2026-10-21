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
driver = read("kernel/src/driver.rs")
ipc = read("kernel/src/ipc.rs")

require("cspaces[slot] = CapSpace::<64>::new()" in process,
        "new user process starts with an empty CSpace")
require("Cap::new_untyped" not in process and "Cap::new_frame" not in process and "Rights::ALL" not in process,
        "process setup grants no fabricated memory objects or broad ambient rights")
require("pub fn process_slot_for_pid(pid: u32) -> Option<usize>" in process,
        "process IDs resolve through the process table")
require("AtomicU32::new((MAX_TASKS as u32) + 2)" in process
        and "NEXT_PID.compare_exchange_weak" in process,
        "user process IDs are disjoint from kernel TIDs and fail instead of wrapping")
require("pid1.checked_add(crate::process::MAX_PROCESSES as u32)" in selftest
        and "process_slot_for_pid(modulo_alias_pid).is_none()" in selftest
        and "process_slot != (pid1 as usize % crate::process::MAX_PROCESSES)" not in selftest
        and "PROCESS_CSPACES.lock()[process_slot]" in selftest,
        "T13 checks exact PID resolution, rejects a modulo-alias PID, and checks the process starts empty")
require("process_slot_for_pid(current_pid as u32)" in syscalls,
        "capability syscalls resolve the process slot before CSpace access")
require("(current_pid as usize) % crate::process::MAX_PROCESSES" not in syscalls,
        "syscall CSpace lookup does not treat a PID as an array index")
require(syscalls.count("None => return SyscallError::InvalidArgument as i64") >= 2,
        "invalid capability rights masks fail instead of defaulting to full rights")
require("% MAX_PROCESSES" not in driver
        and "process_slot_for_pid(pid)" in driver,
        "driver capability lookup cannot alias a PID to another process CSpace")
require("% MAX_PROCESSES" not in ipc
        and ipc.count("process_slot_for_pid(") >= 3,
        "IPC CSpace lookup and delivery use live process-table slots")
require("% MAX_ENDPOINTS" not in ipc
        and "endpoint_slot_for_id" in ipc,
        "IPC endpoint IDs must resolve to an exact live endpoint")
require(ipc.count("wake_task_by_tid(") == 2 and "task_index_for_tid" not in ipc,
        "IPC wakeups resolve and wake live process TIDs atomically under the scheduler lock")
require("provision_driver_cspace" in driver
        and "unavailable" in driver.lower(),
        "driver capability provisioning remains fail-closed until real driver processes exist")

print("All process authority regression checks passed.")
