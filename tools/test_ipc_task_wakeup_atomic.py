#!/usr/bin/env python3
"""Guard IPC task wakeups against slot reuse and premature queue insertion."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
TASK_PATH = ROOT / "kernel/src/task.rs"
IPC_PATH = ROOT / "kernel/src/ipc.rs"


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    assert start >= 0, f"missing function: {signature}"
    opening = source.find("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


def check(task: str, ipc: str) -> None:
    wake_body = function_body(task, "pub fn wake_task_by_tid(tid: u32)")
    assert "let mut sched = SCHEDULER.lock()" in wake_body
    assert "sched.task_index_for_tid(tid)" in wake_body
    assert "sched.wake_task(task_idx)" in wake_body
    assert "sched.enqueue_ready(task_idx)" not in wake_body

    for signature, tid_name in (
        ("pub fn sys_ipc_send(", "receiver_pid"),
        ("pub fn sys_ipc_recv_with_capacity(", "sender_pid"),
    ):
        body = function_body(ipc, signature)
        assert "task_index_for_tid" not in body, f"split TID lookup remains in {signature}"
        assert "wake_task_by_tid" in body, f"atomic scheduler wake missing in {signature}"
        assert f"wake_task_by_tid({tid_name})" in body


def main() -> None:
    task = TASK_PATH.read_text(encoding="utf-8")
    ipc = IPC_PATH.read_text(encoding="utf-8")
    check(task, ipc)
    print("PASS: IPC wake resolves and wakes each TID under one scheduler lock")


if __name__ == "__main__":
    main()
