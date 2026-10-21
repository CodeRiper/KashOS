#!/usr/bin/env python3
"""Guard IPC rendezvous state until the scheduler accepts a peer wake."""

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
source_path = Path(os.environ.get("KASHOS_IPC_SOURCE", ROOT / "kernel/src/ipc.rs"))
source = source_path.read_text(encoding="utf-8")


def function_body(signature: str) -> str:
    start = source.find(signature)
    assert start >= 0, f"missing function: {signature}"
    brace = source.find("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


send = function_body("pub fn sys_ipc_send(")
recv = function_body("pub fn sys_ipc_recv_with_capacity(")

send_wake = send.index("wake_task_by_tid(receiver_pid)")
assert send_wake < send.index("ep.waiting_pid = None"), "send consumes waiter before scheduler wake succeeds"
assert send_wake < send.index("ep.pending_msg = Some(msg)"), "send publishes message before scheduler wake succeeds"
assert send_wake < send.index("pcb.state = ProcessState::Ready"), "send marks PCB Ready before scheduler wake succeeds"
assert "cspaces[cspace_idx].delete(dst)" in send, "send does not roll back transferred cap when wake fails"

recv_wake = recv.index("wake_task_by_tid(sender_pid)")
assert recv_wake < recv.index("ep.waiting_pid = None"), "receive consumes waiter before scheduler wake succeeds"
assert recv_wake < recv.index("ep.pending_msg = None"), "receive consumes message before scheduler wake succeeds"
assert recv_wake < recv.index("pcb.state = ProcessState::Ready"), "receive marks PCB Ready before scheduler wake succeeds"
assert "cspaces[cspace_idx].delete(dst)" in recv, "receive does not roll back transferred cap when wake fails"

print("PASS: IPC endpoint/PCB state is retained when scheduler wake fails")
