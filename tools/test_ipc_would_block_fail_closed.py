#!/usr/bin/env python3
"""Require unmatched IPC calls to fail without recording fake blocked state."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IPC = (ROOT / "kernel/src/ipc.rs").read_text(encoding="utf-8")
SYSCALL = (ROOT / "kernel/src/arch/x86_64/syscall.rs").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")


def function_body(signature: str) -> str:
    start = IPC.find(signature)
    assert start >= 0, f"missing function: {signature}"
    opening = IPC.find("{", start)
    depth = 0
    for index in range(opening, len(IPC)):
        if IPC[index] == "{":
            depth += 1
        elif IPC[index] == "}":
            depth -= 1
            if depth == 0:
                return IPC[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


def wildcard_arm(body: str) -> str:
    match_start = body.rfind("match ep.state")
    assert match_start >= 0, "missing endpoint state match"
    body = body[match_start:]
    start = body.find("        _ => {")
    assert start >= 0, "missing unmatched IPC state arm"
    opening = body.find("{", start)
    depth = 0
    for index in range(opening, len(body)):
        if body[index] == "{":
            depth += 1
        elif body[index] == "}":
            depth -= 1
            if depth == 0:
                return body[opening + 1:index]
    raise AssertionError("unterminated unmatched IPC state arm")


def check() -> None:
    assert "WouldBlock = -9" in SYSCALL, "WouldBlock must have a stable syscall error value"
    assert "s.sync_ipc = crate::status::ComponentStatus::Partial" in SELFTEST
    assert "s.sync_ipc = crate::status::ComponentStatus::Real" not in SELFTEST
    assert "resumable blocking not implemented" in SELFTEST
    send = wildcard_arm(function_body("pub fn sys_ipc_send("))
    recv = wildcard_arm(function_body("pub fn sys_ipc_recv_with_capacity("))
    for label, arm in (("send", send), ("receive", recv)):
        assert "Err(SyscallError::WouldBlock)" in arm, f"{label} must report WouldBlock"
        assert "Ok(" not in arm, f"{label} must not report false success"
        assert "EndpointState::Wait" not in arm, f"{label} must not create a fake waiter"
        assert "ProcessState::Blocked" not in arm, f"{label} must not mark only the PCB blocked"
    assert "scheduler-backed syscall suspension and resumption are not implemented" in IPC
    print("PASS: unmatched IPC fails with WouldBlock and preserves endpoint/process state")


if __name__ == "__main__":
    check()
