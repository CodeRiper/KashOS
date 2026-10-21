#!/usr/bin/env python3
"""Guard IPC syscalls against consuming messages before output validation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSCALL = (ROOT / "kernel/src/arch/x86_64/syscall.rs").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")
QEMU = (ROOT / "tests/test_qemu_boot.py").read_text(encoding="utf-8")


def arm(source: str, start: str, end: str) -> str:
    left = source.index(start)
    right = source.index(end, left)
    return source[left:right]


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


dispatch = function_body(SYSCALL, 'pub extern "sysv64" fn kash_rust_syscall_dispatcher(')
send = arm(dispatch, "nr::SYS_IPC_SEND =>", "nr::SYS_IPC_RECV =>")
recv = arm(dispatch, "nr::SYS_IPC_RECV =>", "nr::SYS_RETYPE =>")

assert "validate_ipc_user_buffer" in SYSCALL
assert send.index("copy_from_user(") < send.index("crate::ipc::sys_ipc_send(")
assert "let copy_result = unsafe" in send
assert "if let Err(error) = copy_result" in send
assert recv.index("validate_ipc_user_buffer(user_buf, user_buf_len)") < recv.index("crate::ipc::sys_ipc_recv(")
assert "let copy_result = unsafe" in recv
assert "if let Err(error) = copy_result" in recv
assert "return error as i64;" in recv
assert "user_buf.is_null()" not in recv, "non-empty null output must be rejected before receive"
assert "validate_ipc_user_buffer(core::ptr::null_mut(), 1) == Err(SyscallError::InvalidMemoryAccess)" in SELFTEST
assert "kash_rust_syscall_dispatcher(nr::SYS_IPC_RECV, usize::MAX, 0, 0, 1, 0)" in SELFTEST
assert '"ipc_user_buffer_preflight": False' in QEMU
assert 'required_markers["ipc_user_buffer_preflight"] = True' in QEMU
print("PASS: IPC syscall user buffers are validated before endpoint state changes")
