#!/usr/bin/env python3
"""Guard syscall user-copy mapping permissions and the mapped user stack."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSCALL = (ROOT / "kernel/src/arch/x86_64/syscall.rs").read_text(encoding="utf-8")
ELF = (ROOT / "kernel/src/elf.rs").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
QEMU = (ROOT / "tests/test_qemu_boot.py").read_text(encoding="utf-8")


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


walk = function_body(SYSCALL, "unsafe fn validate_user_page_range(")
active = function_body(SYSCALL, "fn validate_active_user_pages(")
copy_from = function_body(SYSCALL, "pub unsafe fn copy_from_user(")
copy_to = function_body(SYSCALL, "pub unsafe fn copy_to_user(")
ipc_preflight = function_body(SYSCALL, "pub(crate) fn validate_ipc_user_buffer(")
t11 = function_body(SELFTEST, "pub fn test_elf_loader_and_wx_rejection(")

assert "CR3" in walk and "USER_PAGE" in walk
assert "USER_PAGE_WRITABLE" in walk
assert "USER_PAGE_PRESENT | USER_PAGE_USER" in walk
assert "USER_PAGE_LARGE" in walk
assert "current_tid()" in active and "CR3" in active
assert "validate_active_user_pages" in copy_from
assert "validate_active_user_pages" in copy_to
assert "validate_active_user_pages" in ipc_preflight
assert "validate_active_user_pages" in ipc_preflight[:ipc_preflight.index("Ok(bounded_words)")]
assert "USER_STACK_TOP & !(PAGE_SIZE as u64 - 1)" in ELF
assert "USER_STACK_PAGES - 1" in ELF
assert "USER_STACK_TOP" in t11 and "USER_STACK_BASE" in t11
assert "test_syscall_user_page_permissions.py" in WORKFLOW
assert '"user_page_permissions": False' in QEMU
assert 'required_markers["user_page_permissions"] = True' in QEMU
print("PASS: syscall copies require present user mappings with appropriate write permission")
