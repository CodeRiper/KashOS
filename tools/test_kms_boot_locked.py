#!/usr/bin/env python3
"""Guard against unattended bootstrap credentials and fictitious TPM unlock."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
KMS = (ROOT / "kernel/src/kms.rs").read_text(encoding="utf-8")
VFS = (ROOT / "kernel/src/vfs.rs").read_text(encoding="utf-8")
SHELL = (ROOT / "kernel/src/shell.rs").read_text(encoding="utf-8")
SESSION = (ROOT / "kernel/src/session.rs").read_text(encoding="utf-8")


def body(source: str, start: str, end: str) -> str:
    left = source.index(start)
    right = source.index(end, left)
    return source[left:right]


def main() -> int:
    init = body(KMS, "pub fn init(&mut self)", "/// Derives a domain-separated subkey")
    unlock = body(SHELL, "fn unlock_storage(&mut self)", "/// Execute an interactive administrative shell command")
    dispatch = body(SHELL, '"unlock" => {', '"desktop" => {')
    screen_lock = body(KMS, "pub fn on_screen_lock()", "/// Audits a memory slice")
    vfs_lock = body(VFS, "pub fn lock_all(&mut self)", "    pub fn free_blocks(&self)")
    checks = [
        ("No compiled-in bootstrap credential exists", "DEFAULT_BOOTSTRAP_PASSPHRASE" not in KMS),
        ("Boot initialization does not derive or install a key", "derive_key(" not in init and "self.master_key = Some" not in init),
        ("Boot initialization leaves session locked", "session_locked.store(true" in init),
        ("KMS does not claim a persistent TPM-sealed key", "tpm_sealed: AtomicBool" not in KMS and "sealed_handle" not in KMS),
        ("Console secret uses zeroizing memory", "Zeroizing::new([0u8; 128])" in unlock),
        ("Console secret input is not echoed", "get_char()" in unlock and "ch as char" not in unlock and 'kprint!("{}"' not in unlock),
        ("Passphrase is not accepted as a shell argument", "parts.len() == 1" in dispatch and "self.unlock_storage()" in dispatch),
        ("Failed vault open re-locks KMS", "on_screen_lock()" in unlock),
        ("Session lock scrubs KMS then invalidates VFS while holding KMS lock", screen_lock.index("guard.lock_session();") < screen_lock.index("crate::vfs::lock_root_vault();") and "drop(guard);" not in screen_lock),
        ("Root lock drops the mounted Vault and marks storage unmounted", "drop(self.vault.take());" in vfs_lock and "self.is_mounted = false;" in vfs_lock),
        ("Desktop path waits for mounted vault", "storage_unlocked" in SESSION and "vfs::is_root_mounted()" in SESSION),
    ]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    failures = [name for name, passed in checks if not passed]
    if failures:
        print(f"{len(failures)} KMS boot-lock regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} KMS boot-lock regression checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
