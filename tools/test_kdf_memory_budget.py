#!/usr/bin/env python3
"""Guard the vault unlock path against hostile Argon2 memory parameters."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CRYPTO = (ROOT / "kvault/src/crypto.rs").read_text(encoding="utf-8")
VAULT = (ROOT / "kvault/src/vault.rs").read_text(encoding="utf-8")
VFS = (ROOT / "kernel/src/vfs.rs").read_text(encoding="utf-8")
TESTS = (ROOT / "kvault/tests/vault_tests.rs").read_text(encoding="utf-8")

open_start = VAULT.index("fn open_inner(")
open_end = VAULT.index("fn finish_open(", open_start)
open_inner = VAULT[open_start:open_end]
checks = [
    ("Default vault KDF policy is capped at 256 MiB", "DEFAULT_MAX_KDF_MEMORY_KIB: u32 = 256 * 1024" in CRYPTO),
    ("Advanced KDF policy has a fixed 2 GiB ceiling", "ABSOLUTE_MAX_KDF_MEMORY_KIB: u32 = 2 * 1024 * 1024" in CRYPTO),
    ("KDF validates memory cost before Argon2 allocation", open_inner.index("validate_with_memory_limit(max_memory_kib)") < open_inner.index("kdf_with_memory_limit(password")),
    ("Vault stores the selected budget for later password operations", "kdf_memory_limit_kib: max_memory_kib" in VAULT and "self.kdf_memory_limit_kib" in VAULT),
    ("Kernel uses current largest contiguous free heap block", "let (_, _, largest_free_block) = crate::heap::dump_stats()" in VFS),
    ("Kernel reserves heap memory and passes budget to vault open", "KDF_HEAP_RESERVE_KIB" in VFS and "Vault::open_with_memory_limit(dev, &mut rng, master_key, heap_budget_kib)" in VFS),
    ("Regression test checks hostile header rejection and non-mutation", "hostile_kdf_header_is_rejected_before_kdf_and_without_disk_mutation" in TESTS),
]

for label, passed in checks:
    print(f"{'PASS' if passed else 'FAIL'}: {label}")
failures = [label for label, passed in checks if not passed]
if failures:
    print(f"{len(failures)} KDF budget regression(s) detected.", file=sys.stderr)
    raise SystemExit(1)
print(f"All {len(checks)} KDF memory-budget checks passed.")
