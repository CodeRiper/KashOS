#!/usr/bin/env python3
"""Guard the vault unlock path against hostile Argon2 memory parameters."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CRYPTO = (ROOT / "kvault/src/crypto.rs").read_text(encoding="utf-8")
VAULT = (ROOT / "kvault/src/vault.rs").read_text(encoding="utf-8")
VFS = (ROOT / "kernel/src/vfs.rs").read_text(encoding="utf-8")
TESTS = (ROOT / "kvault/tests/vault_tests.rs").read_text(encoding="utf-8")
KV_CARGO = (ROOT / "kvault/Cargo.toml").read_text(encoding="utf-8")
CI = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

open_start = VAULT.index("fn open_inner(")
open_end = VAULT.index("fn finish_open(", open_start)
open_inner = VAULT[open_start:open_end]
format_start = VAULT.index("pub fn format<")
format_end = VAULT.index("pub fn open<", format_start)
format_body = VAULT[format_start:format_end]
validate_start = CRYPTO.index("pub(crate) fn validate_for_format")
validate_end = CRYPTO.index("\n    }", validate_start) + len("\n    }")
format_policy = CRYPTO[validate_start:validate_end]
checks = [
    ("Default vault KDF policy is capped at 256 MiB", "DEFAULT_MAX_KDF_MEMORY_KIB: u32 = 256 * 1024" in CRYPTO),
    ("Advanced KDF policy has a fixed 2 GiB ceiling", "ABSOLUTE_MAX_KDF_MEMORY_KIB: u32 = 2 * 1024 * 1024" in CRYPTO),
    ("KDF validates memory cost before Argon2 allocation", open_inner.index("validate_with_memory_limit(max_memory_kib)") < open_inner.index("kdf_with_memory_limit(password")),
    ("Vault stores the selected budget for later password operations", "kdf_memory_limit_kib: max_memory_kib" in VAULT and "self.kdf_memory_limit_kib" in VAULT),
    ("Kernel uses current largest contiguous free heap block", "let (_, _, largest_free_block) = crate::heap::dump_stats()" in VFS),
    ("Kernel reserves heap memory and passes budget to vault open", "KDF_HEAP_RESERVE_KIB" in VFS and "Vault::open_with_memory_limit(dev, &mut rng, master_key, heap_budget_kib)" in VFS),
    ("Regression test checks hostile header rejection and non-mutation", "hostile_kdf_header_is_rejected_before_kdf_and_without_disk_mutation" in TESTS),
    ("New vaults enforce OWASP minimum memory and time costs", "MIN_KDF_MEMORY_KIB: u32 = 19 * 1024" in CRYPTO and "MIN_KDF_TIME_COST: u32 = 2" in CRYPTO and "self.t < MIN_KDF_TIME_COST" in CRYPTO),
    ("Vault format validates KDF policy before any disk write", "opts.params.validate_for_format()?" in format_body and format_body.index("validate_for_format()") < format_body.index("// 1. Random-fill everything.")),
    ("Weak legacy KDF headers remain available for recovery", "legacy weak profiles must remain recoverable" in TESTS and "self.m_kib >= 8 * self.p" in CRYPTO),
    ("Fast KDF fixture is gated to debug builds with explicit test feature", "test-fast-kdf = []" in KV_CARGO and "all(feature = \"test-fast-kdf\", debug_assertions)" in format_policy and "#[cfg(feature = \"test-fast-kdf\")]" in CRYPTO),
    ("CI enables the test-only fast profile only for host tests", "cargo test --workspace --exclude kernel --features kvault/test-fast-kdf" in CI),
    ("Runtime kernel self-tests do not use the fast KDF fixture", "TEST_ONLY_INSECURE_FAST" not in (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")),
]

for label, passed in checks:
    print(f"{'PASS' if passed else 'FAIL'}: {label}")
failures = [label for label, passed in checks if not passed]
if failures:
    print(f"{len(failures)} KDF budget regression(s) detected.", file=sys.stderr)
    raise SystemExit(1)
print(f"All {len(checks)} KDF memory-budget checks passed.")
