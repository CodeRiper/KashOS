# First-boot readiness recheck — 2026-10-23

## Checked revision

- Branch: `main`
- HEAD: `e609304` (working tree was clean before this evidence update)
- `rtk` is required by the local repository instructions but is unavailable in
  this PowerShell environment. Commands were run directly.

## What the boot check showed

The release kernel booted in the repository's QEMU T0 profile and reached the
interactive locked shell. The run did not show a kernel crash. Its boot output
includes:

```text
SKIP: T25 root vault is not mounted; refusing to format or modify persistent storage
[kms] Locked: enter the vault passphrase at the console to unlock storage.
[storage] Vault is locked. Use 'unlock'; passphrase input is hidden.
```

The source confirms this path: `kernel/src/shell.rs` requires a mounted root
vault before the `desktop` command can launch; `kernel/src/session.rs` only
starts the desktop session when storage is unlocked; and `kernel/src/selftest.rs`
T25 deliberately skips when no vault is mounted. A fresh image therefore has
no guided first-run installation/vault-provisioning path and lands at a locked
console. That is a missing setup capability, not a successful desktop boot.
Automatically formatting a disk would be unsafe, so this check did not create
or change a vault.

## Verification performed

- `cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none` — passed.
- `python tests/test_qemu_boot.py` — passed its configured T0 boot/shell smoke markers.
- `cargo test --workspace --exclude kernel --features kvault/test-fast-kdf` — completed with passing reported test suites.
- All 32 Python source guards — passed.
- `python tools/claims_lint.py` — passed.
- `python tools/verify_findings.py` — passed; findings F8 and F10 remain present.

## Limits and remaining work

The QEMU profile is one virtual CPU (Conroe model) with 1 GiB RAM. It checks
selected boot markers only. It does not establish physical-device boot,
installer correctness, a desktop session, networking, TPM provisioning,
IOMMU/DMA isolation, SMP correctness, or production security. F8 records the
missing IOMMU/DMA isolation path; F10 records that the normal desktop/session
still runs in Ring 0. The GUI lock remains a display overlay and is not kernel
authentication or a KMS/VFS storage lock (see `A3.md` and `A18.md`).

The next safe product milestone is a first-run installation and vault
provisioning flow that makes the target device and destructive actions explicit,
never formats automatically, and can be tested against disposable images.
Until that and the other roadmap blockers are implemented and verified, KashOS
is a prototype and is not ready to use as a secure daily operating system.
