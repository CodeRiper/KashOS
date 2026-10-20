# KashOS engineering work log

**Last updated:** 2026-10-20  
**Current task branch:** `codex/a1-remove-fake-network-claims`  
**Current task:** A1/A2 hardening, A3 locked boot, safe installer shutdown, and A4/A5 TPM fail-closed audit

## Completed in this task

- Removed fabricated HTTP(S) success, fake TLS framing on the live path, and
  synthetic Tor/DNS socket rows. Remote HTTP(S) now returns `NotAvailable`;
  gateway state starts down and has no runtime “set Up” API.
- Replaced the empty Dillo/Ladybird windows with explicit unavailable results.
  The terminal HTML parser and local pages identify themselves as prototypes.
- Added a CI source regression check for network fail-closed behavior.
- Fixed boot ordering so the heap exists before allocation-using self-tests;
  allocated large network packet rings off the early kernel stack.
- Updated network self-tests and corrected overconfident self-test messages.
- Updated QEMU smoke helper to use the release kernel built from the current
  worktree instead of a potentially stale `isodir` artifact.
- Added the implementation roadmap and official-source security model research.
- Marked legacy Part A and B0-B6 completion statuses for revalidation.
- Audited A2 and removed persistent-disk writes and fallback formatting from
  the boot self-test. Added a CI regression guard; updated A2 evidence and
  task status based on the new source audit.
- Removed mount-time provisioning writes, verified the QEMU test disk hash did
  not change during boot, and downgraded A3 after finding the public default
  passphrase, fast HKDF password derivation, and non-persistent TPM handle.
- A3 follow-up removes automatic use of the public bootstrap phrase, starts
  KMS locked, adds hidden console unlock and gates desktop startup on a mounted
  vault. TPM sealing remains explicitly unavailable; old volumes require the
  legacy phrase and still need a safe migration path.
- Disabled the legacy disk-writing installer after audit found its raw-sector
  writes were synthetic and its success/recovery-token output was fabricated.
  The old installer test script is now a safe source guard. A4 evidence was
  downgraded because it incorrectly treated that script as a real installer
  integration test.
- Disabled the unvalidated production TPM path. Audit found guessed TIS MMIO,
  unparsed ACPI transport data, a CRB fake-success path, ignored command errors,
  and RAM-only PCR/sealed-key models. Production PCR, sealing, measurement, and
  NV anti-rollback APIs now fail unavailable; the self-test software model is
  not treated as hardware protection. Updated A4/A5 evidence, the threat model,
  claims matrix, public README, hardware report, and GUI POST screen; removed
  the fake TPM driver entry and added a CI regression guard.
- Bounded Argon2 work before vault unlock allocates memory. Generic opens cap
  at 256 MiB; the kernel derives the budget from the largest free heap block
  minus a 16 MiB reserve. Added a non-mutation regression test, CI guard, and
  A3 evidence; an explicit-budget recovery API preserves access to higher-cost
  volumes on systems with enough memory.
- Follow-up A3 audit found that new volume formatting accepted 8 KiB KDF costs
  and the runtime kernel self-test used a 64 KiB profile. New persistent
  formats now require the 19 MiB Argon2id floor; low-cost old volumes remain
  openable for recovery. The fast test fixture requires an explicit debug-only
  feature, and the kernel self-test uses the production floor. The legacy
  64 MiB profile's invalid 32-pass value was corrected to 16.
- A18 re-audit found that Settings still claimed native e1000/virtio networking,
  a running `smoltcp` path, and active hardware filtering even though remote
  networking is disabled and the filter is not NIC-integrated. The network
  pane now reports these unavailable states, with regression checks added to
  the network honesty gate. This does not complete A18 or implement networking.

## Verification

See [`EVIDENCE/A1.md`](EVIDENCE/A1.md) and [`EVIDENCE/A3.md`](EVIDENCE/A3.md)
for exact commands and limits. Current local results: workspace host tests
pass (the full vault corruption test took 324 seconds), kernel target check/release build
pass, `kash-ui` tests pass, installer/KMS/storage/network/TPM/KDF source guards
and claims linter pass, and the QEMU T0 smoke test reaches the locked shell with
its required markers. The QEMU vault image SHA-256 was unchanged
(`31B809229EFA682DB6B6041AF61743D3E54D79DDFEB42C79E5BEDD853C5AE012`).
This does not establish TPM, IOMMU, TLS, Tor, browser isolation, Linux
compatibility, or physical-device security.

## Current GitHub state

The task branch is pushed to `origin`. GitHub Actions runs on branch pushes
and pull requests targeting `main`. No pull request has been opened yet because
the available browser session is signed out. Do not merge until the user
reviews the proposed change and platform CI reports its results.

GitHub Actions was enabled for all branch pushes in this task. Run
[`39397626995`](https://github.com/CodeRiper/KashOS/actions/runs/39397626995)
for commit `d49ebbc7a1b5da661f3e1b52faa66c86ea16d63c` completed successfully:
Workspace Subsystem Tests, Build Microkernel (x86-64), and Build Guide v2
Claims & Honesty Gate all passed.
The latest run, [`39398533143`](https://github.com/CodeRiper/KashOS/actions/runs/39398533143)
for commit `3d5b28c24f7a7e6ae711d4878cfb1138609b65dd`, also completed
successfully with all three jobs passing.
Run [`39400063060`](https://github.com/CodeRiper/KashOS/actions/runs/39400063060)
for commit `55ab3aa095454b931bdd21d564d4d4ac236ee86d` completed successfully
with Workspace Subsystem Tests, Build Microkernel (x86-64), and Build Guide v2
Claims & Honesty Gate all passing.
Run [`39403735414`](https://github.com/CodeRiper/KashOS/actions/runs/39403735414)
for commit `764c483dc2f876313bc50610e8717b3c48939179` completed successfully
with all three jobs passing. These results precede the current uncommitted
A18 Settings-pane follow-up.

## Next task

Revalidate A2 and A3 against the current code before changing persistent-data
behavior: inspect vault open/format paths, passphrase lifecycle, derivation,
recovery, and interruption cases. A4/A5 are audited but unavailable until a
real TPM implementation passes hardware/swtpm tests. Then continue the ordered
A6-A21 audit, replacing old model-test claims with runtime evidence and fixing
unsafe or misleading behavior before marking tasks complete.
