# KashOS engineering work log

**Last updated:** 2026-10-20  
**Current task branch:** `codex/a1-remove-fake-network-claims`  
**Current task:** A1/A2 hardening, A3 locked-boot credential work, and safe installer shutdown

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

## Verification

See [`EVIDENCE/A1.md`](EVIDENCE/A1.md) for exact commands and limits. Current
local results: workspace host tests pass, kernel target check/release build
pass, installer/KMS/storage/network source guards and claims linter pass, and
the QEMU T0 smoke test reaches the locked shell with its required markers. The
QEMU vault image SHA-256 was unchanged (`31B809229EFA682DB6B6041AF61743D3E54D79DDFEB42C79E5BEDD853C5AE012`).
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

## Next task

Revalidate A2 and A3 against the current code before changing persistent-data
behavior: inspect vault open/format paths, passphrase lifecycle, derivation,
recovery, and interruption cases. Follow the engineering plan order and add
evidence before marking either task complete. Continue the A4-A21 audit after
those data/key-safety gates.
