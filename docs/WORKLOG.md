# KashOS engineering work log

**Last updated:** 2026-10-20  
**Current task branch:** `codex/a6-network-revalidation`
**Current task:** A6 network path revalidation and fail-closed transport

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
- Additional A18 review removed a false “all permissions denied” browser-demo
  banner and a fabricated three-hop gateway label; the Messages catalog now
  says that no network transport is connected. A dedicated UI honesty guard
  covers these claims. App package metadata and actual permission enforcement
  remain unaudited.
- Follow-up A18 audit removed fictional installed CLI/driver records, fake
  package versions/sizes/dates/signatures and seeded downloads from the
  Settings registry; removed fabricated loaded-driver files; and labeled the
  remaining compiled-in apps and permission settings as unverified UI demos.
  The UI suite passed, as did 13 UI honesty checks, 24 network checks, and the
  claims linter. This does not add package inventory, signature checks, or
  kernel-enforced permission policy.
- Further A18 review removed the developer's hard-coded name/Kash ID and fake
  hardware serial, processor inventory, disk name, refresh rate, and `7 / 7`
  UI self-test claim. About views use the crate version and clearly mark boot
  results as not reported to the UI; the startup panel is labeled as a
  prototype sequence, not firmware POST. The UI tests, 18 UI honesty checks,
  claims linter and 12-finding check passed; this does not implement a live
  account, firmware, CPU inventory or self-test status service.
- Settings follow-up changed unimplemented preference rows from `Standard` to
  `Unavailable`, removed the inactive domain-profile claim, and marked missing
  re-authentication, hardware-key, and vault-key services explicitly. The real
  inactivity auto-lock control remains wired to the desktop idle timer. The
  lock-screen text no longer ties notification privacy to its unconnected
  Lockdown demo. UI tests, 24 UI honesty checks, and the claims linter pass; release kernel
  target check and the 12-finding check pass. QEMU T0 reached the shell with
  all smoke markers; this run's Conroe CPU profile does not support SMEP,
  SMAP or UMIP.

## A3 lock-path follow-up

- KMS zeroization previously left the mounted vault's derived volume, root,
  and folder keys usable. Session lock now drops the mounted vault and marks
  storage unmounted; a KMS guard protects lock ordering and state invalidation.
- The GUI lock screen still has no kernel callback, and returned plaintext
  copies are not covered by this primitive. A3 remains incomplete.

## A6 network revalidation

- Re-audit found that the smoltcp package test ring was not connected to the
  kernel NIC, kernel polling had no runtime caller, the older socket table used
  fixed addresses and simulated handshake transitions, and raw NIC ingress
  could bypass network policy.
- Kernel TCP/DHCP/ingress and polling are disabled pending integration. Kernel
  egress now always fails closed; the socket table labels model entries and
  uses unconfigured addresses. A6 evidence is downgraded from “Completed /
  Verified” to “Needs revalidation.”
- Network honesty guard (34 checks), `cargo test -p knet` (11 tests), claims
  linter, release kernel check, ground-truth check (0/12 present), and QEMU T0
  boot smoke passed. QEMU boot does not exercise live network traffic.

## A7 NIC revalidation

- Found that all three NIC drivers convert kernel virtual pointers to presumed
  DMA physical addresses; PCI probing enabled bus mastering and ignored init
  errors before marking allocated driver objects `Real`. The RTL8139 setup also
  enabled promiscuous receive. None of the existing package tests exercise NIC
  hardware or DMA.
- Disabled all NIC initialization and PCI probing from the NIC service. Device
  init now returns an unavailable error before hardware access, inactive TX/RX
  fail closed, and registry status reports driver stubs. Added a CI guard and
  downgraded A7 evidence to Needs revalidation.
- A7 remains incomplete until DMA-safe physical allocations, verified IOMMU
  isolation, correct driver protocols, QEMU packet-capture validation, and
  physical-device testing are available.

## A9 VT-d revalidation

- Source review showed the `khal` SLPT uses synthetic addresses in a `BTreeMap`,
  while VT-d initialization programmed a Rust array pointer without verified
  physical allocation, context tables, MMIO mapping, or invalidation. The ACS
  probe returned preset “hardened” flags from basic PCIe capability detection;
  DMAR probing also dereferenced firmware pointers without a bounded mapper.
- VT-d activation, runtime DMAR probing and ACS now fail closed. `init_vtd`
  activates no units; maps are rejected; status is Stub; T19 explicitly tests
  the in-memory model separately. DDE memory/DMA allocation now fails rather
  than returning fabricated addresses. Claims and threat docs no longer promise
  hardware DMA protection.
- Local host workspace tests, 12 VT-d checks, 5 DDE checks, 13 NIC checks, 36
  network checks, claims lint, release kernel build, diff check, and T0 QEMU
  smoke passed. The guest reached the locked shell with model-only network and
  VT-d markers.
  Ground-truth audit at that point reported 1/12 present: F8 accurately flags
  the software VT-d model, not a live hardware path. T0 QEMU reached the locked
  shell with T19, T31 and T40/T44 markers.

## A9 GitHub completion

- PR #7 (`security(vtd): disable unverified DMA isolation`) passed all required
  checks and merged to `main` at `06892cf612d111fee3e1a07c5d700a32effbd13a`.
- Local `main` was fast-forwarded to that exact `origin/main` commit.
- A9 remains a fail-closed revalidation; hardware VT-d, ACS, and DMA containment
  are not implemented.

## A10 user-space revalidation

- Reopened A10 after finding the normal boot session invokes GUI and shell code
  in Ring 0 through `session.rs`; moving those calls out of `main.rs` did not
  create a privilege boundary. The synthetic session CSpace setup did not spawn
  a process and has been removed.
- Corrected boot/session logs, the settings and `run-user` shell output, status
  (`Partial`), README, claims, GUI architecture, A10 evidence, and the ground-
  truth verifier. Added a CI regression guard. The prototype UI still boots in
  Ring 0; A10 remains incomplete pending a real user-mode init and services.
- Local A10 guard (9 assertions), claims linter, kernel release check, full
  workspace host suite, and T0 QEMU smoke test passed. The QEMU test reached
  the locked shell and printed the corrected T13 scope. Ground-truth findings
  report F8 and F10 present (2/12); neither hardware DMA containment nor normal
  boot user-service isolation is implemented.

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

PR #4 (vault lifecycle and UI honesty) and PR #5 (network fail-closed behavior)
have been merged to `main`. PR #5 merged at
[`a347b0f`](https://github.com/CodeRiper/KashOS/commit/a347b0f0f4caa9ee744ea27d66eb5adbdd7932b4).
PR #6 (A7 NIC DMA revalidation) is merged to `main` at
[`76d5451`](https://github.com/CodeRiper/KashOS/commit/76d545148791f2991316dc215052a81d56503db8).
PR #7 (A9 VT-d revalidation) is merged to `main` at
[`06892cf`](https://github.com/CodeRiper/KashOS/commit/06892cf612d111fee3e1a07c5d700a32effbd13a).
The A10 user-space revalidation correction is in progress on
`codex/a10-revalidation`; branch pushes trigger GitHub Actions.

## Next task

Continue A10 by designing and testing a real Ring 3 init/session lifecycle and
migrating the shell and compositor behind it. Keep the current prototype UI
clearly labeled Ring 0. Revisit A2/A3 if persistent-data behavior changes; the
local audit does not establish TPM-backed key provisioning or production
recovery.
