# KashOS engineering work log

**Last updated:** 2026-10-20  
**Repository tip checked:** `main` at `2931a8c5a57dbe6706d6f9377322fa2cfe70a8d3`
**Current task branch:** `codex/a10-percpu-syscall-entry`
**Current engineering task:** A10 syscall-entry CPU-local state and user-space lifecycle audit

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
- A second A10 audit also found fabricated broad process capabilities and PID
  modulo-based CSpace indexing. Follow-up work starts process CSpaces empty,
  maps syscalls through the process table, and rejects malformed rights masks.
  The syscall entry still has one global kernel stack, so SMP userland remains
  unsafe and disabled.
- Process-authority guard (7 checks), release kernel build, and T0 QEMU boot
  passed. T13 verified its test process resolves to its actual process-table
  slot despite a different PID modulo value and begins with an empty CSpace.

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
PR #8 (A10 Ring 0 session honesty) is merged to `main` at
[`a41c98b`](https://github.com/CodeRiper/KashOS/commit/a41c98b537cc8df4a6c91af240e13467da9ae874).
PR #9 (process-authority hardening) is merged to `main` at
[`00672ba`](https://github.com/CodeRiper/KashOS/commit/00672ba85cdd4d27bd15a6166f36129c57995deb).
PR #10 (current A10 roadmap/evidence handoff) is merged to `main` at
[`a51ffa9`](https://github.com/CodeRiper/KashOS/commit/a51ffa91a054011dbe819592cb341c298440b2eb).
PR #11 (A10 identifier resolution and fail-closed driver services) is merged to
`main` at
[`2931a8c`](https://github.com/CodeRiper/KashOS/commit/2931a8c5a57dbe6706d6f9377322fa2cfe70a8d3).
Local `main` was verified clean and equal to `origin/main` at that SHA before
the A10 per-CPU syscall-entry branch was created.

## A10 identifier resolution follow-up (PR #11 merged)

- Replaced modulo-derived PID-to-CSpace references in driver and IPC paths with
  process-table lookup; IPC scheduler wakeups now use the scheduler's active
  TID lookup, and endpoint IDs require one exact live endpoint match.
- Disabled synthetic driver service registration, fabricated device
  capabilities, and simulated restart success until real driver processes and
  device mappings exist.
- Moved user PIDs above the bounded kernel-thread TID range and added QEMU
  checks for unknown PID aliases, unknown endpoint aliases, duplicate endpoint
  IDs, and correct scheduler wakeup.
- Local regression guard (13 assertions), kscheduler tests (12), full host
  workspace tests, release kernel check/build, claims lint, findings verifier,
  diff check, and T0 QEMU boot passed. See `docs/EVIDENCE/A10.md` for details.
- This did not finish A10: the normal UI remains in Ring 0 and APs still lack
  per-CPU architecture/user-task setup; F8 and F10 remain present.

## A10 per-CPU syscall-entry follow-up (PR #12 merged)

- Replaced global syscall stack and saved-RSP storage with per-CPU entry state
  selected by current APIC ID.
- Kept user RSP in a scratch register until return RIP validation; malformed
  SYSRET state now builds its IRET frame while still on the trusted kernel
  stack.
- Moved syscall MSR setup after CPU discovery. The official Intel/AMD
  architecture references and design limits are recorded in
  `docs/design/a10-syscall-entry.md`.
- Local syscall-entry guard (10 checks), release kernel check/build, T0 QEMU
  boot, full host workspace suite, all repository source guards, claims lint,
  findings audit, and diff check passed before PR #12 merged. T13 exercised
  Ring 3 entry/return; this is single-CPU evidence only.
- No claim of SMP userland support: APs still idle without per-CPU GDT/IDT/TSS,
  syscall MSRs, and scheduler integration.

## A11 AP startup revalidation (PR #13 merged)

- Intel SDM review confirmed AP INIT returns processor core state to reset
  defaults; IDTR is initialized with base 0 and limit 0xffff, and an interrupt
  vector outside the IDT limit causes #GP. Source review found the previous AP
  path started a periodic timer then enabled interrupts without loading an
  AP-local IDT/TSS or scheduler context.
- Disabled INIT-SIPI-SIPI startup pending per-CPU setup. AP entry now parks
  with interrupts disabled and cannot report itself online. Hardware reporting
  separates discovered from active CPU counts. A regression guard was added to
  CI; see `docs/EVIDENCE/A11.md`.
- Regression guard (9 checks), workspace host tests, all source honesty gates,
  claims lint, release kernel check/build, `git diff --check`, T0 QEMU boot and
  a 4-CPU T2 QEMU boot passed. T2 found four MADT CPU slots and confirmed only
  the BSP active with AP startup disabled. Findings verifier still reports F8
  and F10. This is an A11 fail-closed correction, not SMP implementation; only
  the BSP is usable until AP setup and multi-core execution tests are complete.
- PR #13 passed the required GitHub CI jobs and merged to `main` at
  `facb5c89a3a14fcd54e696e5d84bce9392492a64`. Local `main` was fast-forwarded
  to the same commit; the repository was clean at handoff.

## Public readiness documentation audit (PR #15 merged)

- Reviewed `README.md`, `docs/CLAIMS.md`, and `docs/THREAT_MODEL.md` against
  current source and task evidence. The old documents described networking,
  Qubes-style compartments, active SMP, TPM/measured boot, DMA isolation, and
  completed phases that are not available in the current build.
- Replaced the public summaries with current implementation limits and added
  `tools/test_public_readiness_honest.py` to CI. The test failed before the fix
  because README had no explicit not-ready statement; the final 15-check guard,
  claims linter, and `git diff --check` passed.
- This is a public accuracy fix only. KashOS remains a QEMU/development
  prototype, not an OS for daily or sensitive use. See
  `docs/EVIDENCE/READINESS.md`.
- PR #15 passed GitHub CI and merged to `main` at
  `ea7ba7557e59a98053bb94ccdc2cc9e2364f5a2b`. Local `main` was fast-forwarded
  to that commit.

## Next task

Implement and validate AP-local GDT/IDT/TSS, syscall MSRs, stacks, scheduler
context and interrupt handling before enabling SMP. Then design a real Ring 3
init/session lifecycle and migrate the shell and compositor behind it. Keep
the current prototype UI clearly labeled Ring 0. Revisit A2/A3 if persistent-
data behavior changes; the local audit does not establish TPM-backed key
provisioning or production recovery.

## A11 CPU-local GDT/TSS groundwork (2026-10-20)

- PR #18 replaces shared
  GDT/TSS/IST globals with per-CPU state, resolves TSS stack updates through
  the current APIC ID, and discovers the BSP slot before installing its GDT.
- AP startup remains disabled. The IDT and expected-fault state remain shared,
  and scheduler/timer paths remain single-CPU; this is not SMP support.
- The new baseline-aware source guard, all repository guards, claims lint,
  findings audit, full host workspace tests, release kernel check/build, T0
  QEMU shell smoke test, and T2 four-CPU discovery/one-active-CPU check passed.
  Details are in `docs/EVIDENCE/A11.md`.
- The handoff requests `rtk` prefixes, but `rtk` is unavailable in this shell;
  direct PowerShell commands were used. T2 needed an explicit path to the
  built kernel because the harness default path is absent in this checkout.
- PR #18 merged to `main` at `0995f4dfea3374e0f55809d105f9f17e5d42e695`.
  GitHub CI passed all three jobs on both the code commit and the later branch
  head. Local verification is recorded above. Next, make IDT/exception state
  and scheduler/timer context CPU-local
  and test those paths before any AP startup is re-enabled.
