# KashOS engineering work log

**Last updated:** 2026-10-21
**Repository tip checked:** `main` at `d11213354d4376833a922b8737aede3ab2171bee` (PR #40)
**Current task branch:** `main`
**Current engineering task:** Design transactional blocked IPC with per-thread results and safe user-copy semantics; keep AP startup disabled

## B4 complete-message receive (2026-10-21)

- Found that `SYS_IPC_RECV` copied only `min(buffer capacity, message length)`
  after consuming the complete endpoint message, silently discarding any tail.
- The dispatcher now passes its validated capacity into the receive operation.
  A message larger than that capacity returns `InvalidArgument` before cap
  installation, sender wake, endpoint clearing, or PCB changes. T16 now checks
  the failed short-buffer attempt and a successful full-capacity retry.
- Failure-first behavior is covered by the runtime self-test and a CI source
  guard. Release kernel check/build, full host tests, all 31 source guards,
  claims lint, findings audit, and fresh T0 QEMU passed. Evidence:
  `docs/EVIDENCE/B4-ipc-complete-receive.md`.
- Canonical pointer validation still cannot prove page presence/write
  permission, and an actual copy fault can still occur after consumption.
  Unmatched IPC remains `WouldBlock`; no resumable IPC continuation or atomic
  SMP transaction is implemented. APs stay parked.
- Next: design transactional blocked IPC with per-thread results and a
  fault-safe user-copy contract before enabling unmatched calls to block.
- PR #40 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at
  `d11213354d4376833a922b8737aede3ab2171bee` on 2026-10-21. Local `main` was
  fast-forwarded to that exact `origin/main` commit.

## B4 supervisor blocked-context handoff (2026-10-21)

- Added a scheduler handoff for a current task already marked Blocked, including
  the wake-before-handoff case, and a DPL-0 software interrupt at vector `0xF1`
  that saves/restores the per-thread kernel continuation and FPU state.
- Added `block_current_task` for the actual Running TCB and changed the QEMU
  blocked-to-idle self-test to use the explicit handoff, then verify return
  after the synthetic wake. Scheduler host tests failed before the new API and
  now cover task switch, idle, wake-before-handoff, and invalid current state.
- Verified with the focused source guards, release kernel check/build, and a
  fresh one-CPU QEMU boot. Full workspace tests, all source guards, honesty
  gates, and docs updates are pending before PR.
- No IPC syscall uses this path yet. Unmatched IPC still returns `WouldBlock`;
  there is no saved IPC result object or atomic endpoint/scheduler/PCB/CSpace
  transition. APs remain parked. See
  `docs/EVIDENCE/B4-blocked-syscall-handoff.md`.
- PR #39 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, merged to `main` at
  `65bb765bcf3136153ad3faea1809bcf0c8d66de0`; local `main` fast-forwarded to
  that commit.
- Next: integrate endpoint waiter publication, scheduler blocking, and per-task
  result delivery with rollback before exposing blocking IPC to user tasks.

## B4 IPC wake-failure rollback (2026-10-21)

- Re-read the direct IPC send/receive, scheduler wake, PCB, and capability-space
  paths. Both direct rendezvous branches consumed endpoint state and marked the
  peer Ready before confirming its scheduler wake; a rejected wake could lose
  the waiter/message and leave a transferred cap installed.
- Changed send and receive to keep the endpoint/PCB state intact until
  `wake_task_by_tid` succeeds, and remove a just-installed transferred
  capability if that wake fails. Added a CI guard for both directions.
- The guard failed on pre-change `HEAD` (`send consumes waiter before
  scheduler wake succeeds`) and passes after the fix. Workspace tests, kernel
  check/build, all 30 Python source guards, claims lint, findings verification,
  fresh T0 QEMU, and `git diff --check` passed; details are recorded in
  `docs/EVIDENCE/B4-ipc-wake-failure-rollback.md`.
- PR #38 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, merged to `main` at
  `ed64a42bd6077904611890aa389a86e2adda595b`; local `main` fast-forwarded to
  that commit.
- This is failure rollback groundwork, not an atomic SMP transaction. APs stay
  parked; unmatched IPC remains `WouldBlock`; no resumable syscall result or
  full transactional user-buffer delivery exists.
- Next: define the per-thread syscall result continuation and integrate the
  endpoint, scheduler, PCB, and CSpace transition under a documented and
  tested lock order.

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

Make scheduler, current-task identity, TCB ownership, FPU state, and timer
context safe for per-CPU concurrent execution. Then initialize AP syscall
entry and test multi-CPU scheduling before enabling AP startup. Afterward,
design a real Ring 3 init/session lifecycle and migrate the shell and compositor
behind it. Keep
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
  head. Local verification is recorded in `docs/EVIDENCE/A11.md`.

## A11 CPU-local IDT and exception state (2026-10-20)

- On `codex/a11-percpu-idt-fault-state`, the BSP now gets an indexed IDT and
  per-CPU fault-recovery, user-fault recovery, and timer tick state.
- Expected NX/WP recovery now requires both vector 14 and the exact armed
  faulting instruction address. The expectation is cleared if the write
  returns normally. QEMU exercised the deliberate page fault successfully.
- AP startup remains disabled. The global scheduler, current TID, TCB/FPU
  ownership, and timer context have not been made safe for concurrent CPUs.
- Baseline regression guard, host workspace suite, release kernel check/build,
  T0 QEMU smoke boot, T2 discovery/one-active-CPU check, A10/A11 source guards,
  claims lint, and findings audit passed locally. Full evidence is in
  `docs/EVIDENCE/A11.md`.

## T0 smoke-test reliability follow-up (2026-10-20)

- Fixed the test's blocking serial reader, Windows console encoding failure,
  and stale boot markers. Its regression guard rejects the old unbounded read.
- The corrected T0 test passed against the release kernel and attached test
  vault image; it observed the NX/WP recovery, T13, T22, locked vault, and shell.
- The release build, complete host workspace suite, T2 four-discovered/one-
  active check, claims lint, and findings audit passed. F8 and F10 remain open.
- PR #21 passed all three GitHub CI jobs and merged to `main` at
  `42e80e1022eb0fa8acb6d4db559c33ce769589c0`; local `main` was fast-forwarded.

## A11 CPU-local current-task identity follow-up (2026-10-20)

- `task::current_tid()` previously read a global atomic while the scheduler
  already carried a partially used per-CPU TID field. Generic Linux syscalls
  also converted an unknown TID into root task 1. The active branch uses
  APIC-indexed atomic slots, returns 0 for unknown identity, rejects it in the
  generic syscall path, and removes the duplicate non-atomic field.
- Research/design: `docs/design/a11-percpu-task-identity.md`; evidence and exact
  checks: `docs/EVIDENCE/A11.md`.
- The regression guard rejects the old source. Host tests, optimized kernel
  check/build, T0 boot and shell assertions, T2 four-discovered/one-active gate,
  syscall/process/AP/IDT/GDT/readiness guards, claims lint, and findings audit
  passed locally.
- No AP was started. Global scheduler selection, TCB/FPU ownership, and timer
  context still block SMP. A11 remains in progress.

## Next task

Make scheduler selection and TCB/FPU/timer context correct for per-CPU
execution while keeping AP startup disabled. Add a hardware-path QEMU test for
task identity on multiple CPUs before enabling any AP.

## A11 duplicate scheduler enqueue correction (2026-10-20)

- Audited `QoSScheduler::enqueue_ready` and found that it accepted a task
  already marked `Ready`, allowing duplicate queue entries and repeated
  selection of the same live task.
- Added a failure-first host regression test and `SchedError::AlreadyReady`;
  enqueue also rejects non-live slots. The existing timer preemption path may
  requeue a live `Running` task.
- Evidence: `docs/EVIDENCE/A11-scheduler-ready-state.md`; design:
  `docs/design/a11-scheduler-ready-state.md`.
- Host workspace tests, kernel release check/build, all 19 Python source
  guards, claims lint, findings audit, and the T0 QEMU smoke test passed.
  `cargo fmt --all -- --check` reports repository-wide baseline diffs; no
  unrelated formatting was applied. See evidence for exact limits.
- The T2 harness run observed its entropy event only; it did not test CPU
  scheduling. APs remain parked; A11 remains incomplete.
- PR #23 passed all three required GitHub Actions jobs and merged to `main` at
  `81c90ad99e1de6b776eb03e94f916e5f20429f09`.
- PR #22 passed all three required CI jobs and merged to `main` at
  `3ee53f4bd9e3bc868df6a8154042298e673b44a5`; local `main` was fast-forwarded.

## A11 CPU-indexed scheduler current state (2026-10-21)

- Added per-CPU current task slots and CPU-indexed scheduling, timer, and
  context-plan APIs. Queue selection honors task affinity while leaving the
  ready queues shared under the existing global lock.
- Wired the x86 timer path to its discovered CPU slot. Legacy scheduler APIs
  remain CPU 0.
- Added host checks for two distinct CPU current slots, CPU affinity, priority
  preemption, and invalid CPU indexes. Updated T13's invalid incidental
  `PID % MAX_PROCESSES` inequality to an explicit unknown modulo-alias lookup;
  the source guard rejects the old assertion.
- Evidence and design: `docs/EVIDENCE/A11-percpu-scheduler-current.md` and
  `docs/design/a11-percpu-scheduler-current.md`.
- Host workspace tests, release kernel build/check, all 19 Python source
  guards, claims/finding gates, T0 QEMU shell boot, and T2 four-discovered / one-
  active CPU gate passed locally.
- This is CPU-indexed scheduler policy, not SMP. Ready queues, scheduler lock,
  task table, and FPU/thread storage remain shared; no AP executes KashOS code.
  A11 remains incomplete.
- PR #24 passed all three required GitHub Actions jobs and merged to `main` at
  `5a5a2326d8554b2b8eece38fa0d991ad6dea058e`.

## Next task

Continue A11 with ownership and synchronization of per-CPU run queues, TCB/FPU
state, and timer/context migration. Add QEMU tests that execute concurrently
on multiple CPUs only after AP-local GDT/IDT/TSS, syscall, and interrupt setup
is complete. Keep AP startup disabled until those tests pass.

## A11 FPU initial-state follow-up (2026-10-21)

- Added `FpuState::initial()` with x87 control word `0x037f` and MXCSR
  `0x1f80`; fresh kernel threads, processes, and empty TCB slots now use it.
- Added a failure-first source regression check at
  `tools/test_fpu_initial_state.py`. It initially failed because the valid
  constructor was absent, and now passes.
- Intel's current SDM was consulted; links and exact values are recorded in
  `docs/EVIDENCE/A11-fpu-initial-state.md`.
- Workspace host suite, release kernel check/build, all Python source guards,
  claims linter, findings audit, `git diff --check`, and QEMU T0 shell smoke
  passed. Findings F8 (VT-d remains a stub) and F10 (normal UI remains in Ring
  0) remain present.
- Rust formatting checks still report pre-existing formatting differences
  across unrelated files; no broad formatting rewrite was applied. The
  environment does not have the required `rtk` command, so verification used
  direct commands.
- At that point the interrupt handler still reached Rust before saving the
  outgoing FPU state. The next A11 follow-up below addresses the timer-entry
  save boundary; it does not establish SMP or OS readiness.

## A11 timer-interrupt FPU save boundary (2026-10-21)

- Added a 16-byte-aligned 512-byte FXSAVE image plus an output pointer slot on
  the active interrupt stack. `_isr32` saves before its Rust call and restores
  the scheduler-selected image after Rust returns.
- The timer handler copies the saved image into the outgoing TCB. It selects
  that same image when no switch occurs and selects the incoming TCB image
  after a scheduler handoff. This closes the Rust-handler clobber window for
  the timer path on the currently active BSP.
- A failure-first source guard was added. A boot self-test places a sentinel in
  XMM15, invokes the timer vector with `int 0x20`, and checks the same-task
  return value. QEMU T0 observed the marker and booted through the shell.
- Workspace host suite, release kernel check/build, all source guards, claims
  linter, findings audit, and `git diff --check` passed. F8 and F10 remain.
- The interrupt scratch consumes 528 bytes of the active task stack. Stack
  exhaustion analysis is not complete. The T0 runtime check exercises only the
  same-task return path; it does not test context-switch image selection or
  simultaneous CPUs. Scheduler/TCB state remains shared and APs remain parked.
- PR #26 passed all three required GitHub Actions jobs in both triggered runs
  and merged to `main` at `e0d33360357ea97a1c4b8119d730a4bc7320f451`.
- Next: exercise FPU image selection across an actual task switch, analyze the
  528-byte interrupt stack cost, then address scheduler and TCB ownership. AP
  startup stays disabled until switched-context and concurrent-CPU gates pass.

## A11 switched-task FPU regression (2026-10-21)

- Added a third BSP preemption worker that loads a unique XMM15 sentinel, marks
  itself started, and spins until the boot task sets its stop flag after being
  scheduled again. It then checks XMM15 after a later timer handoff.
- QEMU T0 observed the switched-task marker and booted to the shell. The
  same-task test and switched-task test now have separate required markers.
- Audit removed the old worker test's optimized-away floating-point and
  constant register comparisons; its output now reports only actual counter
  iterations. The dedicated assembly sentinel provides the observable FPU
  check.
- Workspace host tests, release kernel check/build, all Python source guards,
  claims/finding audits, and QEMU T0 passed. F8 and F10 remain present.
- This earlier handoff item was completed in the A11 timer stack budget
  analysis below. Whole-program stack high-water evidence remains outstanding.
- PR #27 passed all three required GitHub Actions jobs in both triggered runs
  and merged to `main` at `7c3a92c815f651b9a8a17f2356b0bc0ec379e9fa`.

## A11 per-thread kernel stack guard pages (2026-10-21)

- Source audit found the kernel image's broad `.data`/`.bss` RW map included
  every nominal `ThreadStack.guard_page`; only the boot stack's guard was
  unmapped. The x86 page-table build now unmaps each thread guard and fails
  closed if any expected unmap fails.
- The deliberate-fault path now requires exact #PF error-code equality as
  well as exact fault RIP. QEMU T0 writes to a reserved thread guard and
  observed supervisor non-present write error code `0x2`, recovered at the
  exact RIP, and reached the locked shell.
- Full workspace host tests, release x86-64 kernel check/build, all Python
  source guards, claims lint, findings audit, and QEMU T0 passed. F8 and F10
  remain present. This checks one guard at runtime on the BSP; APs remain
  parked, A11 remains incomplete, and worst-case interrupt/stack usage remains
  unanalyzed. Evidence: `docs/EVIDENCE/A11-thread-stack-guards.md`.
- Next: specify and test shared scheduler/TCB ownership and lock ordering
  before any AP execution is enabled. Keep the BSP-only gate in place.
- PR #28 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate on the final branch commit and merged
  to `main` at `db6c97cbcbc9698746140b92b6a3295712215fcf` on 2026-10-21.

## A11 timer interrupt stack analysis (2026-10-21)

- Compiler stack-size metadata and disassembly of the release-optimized
  x86-64 kernel/scheduler measured a 935-byte increment along the known normal
  timer scheduling path, conservatively including the 40-byte user-to-kernel
  hardware frame. The 528-byte FXSAVE scratch is part of this amount.
- This is only the interrupt-path increment; it cannot bound the preexisting
  stack depth at arbitrary Ring 0 preemption points or panic/fault paths.
  Therefore it does not establish worst-case stack safety for a 16 KiB thread
  stack. Details and commands: `docs/EVIDENCE/A11-timer-stack-budget.md`.
- A whole-workspace compiler metadata attempt hit host `STATUS_ILLEGAL_INSTRUCTION`
  in third-party `poly1305` and `curve25519-dalek`; targeted metadata builds
  for the kernel crate and scheduler crate passed. No regular kernel build
  regression was observed.
- PR #29 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at
  `d3b8d62e1f4f1fdb5540bcffa9c4d186ca9d0b8b` on 2026-10-21.

## A11 scheduler/TCB ownership (2026-10-21)

- Source review found both IPC rendezvous wake paths resolved a TID to a
  scheduler slot, released the scheduler lock, then later enqueued the saved
  slot. With simultaneous CPUs, termination and slot reuse between those
  operations could enqueue a different task.
- Added `task::enqueue_ready_by_tid`, which resolves the live TID and enqueues
  it while continuously holding `SCHEDULER`; IPC send and receive use it.
  `tools/test_ipc_task_wakeup_atomic.py` failed before the fix and passes after;
  it is now a CI honesty-gate check.
- This only closes that specific wakeup slot-reuse race. Shared scheduler
  queues/TCB/FPU/context state and broader PROCESS_TABLE/PROCESS_CSPACES/IPC
  transaction ownership have not been established as SMP-safe. APs remain parked. See
  `docs/EVIDENCE/A11-scheduler-tcb-ownership.md` and
  `docs/design/a11-scheduler-tcb-ownership.md`.
- Next: establish one coherent ownership/lock-order policy for scheduler,
  TCB, process and endpoint state, then add a real multi-CPU stress test before
  any AP execution is considered.
- PR #30 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate in both branch runs, then merged to
  `main` at `5763c9cced6e6b9d7a1a8ccf5a176d9025d8f5fa` on 2026-10-21.
- Local verification: workspace tests, release kernel check/build, all 24
  Python source guards, claims lint, findings audit, QEMU T0 shell smoke, and
  `git diff --check` passed. The T0 run was single-CPU and does not exercise
  concurrent IPC wakeups. `cargo fmt --all -- --check` reports existing
  formatting drift in untouched workspace files.

## B4 IPC blocking correction (2026-10-21)

- Re-audit found unmatched IPC send/receive returned success after marking only
  the PCB Blocked; the scheduler task continued to run, and receive returned an
  empty message. The syscall path has no resumable blocked-call continuation.
- Unmatched operations now return `SyscallError::WouldBlock` (`-9`) and do not
  alter endpoint or PCB state. Direct delivery to a pre-existing waiter remains
  available. Updated the boot self-test and added a CI source guard.
- True synchronous blocking remains unimplemented. The B4 ledger remains
  `Needs revalidation`; evidence/design: `docs/EVIDENCE/B4-ipc-would-block.md`
  and `docs/design/b4-ipc-blocking.md`.
- Downgraded the boot status from `Real` to `Partial`; corrected T16's output,
  the legacy Phase 3 design note, and `docs/EVIDENCE/B4.md` so the host model
  tests are not presented as kernel blocking evidence.
- PR #31 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate in both branch runs, then merged to
  `main` at `1800e03346ec96982d1f1c039f5b2f9563ef3f37` on 2026-10-21.
- Local verification passed: workspace tests, release kernel check/build, all
  25 source guards, claims lint, findings audit, QEMU T0 with the revised T16
  marker, and `git diff --check`. The QEMU run was single-CPU.

## B4 scheduler block/wake groundwork (2026-10-21)

- Added scheduler policy APIs to block and wake a live task. A blocked current
  task is removed from its CPU slot at the next timer scheduling decision and
  is not requeued. A wake before that decision restores the task in place so
  it cannot be queued while still current.
- Three host regressions cover ready-task blocking/wake, wake after switching
  away, and wake-before-switch. The tests failed before implementation because
  the APIs were absent; they pass after the change.
- Full workspace tests, release x86-64 kernel check/build, all source guards,
  claims lint, findings audit, and QEMU T0 passed. QEMU uses one CPU and does
  not call these new APIs through a live IPC syscall.
- Unmatched IPC remains `WouldBlock`. Syscall continuation, atomic IPC/PCB/TCB
  transaction, idle context, and SMP behavior remain unimplemented. APs stay
  parked. Evidence: `docs/EVIDENCE/B4-scheduler-block-wake.md`.
- Next B4 step: define the saved syscall continuation and a real no-runnable
  idle handoff, then integrate the condition, endpoint, PCB and scheduler
  transitions under an explicit ownership/lock protocol. Keep this policy API
  separate from any claim of completed blocking until the runtime path exists.
- PR #32 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate; it merged to `main` at
  `5ce6861ee41b18064984cb80e6c4c116d3c9e53e` on 2026-10-21. Local `main` was
  fast-forwarded to that exact `origin/main` commit.

## B4 blocked-task idle handoff (2026-10-21)

- Follow-up source trace found the timer handler returned the interrupted stack
  when a blocked current task had no runnable replacement. That resumed the
  blocked task despite the scheduler clearing its current slot.
- The scheduler now makes idle an explicit context-switch target. x86 reserves
  a per-CPU idle stack with an unmapped guard, saves the outgoing blocked
  context, and returns to the idle `sti; hlt` loop. A later timer can select a
  woken task from idle. Stale current TIDs after task termination also hand off
  to idle; a scheduler-selected task without a live thread record halts.
- Host tests cover blocked-last-task to idle and wake-from-idle dispatch. The
  T0 QEMU self-test checked both thread and idle guard pages, then blocked the
  sole boot task, entered idle, consumed a synthetic wake probe, and resumed
  the task on a later timer tick. It reached the locked shell.
- Full workspace tests, release x86-64 kernel check/build, all Python source
  guards, claims lint and findings audit passed. F8 and F10 remain present.
  APs remain parked and shared scheduler state is not SMP-safe.
- Unmatched IPC remains `WouldBlock`; no saved syscall continuation or atomic
  endpoint/PCB/TCB transaction was added. Evidence:
  `docs/EVIDENCE/B4-idle-handoff.md`.
- This verifies the BSP timer/context handoff only. APs remain parked and
  shared scheduler state is not SMP-safe. Unmatched IPC remains `WouldBlock`;
  no saved syscall continuation or atomic endpoint/PCB/TCB transaction was
  added. Next: implement resumable syscall state and atomic IPC task/endpoint
  ownership, with wake-versus-exit and slot-reuse regressions.
- PR #33 merged after all three required GitHub Actions jobs passed, at
  `f4be523d8ef67fa135ad92fb6d16ac21e4406bf1` on 2026-10-21. Local `main` was
  fast-forwarded to that exact `origin/main` commit.
- Final main verification: workspace host suite, release x86-64 kernel
  check/build, all Python source guards, claims lint, findings audit, QEMU T0
  through the locked shell, and `git diff --check` passed. Findings F8 and F10
  remain present; the T0 run is single-CPU and the OS is not production ready.

## A11 IPC wake-before-switch state (2026-10-21)

- The IPC wake helper resolved a live TID under `SCHEDULER` but always called
  `enqueue_ready`. If a blocked task was still current because its timer switch
  had not happened yet, this made one task both current and queued. The
  scheduler's `wake_task` transition already handles that race by restoring
  `Running` in place, and queues only a task that has switched off its CPU.
- Replaced the queue-only helper with `wake_task_by_tid`; it resolves the TID
  and applies `wake_task` within one scheduler lock. IPC send, IPC receive,
  and the synthetic QEMU idle wake probe use this helper.
- The failure-first source regression failed before the change because the
  current helper was missing. Existing host scheduler coverage checks
  wake-before-switch leaves the task Running and prevents duplicate dispatch.
- Research: Intel SDM Version 093, SYSCALL does not save RSP and leaves stack
  preservation to software; seL4 IPC docs describe endpoint wait queues and
  blocked send/receive behavior. These sources support the continuation design
  boundary but do not establish KashOS correctness or parity.
- Verification and exact results: `docs/EVIDENCE/A11-ipc-wake-state.md`.
- This does not implement unmatched IPC blocking or saved syscall continuation.
  PCB state is still updated separately from endpoint and scheduler state;
  APs remain parked and shared scheduler/context state is not SMP-safe.
- Next: design per-thread syscall continuation ownership and a transactional
  IPC state transition before enabling unmatched calls to block.
- PR #34 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at
  `7908a9a3ea44653ce4371d5f3b42d5f5bbd7a47b` on 2026-10-21. Local `main` was
  fast-forwarded to that exact `origin/main` commit.

## A11 per-thread syscall stack ownership (2026-10-21)

- Fast syscall entry previously selected one stack per CPU. Current IA32_FMASK
  clears IF, so ordinary timer preemption does not interrupt syscall dispatch.
  Still, a future syscall-side suspension needs thread-owned frame storage or a
  second task's syscall could overwrite the suspended frame.
- The GS-local stack-top slot is now an aligned atomic at the assembly ABI's
  asserted offset. Task setup and context switches select the owning task's
  kernel stack; idle selects its own stack. A per-CPU bootstrap stack remains
  only for the initialization interval before task setup.
- Every Ring 3 syscall checks that the live dispatcher RSP belongs to the
  current thread's reserved kernel stack and halts on mismatch. T0 QEMU's Ring
  3 self-test observed the ownership marker and reached the locked shell.
- Failure-first source regression, release kernel check/build, workspace tests,
  all Python guards, claims lint, findings audit, and QEMU T0 passed. F8/F10
  remain present; APs remain parked. Research and exact commands:
  `docs/EVIDENCE/A11-per-thread-syscall-stack.md`.
- This provides per-task storage for syscall frames; it does not implement a
  syscall-side block/yield path or saved result continuation. IPC remains
  `WouldBlock` when unmatched, and endpoint/PCB/scheduler commits are not yet
  atomic.
- Next: implement and test an explicit syscall continuation switch path, then
  transact endpoint, PCB, TCB, and scheduler state before unmatched IPC blocks.

- PR #35 passed all required GitHub Actions jobs and merged to `main` at
  `6091ee6e405916903f1477fa85e1dfa49243280e` on 2026-10-21. Local `main`
  was fast-forwarded to that exact origin commit.

## B4 IPC syscall user-buffer preflight (2026-10-21)

- Re-read the syscall, IPC, scheduler, and task code. `SYS_IPC_RECV` consumed a
  message before validating the output pointer, and IPC copy helper errors were
  discarded.
- Added bounded receive-buffer preflight before endpoint lookup, rejects a
  non-empty null buffer, and propagates user-copy helper errors. Added T42
  runtime checks, a QEMU marker, and a CI source-order regression guard.
- Failure-first source guard failed before the fix because the validation helper
  and preflight ordering were absent. Workspace tests, all source guards, release
  kernel check/build, and T0 QEMU passed. See
  `docs/EVIDENCE/B4-ipc-user-buffer-preflight.md`.
- The validator checks only canonical range and arithmetic bounds, not page
  mappings/write permission; a fault during the actual copy may still occur
  after message consumption. Unmatched IPC remains `WouldBlock`; no saved
  syscall continuation or atomic endpoint/PCB/scheduler transaction exists.

- PR #36 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at `4c33be35373ae23e5d9df62822840ab76c65acbd` on
  2026-10-21. Local `main` was fast-forwarded to that exact origin commit.

## B4 syscall user-page permission preflight (2026-10-21)

- Source review found syscall copies and IPC receive validated canonical address
  bounds but not whether each touched page was present, user-accessible, or
  writable. It also found the ELF loader's initial stack pointer above its four
  mapped stack pages.
- Added an x86-64 four-level page-table walk for active Ring 3 copy ranges,
  requiring Present+User at every level and Writable for kernel-to-user output.
  IPC receive output is preflighted before endpoint consumption. Corrected the
  stack base so its four mapped pages contain the configured initial RSP.
- Failure-first source guard failed before implementation. Workspace host
  tests, release kernel check/build, all 32 source guards, claims lint, findings
  audit, and QEMU T0 through the locked shell passed. QEMU verified RX text,
  RW stack, rejected text writes and ranges touching unmapped pages. The QEMU
  script does not build the kernel; the release image was explicitly rebuilt
  before the passing run.
- Evidence and limits: `docs/EVIDENCE/B4-ipc-user-page-permission-preflight.md`.
  This uses the current identity-addressable x86-64 page-table allocator and
  single-CPU configuration; copies are not fault-recoverable and SMP address
  space mutation is not supported. APs remain parked; B4 remains incomplete.
- `rtk` is specified by repository instructions but is not installed in this
  shell. Commands were run directly in PowerShell.
- PR #41 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at
  `5d55ab27bb35343a864695d1adae713cde4fa35b`. Local `main` was fast-forwarded
  to that exact remote commit.

## A1 browser claim cleanup follow-up (2026-10-23)

- A1 evidence said GitHub review was pending even though the network fail-closed
  work had been on `main`. Rechecking current source found browser module docs
  and output still advertised authenticated pages, tracker blocking, cookie
  sandboxing, and a secure privacy browser. Some messages described a kill
  switch or tracker blacklist on error branches the current network code can
  never return.
- Removed those claims and dead branches, retained explicit local viewer and
  remote-unavailable labels, and expanded the network honesty source guard. The
  guard failed before code changes on nine initial assertions and passes all 48
  afterward.
- Workspace host tests, release kernel check/build, all 32 Python source guards,
  claims lint, findings audit, and QEMU T0 through the locked shell passed.
  Findings F8 and F10 remain present. Exact commands and limits are in
  `docs/EVIDENCE/A1.md`.
- No remote network path or browser isolation was implemented. `rtk` is absent
  in this shell, so commands ran directly in PowerShell.
- PR #42 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at
  `44fc9dd0803ae54b17143b8f447181c123a864c0`. Local `main` was fast-forwarded
  to that commit. A1 is now revalidated for fail-closed network behavior and
  honest browser copy; remote services remain unavailable.

## A2 vault non-destructive path revalidation (2026-10-23)

- Rechecked vault mount/open, explicit format references, boot test, interactive
  unlock, and session lock. Mount errors return without formatting; the boot
  storage test skips when the vault is unavailable; no call sites invoke
  `format_root`. Failed unlock locks KMS and drops the VFS mount. The configured
  duress credential remains destructive by design and is a separate A3 policy
  concern.
- `tools/test_storage_non_destructive.py` passed all six checks, and the
  test-only fast-KDF vault suite passed all 21 tests. The default-cost run was
  stopped after exhaustive corruption/crash tests exceeded 60 seconds; no
  assertion failure was reported.
- Fresh QEMU T0 boot reached the locked shell, and the disk image SHA-256 was
  unchanged before/after (`31B809229EFA682DB6B6041AF61743D3E54D79DDFEB42C79E5BEDD853C5AE012`).
  Release kernel check/build and docs claims/finding checks passed.
- Evidence: `docs/EVIDENCE/A2.md`. This does not establish physical media or
  power-loss guarantees; the installer and duress credential policy remain open.

## A11 voluntary syscall yield (2026-10-21)

- Source review found `SYS_YIELD` was a no-op. Added scheduler rotation with no
  fabricated timer accounting, a DPL-0 software reschedule gate at vector 0xF0,
  and a saved interrupt frame on the yielding task's own kernel stack.
- The Ring 3 test program calls SYS_YIELD, then prints a resume marker and exits.
  Host scheduler tests verify same-band rotation, no fake elapsed time, and
  single-task self-selection. T0 QEMU observed the post-yield marker and reached
  the locked shell.
- Failure-first scheduler tests failed before the API existed. Workspace tests,
  release kernel check/build, and all Python source guards passed. Details and
  official sources are in `docs/EVIDENCE/A11-syscall-voluntary-yield.md`.
- This is voluntary yield only. IPC remains direct-only and unmatched operations
  return `WouldBlock`; result continuation and atomic IPC endpoint/PCB/TCB/task
  transitions remain unimplemented. AP startup remains disabled.

- PR #37 passed Workspace Subsystem Tests, Build Microkernel (x86-64), and
  Build Guide v2 Claims & Honesty Gate, then merged to `main` at `2585d23417e412d7ae20856dc54760a479f48fa6` on
  2026-10-21. Local `main` was fast-forwarded to that exact origin commit.
