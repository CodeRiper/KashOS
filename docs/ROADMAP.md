# KashOS implementation roadmap

**Audit date:** 2026-10-21
**Repository state checked:** `main` at `f4be523d8ef67fa135ad92fb6d16ac21e4406bf1` (PR #33)
**Active work branch:** `main`
**Current gate:** A11 groundwork; blocked-task policy now produces an explicit idle switch plan, and x86 uses guarded per-CPU idle stacks. A single-CPU QEMU self-test exercises blocked-task to idle to synthetic wake and resumed task. This does not complete resumable IPC. IPC wake-by-TID resolves and enqueues under one scheduler lock. Architecture identity and scheduler current-task selection are CPU-indexed, but ready queues, scheduler lock, TCB/FPU storage, and timer/context ownership remain shared. APs stay parked until local syscall/interrupt setup and concurrent scheduling are initialized and tested.

**B4 note:** IPC calls with no waiting peer now return `WouldBlock` without
pretending the caller was suspended. Scheduler block/wake and x86 idle handoff
groundwork exist; true IPC syscall resumption remains unimplemented, and the
runtime IPC status is Partial. See
[`EVIDENCE/B4-ipc-would-block.md`](EVIDENCE/B4-ipc-would-block.md) and
[`EVIDENCE/B4-scheduler-block-wake.md`](EVIDENCE/B4-scheduler-block-wake.md) and
[`EVIDENCE/B4-idle-handoff.md`](EVIDENCE/B4-idle-handoff.md).

This repository is an operating-system prototype and is not production ready.
Verification claims are not available. Do not infer feature completion from
names, UI labels, task IDs, or old evidence files. Use source, reproducible
tests, and dated evidence for every completion claim. The engineering plan in
[`MASTER_PLAN.md`](MASTER_PLAN.md) remains the full long-term specification.

See [`RESEARCH_SECURITY_MODELS.md`](RESEARCH_SECURITY_MODELS.md) for the
official-source comparison of the requested reference systems and Linux app
compatibility.

## Current verified gate: A10/A11 fail-closed revalidation (user-space migration and SMP incomplete)

- PR #8 corrected the normal boot-session claim: the desktop, settings UI, and
  shell remain kernel-resident in Ring 0. Ring 3 tests do not establish that
  these services run with user-mode isolation.
- PR #9 removed fabricated broad capabilities from process creation, starts
  user CSpaces empty, resolves syscall and cleanup targets through the process
  table, and rejects invalid rights masks. The regression test checks PID-slot
  resolution and an empty initial CSpace; this is not a complete user-session
  lifecycle or evidence that these services are isolated.
- PR #11 (`codex/a10-identifier-resolution`) replaced the remaining
  modulo-based PID/endpoint lookups with active-table resolution, rejects
  ambiguous endpoint IDs, and disables fabricated driver service
  registration/provisioning and restart reporting. It is merged to `main` at
  `2931a8c`.
- PR #12 merged per-CPU syscall stack/RSP state for the initialized BSP and
  builds malformed-return IRET frames on the trusted kernel stack. T13 syscall
  entry evidence remains single-CPU only.
- PR #13 merged the A11 fail-closed correction to `main` at `facb5c8`. Source
  revalidation found AP startup enabled a local periodic timer and
  interrupts without loading AP-local IDT/TSS state or initializing a scheduler
  context. AP startup is disabled and AP entry stays parked;
  only initialized CPUs are reported online. SMP scheduling remains unavailable.
- PR #18 replaced singleton GDT/TSS/IST storage with CPU-indexed state and
  resolves the TSS stack update using the current APIC ID. APs remain parked.
  See [`EVIDENCE/A11.md`](EVIDENCE/A11.md).
- PR #21 made IDT, fault-recovery, and timer accounting state CPU-local, and
  only accepts an armed protection-test fault at its exact #PF instruction
  address. It also repaired the bounded T0 QEMU smoke test. AP startup remains
  disabled pending scheduler and AP context work; see [`EVIDENCE/A11.md`](EVIDENCE/A11.md).
- PR #22 replaces the global current TID with a CPU-indexed atomic slot and
  rejects unresolved identity rather than mapping it to root task 1. This does
  not make scheduler/TCB/FPU/context switching SMP-safe; APs remain parked.
  See [`EVIDENCE/A11.md`](EVIDENCE/A11.md).
- PR #23 rejects duplicate enqueue of a scheduler task already marked `Ready`;
  failure-first host regression and verification are in
  [`EVIDENCE/A11-scheduler-ready-state.md`](EVIDENCE/A11-scheduler-ready-state.md).
  This fixes queue lifecycle correctness only. Shared scheduler queues, the
  global scheduler lock, TCB/FPU storage, and timer/context ownership still
  block concurrent CPU execution. PR #23 merged to `main` at `81c90ad`; all
  three required GitHub Actions jobs passed.
- PR #24 adds per-CPU current slots and CPU-indexed scheduler
  timer/selection APIs, applies affinity during queue selection, and passes the
  CPU slot through the x86 timer path. Ready queues remain shared and APs remain
  parked. All three required GitHub Actions jobs passed; PR #24 merged to `main`
  at `5a5a232`. See [`EVIDENCE/A11-percpu-scheduler-current.md`](EVIDENCE/A11-percpu-scheduler-current.md).
- Follow-up audit found fresh threads restored an all-zero FXSAVE image. The
  current task initializes new x87/SSE state to Intel's reset defaults
  (`FCW=0x037f`, `MXCSR=0x1f80`) and adds a regression guard. This does not fix
  the separate interrupt-entry save boundary or make the shared scheduler
  SMP-safe. Verification details are in
  [`EVIDENCE/A11-fpu-initial-state.md`](EVIDENCE/A11-fpu-initial-state.md).
  PR #25 merged to `main` at `e883aa0`; required GitHub Actions jobs passed.
- Current A11 follow-up moves timer FXSAVE before Rust entry and FXRSTOR to the
  assembly exit after Rust has selected the next task's image. The BSP QEMU
  self-test verifies XMM15 survives the same-task timer path; APs remain parked.
  See [`EVIDENCE/A11-timer-fpu-save-boundary.md`](EVIDENCE/A11-timer-fpu-save-boundary.md).
  PR #26 merged to `main` at `e0d3336`; all required GitHub Actions jobs passed.
- Current A11 follow-up adds a BSP worker that holds XMM15 across an actual
  timer-driven switch away and back; T0 QEMU observes the pass marker. The old
  worker test's optimized-away floating-point/constant checks were removed from
  its claims. APs remain parked; see
  [`EVIDENCE/A11-switched-fpu-state.md`](EVIDENCE/A11-switched-fpu-state.md).
  PR #27 merged to `main` at `7c3a92c`; required CI jobs passed.
- Current follow-up removes every x86-64 `ThreadStack.guard_page` from the
  broad `.data`/`.bss` mapping and fails boot if an expected removal fails. A
  deliberate QEMU T0 write observed exact non-present supervisor-write #PF
  code `0x2` and recovered at the armed RIP. This BSP/QEMU check does not
  establish AP behavior, worst-case stack safety, or hardware validation;
  evidence: [`EVIDENCE/A11-thread-stack-guards.md`](EVIDENCE/A11-thread-stack-guards.md).
  PR #28 passed all three required CI jobs and merged to `main` at `db6c97c`.
- The current timer-stack analysis measured 935 bytes of additional stack
  consumption along the normal optimized x86-64 timer/scheduler path, including
  the 528-byte FXSAVE scratch. It does not account for arbitrary preexisting
  Ring 0 stack depth or exceptional paths, so worst-case stack safety remains
  unestablished. See [`EVIDENCE/A11-timer-stack-budget.md`](EVIDENCE/A11-timer-stack-budget.md).
  PR #29 passed the three required CI jobs and merged to `main` at `d3b8d62`.
- IPC wakeup no longer retains a scheduler slot across separate locks: each
  wake resolves the TID and enqueues while holding `SCHEDULER`. This narrow
  correction does not establish SMP safety; see
  [`EVIDENCE/A11-scheduler-tcb-ownership.md`](EVIDENCE/A11-scheduler-tcb-ownership.md).
- A10 remains incomplete: the normal desktop/settings/shell stay in Ring 0;
  syscall concurrency and a complete user init/session lifecycle are not
  established.
- PR #7 remains fail-closed: hardware VT-d, ACS validation, and DMA containment
  are not implemented. NIC and DDE hardware DMA paths remain disabled.
- Current ground-truth findings include F8 (hardware DMA/IOMMU path absent) and
  F10 (normal boot session remains Ring 0). Do not report these as resolved.
- PR #15 corrected stale public README, threat-model and claim-inventory status
  statements. The OS remains a development/QEMU prototype and is not ready for
  sensitive use. See
  [`EVIDENCE/READINESS.md`](EVIDENCE/READINESS.md). This documentation audit
  does not change the implementation or make the OS ready for sensitive use.

## A6 network revalidation (historical; fail-closed behavior retained)

- Remote HTTP and HTTPS requests return `NotAvailable`.
- DNS resolution only parses IPv4 literals; DNS protocol lookup is not present.
- The anonymity gateway starts down. Tor, WireGuard, and I2P are not integrated.
- The local HTML-to-text parser is a prototype, not ELinks, Dillo, or Ladybird.
- Graphical web browsers are not implemented.
- The kernel's hand-built TLS record helpers are not a TLS implementation and
  must not be used to send application data as HTTPS.
- CI now has a source regression guard for fabricated network/browser success.
- A6 review found that smoltcp's in-memory test adapter was not connected to
  kernel NIC RX/TX. TCP/DHCP/ingress and polling remain disabled; all kernel
  egress is blocked until the full path and policy checks are integrated.
- Boot initialization now prepares the heap before the acceptance suite uses
  allocations, and large packet rings are allocated off the early kernel stack.
- The QEMU T0 boot smoke test was run against the newly built release kernel;
  it reached the shell and observed its configured markers. This does not
  verify security properties printed by model tests or hardware TPM/IOMMU behavior.

## A2 storage safety audit

- `mount_root` does not format automatically after an open failure.
- The old T25 boot test still formatted an unmounted root volume, and it wrote
  then raw-tampered a test file when a volume was mounted. This follow-up was
  removed; the test is now read-only and skips an unavailable mount.
- Mount no longer provisions missing folders or baseline files; the explicit
  format path initializes those. The test disk SHA-256 stayed unchanged across
  the final QEMU boot.
- A CI regression guard and kvault in-memory wrong-password non-mutation test
  cover these properties. See [`EVIDENCE/A2.md`](EVIDENCE/A2.md).
- The legacy `install-os` path wrote a fabricated partition table and test
  marker/noise to raw sectors, then reported a successful install. It is now
  disabled and guarded in CI; a real installer remains unimplemented.

### A3 re-audit finding

The old A3 evidence was stale. This revision removes automatic use of the
public bootstrap credential and starts KMS locked; a hidden console prompt
unlocks the vault, and the GUI is gated until storage mounts. The compiled-in
salt/HKDF transform and in-memory TPM handle remain insufficient for the
planned key hierarchy. Keep A3 marked Needs revalidation until credential
enrollment, protected GUI input, persistent TPM provisioning, and legacy
volume migration are designed and tested.
- Vault unlock also bounds Argon2 memory before allocation: the library default
  is 256 MiB and the kernel supplies a budget from its largest contiguous free
  heap block. This blocks forged headers from requesting up to 4 GiB and
  exhausting the OS. It does not replace A3's missing versioned KDF, enrollment,
  recovery, and legacy-volume migration.
- New volume formatting now rejects KDF costs below the 19 MiB, t=2, p=1
  Argon2id floor. Lower-cost legacy volumes remain readable for recovery. The
  fast 64 KiB test profile requires a debug build and explicit Cargo feature;
  the kernel boot self-test uses the production floor. Passphrase enrollment,
  recovery keys, TPM provisioning, and GUI credential entry remain incomplete.

### A4/A5 TPM audit finding

- The existing TIS/CRB path was not validated: ACPI TPM2 contents were not
  parsed into a transport address, CRB execution returned synthetic success,
  hardware errors were ignored, and PCR/sealed-key state used RAM-only models.
  Production discovery, measurement, sealing, and NV anti-rollback APIs now
  fail unavailable. Hardware/swtpm conformance, event-log verification,
  persistent sealed-object lifecycle, and rollback-counter tests remain future
  work. See [`EVIDENCE/A4.md`](EVIDENCE/A4.md) and
  [`EVIDENCE/A5.md`](EVIDENCE/A5.md).

## Next work, in order

1. **Revalidate Part A evidence.** The legacy ledger marks A1-A21 complete, but
   several old claims are contradicted by current source. Re-audit each task,
   replace unsupported evidence, and only then restore a completed status.
2. **A2/A3 data and key safety.** Independently verify vault open/format
   behavior, passphrase handling, key derivation, and crash recovery before
   enabling persistent user data.
3. **A6 real networking.** Design and test a real NIC-to-IP-to-DNS-to-TCP path;
   keep egress disabled until packet-level/QEMU tests demonstrate it works.
4. **A8 TLS.** Integrate a maintained, reviewed TLS implementation compatible
   with the target and trust-store model. Verify certificates, hostname checks,
   handshake completion, record encryption/authentication, and failure cases.
5. **A18/A21 honest settings and probes.** Make UI controls reflect actual
   service state and ensure settings cannot assert protections that are absent.
6. **Part B kernel audit.** Compare implemented capability, memory, scheduling,
   address-space, IRQ, DMA, and verification properties with seL4's documented
   guarantees. Feature similarity does not establish equivalent assurance.
7. **Linux application support.** Specify a compatibility boundary (ABI,
   userspace, packaging, graphics, syscall policy) and prove the isolation
   model before advertising support.
8. **Platform comparison.** Qubes and GrapheneOS security properties are not available
   in KashOS until separately implemented and tested. Treat these
   as platform-specific design references, not labels. Domain/VM isolation and
   verified-boot/hardware claims need their own design and test evidence.

## Release gates

- No simulated success or fabricated security status.
- Every feature claim links to implementation and reproducible evidence.
- Kernel builds and host tests pass; QEMU profiles pass for the changes they
  cover; hardware-specific claims have hardware evidence.
- `docs/TASKS.md`, task evidence, UI, and README agree on status.
- Avoid superiority claims about other operating systems without a precise,
  independently measured comparison on the same supported hardware/threat
  model.
