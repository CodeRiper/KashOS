# KashOS Master Task Ledger

> Audit note (2026-10-21): legacy completion marks are not sufficient evidence. A1 is being re-audited because current source contradicted its old evidence. Other Part A and B0-B6 entries are marked for revalidation until their implementation and evidence are checked against the plan. PRs #7–#33 are merged to `main`; they correct claims and fail closed where hardware support is absent, but do not complete A9, A10, or A11.

| Task ID | Title | Status | Branch | Evidence File |
|---|---|---|---|---|
| A1 | Remove every fake network and Tor output | Ready for review | main | docs/EVIDENCE/A1.md |
| A2 | Stop the data-loss bug (vault open versus format) | Ready for review | main | docs/EVIDENCE/A2.md |
| A3 | Real key hierarchy: passphrase first, TPM second | Needs revalidation | main | docs/EVIDENCE/A3.md |
| A4 | Real TPM 2.0 driver (TIS first, CRB second) | Not implemented | main | docs/EVIDENCE/A4.md |
| A5 | Measured boot, sealing and anti-rollback | Not implemented | main | docs/EVIDENCE/A5.md |
| A6 | Real TCP/IP with smoltcp | Needs revalidation | main | docs/EVIDENCE/A6.md |
| A7 | NIC drivers: real, many, tested | Needs revalidation | main | docs/EVIDENCE/A7.md |
| A8 | TLS and HTTPS | Needs revalidation | main | docs/EVIDENCE/A8.md |
| A9 | Real IOMMU (Intel VT-d) | Needs revalidation | main | docs/EVIDENCE/A9.md |
| A10 | Move out of Ring 0: real user-space services | Needs revalidation | main | docs/EVIDENCE/A10.md |
| A11 | SMP and scheduler | In progress (BSP FPU and unmapped thread/idle stack guards; timer path measures 935-byte increment; IPC TID wake uses scheduler wake transition under one lock; block/wake policy and x86 idle handoff added; shared queues/context; AP startup disabled) | codex/b4-ipc-wakeup-state | docs/EVIDENCE/A11.md; docs/EVIDENCE/A11-percpu-scheduler-current.md; docs/EVIDENCE/A11-fpu-initial-state.md; docs/EVIDENCE/A11-timer-fpu-save-boundary.md; docs/EVIDENCE/A11-switched-fpu-state.md; docs/EVIDENCE/A11-thread-stack-guards.md; docs/EVIDENCE/A11-timer-stack-budget.md; docs/EVIDENCE/A11-scheduler-tcb-ownership.md; docs/EVIDENCE/B4-scheduler-block-wake.md; docs/EVIDENCE/B4-idle-handoff.md; docs/EVIDENCE/A11-ipc-wake-state.md |
| A12 | Persistent filesystem and disk layout | Needs revalidation | main | docs/EVIDENCE/A12.md |
| A13 | USB: xHCI, HID and mass storage | Needs revalidation | main | docs/EVIDENCE/A13.md |
| A14 | UEFI boot, Secure Boot and a loader that measures | Needs revalidation | main | docs/EVIDENCE/A14.md |
| A15 | Storage drivers: NVMe, hardened AHCI | Needs revalidation | main | docs/EVIDENCE/A15.md |
| A16 | Display (double-buffering, virtio-gpu 2D) | Needs revalidation | main | docs/EVIDENCE/A16.md |
| A17 | ACPI, power and platform | Needs revalidation | main | docs/EVIDENCE/A17.md |
| A18 | Make the UI honest and connected to real services | Needs revalidation | main | docs/EVIDENCE/A18.md |
| A19 | libc, Rust std and a POSIX layer | Needs revalidation | main | docs/EVIDENCE/A19.md |
| A20 | Re-verify the old audit and finish hardening | Needs revalidation | main | docs/EVIDENCE/A20.md |
| A21 | Status registry from real probes; CI that blocks fakes | Needs revalidation | main | docs/EVIDENCE/A21.md |

## Part B: Kash Kernel 2.0 (seL4-Class Microkernel in Rust)

| Task ID | Title | Status | Branch | Evidence File |
|---|---|---|---|---|
| B0 | Architecture & CapRights Foundations | Needs revalidation | main | docs/EVIDENCE/B0.md |
| B1 | Untyped Memory Model & Watermark Allocator | Needs revalidation | main | docs/EVIDENCE/B1.md |
| B2 | CNode Guarded Radix Trees & Capability Derivation Tree (CDT) | Needs revalidation | main | docs/EVIDENCE/B2.md |
| B3 | Transitive Revocation & Amnesic Memory Zeroing | Needs revalidation | main | docs/EVIDENCE/B3.md |
| B4 | Badged Synchronous Endpoints & Capability Routing | Needs revalidation (direct delivery only; scheduler block/wake and x86 idle handoff groundwork exist, but unmatched calls return WouldBlock until resumable syscall blocking and atomic IPC state transitions exist) | main | docs/EVIDENCE/B4.md; docs/EVIDENCE/B4-ipc-would-block.md; docs/EVIDENCE/B4-scheduler-block-wake.md; docs/EVIDENCE/B4-idle-handoff.md |
| B5 | Asynchronous Notifications & Event Signaling | Needs revalidation | main | docs/EVIDENCE/B5.md |
| B6 | Thread Control Blocks (TCBs), Fault Handlers & State | Needs revalidation | main | docs/EVIDENCE/B6.md |
| B7 | Mixed-Criticality Scheduling (MCS): SchedContext & Temporal Isolation | Planned | - | docs/EVIDENCE/B7.md |
| B8 | Reply Capabilities & One-Shot RPC Protocol | Planned | - | docs/EVIDENCE/B8.md |
| B9 | Virtual Memory Architecture: VSpace, PageDirectory, PageTable, Frames | Planned | - | docs/EVIDENCE/B9.md |
| B10 | Address Space Identifiers (ASIDControl & ASIDPool) | Planned | - | docs/EVIDENCE/B10.md |
| B11 | Hardware Interrupt Subsystem: IrqControl & IrqHandler Caps | Planned | - | docs/EVIDENCE/B11.md |
| B12 | Port I/O Capability Firewall: IoPortControl & IOPort Caps | Planned | - | docs/EVIDENCE/B12.md |
| B13 | I/O Space & DMA Remapping (IOMMU Domain Device Caps) | Planned | - | docs/EVIDENCE/B13.md |
| B14 | Hardware Virtualization Extensions: Vcpu Capabilities | Planned | - | docs/EVIDENCE/B14.md |
| B15 | Runtime Invariant Verifier Engine: Invariants I1–I4 | Planned | - | docs/EVIDENCE/B15.md |
| B16 | Runtime Invariant Verifier Engine: Invariants I5–I7 | Planned | - | docs/EVIDENCE/B16.md |
| B17 | seL4 System Call Dispatcher & C-ABI Compatibility Gate | Planned | - | docs/EVIDENCE/B17.md |

## Current implementation handoff

- Verified repository tip: `main` at `f4be523d8ef67fa135ad92fb6d16ac21e4406bf1` (PR #33).
- A9 is still incomplete: VT-d/ACS activation and hardware DMA containment are unavailable and fail closed; see `docs/EVIDENCE/A9.md`.
- PR #11 merged the modulo-based identifier fixes and disabled fabricated driver provisioning/restarts.
- PR #12 merged per-CPU syscall entry state for the initialized BSP. The malformed-return IRET frame stays on the trusted kernel stack; its T13 evidence is single-CPU.
- A10 is still incomplete: ordinary desktop/settings/shell boot in Ring 0. APs do not have the per-CPU architecture state or user-task setup required for SMP userland; see `docs/EVIDENCE/A10.md`.
- PR #13 merged the A11 revalidation: the AP path previously enabled local timer interrupts before loading an AP-local IDT and had no TSS or scheduler context. Secondary CPUs now remain parked and only initialized CPUs report online. SMP remains unavailable pending full per-CPU setup and multi-core execution tests.
- PR #18 merged CPU-indexed GDT/TSS/IST state and APIC-indexed TSS stack updates. PR #21 added CPU-local IDT, fault-recovery, and timer state, exact-RIP deliberate #PF recovery, and a bounded/current-marker T0 QEMU smoke test. Global scheduler/task state still prevents AP execution. Verification is recorded in `docs/EVIDENCE/A11.md`.
- PR #22 replaces the global current TID with an APIC-indexed atomic slot, uses TID 0 for unresolved CPU identity, and rejects that identity in generic syscalls instead of falling back to root. This is identity groundwork only; APs remain parked.
- PR #28 removes all x86-64 thread stack guard pages from the writable image mapping, matches expected page-fault error codes exactly, and verifies one guard write under T0 QEMU. All three required CI jobs passed; see `docs/EVIDENCE/A11-thread-stack-guards.md`.
- PR #15 corrected README, threat model and claims inventory to describe the prototype status and unavailable networking, TPM, DMA isolation, user services and SMP; see `docs/EVIDENCE/READINESS.md`.
- Timer stack analysis records a 935-byte normal-path increment but does not establish total stack safety; see `docs/EVIDENCE/A11-timer-stack-budget.md`. IPC wake-by-TID now resolves and enqueues under one scheduler lock; broader shared-state ownership remains open. See `docs/EVIDENCE/A11-scheduler-tcb-ownership.md`; AP startup remains disabled.

