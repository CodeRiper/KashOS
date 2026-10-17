# Design Note: Phase 3 — Capabilities & IPC Enforced

**Date:** Oct 17, 2026  
**Author:** Akash <akash.official.j@gmail.com>  
**Status:** 100% Completed, Verified Live in QEMU, Accepted (Phase 3)

---

## 1. Overview & Goals

Phase 3 implements the seL4-style capability security model and synchronous inter-process communication (IPC) for KashOS, eliminating all ambient authority from user processes.

In accordance with the *KashOS Build Guide* and the 10 Non-Negotiable Rules:
1. **Per-Process CSpace**: Every process possesses an isolated Capability Space (`CapSpace`) managed by the microkernel. A user process names kernel resources (memory frames, IPC endpoints, notifications, TCBs, and thread scheduler contexts) strictly through capability pointers (`cptr`), which index its private CSpace.
2. **Authority Only Shrinks (Monotonicity)**: Capabilities can only be copied or minted with rights less than or equal to the source capability (`CapRights::intersect`).
3. **Capability Derivation Tree (CDT)**: Retyping and minting operations are recorded in the CDT. Revoking a parent capability recursively invalidates and zeroes all derived child capabilities across all processes in under 1 millisecond.
4. **Synchronous IPC & Capability Transfer**: Processes communicate via synchronous, rendezvous IPC endpoints (`kipc`). Senders can transfer messages and capabilities across endpoints with unforgeable compartment badges.
5. **No Ambient Authority**: Standard POSIX operations (file open, network access, hardware control) require explicit capability tokens or unveil grants derived from parent capabilities. Global ambient namespaces are strictly deleted.
6. **Kernel Object Quota Isolation**: Untyped memory allocations fund all kernel objects per process. One process exhausting its memory quota cannot starve or crash other processes.
7. **Acceptance Gate Criteria**:
   - Negative test: Process A cannot invoke or read Process B's capabilities or memory.
   - Revoke performance: Recursive revocation of 1,000 derived capabilities completes in $< 1\text{ ms}$ with memory zeroed.
   - Kernel quota: A process exhausting its Untyped quota receives `NotEnoughMemory` while the rest of the microkernel continues uninterrupted.
   - Synchronous IPC test: Ping-pong IPC with capability transfer verified in QEMU.

---

## 2. Architecture & Data Structures

```
  Process A (Ring 3)                         Process B (Ring 3)
┌───────────────────────┐                  ┌───────────────────────┐
│ Private CSpace:       │                  │ Private CSpace:       │
│  Slot 1: TCB (Self)   │                  │  Slot 1: TCB (Self)   │
│  Slot 2: VSpace (PML4)│                  │  Slot 2: VSpace (PML4)│
│  Slot 3: Untyped RAM  │                  │  Slot 3: Untyped RAM  │
│  Slot 4: Endpoint EP1 ├───────┐  ┌───────┤  Slot 4: Endpoint EP1 │
└───────────────────────┘       │  │       └───────────────────────┘
                                ▼  ▼
                   ══════════════════════════ [Privilege Boundary]
                   ┌────────────────────────┐
                   │  Endpoint (Microkernel)│
                   │  - State: Idle / Wait  │
                   │  - Queue: Senders/Recv │
                   │  - Badge: Unforgeable  │
                   └────────────────────────┘
```

### 2.1 Capability System Calls
- `SYS_CAP_INVOKE` (1): Invoke a capability method (`untyped_retype`, `cnode_copy`, `cnode_mint`, `cnode_revoke`, `tcb_configure`).
- `SYS_IPC_SEND` (2): Synchronous send to an Endpoint capability with message buffer and optional capability to transfer.
- `SYS_IPC_RECV` (3): Synchronous receive from an Endpoint capability into a user buffer and destination capability slot.
- `SYS_IPC_CALL` (4): Atomic send-then-receive RPC operation.
- `SYS_PLEDGE` (5): Monotonic restriction of active process promises.
- `SYS_UNVEIL` (6): File access path unveiled under a directory capability.

### 2.2 Endpoint Rendezvous Protocol
1. **Send**:
   - The kernel validates that the caller holds an Endpoint capability with `CapRights::WRITE`.
   - If a receiver is already waiting on the endpoint:
     - The message payload is copied directly from sender buffer to receiver buffer under SMAP protection.
     - If a capability is attached (`cap_transfer != 0`), it is verified, derived with rights mask, and installed into the receiver's CSpace.
     - The receiver's thread state is changed to `Ready`, and the sender continues.
   - If no receiver is waiting:
     - The sender is added to the endpoint's wait queue and marked `ProcessState::Blocked(BlockedReason::IpcSend)`.
     - The scheduler yields the CPU.
2. **Receive**:
   - The kernel validates that the caller holds an Endpoint capability with `CapRights::READ`.
   - If a sender is already waiting on the endpoint:
     - The message and badge are delivered directly to the receiver.
     - The sender is unblocked and enqueued in the scheduler.
   - If no sender is waiting:
     - The receiver is added to the endpoint's wait queue and marked `ProcessState::Blocked(BlockedReason::IpcReceive)`.
     - The scheduler yields the CPU.

---

## 3. Acceptance Gate Results (QEMU Live Verification)

All 4 acceptance criteria have been verified on real hardware CPU instructions in QEMU:

| Test ID | Gate Requirement | Result | Measured Evidence |
| :--- | :--- | :---: | :--- |
| **T14** | **Capability Isolation & Rights Monotonicity (Negative Test)** | **PASSED** | Authority escalation rejected; empty slots return `KError::SlotEmpty`; invalid slot indices safely caught without panics; cross-CSpace isolation enforced (zero ambient authority). |
| **T15** | **1,000-Node Capability Revocation Benchmark** | **PASSED** | 1,000 derived capabilities recursively revoked in **345 $\mu\text{s}$** (866,515 CPU cycles, well under the $1,000\ \mu\text{s}$ threshold) with all physical memory zeroed. |
| **T16** | **Synchronous IPC Rendezvous & Capability Transfer** | **PASSED** | Sender blocked until receiver met at endpoint; unforgeable compartment badge `0xBEEF7777` delivered; transferred `Frame` capability installed into receiver's private CSpace at slot 2 with full rights. |
| **T17** | **Kernel-Object Quota Isolation** | **PASSED** | Process exhausting its 64 KiB Untyped quota received `KError::NoMemory` without crashing the microkernel; sibling process allocated normally from its own quota. |

```
[selftest] ✓ T14 Capability Isolation & Rights Monotonicity fully verified (zero ambient authority)
[selftest] ✓ T15 Capability Revocation Benchmark: 1,000 derived caps revoked in 345 us (866515 cycles, < 1000 us limit)
[selftest] ✓ T16 Synchronous IPC Rendezvous & Capability Transfer verified (unforgeable badge 0xBEEF7777 + Frame transferred)
[selftest] ✓ T17 Kernel-Object Quota Isolation: process quota exhaustion safely rejected (KError::NoMemory), microkernel stable
```

Status Registry verified in boot banner:
```
| [OK]        Capability Engine                    : handles, CSpace, revocation & IPC |
| [OK]        Synchronous Rendezvous IPC           : badged endpoints & cap transfer |
```
