# Design Note: Phase 3 — Capabilities & IPC Enforced

**Date:** Oct 17, 2026  
**Author:** Akash <akash.official.j@gmail.com>  
**Status:** Reopened for Stage C (Capability Core library tested in kcore)

> This is a legacy design note, not current implementation evidence. The old
> T16 synchronous-blocking claim was contradicted by source and has been
> corrected below. Current B4 evidence is in
> [`../EVIDENCE/B4-ipc-would-block.md`](../EVIDENCE/B4-ipc-would-block.md).

---

## 1. Overview & Goals

Phase 3 implements the seL4-style capability security model and synchronous inter-process communication (IPC) for KashOS, eliminating all ambient authority from user processes.

In accordance with the *KashOS Build Guide* and the 10 Non-Negotiable Rules:
1. **Per-Process CSpace**: Every process possesses an isolated Capability Space (`CapSpace`) managed by the microkernel. A user process names kernel resources (memory frames, IPC endpoints, notifications, TCBs, and thread scheduler contexts) strictly through capability pointers (`cptr`), which index its private CSpace.
2. **Authority Only Shrinks (Monotonicity)**: Capabilities can only be copied or minted with rights less than or equal to the source capability (`CapRights::intersect`).
3. **Capability Derivation Tree (CDT)**: Retyping and minting operations are recorded in the CDT. Revoking a parent capability recursively invalidates and zeroes all derived child capabilities across all processes in under 1 millisecond.
4. **IPC & Capability Transfer (design target)**: The intended contract is synchronous rendezvous. Current code only delivers directly to an already staged waiter; unmatched calls return `WouldBlock`. Resumable blocking is not implemented.
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
- `SYS_IPC_SEND` (2): Send to an Endpoint capability; unmatched calls return `WouldBlock`.
- `SYS_IPC_RECV` (3): Receive from an Endpoint capability; unmatched calls return `WouldBlock`.
- `SYS_IPC_CALL` (4): Atomic send-then-receive RPC operation.
- `SYS_PLEDGE` (5): Monotonic restriction of active process promises.
- `SYS_UNVEIL` (6): File access path unveiled under a directory capability.

### 2.2 Current Endpoint Behavior

The kernel validates endpoint capability rights and can directly deliver a
message to an endpoint that already has a staged peer. An unmatched send or
receive returns `WouldBlock` without recording a waiter, changing the PCB, or
returning an empty message. There is no syscall continuation or scheduler yield
for IPC yet. The direct-delivery self-test stages its waiter internally and
does not establish a complete user-facing rendezvous lifecycle.

---

## 3. Legacy Acceptance Gate Notes

The prior status labels in this table are historical and are not current
verification. The repository task ledger is authoritative; B0-B6 remain under
revalidation.

| Test ID | Gate Requirement | Result | Measured Evidence |
| :--- | :--- | :---: | :--- |
| **T14** | Capability Isolation & Rights Monotonicity | Needs revalidation | See the B0-B6 task ledger and current capability-core evidence. |
| **T15** | 1,000-Node Capability Revocation Benchmark | Needs revalidation | Historical measurements in this document are not current evidence. |
| **T16** | Direct IPC Delivery & Capability Transfer | Partial | Direct transfer and `WouldBlock` non-mutation checks run; blocking/resumption is not implemented. |
| **T17** | Kernel-Object Quota Isolation | Needs revalidation | See the B0-B6 task ledger. |

```text
[selftest] PASS: T16 direct IPC delivery and WouldBlock state checks passed; resumable blocking not implemented
```

Current runtime status reports IPC as `PARTIAL`; see `kernel/src/selftest.rs`
and `kernel/src/status.rs`.
