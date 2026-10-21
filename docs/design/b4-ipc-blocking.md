# B4 IPC blocking boundary

## Current contract

KashOS can deliver a message directly to an endpoint whose peer is already
waiting. If no peer is waiting, send and receive return `WouldBlock` and leave
endpoint and process state unchanged.

## Why unmatched calls do not claim to block

The earlier code set a process-table entry to Blocked but returned from the
syscall immediately. It did not transition the scheduler TCB out of Running,
save a resumable IPC syscall continuation, or ensure a later wake returned the
message/result to the original caller. Receive returned an empty message on
that path. These transitions did not implement a blocking IPC contract.

Implementing true blocking needs a kernel-owned saved syscall continuation,
atomic scheduler/PCB/endpoint state transitions, and tests for wake-versus-exit
and task-slot reuse. The x86 timer path now has an idle context for a CPU with
no runnable task. The full syscall and IPC transaction work is still required
before B4 can be described as complete.

## Scheduler policy groundwork

`kscheduler` now exposes `block_task` and `wake_task` transitions. Blocking a
ready task removes it from ready queues; the timer path clears a blocked or
terminated current slot and does not requeue it. Waking a task that is still
the current context restores it to `Running` without a duplicate queue entry;
waking a task already switched off its CPU enqueues it once.

These APIs change scheduler policy state only. They do not save a resumable IPC
syscall continuation, atomically update PCB and endpoint state, or provide an
user-visible IPC result when woken. Kernel IPC therefore continues to return
`WouldBlock` for unmatched calls. The x86 timer now switches the last blocked
current task to a guarded per-CPU idle stack and can select a woken task from
idle on a later timer tick. A BSP QEMU self-test exercises this scheduler
handoff with a synthetic wake probe; it does not exercise an IPC syscall
continuation. See
[`../EVIDENCE/B4-idle-handoff.md`](../EVIDENCE/B4-idle-handoff.md).

## Error value

`SyscallError::WouldBlock = -9` is appended to the syscall error enum. Existing
values remain unchanged. Callers can retry or report unavailable behavior;
they must not interpret an unmatched call as delivered or received.
