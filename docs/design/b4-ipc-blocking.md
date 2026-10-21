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
atomic scheduler/PCB/endpoint state transitions, a scheduler path that does not
requeue blocked tasks, and tests for wake-versus-exit and task-slot reuse. That
work is still required before B4 can be described as complete.

## Error value

`SyscallError::WouldBlock = -9` is appended to the syscall error enum. Existing
values remain unchanged. Callers can retry or report unavailable behavior;
they must not interpret an unmatched call as delivered or received.
