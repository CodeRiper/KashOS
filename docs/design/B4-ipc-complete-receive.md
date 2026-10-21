# B4 complete-message receive contract

Date: 2026-10-21

## Finding

`SYS_IPC_RECV` bounded its user copy to the caller's buffer capacity, but the
endpoint receive consumed the whole message and woke a waiting sender first.
A short buffer therefore returned apparent success with a silently truncated
message.

## Change

- Pass the validated word capacity into the endpoint receive operation.
- Compare it with the pending message length while the endpoint lock is held.
- If the message does not fit, return `InvalidArgument` before capability
  installation, peer wake, endpoint consumption, or PCB state change.
- Preserve the existing direct receive helper for kernel callers by giving it
  the maximum IPC word capacity.
- Exercise a too-small failure followed by a complete retry in the boot
  self-test, and guard the source ordering in CI.

## Limits

The preflight still checks canonical user address bounds, not page presence or
write permission. A page fault during the eventual copy can still happen after
endpoint consumption. Unmatched IPC is still `WouldBlock`; this change does
not add syscall blocking, continuation results, atomic SMP transactions, or
multi-waiter queues. AP startup remains disabled.
