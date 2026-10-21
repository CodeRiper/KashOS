# B4 IPC user buffer preflight — 2026-10-21

## Finding

The SYS_IPC_RECV dispatcher called the endpoint receive operation before checking
its output pointer. A bad pointer could therefore consume a queued message and
wake its sender before the receiver buffer was rejected. Both IPC syscall arms
also discarded errors returned by their user-copy helpers.

## Change

- Bound the receive capacity to MAX_IPC_WORDS and validate the full bounded
  byte range before endpoint lookup; a non-empty null pointer is rejected.
- Propagate user-copy helper errors from IPC send and receive.
- Add T42 runtime boundary checks and a QEMU-required marker, plus a CI source
  guard that enforces validation-before-receive ordering.

## Limits

The current validator checks nullness, integer overflow, and the canonical user
address range; it does not establish that every page is mapped writable. A page
fault during the actual copy can still terminate the user process after the
message has been consumed. IPC delivery remains direct-only, unmatched calls
return WouldBlock, and endpoint/PCB/scheduler state is not one atomic
transaction. This change does not implement saved syscall continuation.
