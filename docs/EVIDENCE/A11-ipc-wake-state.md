# A11 IPC wake-before-switch state — 2026-10-21

## Finding

IPC's TID-safe wake helper held `SCHEDULER` while resolving the live task, but
always called `enqueue_ready`. The scheduler already supported a subtler case:
a thread can become blocked while it is still the current CPU context, before
the next timer switch-out. If it is woken in that interval, enqueueing it marks
it Ready while the CPU still considers it current. A later scheduling decision
can then create a duplicate dispatch of one TCB.

## Change

- Replaced `enqueue_ready_by_tid` with `wake_task_by_tid`.
- The helper resolves the live TID and calls `QoSScheduler::wake_task` while
  holding the same `SCHEDULER` lock. `wake_task` restores a still-current task
  to Running; after switch-out it inserts the blocked task in a ready queue.
- IPC send/receive and the idle-handoff QEMU probe use this helper.
- Updated source guards to require the current-aware wake transition and reject
  queue-only insertion.

## Research

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Version 093,
  instruction reference for `SYSCALL` (manual page updated 2026-10-09):
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  It specifies that SYSCALL does not save RSP; software must preserve the user
  stack if it switches stacks. This informs the future continuation boundary,
  but does not validate the KashOS syscall return implementation.
- seL4, *IPC Tutorial*, reviewed 2026-10-21:
  https://docs.sel4.systems/Tutorials/ipc
  It describes endpoint queues, blocked send/receive, and the TCB-owned reply
  capability used by Call. This is a reference design, not a parity claim.

## Failure-first regression

The updated source guard was run before the implementation change:

```text
python tools/test_ipc_task_wakeup_atomic.py
FAIL as expected: missing function: pub fn wake_task_by_tid(tid: u32)
```

After the fix, the guard passes and requires resolution plus `wake_task` under
one scheduler lock. The host scheduler regression
`wake_before_blocked_current_is_switched_out_does_not_duplicate_queue_entry`
verifies the current-task case.

## Verification

```text
python tools/test_ipc_task_wakeup_atomic.py PASS
cargo test -p kscheduler --test scheduler_tests PASS (22 tests)
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
Get-ChildItem tools/test_*.py | ForEach-Object { python $_.FullName } PASS (all repository source guards)
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (T0, one CPU; blocked idle handoff marker and shell reached)
git diff --check PASS
```

The QEMU run checks that the synthetic idle wake still works through the
current-aware helper. It does not exercise a blocked user IPC syscall. PCB
state is still not committed atomically with endpoint and scheduler state;
there is no saved syscall continuation, and APs remain parked. This fix does
not complete B4 or establish SMP safety.
