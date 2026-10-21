# A11 supervisor reschedule for SYS_YIELD — 2026-10-21

## Finding

`SYS_YIELD` returned zero without scheduling another task. The scheduler had a
timer-only decision path, so invoking the yield syscall did not yield.

## Design

- Add a scheduler transition that requeues the running task, selects the next
  runnable task, and does not charge fabricated timer duration.
- Route `SYS_YIELD` through a DPL-0 software interrupt at vector `0xF0` while
  already in Ring 0. The IDT gate remains unavailable to direct Ring 3 `INT`.
- Save all general registers and FPU/SSE state using an interrupt frame on the
  current task's guarded kernel stack. Use the same architecture task-context
  restore contract as the timer ISR, including CR3/TSS/syscall-stack updates.
- If another task is selected, save this supervisor interrupt frame in the
  yielding thread. When rescheduled, restore it so the original syscall
  dispatcher continues and returns zero to Ring 3.
- If the only task is selected again, return through its current interrupt
  frame without creating a duplicate queue entry.

## Tests

Host scheduler tests cover rotation, no synthetic time charge, single-task
self-selection, and invalid CPU index. The T0 QEMU Ring 3 test executes
`SYS_YIELD`, prints a post-resume marker, and exits. CI also checks that the
syscall uses the DPL-0 gate and the assembly preserves the context.

## Limits

This enables only voluntary scheduling across a syscall boundary. It does not
suspend IPC or save an IPC result, add a reply capability, or atomically update
endpoint/PCB/TCB/scheduler state. A11 remains single-CPU tested and APs stay
parked. This is a bounded scheduler change, not a complete IPC or seL4-style kernel implementation.
