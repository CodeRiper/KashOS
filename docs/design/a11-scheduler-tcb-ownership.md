# A11 scheduler, TCB and IPC wake ownership

## Scope

Before AP execution, every operation that changes a task's scheduler state must
refer to the live TID and scheduler TCB as one synchronized operation. A slot
number is not a durable task identity: termination makes a slot reusable.

## Existing ownership

The scheduler policy table and its ready queues are protected by
`task::SCHEDULER`. Kernel thread records and stack allocations use separate
locks, `task::THREADS` and `task::THREAD_STACKS`. Process metadata and
capability spaces likewise use `process::PROCESS_TABLE` and
`process::PROCESS_CSPACES`. Endpoint rendezvous state is protected by
`ipc::ENDPOINTS`. Each `TicketSpinLock` disables interrupts on the acquiring
CPU, but that does not serialize a different CPU. Disabling local interrupts
does not establish an SMP lock order or ownership model.

Observed composite acquisition orders in current code include:

- Task initialization, timer scheduling, exit, and process-fault cleanup:
  `SCHEDULER -> THREADS`.
- Kernel thread creation: `SCHEDULER -> THREADS -> THREAD_STACKS`.
- User process creation: `SCHEDULER -> THREADS -> THREAD_STACKS ->
  PROCESS_TABLE -> PROCESS_CSPACES`.
- IPC rendezvous: `ENDPOINTS` is held across process metadata/capability
  operations and task wakeup. The wakeup then acquires `SCHEDULER`, so this
  path nests `ENDPOINTS -> SCHEDULER`.

This is a source-level inventory and does not rule out other orders or
cycles. In particular, process state and scheduler state are still updated in
separate critical sections, and endpoint messages are not transactionally
coupled to task termination. A full lock graph and explicit subsystem
ownership model remain required before AP startup.

## Implemented invariant

`task::wake_task_by_tid(tid)` obtains `SCHEDULER`, resolves the active TID to
its slot, and applies `QoSScheduler::wake_task` before releasing the same lock.
IPC send and receive use this function to wake a blocked rendezvous peer. They
do not carry a slot index across an unlocked interval where termination and
slot reuse could redirect the wake to a different task. The scheduler wake
transition restores `Running` in place if the task is still current (it has
not yet reached its timer switch-out); otherwise it queues the task once.

The API returns `NoSuchTask` if the TID is no longer active and propagates
scheduler wake errors. IPC maps either to `InvalidCapability` at the syscall
boundary. This closes the wake-before-switch duplicate-queue case; it does not
make PCB state updates atomic with endpoint/scheduler transitions, nor does it
make queues, TCB/FPU/context state, syscall entry, or CPU-local architecture
setup safe for simultaneous execution.

## Gate

Keep APs parked. Before relaxing that gate, define and enforce a whole-system
lock order (including interrupt-context rules), make process/endpoint/task
transitions atomic or explicitly state-machine safe, and run concurrent tests
that exercise wake-versus-exit, task-slot reuse, and cross-CPU scheduling.
