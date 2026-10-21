# A11 CPU-indexed scheduler current state

## Goal

Stop representing the currently running task with one global scheduler slot.
Route timer selection through the CPU slot already resolved from the local
APIC ID, and ensure a CPU only dequeues tasks allowed by their affinity mask.

## Design

- `QoSScheduler` stores one current TCB index per configured CPU slot.
- Task termination removes queued references before the TCB slot can be
  reused, preventing stale entries from scheduling a replacement twice.
- The existing priority-band ready queues remain shared and are protected by
  the kernel's existing scheduler lock. This is not a per-CPU run-queue design.
- `schedule_on_cpu`, `current_task_on_cpu`, `on_timer_tick_on_cpu`, and
  `plan_context_switch_on_cpu` take a CPU slot and reject out-of-range slots.
- Legacy host APIs map to CPU slot 0.
- Queue scanning leaves live tasks for other CPUs queued and continues looking
  for an eligible task. Priority preemption ignores queued tasks that are
  pinned to another CPU.
- The x86 timer path passes its discovered `cpu_index` to scheduler context
  selection and looks up that CPU's current TCB when no switch is required.
- `kscheduler::MAX_CPUS` is the shared bound for the scheduler and the x86
  per-CPU tables.

## Remaining boundary

The scheduler table/ready queues and kernel TCB/FPU storage are still global,
the ready queues are not independently owned per CPU, and no AP-local context
is initialized. This change supplies CPU-indexed policy state only. Keep AP
startup disabled until TCB/FPU ownership, interrupt/syscall state, context
migration, and multi-CPU QEMU/hardware tests are complete.

## Research

- The seL4 threads tutorial describes choosing a runnable thread for a
  processing core; this change implements only CPU-indexed choice and affinity,
  not seL4 scheduling semantics or assurance:
  https://docs.sel4.systems/Tutorials/threads.html
- The seL4 MCS tutorial describes per-CPU scheduling-control capabilities.
  KashOS does not implement scheduling contexts or budgets:
  https://docs.sel4.systems/Tutorials/mcs.html
