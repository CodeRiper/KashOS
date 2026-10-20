# A11 scheduler ready-state guard

## Scope

This change prevents a task already marked `Ready` from being inserted into a
second scheduler band-queue entry. Such duplicate entries could cause a task
to be selected again while it was already running. It does not make the
scheduler concurrent or enable secondary CPUs.

## Current design facts

- `QoSScheduler` has one `current` task and three global band queues.
- Kernel timer scheduling uses one global `SCHEDULER` lock.
- The timer path legitimately re-enqueues a task transitioning from `Running`
  after its slice expires or a higher-priority task arrives.
- Task state is the existing lifecycle marker; a live `Ready` task already
  has queue ownership.
- Enqueueing a slot that is not live is rejected as `NoSuchTask`.
- A task in `Running` state remains enqueueable for the existing timer
  preemption path; this change does not redesign blocking or wakeup states.

## Change and validation

Add `SchedError::AlreadyReady`, check liveness and state before queue mutation,
and test that a duplicate enqueue is rejected and only one queue selection is
possible. Run the scheduler tests, full host workspace tests, kernel target
check/build, source guards, claims/finding checks, and the T0 QEMU smoke test.
Keep the AP startup gate disabled. The broader A11 design still requires
per-CPU run-queue/current-task/context state and a multi-CPU hardware-path test.

## Research

- Rust `core::result::Result` documents the `Ok`/`Err` contract used to report
  the new scheduler error: https://doc.rust-lang.org/stable/core/result/enum.Result.html
- The Embedded Rust Book describes `no_std`/`core` use in bare-metal systems:
  https://doc.rust-lang.org/embedded-book/intro/no-std.html
