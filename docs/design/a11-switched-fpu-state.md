# A11 switched-task FPU regression

## Finding

The previous timer FPU check injected vector 32 while the boot task was the
only runnable task. It exercised same-task save/restore but did not prove the
scheduler selected and restored a different TCB's FPU image.
The existing worker test's floating-point variables and constant comparisons
were not consumed observably and could be optimized away.

## Design

- Extend the existing BSP preemption acceptance test with one kernel worker
  whose assembly loop holds a unique 128-bit sentinel in XMM15.
- Publish a start flag only after XMM15 is loaded. The boot task must observe
  this flag after being scheduled again before it sets the worker stop flag;
  this requires at least one timer-driven switch away from the worker.
- On a later switch back, the worker stores XMM15 to its own stack and checks
  the sentinel before returning.
- Require the QEMU T0 smoke test to observe a dedicated PASS marker.
- Keep the test single-CPU. It does not validate shared-queue ownership or AP
  scheduling.
- Report only completed counter iterations and the explicit XMM sentinel
  result; do not describe the old constant comparison as register-integrity
  coverage.

## Verification boundary

The test relies on the existing same-class round-robin preemption path and the
current kernel-thread bootstrap frame. If the test exposes a stack alignment or
context restore bug, fix that bug in the same isolated task only when it is
necessary for the regression to execute correctly. Do not enable AP startup.
