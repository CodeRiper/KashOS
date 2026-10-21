# A11 FPU initial state

## Finding

New threads and processes initialized `FpuState` to 512 zero bytes and restored
that image with `FXRSTOR64`. This does not match the architectural initial x87
and SSE environment: it changes the exception masks and rounding configuration.

## Design

- Give `FpuState` one named `initial()` constructor and remove zero-image use.
- Initialize the x87 control word at FXSAVE bytes 0–1 to `0x037f`.
- Initialize MXCSR at bytes 24–27 to `0x00001f80`; leave status, tag, register,
  and reserved fields zero.
- Use the constructor for empty TCB slots, kernel threads, and user processes.
- Add a source regression guard for the defined values and all constructors.
- Keep the finding scoped to initial-state correctness. The interrupt path still
  saves FPU state after entering Rust code; proving that path preserves the
  interrupted task's registers is a separate A11 context-switch task.

## Verification boundary

The source guard and kernel build establish the image definition and wiring.
They do not demonstrate concurrent scheduling, safe interrupt-time SIMD use,
or SMP operation. AP startup remains disabled.
