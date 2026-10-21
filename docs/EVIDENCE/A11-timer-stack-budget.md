# A11 timer ISR stack budget — 2026-10-21

## Result

Inspection of the current optimized x86-64 kernel and scheduler reports a
935-byte maximum increment for the known normal timer-switch call path,
measured from the pre-interrupt RSP and conservatively assuming the 40-byte
Ring 3 to Ring 0 CPU frame. Same-CPL timer entry pushes a 24-byte CPU frame.
The increment includes 120 GPR-save bytes, up to 15 bytes of alignment loss,
528 bytes reserved by `_isr32`, compiler stack frames for the handler/task/
scheduler functions, and nested return addresses. The model and its limits are
documented in [`../design/a11-timer-stack-budget.md`](../design/a11-timer-stack-budget.md).

Compiler metadata for the normal path:

```text
x86_timer_handler                         0x08 bytes
kernel::task::on_timer_tick               0x68 bytes
QoSScheduler::plan_context_switch_on_cpu   0x28 bytes
QoSScheduler::on_timer_tick_on_cpu         0x18 bytes
QoSScheduler::schedule_on_cpu             0x18 bytes
```

Disassembly verified the ISR reserves 528 bytes, saves 15 GPRs, aligns RSP,
and calls `x86_timer_handler`; that handler tail-calls `task::on_timer_tick`.
The scheduler timer function may call `schedule_on_cpu` on its fallback path.

## Commands

The repository toolchain is `rustc 1.99.0 (b940084d7 2026-09-28)` on the
recorded host. `rtk` is unavailable; direct commands were used.

```text
$env:RUSTC_BOOTSTRAP='1'; $env:CARGO_TARGET_DIR='target/stack-analysis'; cargo rustc --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none --config 'profile.release.strip="none"' --config 'profile.release.debug=true' -- -Z emit-stack-sizes
PASS (kernel metadata emitted)

$env:RUSTC_BOOTSTRAP='1'; cargo rustc -p kscheduler --release --target x86_64-unknown-none --config 'profile.release.strip="none"' --config 'profile.release.debug=true' -- -Z emit-stack-sizes
PASS (scheduler metadata emitted)

llvm-readobj --stack-sizes target/stack-analysis/x86_64-unknown-none/release/kernel
PASS (kernel frames: x86_timer_handler 8 bytes; task::on_timer_tick 104 bytes)

llvm-ar x target/x86_64-unknown-none/release/deps/libkscheduler-7c610b5e42fb4e2b.rlib
llvm-readobj --stack-sizes <extracted scheduler object>
PASS (plan 40 bytes; scheduler tick 24 bytes; schedule fallback 24 bytes)

llvm-objdump -d <analysis kernel>
PASS (verified `_isr32`, handler tail call, and timer call chain)
```

An attempt to propagate `-Z emit-stack-sizes` through every third-party
dependency failed because the host Rust compiler exited with
`STATUS_ILLEGAL_INSTRUCTION` while compiling `poly1305` and
`curve25519-dalek`. The targeted kernel and scheduler metadata commands above
completed successfully. This does not change the regular target build status.

## Limits and next step

935 bytes is only the measured normal timer-path increment for this build. It
does not include the pre-existing stack depth at an arbitrary interrupted
Ring 0 point, exception/panic paths, other compiler configurations, or a
formal whole-program call-depth bound. A stack high-water measurement and
worst-case workload analysis remain needed before asserting stack safety.
APs remain parked, and A11 remains incomplete. Next: specify and test
scheduler/TCB ownership and lock ordering before any AP execution is enabled.
# A11 timer ISR stack budget — 2026-10-21
