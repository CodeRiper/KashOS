# A11 scheduler/TCB ownership and IPC wakeup — 2026-10-21

## Finding

Before this change, both IPC rendezvous wake paths called
`SCHEDULER.lock().task_index_for_tid(tid)`, dropped the lock, updated the PCB,
then acquired `SCHEDULER` again to enqueue the saved array slot. If another
CPU terminated the target and reused that slot in the gap, IPC could enqueue
the wrong task. APs are currently parked, so this was a latent concurrency
hazard rather than an observed multi-core failure.

## Change and regression check

Added `task::enqueue_ready_by_tid`, keeping TID resolution and queue insertion
inside one scheduler critical section. Both IPC send and receive wake paths
call it. Errors fail at the syscall boundary as `InvalidCapability`.

The source guard `tools/test_ipc_task_wakeup_atomic.py` was first run against
the pre-fix working source and failed because the atomic API was absent. It
passes after the change and is added to `.github/workflows/ci.yml`.

## Lock inventory and limits

The current acquisition paths and their limits are described in
[`../design/a11-scheduler-tcb-ownership.md`](../design/a11-scheduler-tcb-ownership.md).
Notably, interrupt disabling only affects the local CPU, IPC and process
metadata changes are not a single transaction, and shared scheduler queues,
TCB/FPU/context state, and broader process/endpoint lifecycle races have not
been established as safe for AP execution. This work does not enable AP startup.

## Verification (2026-10-21)

```text
python tools/test_ipc_task_wakeup_atomic.py PASS
python tools/test_process_authority_fail_closed.py PASS
all 24 tools/test_*.py source guards PASS
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (single-CPU T0 reached locked shell and required markers)
git diff --check PASS
```

The QEMU run uses one CPU and does not exercise concurrent IPC wakeups. APs
remain parked. `cargo fmt --all -- --check` was also attempted; it reports
formatting differences across untouched workspace files, so no repository-wide
formatting rewrite was applied. The required CI workflow passed all three jobs
in both branch runs. PR #30 merged to `main` at
`5763c9cced6e6b9d7a1a8ccf5a176d9025d8f5fa` on 2026-10-21.
