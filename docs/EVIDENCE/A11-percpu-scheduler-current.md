# A11 CPU-indexed scheduler current state — 2026-10-21

## Finding and change

The scheduler had one `current: Option<usize>` and its affinity check was not
used when dequeuing. The kernel timer already resolves the executing CPU slot,
but always called the scheduler's CPU-0 context path. The scheduler now stores
one current slot per CPU, exposes CPU-indexed selection/timer/context-plan
methods, and filters shared ready queues by affinity. The legacy calls still
address CPU 0. `kernel::task::on_timer_tick` now passes its discovered CPU slot.
Task termination also removes queued references before a TCB slot is reused.
The ready queues and kernel scheduler lock remain shared; AP startup remains
disabled.

A failure-first host test initially failed to compile because the
CPU-indexed API did not exist. After implementation, tests cover independent
CPU current slots, affinity-based selection, timer priority checks against
only tasks runnable on that CPU, invalid CPU indexes, and terminated-slot
reuse. The slot-reuse test failed before the fix because an old queue entry
selected the replacement task twice.

The first T0 QEMU run exposed a brittle existing T13 self-test assertion: it
required the process-table slot to differ from `PID % MAX_PROCESSES`, which is
not a valid invariant when the values happen to coincide. The check now
resolves `PID + MAX_PROCESSES` and requires that unknown alias to have no
process-table entry. The source regression guard was updated first and failed
on the old assertion; it passes after the correction. T0 QEMU then passed.

Design and primary references reviewed 2026-10-21:

- [`../design/a11-percpu-scheduler-current.md`](../design/a11-percpu-scheduler-current.md)
- seL4 threads tutorial: https://docs.sel4.systems/Tutorials/threads.html
- seL4 MCS tutorial: https://docs.sel4.systems/Tutorials/mcs.html

## Verification

```text
cargo test -p kscheduler                                                                  PASS (17 tests)
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf                   PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none       PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none       PASS
python -c "from pathlib import Path; import subprocess,sys; scripts=sorted(Path('tools').glob('test_*.py')); results=[(p.name,subprocess.run([sys.executable,str(p)],capture_output=True,text=True)) for p in scripts]; [print(f'{name}: '+('PASS' if proc.returncode==0 else 'FAIL')+('\\n'+proc.stdout+proc.stderr if proc.returncode else '')) for name,proc in results]; sys.exit(any(proc.returncode for _,proc in results))"  PASS (19 scripts)
python tools/claims_lint.py                                                                  PASS
python tools/verify_findings.py                                                              PASS (F8 and F10 remain)
python -u tests/test_qemu_boot.py                                                            PASS (T0 reaches shell and emits required markers)
python -c "import sys; sys.stdout.reconfigure(errors='replace'); from tools.harness.runner import QemuHarness; h=QemuHarness(kernel_path='target/x86_64-unknown-none/release/kernel', profile='T2', timeout_secs=8); h.run(); log='\\n'.join(h.raw_logs); assert '4 CPU core(s) detected' in log; assert '4 discovered; 1 active' in log"  PASS (4 discovered; 1 active; AP startup disabled)
git diff --check                                                                            PASS
```

T2 verifies CPU discovery and the AP-disabled gate only; it does not execute
scheduler code on APs and does not verify multi-CPU execution. These results
do not establish equivalent assurance or a production-ready OS. `rtk` is not
installed in the environment, so PowerShell commands were run directly.

PR #24 passed all three required GitHub Actions jobs and merged to `main` at
`5a5a2326d8554b2b8eece38fa0d991ad6dea058e`.
