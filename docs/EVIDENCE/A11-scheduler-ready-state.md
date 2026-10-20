# A11 scheduler ready-state guard — 2026-10-20

## Finding and change

Source inspection found that `QoSScheduler::enqueue_ready` accepted any
existing slot without checking whether it was already `Ready`. Calling it
twice inserted duplicate queue entries. `schedule()` could then return the
same TCB again while it was already running. A new regression test failed on
the pre-fix implementation and passes after the change. Enqueue now rejects a
non-live task as `NoSuchTask` and a task already marked `Ready` as
`AlreadyReady`; timer preemption of a live `Running` task still follows the
existing requeue path.

This is a scheduler correctness fix. It does not implement per-CPU queues,
parallel task selection, AP-local timer context, or SMP. Secondary CPUs remain
parked. A11 remains incomplete.

Design and research: [`../design/a11-scheduler-ready-state.md`](../design/a11-scheduler-ready-state.md).
Primary references reviewed 2026-10-20:

- Rust core `Result`: https://doc.rust-lang.org/stable/core/result/enum.Result.html
- Embedded Rust Book, `no_std`: https://doc.rust-lang.org/embedded-book/intro/no-std.html

## Verification

The regression test was run before the fix and failed because the second
enqueue unexpectedly returned `Ok(())`. After the fix:

```text
cargo test -p kscheduler duplicate_ready_enqueue_is_rejected_without_scheduling_one_task_twice  PASS
cargo test -p kscheduler                                                                      PASS (13 tests)
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf                       PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none           PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none           PASS
python -c "from pathlib import Path; import subprocess,sys; scripts=sorted(Path('tools').glob('test_*.py')); results=[]; [(results.append((p.name,subprocess.run([sys.executable,str(p)],capture_output=True,text=True)))) for p in scripts]; [print(f'{name}: '+('PASS' if proc.returncode==0 else 'FAIL')+('\\n'+proc.stdout+proc.stderr if proc.returncode else '')) for name,proc in results]; sys.exit(any(proc.returncode for _,proc in results))"  PASS (19 scripts)
python tools/claims_lint.py                                                                      PASS
python tools/verify_findings.py                                                                  PASS (F8 and F10 remain)
python -u tests/test_qemu_boot.py                                                                PASS (T0 shell and required boot markers)
QemuHarness(kernel_path='target/x86_64-unknown-none/release/kernel', profile='T2')              PASS (entropy event only)
git diff --check                                                                                PASS
```

The T2 harness exercised its entropy profile; it did not prove CPU scheduling
or SMP. `cargo fmt --all -- --check` and `cargo fmt -p kscheduler -- --check`
report broad pre-existing formatting differences. No repository-wide
reformatting was applied. The user environment requests the `rtk` command
prefix, but `rtk` is unavailable, so PowerShell commands were run directly.

PR #23 passed all three required GitHub Actions jobs and merged to `main` at
`81c90ad99e1de6b776eb03e94f916e5f20429f09`. Local verification does not
replace multi-CPU hardware coverage. AP startup remains disabled pending real
per-CPU scheduler, TCB/FPU, timer-context, syscall, and QEMU SMP work.
