# A11 per-thread fast syscall stack — 2026-10-21

## Finding

Fast syscall entry switched to a single kernel stack per CPU. The current
IA32_FMASK clears IF, so ordinary timer preemption does not interrupt the
dispatcher today. However, retaining a syscall frame across any future
syscall-side suspension or interruptible wait requires a stack owned by that
task; otherwise another task's syscall could overwrite its frame.

## Change

- The CPU-local GS entry block now points at the active task's stack top using
  an aligned `AtomicU64`. A compile-time assertion preserves the assembly ABI
  (`kernel_stack_top` remains at GS offset 8).
- Task initialization selects the BSP root stack. Timer context switches
  select the incoming task's stack for both TSS.RSP0 and fast syscall entry;
  idle selects the reserved idle stack. A per-CPU bootstrap stack is retained
  for syscall initialization before task setup.
- Every Ring 3 syscall checks that the live Rust dispatcher RSP lies inside the
  current task's reserved thread stack. An ownership mismatch halts; the first
  successful Ring 3 entry emits a QEMU-required marker.
- Added a source guard to CI and extended the QEMU boot assertion for the
  runtime ownership marker.

## Research

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Version 093
  (landing page updated 2026-10-09), Volume 2B, SYSCALL instruction:
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
  SYSCALL saves the return RIP and flags but does not save RSP; software must
  preserve user RSP. This informs the entry-frame ownership design, but does
  not prove KashOS continuation correctness.
- seL4, *IPC Tutorial*, reviewed 2026-10-21:
  https://docs.sel4.systems/Tutorials/ipc
  It describes blocking endpoint operations and the TCB-owned reply capability
  for Call. This remains design context, not a parity claim.

## Failure-first regression

The new source guard was run before implementation:

```text
python tools/test_syscall_stack_ownership.py
FAIL as expected: assertion failed because set_current_kernel_stack_top was absent
```

After the implementation, the source guard passed. QEMU T0 observed
`[syscall] PASS: Ring 3 syscall used its owning thread kernel stack` during the
real user program's SYS_PRINT call and reached the locked shell.

## Verification

```text
python tools/test_syscall_stack_ownership.py PASS
python tools/test_syscall_entry_fail_closed.py PASS
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf PASS
cargo check --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
cargo build --release --manifest-path kernel/Cargo.toml --target x86_64-unknown-none PASS
Get-ChildItem tools/test_*.py | ForEach-Object { python $_.FullName } PASS (all source guards)
python tools/claims_lint.py PASS
python tools/verify_findings.py PASS (F8 and F10 remain present)
python -u tests/test_qemu_boot.py PASS (T0, one CPU; syscall stack marker and shell reached)
git diff --check PASS
```

The repository instruction requests the `rtk` command prefix, but `rtk` is not
installed in this environment; commands above ran directly in PowerShell.

## Limits

This gives a user task's syscall frame thread-owned storage for a future
suspension path. Current syscall entry masks ordinary interrupts, and this
change does not add syscall-side blocking/yield, a saved result continuation,
or atomic endpoint/PCB/scheduler transitions. The QEMU check is single-CPU and
exercises ordinary Ring 3 syscalls, not a blocked IPC call. APs remain parked,
worst-case kernel stack use is unproven, and B4 remains partial.
