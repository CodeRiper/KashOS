# Per-thread fast syscall stack ownership

## Goal

Give each Ring 3 task an exclusive kernel stack for fast syscall entry so its
saved syscall frame has thread-owned storage when syscall-side suspension is
implemented. Keep unmatched IPC fail-closed until continuation return semantics
exist.

## Design

- Keep the GS entry state CPU-local because `SWAPGS` selects it before GPRs can
  be saved.
- Store the active kernel stack top in an aligned atomic at the assembly ABI's
  fixed GS offset 8; assert that offset at compile time.
- Initialize a bootstrap fallback stack before enabling the syscall MSRs.
- After root task setup, select that task's kernel stack. On every task or idle
  switch, update both TSS.RSP0 and the fast-syscall stack top.
- Identify user task IDs by the process PID range and verify the dispatcher RSP
  lies inside the current thread's reserved stack before handling syscall args.
  Halt on an ownership mismatch and cover a real Ring 3 syscall with a QEMU
  marker.
- Keep AP startup disabled. This proves only initialized BSP routing and does
  not establish continuation correctness, SMP safety, or worst-case stack use.

## Return/continuation boundary

Intel SYSCALL does not save RSP; the entry code saves user RSP and puts it into
the stack frame. Today IA32_FMASK clears IF, so ordinary timer preemption does
not occur during the dispatcher, and no syscall-side block/yield operation
exists. The per-thread stack is groundwork for a future suspended syscall; it
does not prove a continuation path. KashOS still lacks return-value
continuation state and an atomic endpoint/PCB/scheduler transaction. Do not
change unmatched IPC from `WouldBlock` on the strength of this stack work alone.
