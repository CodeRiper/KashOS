# A11 design: CPU-local current-task identity

## Scope

Replace the singleton current TID with one atomic slot per discovered CPU. Resolve the running CPU through its local APIC ID and the MADT-derived CPU table. An unknown CPU resolves to TID 0; it must never inherit another CPU's identity or silently become root TID 1. Keep AP startup disabled.

## Changes

- Add `[AtomicU32; MAX_CPUS]` task identity slots and use acquire/release operations for reads and context-switch updates.
- Initialize the BSP's slot to TID 1 only after CPU discovery.
- Remove the duplicate, non-atomic `PerCpuData.current_pid` field so there is one identity source.
- Reject unresolved identity in the generic syscall path; process/capability syscalls already reject PIDs that do not resolve to a live process.
- Add a baseline-aware source guard and run host tests, kernel check/build, and T0/T2 QEMU tests.

## Limits

This change does not make the scheduler, TCB table, FPU save/restore, or context-switch path SMP-safe. The global scheduler remains serialized and APs stay parked. No SMP support claim is permitted.

## Research

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Vol. 3A, local APIC ID register: https://cdrdv2-public.intel.com/835754/253668-sdm-vol-3a.pdf
- Rust `AtomicU32` load/store ordering reference: https://doc.rust-lang.org/core/sync/atomic/type.AtomicU32.html

Research checked 2026-10-20. The Intel manual documents the local APIC ID register; source inspection confirms KashOS reads the xAPIC ID register and maps that byte to its MADT-discovered CPU slot. Rust atomic ordering is used for the slot value, not as a claim that the surrounding scheduler is SMP-safe.
