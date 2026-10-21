# A11 per-thread kernel stack guards

## Finding

`mmu::build` identity-maps the kernel image's `.data` and `.bss` writable.
`THREAD_STACKS` lives in `.bss`, and each `ThreadStack` begins with a page
documented as a guard. The x86 boot-stack guard was explicitly unmapped, but
the per-thread guard pages remained present and writable. A stack overflow
could therefore cross the nominal guard without a page fault.

## Design

- Enumerate each static `ThreadStack.guard_page` address from the stack table.
- After the broad kernel image map is built, remove every thread guard page
  from the x86 identity map. Fail boot if any expected unmap fails.
- Keep the existing boot-stack guard unmap and make its failure fatal too.
- Arm expected page-fault recovery with the exact fault RIP, recovery RIP, and
  error code. Preserve the NX/WP test's exact error code (`0b011`).
- Exercise a write to a thread guard in QEMU. Require the supervisor,
  non-present-page write error code (`0b010`) and exact instruction RIP before
  recovery; panic if the write unexpectedly succeeds.
- Require the QEMU smoke test to observe the guard-fault pass marker.

## Scope and limits

This changes x86-64 paging only. The QEMU test writes to one reserved guard
page; source checks and fail-closed page-table construction cover enumeration
and removal of the full static array. This is not a stack-usage bound, a proof
of fault-handler safety under arbitrary stack exhaustion, AP/SMP coverage, or
physical hardware validation. APs remain parked and A11 remains incomplete.

## Research

- Intel, *Intel 64 and IA-32 Architectures Software Developer's Manual*, Vol.
  3A, §4.7, page-fault error code: P=0 indicates a non-present page, W/R=1 a
  write, and U/S=0 a supervisor access. That yields `0b010` for the test.
  <https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-system-programming-manual-325384.pdf>
