# B4 user-page permission preflight

Date: 2026-10-21

## Finding

Canonical address checks do not prove a user page is present or writable. IPC
receive currently consumes a message before the later copy can fault. Source
review also found the ELF loader returned a user stack pointer above the four
pages it mapped.

## Change

- Walk the active x86-64 four-level page tables for each page in a bounded user
  buffer and require present and user-accessible entries at every level.
- For output copies, require writable permission at every level; reject large
  pages because this implementation only constructs 4 KiB user mappings.
- Apply the check before IPC receive can inspect/consume its endpoint and again
  before ordinary user-copy operations.
- Map the stack pages immediately below the configured user stack pointer.
- Exercise user RX, RW, unmapped, cross-page, and stack-range cases against the
  actual page tables produced by the ELF loader in QEMU.

## Limits

This follows the current x86-64 4-level, 4 KiB page-table format and current
kernel-addressable frame allocator contract. It does not add page-fault-safe
copy recovery, dynamic page mapping, SMP address-space mutation, or AArch64
syscall support. The check and copy are stable in the current single-CPU
configuration because APs remain parked and there is no user page-map syscall.
