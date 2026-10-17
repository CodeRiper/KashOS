# Design Note: Phase 2 — Real User Mode & Syscalls

**Date:** Oct 17, 2026  
**Author:** Akash <akash.official.j@gmail.com>  
**Status:** Approved & Implementing (Phase 2)

---

## 1. Overview & Goals

Phase 2 transitions KashOS from a system executing solely in supervisor mode (Ring 0) into a true multi-privilege microkernel executing unprivileged user processes in Ring 3 (User Space).

In accordance with the 10 Non-Negotiable Rules of the *KashOS Build Guide*, Phase 2 delivers:
1. **ELF64 Executable Loader:** Validates ELF64 headers and segments, enforces $W\oplus X$ (rejecting segments with both Write and Execute bits), and maps segments into a fresh, isolated user address space (`VirtualSpace`) with exact permissions (`Perm::USER_RO`, `Perm::USER_RW`, `Perm::USER_RX`).
2. **User Address Space & Stack:** Installs an isolated lower-half address space ($< \text{0x0000\_8000\_0000\_0000}$) with shared higher-half kernel entries (256..511), a 16 KiB user stack, and an unmapped 4 KiB guard page.
3. **Ring 3 Transition:** Prepares TSS `rsp0`, sets User Data (`0x1B`) and User Code (`0x23`) segment selectors with RPL=3, and executes atomic privilege transition via `iretq` or `sysretq`.
4. **Syscall Boundary Hardening:** Enforces canonical user address bounds validation, hardware SMAP copy routines (`stac`/`clac`), and comprehensive error codes (`SyscallError`), guaranteeing the kernel **never** panics on invalid user arguments.
5. **Fault Containment:** Intercepts Ring 3 exceptions (`#PF`, `#GP`, `#UD`) in the hardware IDT handler, terminates the faulting process, logs fault diagnostics, and returns cleanly without kernel panic or system crash.
6. **Init & Test Executables:** Implements a tiny `no_std` Rust `init` executable, bad-pointer fault test programs, and a 10,000 iteration random-syscall fuzzer.
7. **Phase 2 Acceptance Gate:** Verified in QEMU:
   - A user program prints through a syscall (`sys_print` / `sys_write`).
   - A program that dereferences null or kernel memory is cleanly killed while the kernel continues executing.
   - A 10,000 random-syscall fuzz stress test completes with 0 kernel panics.

---

## 2. Architectural Design & Security Model

```
   ┌────────────────────────────────────────────────────────┐
   │                  Ring 3: User Space                    │
   │  ┌───────────────────────┐  ┌───────────────────────┐  │
   │  │   Init Process (PID 1)│  │   Test App (PID 2)    │  │
   │  │ .text RX  .data/.bss RW│ │ .text RX  .data/.bss RW│ │
   │  │ User Stack (16 KiB)   │  │ User Stack (16 KiB)   │  │
   │  └───────────┬───────────┘  └───────────┬───────────┘  │
   └──────────────┼──────────────────────────┼──────────────┘
                  │  syscall (IA32_LSTAR)    │  Hardware Fault (#PF, #GP)
   ═══════════════╪══════════════════════════╪════════════════ [Privilege Boundary]
   ┌──────────────┼──────────────────────────┼──────────────┐
   │              ▼                          ▼              │
   │      Syscall Dispatcher        Fault Containment       │
   │   - Validate Pointer Bounds  - Log Fault Diagnostics   │
   │   - Hardware SMAP (stac/clac)- Terminate Process       │
   │   - Return Error (no panic!) - Keep Kernel Alive!      │
   │                                                        │
   │              Ring 0: Microkernel Core                  │
   │     - TSS RSP0 Switch          - Preemptive Scheduler  │
   │     - Isolated PML4 Per Process- Frame Quota Allocator │
   └────────────────────────────────────────────────────────┘
```

### 2.1 ELF64 Binary Loader
The loader inspects a byte slice containing an ELF64 executable:
- **ELF Header Validation:**
  - `e_ident[EI_MAG0..3] == b"\x7fELF"`
  - `e_ident[EI_CLASS] == 2` (64-bit)
  - `e_ident[EI_DATA] == 1` (Little-endian)
  - `e_type == 2` (`ET_EXEC`)
  - `e_machine == 0x3E` (`EM_X86_64`)
- **Segment Loading:**
  - For each `PT_LOAD` entry:
    - Verifies $vaddr + memsz \le \text{USER\_SPACE\_CEILING}$ (`0x0000_7FFF_FFFF_FFFF`).
    - Enforces $W\oplus X$: fails if $(p\_flags \& PF\_W) \ne 0 \land (p\_flags \& PF\_X) \ne 0$.
    - Sets page permissions:
      - $PF\_R \implies \text{Perm::USER\_RO}$
      - $PF\_R \mid PF\_W \implies \text{Perm::USER\_RW}$
      - $PF\_R \mid PF\_X \implies \text{Perm::USER\_RX}$
    - Allocates physical frames from domain quotas, maps the virtual range, copies `filesz` bytes from the ELF image, and zeroes the remainder up to `memsz` (BSS).

### 2.2 User Stack & TSS RSP0 Configuration
- User stack allocated at `0x0000_7FFF_FFFF_0000..0x0000_7FFF_FFFF_F000` (16 KiB) with `Perm::USER_RW`.
- Guard page below the user stack (`0x0000_7FFF_FFFE_F000..0x0000_7FFF_FFFF_0000`) remains strictly unmapped.
- Dedicated kernel stack allocated per process (`16 KiB`). Whenever the scheduler context-switches to this process, TSS `rsp0` is loaded with this process's kernel stack top via `set_tss_rsp0(kernel_stack_top)`.

### 2.3 Syscall Validation & SMAP
- Canonical address check: all user pointers must be $> 0$ and $< \text{0x0000\_8000\_0000\_0000}$.
- SMAP Protection: `copy_from_user` and `copy_to_user` execute `stac` before accessing user memory and `clac` immediately after.
- Failure Mode: Invalid addresses, unmapped pages, or null pointers return `Err(SyscallError::InvalidMemoryAccess)` or `Err(SyscallError::PrivilegeEscalationAttempted)` without panicking.

### 2.4 Fault Containment & Lifecycle
- When an exception occurs while $CPL = 3$ (`frame.cs & 3 != 0`):
  - The hardware IDT handler intercepts `#PF`, `#GP`, `#UD`, etc.
  - Logs fault details (faulting RIP, RSP, error code, CR2).
  - Marks the process state as `Zombie(exit_code)`.
  - Removes the process from the scheduler ready queues.
  - Switches context to the next ready task or kernel thread.
  - **The kernel remains 100% operational.**

---

## 3. Verification & Acceptance Gate Results (QEMU & Hardware)

### 3.1 Acceptance Criteria Verification Log
Executed on real x86-64 CPU hardware in QEMU:
```
[selftest] T11: verifying ELF64 loader and mandatory W^X policy...
[selftest] ✓ T11 ELF64 loader verified: W^X enforced (W|X rejected), bounds protected, PML4 isolated
[selftest] T12: launching 10,000 random-syscall fuzz stress test on dispatcher...
[selftest] ✓ T12 10,000 syscall fuzz calls survived with 0 kernel panics (7362 rejected safely)
[selftest] T13: testing unprivileged Ring 3 execution & fault containment...
[user] Hello from Ring 3 syscall!
[process] PID 10 exited voluntarily with status 0
[selftest] ✓ Sub-test A passed: user program executed SYS_PRINT and exited voluntarily with code 0

[USER-FAULT] Exception in user mode process (PID 11): #PF Page Fault (vector=0xe err=0x4)
  Faulting User RIP=0x0000000100000078 RSP=0x00007fffffffefe0 RFLAGS=0x0000000000010202
  Faulting Address (CR2)=0x0000000000000000
[USER-FAULT] Terminating faulting process safely (fail-closed) — microkernel continues running.
[process] Fault containment: PID 11 terminated with signal -15 (#PF/#GP)
[selftest] ✓ Sub-test B passed: user null-dereference #PF trapped, PID 11 killed, microkernel survived!
[selftest] ✓ T13 User Mode Ring 3 & Fault Containment fully verified
```

### 3.2 Acceptance Gate Status
- [x] **ELF64 Executable Loader**: Validates headers, rejects W^X violations, isolates per-process PML4.
- [x] **Unprivileged Ring 3 Execution**: Transitions via `iretq` (`CS=0x23`, `SS=0x1B`, RPL=3).
- [x] **Hardened Syscall Layer**: Bounds checked (`USER_SPACE_FLOOR` to `USER_SPACE_CEILING`), SMAP `stac`/`clac` safety.
- [x] **10,000 Random Syscall Fuzz**: 0 kernel panics (7,362 calls rejected safely).
- [x] **Hardware Fault Containment**: Null pointer dereference trapped by hardware `#PF`, faulting process PID 11 terminated, microkernel continued running uninterrupted.
- [x] **StatusRegistry**: Both `elf_loader` and `user_mode_ring3` set to `ComponentStatus::Real` (`[OK]`).

