# Design Note: Phase 1 — Kernel Core Hardening, Preemption & SMP

**Date:** Oct 17, 2026  
**Author:** Akash <akash.official.j@gmail.com>  
**Status:** In Progress (Phase 1)

---

## 1. Overview & Goals

Phase 1 transitions KashOS from a single-core ring-0 bootstrap into a robust, preemptive, multicore microkernel core. In accordance with the 10 Non-Negotiable Rules of the *KashOS Build Guide*, all kernel state is real, verified via automated tests, and strictly bounded.

The Phase 1 deliverables are:
1. **Interrupt-safe spinlocks & SMP ticket locks:** RFLAGS save/restore (`cli`/`sti`) with FIFO ticket locks to eliminate IRQ handler deadlocks and ensure fair SMP acquisition.
2. **Physical frame allocator with domain quota tracking:** Bounding kernel and compartment memory allocation per domain without relying on unbounded heap growth.
3. **Higher-half kernel mapping & per-process address spaces (`kpaging`):** PML4 isolation with higher-half kernel sharing (entries 256..511) and unmapped guard pages.
4. **CPU Security Hardening:** Real detection, activation, and verification of NX, SMEP, SMAP, UMIP, and WP, with deliberate fault-trap handlers.
5. **Real timer-driven preemptive scheduler (`kscheduler`):** Hardware APIC timer preemption (vector 32), per-thread kernel stacks, FPU/SSE save/restore (`fxsave64`/`fxrstor64`), callee-saved register context switching, and real `current_pid` tracking.
6. **ACPI MADT parsing & SMP bringup:** Multicore CPU enumeration from the ACPI MADT table, AP initialization via INIT-SIPI sequence, per-CPU data structures, and TLB shootdown IPI.
7. **Phase 1 Acceptance Gate:** 4-vCPU QEMU boot, 1,000,000 thread preemption stress test without register or stack corruption, deliberate NX/SMEP trap caught and logged, and all CI tests green.

---

## 2. Research Questions & Design Decisions

### Question 1: Which scheduling model matches the claims you want to keep, and what is the measured overhead?
- **Decision:** A 3-band strict-priority QoS scheduling model (implemented in `kscheduler`):
  - **Band 0: `UserInteractive` (2 ms slice):** Compositor and direct user input. Preempts all lower bands immediately upon readiness.
  - **Band 1: `RealTimeIO` (5 ms slice):** Storage block drivers, network packet processing, and audio streaming.
  - **Band 2: `Background` (20 ms slice):** Batch processing, compilation, and indexing tasks.
- **Overhead Analysis:**
  - Dequeue and queue operations are $O(1)$ ring buffers per band.
  - Context switch overhead consists of saving 7 callee-saved GPRs (56 bytes), `rflags`, `rip`, `cr3` (when switching address spaces), and a 512-byte aligned SSE/FPU block (`fxsave64`/`fxrstor64`).
  - Total context switch overhead is under 350 CPU cycles on modern x86_64, well within the 0.05% CPU time budget at a 100 Hz APIC timer frequency.
  - Tickless idle: when all runqueues are empty, the CPU executes `hlt` waiting for the next hardware interrupt without burning cycles.

### Question 2: How will the kernel keep object memory bounded per process (quotas) without a general kernel heap?
- **Decision:** Capability-backed physical frame allocation with `DomainMemoryQuota`.
  - In traditional monolithic kernels, user processes trigger unbounded kernel heap allocations (e.g., via socket buffers, file descriptor tables).
  - KashOS replaces ambient heap allocation with explicit domain quotas: each domain (Personal, Work, Vault, Net, USB, Disposable) receives a fixed frame budget from untyped memory.
  - Page table frames, TCBs, and IPC endpoint buffers must be drawn from the invoking domain's quota. If a domain exhausts its quota, its allocation fails with `PageError::OutOfFrames` or `SchedError::TableFull`, completely isolating other domains from memory exhaustion attacks.

### Question 3: What is the smallest driver-domain interface each device class needs?
- **Storage (virtio-blk / AHCI / NVMe):**
  - MMIO / BAR address capability (explicit 4 KiB pages mapped).
  - Dedicated MSI/MSI-X interrupt vector.
  - DMA frame grant capability bounded by an IOMMU / VT-d domain window (no direct physical memory access).
- **Network (virtio-net / e1000):**
  - Device MMIO register pages.
  - RX/TX ring buffer pages explicitly shared with IOMMU protection.
  - Network packet transfer IPC endpoint.
- **Input (PS/2 / USB HID via xHCI):**
  - I/O port capability (0x60, 0x64) or xHCI MMIO operational register range.
  - IRQ 1 / IRQ 12 vector handling.
  - Event channel capability directed exclusively to the display compositor.

---

## 3. Component Design & Implementation Details

### 3.1 Interrupt-Safe Ticket Spinlocks (`kernel/src/sync.rs`)
To prevent deadlocks where an IRQ handler fires on the same core while a lock is held and attempts to acquire it:
```rust
pub struct TicketSpinLock<T> {
    next_ticket: AtomicU32,
    now_serving: AtomicU32,
    data: UnsafeCell<T>,
}
```
1. `lock()` reads `RFLAGS`, disables interrupts with `cli` if IF was set, and stores the previous flag state in the lock guard.
2. It fetches a ticket via `next_ticket.fetch_add(1, Ordering::Relaxed)`.
3. It spins with `core::hint::spin_loop()` until `now_serving.load(Ordering::Acquire) == ticket`.
4. `drop()` increments `now_serving.fetch_add(1, Ordering::Release)` and restores the previous `RFLAGS` (re-enabling interrupts only if they were enabled prior to acquiring the lock).

### 3.2 Physical Frame Allocator with Domain Ownership
```rust
pub struct QuotaFrameAllocator {
    base_paddr: u64,
    total_frames: usize,
    used_frames: usize,
    domain_quotas: [usize; 8],
    domain_usage: [usize; 8],
}
```
Each frame allocation requests an allocation on behalf of a `domain_id` (0 = kernel/dom0, 1 = sys-net, 2 = personal, etc.). If `domain_usage[id] >= domain_quotas[id]`, allocation fails immediately.

### 3.3 Hardware Mitigation & Security Features
- **NX:** EFER.NXE bit 11 enabled and checked; page table entries have bit 63 set on all writable data, heap, and stack pages.
- **SMEP:** CR4 bit 20 enabled to prevent supervisor execution of user-mode pages.
- **SMAP:** CR4 bit 21 enabled to prevent supervisor access to user-mode data without explicit STAC/CLAC toggles.
- **UMIP:** CR4 bit 11 enabled (User-Mode Instruction Prevention) to prevent user-mode reads of SGDT, SIDT, SLDT, SMSW, and STR.
- **WP:** CR0 bit 16 enabled (Write Protect) so the supervisor cannot write to read-only pages.
- **Stack Guard Page:** The page immediately below every thread kernel stack is left unmapped (`P=0`). Stack overflows trigger an immediate `#PF` onto dedicated IST stacks rather than silently corrupting memory.

### 3.4 ACPI MADT Parsing & Multiprocessor (SMP) Bringup
1. Read RSDP from BIOS memory (0xE0000..0x100000) or UEFI EFI configuration table.
2. Locate MADT with signature `b"APIC"`.
3. Parse Type 0 records (`Processor Local APIC`) to identify all APIC IDs.
4. Allocate per-CPU structures (`PerCpuData`) for up to 64 CPUs, containing:
   - `cpu_id` / `apic_id`
   - Local TCB pointers and idle thread
   - Per-CPU Local APIC timer state
5. Send INIT-SIPI-SIPI sequence to each AP using the Local APIC Interrupt Command Register (ICR).
6. APs boot through the 16-bit real-mode trampoline at physical address `0x8000`, switch to long mode, load CR3, initialize their GDT/IDT and Local APIC, and report online.

### 3.5 Real Preemption & Context Switch Assembly
In `_isr32` (Timer ISR):
1. Save all GPRs (rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r15).
2. Save FPU/SSE state via `fxsave64 [rsp0 - 512]`.
3. Call `scheduler_preempt(rsp) -> next_rsp`.
4. If a task switch occurred:
   - Restore target task's FPU/SSE state via `fxrstor64`.
   - Update TSS `rsp0` with the target task's kernel stack top.
   - Switch CR3 if the target task belongs to a distinct address space.
   - Switch stack pointer to `next_rsp`.
5. Restore GPRs and issue `iretq`.

---

## 4. Acceptance Criteria & Test Plan
- **CI Unit Tests:** All workspace crates (`kcore`, `kpaging`, `kscheduler`, `kipc`, `kblock`, `kheap`, `kvault`) compile and pass all tests.
- **QEMU Multicore Execution:** Boot QEMU with `-smp 4` and verify that all 4 CPUs are enumerated from ACPI MADT and brought online.
- **1M Preemption Verification:** Two threads run concurrently and increment shared atomic counters across 1,000,000 timer preemption ticks with zero data corruption.
- **Hardware Traps:** Verify that a deliberate write to a non-executable page or an illegal SMEP execution triggers an immediate `#PF` exception logged to serial without kernel corruption.
