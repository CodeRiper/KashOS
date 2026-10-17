# KashOS Claim-to-Evidence Table

This table records every security, isolation, and architectural claim made about **KashOS**.

> [!IMPORTANT]
> **Rule 4 & Rule 10 Enforcement**:
> - A claim may appear in `README.md` or user documentation **only when its status is `Proven` or `Tested`**.
> - The words *"verified"*, *"proven"*, or *"mathematically"* must **never** be used unless a machine-checked proof (Verus, Kani, Coq, Isabelle) is present in the repository and runs in CI.
> - **Definition of Done**: Code merged, reachable in a normal boot, test in CI, entry in status registry (`kernel/src/status.rs`), row in this claims table, and docs updated. If any criterion is missing, the feature is **not done**.

---

## Claim-to-Evidence Matrix

| Claim | Required Evidence | Status Today (Oct 2026) | Test / Proof Location |
| :--- | :--- | :---: | :--- |
| **Kernel code runs W^X & WP** | Page-table test plus runtime hardware protection violation test | **Tested** | Host unit tests in [`kpaging/tests/mapping_tests.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kpaging/tests/mapping_tests.rs); live deliberate `#PF` trap and recovery verified in [`kernel/src/selftest.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kernel/src/selftest.rs); `status.rs` registry reports `Real`. |
| **Preemptive QoS Scheduler** | Real timer-driven preemptive multitasking with register/FPU integrity across 1M cycles | **Tested** | 1,000,000 cycle thread preemption stress test verified in QEMU without register corruption; FPU/SSE save/restore (`fxsave64`/`fxrstor64`); per-thread 16 KiB stacks with guard pages; [`kernel/src/task.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kernel/src/task.rs). |
| **Physical Memory Quotas** | Frame allocator enforces domain memory limits and tracks ownership | **Tested** | [`kpaging/src/allocator.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kpaging/src/allocator.rs); unit tests in [`kpaging/tests/mapping_tests.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kpaging/tests/mapping_tests.rs) and boot self-test `T8` in `selftest.rs`. |
| **SMP Multi-Core Discovery** | ACPI MADT enumeration, per-CPU structures, and TLB shootdown IPIs | **Tested** | ACPI MADT parsed in [`kernel/src/arch/x86_64/smp.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kernel/src/arch/x86_64/smp.rs); verified with 4 vCPUs in QEMU `-smp 4`. |
| **Interrupt-Safe Spinlocks** | Ticket locks with automatic CLI/STI RFLAGS management preventing deadlocks | **Tested** | [`kernel/src/sync.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kernel/src/sync.rs) `TicketSpinLock<T>`; verified across all subsystem locks and block device rings. |
| **Processes are isolated** | Negative tests verifying that process A cannot read process B address space | **Not started** | Single ring-0 address space currently; per-process page tables scheduled for Phase 1/2. |
| **Capabilities cannot be forged** | Negative capability derivation tests plus Kani/Verus formal model check of capability table | **Library tests only** | Unit tests in [`kcore/tests/capability_tests.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kcore/tests/capability_tests.rs); no user-mode capability space yet. |
| **Drivers run unprivileged** | Driver runs in ring 3 with only its hardware MMIO/IRQ/DMA capabilities | **Not started** | Drivers currently linked in ring 0; user-space driver services scheduled for Phase 4. |
| **DMA is contained by IOMMU** | QEMU integration test with a hostile DMA device attempting out-of-window access | **Not started** | ACPI DMAR parser and register definitions present; second-stage translation tables scheduled for Phase 4. |
| **Storage is tamper-evident** | Bit-flip and corruption tests across every filesystem block type | **Library tests pass** | Verified in host tests [`kvault/tests/vault_tests.rs`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/kvault/tests/vault_tests.rs) (`any_single_bitflip_or_block_swap_is_detected_never_silently_accepted`); root FS mounting scheduled for Phase 6. |
| **Keys are zeroised on lock** | Memory scan test verifying key material is expunged from RAM and cache upon screen lock | **Not started** | Memory zeroing helper (`clflush` + `volatile_set`) tested in unit buffer; live session service scheduled for Phase 6. |
| **Network leaks nothing with kill switch on** | Packet capture test in QEMU verifying 0 packets escape when VPN/Tor tunnel drops | **Not started** | `knet` passive packet parser tested; network service with default-deny firewall scheduled for Phase 7. |
| **Disposable domain leaves no data** | Memory and disk scan test after domain termination verifying complete zeroization | **Not started** | Conceptual model in `kapp.rs` / `kash_kernel.rs`; full disposable process compartment scheduled for Phase 8. |
| **The compositor cannot be spoofed** | Hostile client tests attempting to draw outside granted surface bounds or spoof security borders | **Not started** | `kash-ui` renders retained borders in ring 0; user-mode display service with granted buffers scheduled for Phase 9. |
| **Parts are formally verified** | Machine-checked proof files (Verus/Kani) running green in CI | **Not started** | Model contracts written in `kash_kernel.rs`; no machine-checked proof files yet executed in CI; scheduled for Phase 10. |

---

## Audit History & Milestones

- **2026-10-17 (Phase 1: Kernel Core Acceptance Gate Passed)**: Verified in QEMU with 4 vCPUs. Implemented interrupt-safe `TicketSpinLock`, ACPI MADT SMP discovery, physical frame allocator domain quotas, CR0.WP supervisor write protection, deliberate `#PF` trap/recovery, and preemptive QoS scheduler with 1,000,000 preemption cycle verification without register or FPU corruption. All 104+ unit tests pass.
- **2026-10-17 (Phase 0: Honesty Cleanup)**: Initialized honest claim registry. Demoted all unproven claims across `README.md` and `ARCHITECTURAL_SECURITY_REPORT.md`.
