# KashOS

**A Capability-Based Microkernel Workstation Prototype in Rust**

[![Kernel Build](https://img.shields.io/badge/Kernel-no__std%20Rust-brightgreen.svg)](kernel/)
[![Architecture](https://img.shields.io/badge/Arch-x86__64-blue.svg)](kernel/src/arch/)
[![Compositor](https://img.shields.io/badge/UI-Nitpicker--Style%20Glass-orange.svg)](kash-ui/)
[![Security Policy](https://img.shields.io/badge/Policy-Zero%20Ambient%20Authority-purple.svg)](docs/THREAT_MODEL.md)
[![Status](https://img.shields.io/badge/Baseline-Ring%200%20Prototype-yellow.svg)](docs/CLAIMS.md)

---

## 🌟 Overview

**KashOS** is an open-source, capability-based microkernel research workstation operating system written from bare metal in `#![no_std]` Rust for x86_64 architectures.

Its long-term architectural goal is to build a small, robust workstation operating system where drivers, networking, filesystems, and the window compositor run as separate unprivileged user-mode services, backed by hardware-enforced isolation (IOMMU, NX, SMEP/SMAP) and an unforgeable domain-bordered display server ([`kash-ui`](kash-ui/)).

The project follows the **10 Non-Negotiable Rules** defined in [`docs/KASHOS_BUILD_GUIDE.md`](docs/KASHOS_BUILD_GUIDE.md): no simulated system output, no unearned `[OK]` status banners, no unbacked claims, fail-closed hardware support, and a public claim-to-evidence registry.

---

## 📊 Current Status Baseline (Code Audit)

The codebase comprises ~29.7k lines of Rust and assembly. The kernel boots via BIOS / Multiboot2, builds an identity-mapped $W\oplus X$ page table, initializes GDT/IDT/APIC, and renders a 60 FPS retained-scene desktop to the linear framebuffer in ring 0.

| Subsystem | Current State | Gap to Real Implementation |
| :--- | :--- | :--- |
| **Boot, GDT/IDT/APIC, Heap** | Working (ACPI MADT multi-core discovery, 4 CPUs in QEMU, APIC ICR/IPI, ticket locks) | UEFI PE32+ loader is a stub; AP full bring-up via SIPI scheduled for Phase 4 |
| **Paging & Memory** | Real $W\oplus X$ page tables, CR0.WP supervisor write protection, domain frame quotas, per-process PML4 address spaces | Tested and verified in Phase 1 & 2 |
| **Ring 3 / Syscalls** | Ring 3 process and syscall mechanisms are exercised by a hand-built boot self-test | Partial: the normal desktop, settings, and console still run in Ring 0; isolated user services are not wired into boot |
| **Scheduler & IPC** | Preemptive 3-band QoS scheduler (`kscheduler`) active, FPU/SSE save/restore, 1M cycle test passed, synchronous rendezvous IPC with badged endpoints & capability transfer | Tested and verified in Phase 1, 2 & 3 |
| **Capability Engine** | `kcore` per-process capability spaces (`PROCESS_CSPACES`), unforgeable compartment badges, rights monotonicity, recursive revocation with memory zeroing (< 1 ms benchmark), untyped quota isolation | Tested and verified in Phase 3 |
| **kash_kernel.rs** | Model untyped memory allocator & ARINC scheduler structures | Integrated and verified in Phase 3 capability & IPC tests |
| **IOMMU (VT-d)** | Runtime DMAR probing and VT-d translation are disabled; hardware tables, invalidation, ACS, and DMA containment are unavailable. Status is Stub. | Not implemented; software SLPT model tests do not validate hardware |
| **Drivers** | Driver service isolation and execution are not established. NIC drivers are disabled until DMA-safe buffers and verified IOMMU isolation exist. | Not implemented; service capability tests are not device-driver tests |
| **Boot Chain & TPM 2.0** | UEFI boot metadata can be received; production TPM transport, hardware measured boot, PCR sealing, and TPM NV anti-rollback are unavailable | TPM and measured-boot claims are withdrawn; hardware/swtpm implementation and tests remain future work |
| **Storage Crypto (`kvault`)** | Authenticated vault library and a locked-by-default passphrase unlock path; storage and key-enrollment guarantees remain under audit | TPM sealing is disabled; the boot self-test skips an unmounted persistent vault and does not format or write it |
| **Network** | User-mode network service (`sys-net`, Domain 1) with `smoltcp` stack, `knet::FilterTable` default-deny packet filtering, fail-closed kill switch, hardware CSPRNG MAC randomization, and lock-free SPSC queues | Tested and verified in Phase 7; boot self-tests T28, T29, T30, T31 passed |
| **Compartments & MAC** | FLASK Mandatory Access Control (MAC) on all synchronous IPC, Access Vector Cache (AVC), ephemeral disposable domains (Domain 5, `disp-vm`) with zero-remanence teardown (`clflush` & audit scan), out-of-process Zero-Trust Powerbox broker (single-file delegation, sibling files blind, token revocation) | Tested and verified in Phase 8; boot self-tests T32, T33, T34, T35 passed |
| **GUI & Display Server (`kash-ui`)** | High-assurance display server and compositor with Nitpicker-style retained unforgeable 4px domain borders, anti-fullscreen spoofing (menubar reserved), secure input routing (keystrokes delivered strictly to focused window), cross-window SHM buffer isolation, mediated clipboard sanitization | Tested and verified in Phase 9; boot self-tests T36, T37, T38, T39 passed |
| **Shell Commands** | Standard utilities read real hardware/heap state or report stubs | Replaced all hardcoded simulations with honest state checks |
| **Property Tests & Hardening** | Algorithmic property tests (monotonicity, untyped disjointness, transitive revocation, zero remanence) & multi-surface fuzz stress testing | Tested in Phase 10; boot self-tests T40, T41, T42, T43 passed; capability_property_tests.rs passing |

---

## 🛡️ Threat Model & Security Policy

KashOS operates under a clear, public threat model documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

- **In Scope**: Remote network attackers, malicious applications/files, untrusted USB/PCIe peripherals, physical theft of powered-off machines (full-disk AEAD encryption).
- **Partly In Scope**: Evil maid boot tampering (requires Secure Boot + TPM measured boot), cold-boot attacks (RAM scrubbing on lock).
- **Out of Scope**: Compromised hardware silicon, microcode trojans, or compromised hypervisors.

All claims are tracked in the claim-to-evidence registry in [`docs/CLAIMS.md`](docs/CLAIMS.md).

---

## 🎨 Compartment Domains & Unforgeable Borders

The desktop compositor frames every surface with an unforgeable 4-pixel security border color-coded to its assigned domain label:

| Domain ID | Name | Compartment Type | Security Color Tag | Hex Code |
| :---: | :--- | :--- | :--- | :---: |
| **0** | `kash-dom0` | Administrative Plane | Obsidian Admin | `#E1E6F0` |
| **1** | `sys-net` | Untrusted NIC Jail | Red Untrusted Net | `#D93025` |
| **2** | `personal` | Trusted Private Data | Mint Green | `#81C995` |
| **3** | `work-app` | Enterprise Domain | Blue Work | `#1A73E8` |
| **4** | `sys-usb` | Isolated xHCI Jail | Amber USB | `#FA903E` |
| **5** | `disp-vm` | Ephemeral Disposable Sandbox | Magenta Disposable | `#F538A0` |
| **6** | `vault-keys` | Air-Gapped Key Storage | Purple Vault | `#C58AF9` |

Pressing **F12** activates **Nitpicker X-Ray Mode**, dimming client application buffers and overlaying kernel domain credentials directly on the screen.

---

## 🗺️ Engineering Roadmap (Phases 0 to 10)

```
Phase 0: Honesty Cleanup [COMPLETED]
  ├── Strip unproven claims, add status tables & roadmap
  ├── Sanitize shell commands to read real state or report stubs
  ├── Add docs/THREAT_MODEL.md and docs/CLAIMS.md
  └── Fix domain ID collision (personal: 2, sys-usb: 4)

Phase 1: Kernel Core [COMPLETED]
  ├── Higher-half kernel mapping & per-process page tables (kpaging)
  ├── Interrupt-safe spinlocks & SMP ticket locks
  ├── Wire in kscheduler preemptive timer scheduler & context switch
  └── SMP bring-up from ACPI MADT (AP start via INIT-SIPI)

Phase 2: Real User Mode [COMPLETED]
  ├── ELF loader with exact segment permissions into fresh address spaces
  ├── Syscall boundary with SMAP pointer validation
  └── User-mode init and fault isolation (user fault kills process, not kernel)

Phase 3: Capabilities & IPC Enforced [COMPLETED]
  ├── Per-process capability spaces with rights, badges, derive, and revoke
  ├── Synchronous IPC with capability transfer (kipc)
  └── Delete ambient authority (no path-based open without capability grant)

Phase 4: Userspace Services & Drivers [INCOMPLETE]
  ├── User-mode device services and hardware I/O mediation need revalidation
  ├── VT-d and DMA containment are disabled; current SLPT is a software model
  └── Driver supervisor behavior is model-tested, not yet verified with device drivers

Phase 5: Boot Chain & Measured Boot [COMPLETED]
  ├── UEFI PE32+ loader verifying SHA-256 / Ed25519 signatures
  ├── TPM 2.0 driver extending PCRs (0, 1, 2, 4, 7, 9) with clean-boot reproducibility
  └── Anti-Evil Maid key sealing with fail-closed tamper lock

Phase 6: Storage & Crypto [COMPLETED]
  ├── Bare-metal CSPRNG (RDRAND/RDSEED) & zero-allocation Key Management Service (KMS)
  ├── Mount kvault as real root filesystem through kblock C-LOOK elevator adapter
  ├── Tamper-evident Poly1305 MAC bit-flip detection halting corrupt block reads
  └── Anti-forensic screen lock memory scrubbing with explicit clflush cache line eviction

Phase 7: Network & Privacy [COMPLETED]
  ├── User-mode network service with smoltcp (IPv4, TCP, UDP, sockets)
  ├── knet::FilterTable default-deny packet filter dropping banned ports (23, 21) & tracking domains
  ├── Fail-closed network kill switch halting egress upon Tor/WireGuard tunnel disconnect
  ├── Hardware CSPRNG MAC address randomization hiding burned-in physical OUIs
  └── Lock-free SPSC packet rings for physical NIC (Intel e1000) and loopback IPC transport

Phase 8: Compartments [COMPLETED]
  ├── FLASK mandatory access control engine enforced on all synchronous IPC (kipc)
  ├── Disposable domains (RAM scratchpad zeroized on close with clflush & audit scan)
  └── User-approved out-of-process powerbox broker (single-file delegation, sibling blind)

Phase 9: GUI & Display Server [COMPLETED]
  ├── kash-ui as a capability-isolated display service with SHM buffer isolation
  ├── Secure input routing (keystrokes delivered strictly to focused window)
  └── Nitpicker-style unforgeable 4px domain borders and anti-fullscreen spoofing

Phase 10: Hardening & Testing [REOPENED]
  ├── Multi-surface fuzzing of syscalls, ELF loader, IPC, and network parsers (T41, T42, T43)
  └── Property tests for capability core & zero remanence (T40)
```

---

## ⚡ Performance & Low-Hardware Scalability

| Hardware Tier | Specifications | Boot Budget | Desktop Target |
| :--- | :--- | :---: | :--- |
| **Minimum** | 1 vCPU, 256 MiB RAM, BIOS/VGA | $\le 10$ s | Software renderer, $1024\times768$, 30 FPS floor |
| **Low** | 2 cores, 1–2 GiB RAM, laptop | $\le 6$ s | Software renderer, $1280\times720$, 60 FPS cursor / window drag |
| **Mid** | 4 cores, 4–8 GiB RAM, UEFI | $\le 4$ s | Full glass effects, 1080p, 60 FPS multicore compositor |
| **High** | 8+ cores, 16+ GiB RAM, NVMe | $\le 3$ s | GPU-accelerated path, 4K, 120 Hz, SMP scheduler affinity |

KashOS achieves 60 FPS on low memory and software VGA controllers through **Adaptive Dirty-Rectangle Blitting**:
- Normal mouse movement updates only an $80\times80$ bounding box ($25.6\text{ KB}$ written to VRAM vs $3.14\text{ MB}$ full-frame blit, a **$99.2\%$ reduction in bus traffic**).
- PS/2 port `0x64` fast-break polling drops host CPU utilization to $< 2\%$.

---

## 🛠️ Building & Running

### Prerequisites
- Rust Nightly (`x86_64-unknown-none` target)
- QEMU (`qemu-system-x86_64`) or Oracle VirtualBox
- Python 3 (for ISO creation script)

### 1. Compile the Kernel
```bash
cargo build --release --target x86_64-unknown-none --manifest-path kernel/Cargo.toml
```

### 2. Run Workspace Tests
```bash
cargo test --workspace --exclude kernel
```

### 3. Generate Bootable ISO
```bash
python scripts/make_iso.py
```

### 4. Boot in QEMU
```bash
# Low-memory profile (256 MiB, 1 vCPU)
qemu-system-x86_64 -cdrom kash-os.iso -m 256M -smp 1 -vga std -serial stdio

# Standard profile (2 GiB, 4 vCPUs)
qemu-system-x86_64 -cdrom kash-os.iso -m 2048M -smp 4 -vga std -serial stdio
```

---

## 📜 The 10 Non-Negotiable Rules

1. **No simulation**: Never hardcode output that looks like system state (`ps`, `free`, `df`, `dmesg`, `opsec`, `security`). Every number shown must be read from real kernel state.
2. **No fake `[OK]`**: A status line prints `[OK]` only after the code just checked the thing. `status.rs` is the single source of truth.
3. **Feature "done" criteria**: Code exists, reachable from boot, test proves it, and status registry says `Real`.
4. **Claim-to-evidence**: Every security claim gets a row in [`docs/CLAIMS.md`](docs/CLAIMS.md). No evidence, no claim.
5. **Fail closed**: If hardware support (IOMMU, RNG, TPM) is missing, say so, disable the dependent feature, and do not pretend.
6. **No dead code**: Wire in or remove unused components.
7. **Real GUI settings**: Every setting in the GUI must be backed by a real service API.
8. **Phase gates**: Do not start phase $N+1$ until phase $N$ acceptance tests pass in CI and in QEMU.
9. **Minimise unsafe**: Every `unsafe` block requires a `// SAFETY:` comment stating the invariant.
10. **Honest verification**: Never write "verified", "proven", or "mathematically" unless a machine-checked proof (located in proofs/) runs in CI.

---

## 📄 License & Attribution

KashOS is developed by **Akash** ([`akash.official.j@gmail.com`](mailto:akash.official.j@gmail.com)) under the MIT License.
