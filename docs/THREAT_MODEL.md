# KashOS Threat Model

This document defines the official threat model, security perimeter, and explicit trust assumptions for **KashOS**, adhering to the 20 Non-Negotiable Rules in [`docs/KASHOS_BUILD_GUIDE.md`](KASHOS_BUILD_GUIDE.md).

---

## 1. System Target & Core Architecture

- **Target**: A capability-based microkernel workstation OS in `#![no_std]` Rust. Separate unprivileged device and network services remain a target, not a property of the current build.
- **Current hardware isolation**: NX and CR0.WP have partial implementation/test coverage. SMEP/SMAP are CPU-gated. VT-d activation and PCIe ACS are disabled; this build does not claim DMA isolation.
- **Microkernel Minimal TCB**: The kernel is restricted to thread scheduling, per-process address spaces, capability derivation and revocation, synchronous IPC, hardware interrupt routing, and IOMMU configuration. Everything else executes in user mode.
- **Capability Paradigm**: Zero ambient authority. A user process possesses no implicit permissions; all resources (memory, IPC endpoints, device I/O) are named strictly via unforgeable capability handles.
- **Cryptographic Storage**: AEAD-authenticated block storage with Argon2id key derivation, Merkle CoW tree integrity, and duress/emergency wipe capabilities.

---

## 2. Threat Matrix

| Attacker / Threat Vector | In Scope | Primary Defense Mechanism | Residual Risk / Limitations |
| :--- | :---: | :--- | :--- |
| **Remote Network Attacker** | **Yes** | Network stack isolated in its own user-mode service (`sys-net`); default-deny firewall; no ambient network authority for applications. | Bugs in net stack or NIC driver compromise only `sys-net`, not kernel memory or vault keys. |
| **Malicious Application or File** | **Yes** | Per-app capability spaces; disposable execution compartments (`disp-vm`) with volatile RAM scratchpads; zero shared memory without explicit capability grant. | Applications with legitimate file write capability can still corrupt permitted files. |
| **Malicious USB / PCIe Device** | **No** | NIC activation and DDE DMA allocation fail closed. VT-d and ACS are unavailable. | This build does not protect host memory from a malicious bus-mastering device or firmware-preconfigured DMA. Do not attach untrusted DMA-capable devices. |
| **Physical Thief (Powered Off)** | **Partly** | The vault has authenticated encryption and a passphrase unlock path. TPM sealing and measured boot are unavailable. | Passphrase KDF/enrollment and legacy volume migration require revalidation; no TPM rate limiting or hardware-bound key protection is provided. |
| **Evil Maid (Boot Tampering)** | **No verified mitigation** | UEFI boot metadata may be received, but secure-boot enforcement and TPM-backed PCR attestation are not established. | Assume a modified boot chain may run; do not rely on this build to detect boot tampering. |
| **Cold-Boot / DMA with Machine On** | **No** | A3 has a partial lock-path key scrub. No hardware IOMMU is active. | DMA access while powered on is not contained. Cold-boot resistance and complete key-remanence guarantees are not established. |
| **Compromised Hypervisor / Firmware / Hardware Backdoors** | **No** | **Out of scope.** KashOS explicitly assumes the CPU silicon, hardware microcode, and lowest-level platform firmware execute correctly according to architectural specifications. | Hardware trojans or hypervisor introspection cannot be mitigated by guest OS software. |
| **Side Channels (Spectre / Meltdown / L1TF / MDS)** | **Partly** | Kernel enables hardware speculation barriers (`IBRS`, `STIBP`, `SSBD`), disables speculation across security boundaries where supported, and executes `L1D_FLUSH` on context switches. | Microarchitectural side channels evolve continuously; residual timing leak risks remain on older CPUs lacking silicon-level mitigations. |

---

## 3. Tier 0 (T0 Baseline) Fallbacks & Honest Degradation Modes

On legacy T0 hardware (2006-2009 Core 2 class laptops, 1 core, 1 GiB RAM, BIOS, no TPM, no IOMMU, no RDRAND):

1. **No RDRAND/RDSEED Entropy Fallback**:
   - Entropy is harvested from CPU jitter (TSC delta variances around cache/memory loops), PS/2 keyboard/mouse interrupt timing, RTC, and an encrypted random seed persisted between boots.
   - Master key generation strictly fails closed (`Err(NotEnoughEntropy)`) if the conservative entropy estimator is below 256 bits, requiring interactive keystroke timing input.
2. **No TPM 2.0 Fallback**:
   - TPM status is reported as `NotAvailable`. TPM sealing APIs fail unavailable. The passphrase unlock path is separate; its KDF/enrollment still needs revalidation. No software TPM emulation is treated as hardware sealing.
3. **No IOMMU Fallback**:
   - VT-d translation and DMA-capable NIC/DDE features remain disabled, whether or not a DMAR table is found. No bounce-buffer protection is claimed.
4. **No AES-NI Fallback**:
   - XChaCha20-Poly1305 remains the default cipher for all storage and IPC cryptography, avoiding cache-timing vulnerabilities in software AES.

---

## 4. Honest Security Principles

1. **No Unproven Marketing**: No security claim is published in documentation or emitted at boot unless backed by a test, a fuzzing run, or a machine-checked proof (located in `proofs/`) recorded in [`docs/CLAIMS.md`](CLAIMS.md).
2. **Fail Closed**: If essential hardware security features (IOMMU, hardware RNG, TPM) are absent, the OS explicitly reports the absence, disables dependent functionality, and does not pretend protection exists.
3. **Auditability**: Every `unsafe` block must be accompanied by a `// SAFETY:` rationale documenting the exact invariant required and upheld.
