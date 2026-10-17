# KashOS Threat Model

This document defines the official threat model, security perimeter, and explicit trust assumptions for **KashOS**, adhering to the 10 Non-Negotiable Rules in [`docs/KASHOS_BUILD_GUIDE.md`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/docs/KASHOS_BUILD_GUIDE.md).

---

## 1. System Target & Core Architecture

- **Target**: A capability-based microkernel workstation OS in `#![no_std]` Rust, where device drivers, networking, filesystems, and the window compositor run as separate unprivileged user-mode services.
- **Hardware Isolation**: IOMMU (Intel VT-d / AMD-Vi), Page Table NX (No-Execute), SMEP, SMAP, UMIP, and WP.
- **Microkernel Minimal TCB**: The kernel is restricted to thread scheduling, per-process address spaces, capability derivation and revocation, synchronous IPC, hardware interrupt routing, and IOMMU configuration. Everything else executes in user mode.
- **Capability Paradigm**: Zero ambient authority. A user process possesses no implicit permissions; all resources (memory, IPC endpoints, device I/O) are named strictly via unforgeable capability handles.
- **Cryptographic Storage**: AEAD-authenticated block storage with Argon2id key derivation, Merkle CoW tree integrity, and duress/emergency wipe capabilities.

---

## 2. Threat Matrix

| Attacker / Threat Vector | In Scope | Primary Defense Mechanism | Residual Risk / Limitations |
| :--- | :---: | :--- | :--- |
| **Remote Network Attacker** | **Yes** | Network stack (`smoltcp`) isolated in its own user-mode service (`sys-net`); default-deny firewall; no ambient network authority for applications. | Bugs in `smoltcp` or NIC driver compromise only `sys-net`, not kernel memory or vault keys. |
| **Malicious Application or File** | **Yes** | Per-app capability spaces; disposable execution compartments (`disp-vm`) with volatile RAM scratchpads; zero shared memory without explicit capability grant. | Applications with legitimate file write capability can still corrupt permitted files. |
| **Malicious USB / PCIe Device** | **Yes** | Hardware IOMMU DMA remapping per device (`Bus:Device.Function`); USB stack isolated in user-mode `sys-usb`; strict USB device class allow-listing. | Devices on legacy hardware without IOMMU or with broken ACPI DMAR tables cannot be protected against bus-master DMA attacks. |
| **Physical Thief (Powered Off)** | **Yes** | Full-disk AEAD encryption (`kvault`), Argon2id password hashing, TPM 2.0 sealed keys, and measured boot chain. | Passwords with low entropy remain vulnerable to offline dictionary attack if TPM rate limiting is bypassed. |
| **Evil Maid (Boot Tampering)** | **Partly** | UEFI Secure Boot, TPM PCR extension across boot stages, cryptographic signature verification of kernel and init images. | Requires authentic hardware platform with uncompromised UEFI firmware and physical Secure Boot keys. |
| **Cold-Boot / DMA with Machine On** | **Partly** | Hardware IOMMU blocks external DMA; volatile RAM scrubbing on screen lock; master encryption key zeroization upon lock or duress trigger. | Physical RAM chip freezing attacks within seconds of power-off before memory decay occurs. |
| **Compromised Hypervisor / Firmware / Hardware Backdoors** | **No** | **Out of scope.** KashOS explicitly assumes the CPU silicon, hardware microcode, and lowest-level platform firmware execute correctly according to architectural specifications. | Hardware trojans or hypervisor introspection cannot be mitigated by guest OS software. |
| **Side Channels (Spectre / Meltdown / L1TF / MDS)** | **Partly** | Kernel enables hardware speculation barriers (`IBRS`, `STIBP`, `SSBD`), disables speculation across security boundaries where supported, and executes `L1D_FLUSH` on context switches. | Microarchitectural side channels evolve continuously; residual timing leak risks remain on older CPUs lacking silicon-level mitigations. |

---

## 3. Honest Security Principles

1. **No Unproven Marketing**: No security claim is published in documentation or emitted at boot unless backed by a test, a fuzzing run, or a machine-checked proof recorded in [`docs/CLAIMS.md`](file:///c:/Users/Akash.J/Documents/KashOS%20Kernal/kash-kernel/docs/CLAIMS.md).
2. **Fail Closed**: If essential hardware security features (IOMMU, hardware RNG, TPM) are absent, the OS explicitly reports the absence, disables dependent functionality, and does not pretend protection exists.
3. **Auditability**: Every `unsafe` block must be accompanied by a `// SAFETY:` rationale documenting the exact invariant required and upheld.
