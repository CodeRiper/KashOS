# KashOS Master Task Ledger

| Task ID | Title | Status | Branch | Evidence File |
|---|---|---|---|---|
| A1 | Remove every fake network and Tor output | Done | main | docs/EVIDENCE/A1.md |
| A2 | Stop the data-loss bug (vault open versus format) | Done | main | docs/EVIDENCE/A2.md |
| A3 | Real key hierarchy: passphrase first, TPM second | Done | main | docs/EVIDENCE/A3.md |
| A4 | Real TPM 2.0 driver (TIS first, CRB second) | Done | main | docs/EVIDENCE/A4.md |
| A5 | Measured boot, sealing and anti-rollback | Done | main | docs/EVIDENCE/A5.md |
| A6 | Real TCP/IP with smoltcp | Done | main | docs/EVIDENCE/A6.md |
| A7 | NIC drivers: real, many, tested | Done | main | docs/EVIDENCE/A7.md |
| A8 | TLS and HTTPS | Done | main | docs/EVIDENCE/A8.md |
| A9 | Real IOMMU (Intel VT-d) | Done | main | docs/EVIDENCE/A9.md |
| A10 | Move out of Ring 0: real user-space services | Done | main | docs/EVIDENCE/A10.md |
| A11 | SMP and scheduler | Done | main | docs/EVIDENCE/A11.md |
| A12 | Persistent filesystem and disk layout | Done | main | docs/EVIDENCE/A12.md |
| A13 | USB: xHCI, HID and mass storage | Done | main | docs/EVIDENCE/A13.md |
| A14 | UEFI boot, Secure Boot and a loader that measures | Done | main | docs/EVIDENCE/A14.md |
| A15 | Storage drivers: NVMe, hardened AHCI | Done | main | docs/EVIDENCE/A15.md |
| A16 | Display (double-buffering, virtio-gpu 2D) | Done | main | docs/EVIDENCE/A16.md |
| A17 | ACPI, power and platform | Done | main | docs/EVIDENCE/A17.md |
| A18 | Make the UI honest and connected to real services | Done | main | docs/EVIDENCE/A18.md |
| A19 | libc, Rust std and a POSIX layer | Done | main | docs/EVIDENCE/A19.md |
| A20 | Re-verify the old audit and finish hardening | Done | main | docs/EVIDENCE/A20.md |
| A21 | Status registry from real probes; CI that blocks fakes | Done | main | docs/EVIDENCE/A21.md |

## Part B: Kash Kernel 2.0 (seL4-Class Microkernel in Rust)

| Task ID | Title | Status | Branch | Evidence File |
|---|---|---|---|---|
| B0 | Architecture & CapRights Foundations | Done | main | docs/EVIDENCE/B0.md |
| B1 | Untyped Memory Model & Watermark Allocator | Done | main | docs/EVIDENCE/B1.md |
| B2 | CNode Guarded Radix Trees & Capability Derivation Tree (CDT) | Done | main | docs/EVIDENCE/B2.md |
| B3 | Transitive Revocation & Amnesic Memory Zeroing | Done | main | docs/EVIDENCE/B3.md |
| B4 | Badged Synchronous Endpoints & Capability Routing | Done | main | docs/EVIDENCE/B4.md |
| B5 | Asynchronous Notifications & Event Signaling | Done | main | docs/EVIDENCE/B5.md |
| B6 | Thread Control Blocks (TCBs), Fault Handlers & State | Done | main | docs/EVIDENCE/B6.md |
| B7 | Mixed-Criticality Scheduling (MCS): SchedContext & Temporal Isolation | Planned | - | docs/EVIDENCE/B7.md |
| B8 | Reply Capabilities & One-Shot RPC Protocol | Planned | - | docs/EVIDENCE/B8.md |
| B9 | Virtual Memory Architecture: VSpace, PageDirectory, PageTable, Frames | Planned | - | docs/EVIDENCE/B9.md |
| B10 | Address Space Identifiers (ASIDControl & ASIDPool) | Planned | - | docs/EVIDENCE/B10.md |
| B11 | Hardware Interrupt Subsystem: IrqControl & IrqHandler Caps | Planned | - | docs/EVIDENCE/B11.md |
| B12 | Port I/O Capability Firewall: IoPortControl & IOPort Caps | Planned | - | docs/EVIDENCE/B12.md |
| B13 | I/O Space & DMA Remapping (IOMMU Domain Device Caps) | Planned | - | docs/EVIDENCE/B13.md |
| B14 | Hardware Virtualization Extensions: Vcpu Capabilities | Planned | - | docs/EVIDENCE/B14.md |
| B15 | Runtime Invariant Verifier Engine: Invariants I1–I4 | Planned | - | docs/EVIDENCE/B15.md |
| B16 | Runtime Invariant Verifier Engine: Invariants I5–I7 | Planned | - | docs/EVIDENCE/B16.md |
| B17 | seL4 System Call Dispatcher & C-ABI Compatibility Gate | Planned | - | docs/EVIDENCE/B17.md |

