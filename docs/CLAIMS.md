# KashOS claims and evidence inventory

**Audit date:** 2026-10-20. **Code state reviewed:** `main` at
`c4803a3013ada3597971e1a437ae7f6eacf32d0b`.

This inventory separates tested prototype behavior from unavailable system
features. A test result applies only to the code path and configuration named
in its evidence. Passing a helper or software-model test is not evidence of
hardware behavior.

Software-model test results do not establish hardware isolation.

## Current implementation status

| Area | Status supported by current evidence | Limits and evidence |
| --- | --- | --- |
| x86-64 T0 boot | Tested in configured QEMU profile | The smoke test reaches the locked shell on a one-CPU Conroe profile. It does not establish physical-hardware safety. See [`docs/EVIDENCE/A11.md`](EVIDENCE/A11.md). |
| Page tables and supervisor write protection | Selected paths tested | T0 boot exercises W^X page-table setup and CR0.WP. CPU-specific SMEP, SMAP and UMIP may be unavailable; do not infer complete memory-safety assurance. |
| Ring 3 and syscalls | Partial | Hand-built Ring 3 tests exercise mechanisms. Desktop, settings and shell remain in Ring 0. See [`docs/EVIDENCE/A10.md`](EVIDENCE/A10.md). |
| Capabilities, IPC and scheduler | Selected host and QEMU paths tested | Tests exercise crate mechanisms and selected boot self-tests. They do not establish formal assurance or normal-session isolation. |
| CPU discovery and SMP | Discovery tested; SMP execution unavailable | T2 QEMU discovered four CPU slots and confirmed one active BSP. AP startup is intentionally disabled. See [`docs/EVIDENCE/A11.md`](EVIDENCE/A11.md). |
| Vault library | Host tests pass; system key lifecycle incomplete | TPM sealing, key enrollment/recovery and complete persistent-data security are unavailable. See [`docs/EVIDENCE/A3.md`](EVIDENCE/A3.md), [`docs/EVIDENCE/A4.md`](EVIDENCE/A4.md), and [`docs/EVIDENCE/A5.md`](EVIDENCE/A5.md). |
| Remote networking, Tor and VPN | Unavailable | NIC activation, DNS transport, remote TCP, HTTP, HTTPS, Tor and VPN services are not connected. The network path fails closed. See [`docs/EVIDENCE/A6.md`](EVIDENCE/A6.md) and [`docs/EVIDENCE/A7.md`](EVIDENCE/A7.md). |
| TPM, measured boot and anti-rollback | Unavailable | Production TPM transport and hardware-backed measurements, sealing and rollback protection are not implemented. |
| VT-d and DMA containment | Unavailable | Hardware activation is disabled; the software translation model is not hardware isolation. See [`docs/EVIDENCE/A9.md`](EVIDENCE/A9.md). |
| Device drivers | Unavailable for production use | NIC and DMA paths fail closed pending safe buffers and hardware isolation. |
| Desktop and settings | Prototype, runs in Ring 0 | UI helper tests do not make the UI a separate isolated service. See [`docs/EVIDENCE/A10.md`](EVIDENCE/A10.md) and [`docs/EVIDENCE/A18.md`](EVIDENCE/A18.md). |
| Linux applications and platform parity | Unavailable | Linux compatibility and security parity with other operating systems have not been implemented or established. |

## Evidence rules

- Do not describe KashOS as production-ready or suitable for sensitive data.
- Do not turn a test of a model into a hardware or isolation claim.
- Keep each feature status tied to source, its evidence file, and the exact
  tested configuration.
- The master engineering plan is a target. Its task names and old completion
  marks do not establish that a feature exists today.
