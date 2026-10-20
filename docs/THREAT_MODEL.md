# KashOS current security scope

**Status date: 2026-10-20.** This page describes the checked-in development
prototype, not the long-term target described in the master engineering plan.
KashOS is not ready for daily or security-sensitive use. Use it for development
and QEMU testing only.

## Current state

- The x86-64 kernel boots in the configured T0 QEMU profile. This does not
  establish safe operation on physical hardware.
- The normal desktop, settings interface and shell execute in Ring 0. Ring 3
  entry and fault tests do not isolate the normal session.
- ACPI CPU discovery works in QEMU. AP startup is disabled; only the BSP is
  active. SMP scheduling is unavailable.
- External network access is unavailable. NIC initialization, remote TCP,
  DNS transport, HTTP and HTTPS are disabled. This absence of a network stack is
  not a network security service or anonymity protection.
- VT-d activation and hardware DMA containment are unavailable. Avoid
  untrusted DMA-capable devices.
- Production TPM transport, measured boot, persistent TPM sealing, and
  hardware rollback protection are unavailable. Secure Boot enforcement is
  also not established.
- The vault library provides authenticated storage primitives and has host
  tests, but credential enrollment, recovery, TPM-backed key lifecycle and
  complete persistent-data behavior remain incomplete.
- Linux application support and isolated third-party user services are not
  implemented.
- Test results cover selected code paths. Model tests do not establish
  end-to-end isolation, physical-device security, or security certification.

## Threat assessment for this build

| Threat | Current protection and limitation |
| --- | --- |
| Network attacker | Remote networking is unavailable and NIC drivers are disabled. No claim is made about a live firewall, VPN, Tor, or network-service isolation. |
| Malicious application or file | The normal UI runs in Ring 0 and general third-party app isolation is unavailable. Do not run untrusted applications or files. |
| Malicious USB, PCIe or DMA device | Hardware DMA isolation is unavailable. Do not connect untrusted DMA-capable hardware. |
| Theft of a powered-off system | A vault library and passphrase unlock path exist, but boot integrity, key enrollment, recovery, and hardware-sealed key protections remain incomplete. Do not depend on this prototype to protect confidential data. |
| Boot tampering | Secure Boot enforcement and TPM-backed measurements are unavailable. Assume a modified boot chain could execute without detection. |
| Attack against a running system | Ring 0 services, incomplete user isolation, unavailable IOMMU protection, and incomplete key lifecycle leave major gaps. The prototype is not suitable for sensitive workloads. |
| Firmware, hypervisor or hardware compromise | No mitigation is claimed. QEMU is a development environment and its host remains part of the trust boundary. |
| Microarchitectural side channels | No comprehensive, configuration-specific mitigation assessment is available. |

The project can revisit these threats only after the corresponding implementation
is reachable from normal boot and supported by direct, reproducible tests. The
security-system comparison in
[`RESEARCH_SECURITY_MODELS.md`](RESEARCH_SECURITY_MODELS.md) describes design
references; it does not assert parity with them.
