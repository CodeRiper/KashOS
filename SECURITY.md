# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

## Reporting a Vulnerability

Security is the core mission of **KashOS**. We take all security advisories and vulnerability reports seriously.

If you believe you have discovered a vulnerability in:
- The `kash-kernel` separation microkernel (capability leakage, memory isolation breach, integer overflow in watermarks)
- Intel VT-d IOMMU DMA remapping or peripheral jails
- The `kash-ui` Nitpicker zero-trust compositor (border spoofing, view buffer evasion)
- The `kvault` cryptographic storage subsystem or duress wiping

**Please DO NOT report security issues via public GitHub issues.**

### How to Report Privately:
1. Open a **Private Security Advisory** via the repository's GitHub Security tab:
   [https://github.com/CodeRiper/KashOS/security/advisories/new](https://github.com/CodeRiper/KashOS/security/advisories/new)
2. Include:
   - A detailed description of the vulnerability.
   - Proof-of-concept (PoC) code or steps to reproduce the issue in QEMU or VirtualBox.
   - The affected subsystems and impact assessment.

### Vulnerability Response Timeline:
- **Initial Response**: Within 48 hours.
- **Triage & Assessment**: Within 5 business days.
- **Coordinated Disclosure**: We adhere to responsible disclosure principles and will work with you to verify and release a security advisory alongside a patched release.
