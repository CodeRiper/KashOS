# Public readiness and claims audit

**Audit date:** 2026-10-20

**Code state reviewed:** `main` at `c4803a3013ada3597971e1a437ae7f6eacf32d0b`
**Result:** KashOS is a development prototype and is not ready for daily or
security-sensitive use.

## Source review

The prior README and threat model described a live isolated network service,
Tor/VPN kill switch, active SMP, measured boot, hardware TPM, IOMMU containment,
isolated GUI services, and completed security phases. Those statements did not
match the current implementation/evidence:

- NIC initialization, remote TCP, DNS transport, HTTP and HTTPS fail closed;
  no network service or Tor/VPN integration is connected.
- VT-d activation is disabled, so hardware DMA containment is unavailable.
- TPM production transport, hardware measurement, persistent sealing and
  anti-rollback are unavailable.
- The A11 follow-up disables AP startup. QEMU T2 discovered four CPU slots but
  only the BSP was active.
- Normal desktop, settings and shell code remain in Ring 0.
- The vault library has host tests, but the persistent-data and key lifecycle
  are incomplete.
- Linux application compatibility and the isolation architectures referenced
  by Qubes OS and GrapheneOS are not implemented in this build.

The attached Master Engineering Plan itself describes KashOS as a prototype,
states that a complete OS is a multi-year effort, and distinguishes feature
similarity from seL4 verification claims. The current README and threat model now make
these limits visible instead of presenting design targets as implemented
protections.

## Primary external references reviewed

- Intel, *64 and IA-32 Architectures Software Developer's Manual*, Vol. 3A,
  IDTR/IDT and INIT state: https://cdrdv2-public.intel.com/812386/253668-sdm-vol-3a.pdf
- seL4 13.0.0 release notes, configuration-specific SMP caveats:
  https://docs.sel4.systems/releases/sel4/13.0.0.html
- Qubes OS security design goals, compartmentalization model:
  https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html
- GrapheneOS features and security model: https://grapheneos.org/features. Scope comparison recorded in docs/EVIDENCE/READINESS.md.

These sources describe reference architectures. They do not certify KashOS or
establish feature parity.

## Changes and regression coverage

- Replaced obsolete README phase-completion and feature tables with a dated
  implementation summary, explicit not-ready notice, actual limits, and
  reproducible T0 build/test commands.
- Rewrote the threat model to describe the current build and its limits.
- Replaced stale `Tested` claims in the public claim inventory with current
  evidence scope and unavailable features.
- Added `tools/test_public_readiness_honest.py` and a CI step. Its first run
  failed before the documentation fix because the README lacked a not-ready
  warning. The final run passed all 15 assertions.

## Verification

```text
python tools/test_public_readiness_honest.py  PASS (15 assertions)
python tools/claims_lint.py                    PASS
git diff --check                               PASS
```

This is a documentation accuracy correction. It does not add security
functionality, make hardware safer, or change the readiness conclusion.

PR #15 passed GitHub CI and merged to `main` at
`ea7ba7557e59a98053bb94ccdc2cc9e2364f5a2b`.
