# Security model research notes

**Reviewed:** 2026-10-20  
**Sources:** official project documentation, linked below

These projects are useful design references, not labels KashOS can inherit.
Compare a specific security property, supported configuration, attacker, and
hardware platform before making claims.

## seL4

seL4 has machine-checked proofs for selected architecture/platform/configuration
combinations. Its own documentation tracks which properties are proved for
each verified configuration; the proof result does not automatically cover
every build option, device, boot path, or system component. Some hardware and
configuration assumptions sit outside the kernel proof. KashOS currently has
no corresponding machine-checked refinement proof, so capability API
similarity, QEMU tests, or runtime assertions do not establish seL4 proof
parity.

Sources: [seL4 proof statements](https://sel4.systems/Verification/proofs.html),
[verified configurations](https://docs.sel4.systems/projects/sel4/verified-configurations.html),
[supported platform verification matrix](https://docs.sel4.systems/Hardware/).

## Qubes OS

Qubes uses compartmentalization through virtual machines (currently Xen
domains), with system services such as networking placed in separate domains.
Its security goals explicitly do not provide isolation between applications
that run in the same qube. A KashOS process table or capability-space data
structure is not equivalent to a hardware-enforced VM boundary. A Qubes-style
design for KashOS needs a hypervisor or a verified kernel boundary, device and
DMA mediation, lifecycle/update policy, and tests for cross-domain channels.

Sources: [Qubes architecture](https://www.qubes-os.org/doc/QubesArchitecture/),
[Qubes security design goals](https://doc.qubes-os.org/en/r4.2/developer/system/security-design-goals.html),
[Qubes introduction](https://doc.qubes-os.org/en/latest/introduction/intro.html).

## GrapheneOS

GrapheneOS is an Android-based system whose security model depends on supported
mobile devices and their firmware/hardware capabilities. Its work includes
hardening Android app sandbox policies and platform components, verified boot,
and device-specific protections. It is not a desktop Linux distribution or an
independent Rust microkernel. KashOS can study particular mitigations, but
cannot claim GrapheneOS parity without matching the device support, update
chain, sandbox behavior, and evidence for each property.

Sources: [GrapheneOS features](https://grapheneos.org/features),
[supported devices and FAQ](https://grapheneos.org/faq),
[official build targets](https://grapheneos.org/build).

## Linux application compatibility

“Linux application support” requires a stated compatibility contract: target
architecture, ELF and dynamic-loader behavior, system-call ABI, libc and
runtime interfaces, filesystem conventions, packaging, graphics/audio/input
APIs, and kernel/user-space boundary. An ELF parser, syscall dispatcher tests,
or a Linux-looking shell command does not by itself run ordinary Linux
applications. Decide whether the intended boundary is a POSIX subsystem, a
compatibility layer, a VM, or a Linux host; each has different isolation and
maintenance costs.

## KashOS implications

- Keep remote networking disabled until DNS, TCP, TLS, certificate validation,
  HTTP parsing, and egress enforcement are connected and tested end to end.
- Treat assertions against helper structs and mock devices as model tests.
  Label them accordingly and do not use them as hardware proof.
- Keep QEMU smoke results separate from hardware claims. QEMU may not implement
  every firmware, TPM, IOMMU, or device behavior required by a claim.
- Define a threat model and supported hardware matrix before promising maximum
  privacy, universal Linux application support, or superiority over another OS.
