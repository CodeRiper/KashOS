# KashOS

**A Rust operating-system research prototype for x86-64.**

![Status: development prototype](https://img.shields.io/badge/status-development%20prototype-yellow)

## Read before trying KashOS

**KashOS is not ready for daily or security-sensitive use.** Use it for
development and QEMU testing only. Do not store important data in it, rely on it
for privacy or malware containment, or install it as your primary operating
system.

The repository builds a bootable x86-64 kernel prototype. A T0 QEMU smoke test
reaches its locked shell. That test checks one emulated configuration; it is not
a security certification or evidence of safe operation on physical hardware.
The desktop, settings and shell still run in Ring 0.

## Current implementation status

The current state is documented in [`docs/ROADMAP.md`](docs/ROADMAP.md),
[`docs/TASKS.md`](docs/TASKS.md), and the task-specific evidence under
[`docs/EVIDENCE/`](docs/EVIDENCE/).

| Area | Current status |
| --- | --- |
| Boot | x86-64 kernel boots in the configured T0 QEMU profile. UEFI Secure Boot enforcement is unavailable. |
| CPU cores | ACPI can discover CPUs. Only the bootstrap processor is active; AP startup and SMP scheduling are disabled. |
| User mode | Ring 3 mechanisms have boot self-tests. The normal desktop, settings and shell remain in Ring 0. |
| Networking | External network access is unavailable. NIC activation, DNS transport, remote TCP, HTTP and HTTPS are disabled. Tor and VPN integration are absent. |
| DMA protection | VT-d is disabled. Hardware DMA containment is unavailable. |
| TPM and boot integrity | Hardware TPM transport, measured boot, persistent key sealing and anti-rollback are unavailable. |
| Storage | The vault library has host tests, but key enrollment, recovery and the complete persistent-data security lifecycle remain incomplete. |
| Applications | Linux application compatibility, a production browser and isolated third-party app services are unavailable. |
| Security assurance | Host and QEMU tests cover selected code paths. They do not establish seL4 assurance, Qubes-style VM isolation, mobile OS parity, or a security certification. |

Some test output exercises software models or helper functions. Passing those
tests does not establish hardware isolation or end-to-end security. The
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) describes current limitations;
the [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) is a long-term engineering plan,
not a list of completed features.

## Build and test in QEMU

### Requirements

- Rust nightly with the `x86_64-unknown-none` target
- Python 3
- QEMU with `qemu-system-x86_64`

Build the kernel:

```sh
cargo build --release --target x86_64-unknown-none --manifest-path kernel/Cargo.toml
```

Run host subsystem tests:

```sh
cargo test --workspace --exclude kernel --features kvault/test-fast-kdf
```

Run the configured T0 QEMU boot smoke test:

```sh
python tests/test_qemu_boot.py
```

The T0 profile uses one CPU, 1 GiB RAM and a Conroe CPU model. The QEMU test
checks that the guest boots to the shell and prints selected smoke-test
markers. It does not exercise live networking, TPM, IOMMU, secure boot, physical
devices or SMP operation.

## Development policy

KashOS follows the project rules in [`docs/KASHOS_BUILD_GUIDE.md`](docs/KASHOS_BUILD_GUIDE.md):
report unavailable features honestly, fail closed when required support is
missing, keep implementation claims tied to evidence, and do not mark a task
complete from model tests alone. See [`docs/CLAIMS.md`](docs/CLAIMS.md) for the
current claims inventory.

## License

MIT. See [`LICENSE`](LICENSE).
