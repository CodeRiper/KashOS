# Contributing to KashOS

Thank you for your interest in contributing to **KashOS**! 

KashOS is a high-assurance, compartmentalized operating system combining mathematical microkernel assurance with a Nitpicker-style zero-trust desktop compositor. Because this is a security-critical project with formal verification guarantees, all contributions must adhere to strict architectural rules.

---

## 🏛️ Architectural Rules & Principles

Every PR submitted to KashOS must respect these non-negotiable architectural boundaries:

1. **Zero Dynamic Kernel Heap Post-Boot**:
   - `kash-kernel` contains zero post-boot dynamic heap allocations.
   - All physical memory must originate as `UntypedCapability` regions managed via monotonic watermark pointers.
   - Memory must be revocable in $O(1)$ amortized time via `revoke_all()`.
2. **`#![no_std]` and Safe Rust**:
   - The kernel and core subsystems are `#![no_std]`.
   - `unsafe` code must be minimized, well-documented with a `// SAFETY:` invariant comment, and isolated into architecture-specific modules (`src/arch/`).
3. **Formal Verification (Verus)**:
   - When introducing state transitions, capability retyping, or IOMMU descriptors, provide Verus mathematical contracts (`requires`, `ensures`) and ghost proofs.
4. **Hardware-Enforced Isolation**:
   - Device drivers (NIC, USB, storage) must NOT run in kernel ring 0.
   - All physical peripherals must be encapsulated inside isolated user-space jails (`sys-net`, `sys-usb`) governed by Intel VT-d / AMD-Vi second-stage page tables.
5. **Nitpicker Zero-Trust GUI Invariants**:
   - Untrusted applications must NEVER be capable of overdrawing their outer 4-pixel security borders.
   - Window titles must be sanitized against UTF-8 homographs and prefixed with `[DomainID: Name]`.

---

## 🛠️ Development Setup

### 1. Prerequisites
- **Rust Toolchain**: Nightly (installed via `rustup`)
  ```bash
  rustup toolchain install nightly
  rustup default nightly
  rustup target add x86_64-unknown-none
  rustup component add rust-src llvm-tools-preview
  ```
- **Virtualization Tools**:
  - QEMU (`qemu-system-x86_64`)
  - Oracle VirtualBox 7.x
- **Build Tools**:
  - `grub-mkrescue`, `xorriso`, `mtools` (for creating bootable ISOs)

### 2. Building the Project
```bash
# Build the microkernel in release mode
cargo build --release --target x86_64-unknown-none --manifest-path kernel/Cargo.toml

# Build the complete workspace (libraries and test suites)
cargo test --workspace --exclude kernel
```

### 3. Creating the Bootable ISO
```bash
# Strip kernel debug symbols
llvm-strip --strip-debug -o isodir/boot/kash-kernel target/x86_64-unknown-none/release/kernel

# Package into hybrid ISO
grub-mkrescue -o kash-os.iso isodir
```

### 4. Running Locally
- **QEMU**: Run `Launch_KashOS.bat` (Windows) or `./scripts/make_iso.py`
- **VirtualBox**: Run `launch_virtualbox.bat`

---

## 🧪 Testing Guidelines

Before opening a pull request, ensure all workspace tests pass:
```bash
cargo test --workspace --exclude kernel
```

Tests cover:
- `kheap`: Quantized intrusive slab allocator & block coalescing.
- `kpaging`: 4-level page tables with strict W^X enforcement.
- `kscheduler`: 3-band strict-priority QoS scheduling & preemption.
- `kvault`: Merkle tree integrity, secret splitting, and duress wipe triggers.
- `kipc`: Lock-free circular ring buffers.

---

## 📬 Pull Request Process

1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Write clean, readable Rust with comments explaining non-trivial systems logic.
3. Verify formatting and linting:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --exclude kernel
   ```
4. Commit your changes following conventional commits:
   - `feat: add AHCI NCQ queue depth optimization`
   - `fix: prevent potential invalid opcode on CPUs without SMAP`
   - `docs: update ARINC 653 timing parameters`
5. Push to your fork and submit a Pull Request to `CodeRiper/KashOS` on GitHub.

---

## 💬 Community & Code of Conduct

We are committed to providing a welcoming, constructive environment for everyone. Please be respectful, considerate, and collaborative in all discussions and code reviews.
