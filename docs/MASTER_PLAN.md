# KashOS Master Engineering Plan: Make It Real, Then Build Kash Kernel 2.0

*From prototype to a real, secure, complete OS. Part A makes every fake or partial piece real. Part B designs Kash Kernel 2.0, an seL4-class kernel written in Rust. Part C finishes the rest of the OS.*

Prepared for Kash (CodeRiper) · Based on a manual review of kashos-source.zip (v0.2.0) · 18 October 2026

---

## 0. Read this first

### 0.1 What this document is
This is the single instruction file for the Antigravity AI. For every problem it gives: what is wrong, proof (a command the AI can run), exactly what to build, how to test it in QEMU, and when the task counts as done. Work in order. Never skip the proof step. Never mark a task done without test evidence.

| Part | Sections | Goal |
|---|---|---|
| A | 3 to 5 | Turn every fake, simulated or partial piece into real working code, or delete it |
| B | 6 to 8 | Design and build Kash Kernel 2.0: all seL4 features, plus measurable improvements |
| C | 9 | Finish the OS: userland, apps, real Tor, Wi-Fi, hardware from old to new |
| D | 10 | Research notes and sources |
| Appendices | 11 | Task template, kickoff prompt, checklists |

### 0.2 Honest limits (read before starting)
- This review was done by reading the source. It was not compiled or booted. Every finding in section 1 has a proof command. Run it first. If the code disagrees with this document, trust the code, write the difference in `docs/EVIDENCE/` and continue.
- "Beat seL4 in every way" cannot be true on day one. seL4 has machine-checked proofs built over many years (functional correctness, integrity and information flow on verified configurations; the proofs are now close to a million lines of proof steps). Source: trustworthy.systems/projects/seL4-verification.
- seL4 itself has gaps you can use as a target: its MCS (real-time) configuration is still being verified, and its SMP configuration is supported but not formally verified (seL4 CAVEATS.md). So "feature parity" and "proof parity" are different goals. Section 6 splits them into measurable targets.
- A complete OS (Wi-Fi, GPU, browser, apps) is a multi-year job. This plan orders the work so that every step leaves a working, honest system.

### 0.3 The rules (the AI must obey all of them)
R1 to R10 are the base honesty rules. R11 to R20 are added by this plan.
1. **R1 No simulation.** Never hardcode output that looks like system state.
2. **R2 No fake [OK].** Print OK only after the code just checked the thing.
3. **R3 Done means:** code exists, reachable from boot, a test proves it on the real code path, status registry says Real.
4. **R4 Claim to evidence.** Every security claim has a row in `docs/CLAIMS.md` with a test.
5. **R5 Fail closed.** Missing hardware means: say so, disable the feature, keep booting if safe.
6. **R6 No dead code.** Wire it in or delete it.
7. **R7 Real settings.** Every GUI setting must call a real service.
8. **R8 Phase gates.** Do not start the next gate until the current gate's tests pass in CI and QEMU.
9. **R9 Minimise unsafe.** Every unsafe has a `// SAFETY:` comment stating the invariant.
10. **R10 Honest words.** Never write "verified", "proven" or "mathematically" unless a machine-checked proof runs in CI.
11. **R11 Verify before you fix.** Run the proof command of the finding first. Save output in `docs/EVIDENCE/<task>.md`.
12. **R12 One task, one branch, one pull request.** Tests are in the same commit as the code.
13. **R13 Model tests do not count.** A test that checks a software model (for example a table pretending to be an IOMMU) cannot flip a status to Real. The test must make real hardware (or QEMU's emulation of it) behave differently.
14. **R14 Never weaken a test to get green.** If a test fails, fix the code or write a documented, reviewed exception.
15. **R15 Research first.** Before each task, search the internet for the current official spec, crate version and known bugs. Write the links, versions and date in the evidence file. Prefer official specs and upstream docs over blog posts.
16. **R16 No secrets in output.** Keys, passphrases and seeds must never reach the serial log, panic message or framebuffer.
17. **R17 Remove, don't pretend.** If a feature cannot be made real in this task, delete the UI and the claim and add a row in `docs/ROADMAP.md`.
18. **R18 Budget.** Track kernel lines of code and unsafe count in CI. Ring 0 may only shrink after gate A3.
19. **R19 Old hardware stays supported.** Every change must still boot in profile T0 (1 core, 1 GB, no RDRAND) from section 2.
20. **R20 Stop and ask.** If a task needs a decision not covered here (licence, hardware purchase, big design change), stop and write the question in `docs/QUESTIONS.md`.

### 0.4 The work loop for every task
1. Read the task card. Run the Proof command. Record the output.
2. Research (R15). Save links and versions.
3. Write a short design note (10 to 30 lines) in `docs/design/<task>.md`.
4. Write the failing test first where possible.
5. Implement in small commits.
6. Run: `cargo test --workspace --exclude kernel`, the kernel build, and the QEMU profiles listed in the task.
7. Update `docs/CLAIMS.md`, `status.rs` and `README` only to match what the tests prove.
8. Write the evidence file: commands run, output, date, commit hash.
9. Open the pull request with the "Done when" checklist ticked.

---

## 1. Ground truth: what the code really is today
Severity: S1 misleading or dangerous, S2 important gap, S3 cleanup.

### 1.1 Findings with proof
| ID | Sev | Finding | Where | Proof command | Fix |
|---|---|---|---|---|---|
| F1 | S1 | `http_get` returns built-in HTTP responses, including a page that says "Congratulations. This browser is configured to use Tor". No packets reach the internet. | `kernel/src/net.rs` | `grep -n "Congratulations" kernel/src/net.rs` | A1 |
| F2 | S1 | DNS is a hard-coded host table. Unknown names get the made-up address `104.244.76.13` labelled "Tor exit". | `kernel/src/net.rs` | `grep -n "Default Tor Exit" kernel/src/net.rs` | A1, A6 |
| F3 | S1 | TCP `connect()` sets the socket to Established immediately. No handshake. | `knet/src/lib.rs` | `grep -n "TcpState::Established" knet/src/lib.rs` | A6 |
| F4 | S2 | README says the network uses smoltcp. It is in no Cargo.toml. | Cargo.toml files | `grep -rn smoltcp --include=Cargo.toml .` (empty) | A6 |
| F5 | S1 | The "TPM" is a software PCR array and a table of "sealed" secrets in RAM. Only the DID/VID register is read. No TPM command is ever sent. After reboot it is gone. | `kernel/src/arch/x86_64/tpm.rs` | `grep -n "pcr_bank\|sealed_items" kernel/src/arch/x86_64/tpm.rs` | A4, A5 |
| F6 | S1 | The disk master key is random at every boot (`sealed_handle` starts at 0). No user passphrase is involved. | `kernel/src/kms.rs` | `grep -n "generating fresh master key" kernel/src/kms.rs` | A3 |
| F7 | S1 | `mount_root` treats any `Vault::open` error (including wrong key) as "no vault yet" and formats the disk. With F6, a real disk is wiped at each reboot. | `kernel/src/vfs.rs` | `grep -n "Err(open_fail)" -A3 kernel/src/vfs.rs` | A2 |
| F8 | S1 | VT-d page tables remain an in-memory `BTreeMap` model with fabricated frame addresses; they are not hardware DMA tables. Hardware activation is disabled and status is Stub pending real physical allocation, MMIO mapping, context programming and invalidation. | `khal/src/vtd.rs`, `kernel/src/arch/x86_64/vtd.rs` | `grep -n "next_phys_frame: 0x4000_0000" khal/src/vtd.rs` | A9 |
| F9 | S1 | After a block of self-tests, statuses for IOMMU, TPM, measured boot, user drivers and DDE-Linux are all set to Real in one call, even though F5 and F8 are models. | `kernel/src/selftest.rs` | `grep -n "s.tpm2_crtm = " kernel/src/selftest.rs` | A21 |
| F10 | S2 | Ring 3 process/syscall mechanisms are exercised only by hand-built self-tests. The normal desktop, settings, and shell still execute in Ring 0 through `session.rs`. | `kernel/src/session.rs`, `selftest.rs` | `rg -n "run_desktop_session|run_interactive_terminal" kernel/src/session.rs` | A10 |
| F11 | S2 | The Files app shows a hard-coded fake folder tree (invented PDFs, pcap, resume). | `kash-ui/.../apps/files.rs` | `grep -n "fn build_fs" -A12 kash-ui/crates/kash-ui/src/apps/files.rs` | A18 |
| F12 | S2 | "Browser" renders about: pages and canned HTML with a tiny parser. No HTTPS, no JavaScript. | `kernel/src/browser.rs` | `grep -n "about:privacy" kernel/src/browser.rs` | A8, C4 |
| F13 | S3 | Several settings panes only say "Not implemented". | `kash-ui/.../apps/settings.rs`, `panes.rs` | `grep -rn "Not implemented" kash-ui/` | A18 |
| F14 | S3 | Docs say 412 unsafe uses in the kernel; grep finds about 470 lines that mention unsafe. | `docs/KERNEL_INVENTORY.md` | `grep -rn unsafe --include=*.rs kernel \| wc -l` | A21 |
| F15 | S2 | The kernel contains the shell and browser; both remain kernel-resident and must move behind real user-service boundaries. | `kernel/src/shell.rs`, `kernel/src/browser.rs` | `rg -n "pub struct KashShell|about:privacy" kernel/src/shell.rs kernel/src/browser.rs` | A10 |
| F16 | S2 | Honest stubs: xHCI USB, UEFI loader, pledge/unveil, nmap/aircrack/hydra/sqlmap/metasploit commands, multi-language runtimes. | various | `grep -rn "NOT IMPLEMENTED\|driver not implemented" kernel/` | A13, A14, A19 |
| F17 | S2 | Documentation lags the code: README says phases 4 to 9 are "verified", but the shipped boot log shows e1000, VirtIO and IOMMU as NOT AVAILABLE. | `README.md`, `kash_serial.log` | `grep -n "NOT AVAIL" kash_serial.log` | A21 |
| F18 | S2 | Earlier critique items (unveil prefix match, global sandbox, user path in build.rs, no .gitignore) must be re-verified; the report says fixed but no proof is shown. | `CRITIQUE_AND_VERIFICATION_REPORT.md` | see A20 | A20 |

---

## 2. The test lab
Everything in this plan is tested in QEMU first, then on real old hardware. No task is done on "it compiled".

### 2.1 QEMU profiles
- **T0-oldlaptop**: 1 core, 1 GB, no RDRAND, BIOS, IDE (`qemu-system-x86_64 -machine pc -cpu Conroe -smp 1 -m 1024M -vga std -net nic,model=rtl8139 -net user`)
- **T0-lowmem**: Minimum RAM check (same with `-m 256M`)
- **T1-modern**: q35, 4 cores, AHCI, e1000 (`qemu-system-x86_64 -machine q35 -cpu max -smp 4 -m 2048M -device e1000,netdev=n0 -netdev user,id=n0`)
- **T2-iommu**: VT-d tests (`qemu-system-x86_64 -machine q35,kernel-irqchip=split -device intel-iommu,intremap=on,caching-mode=on -cpu max -smp 4 -m 2048M`)
- **T2-tpm**: Real TPM 2.0 commands via swtpm socket
- **T2-usb**: xHCI and HID (`-device qemu-xhci -device usb-kbd -device usb-mouse`)
- **T2-nvme**: NVMe controller tests
- **T2-uefi**: UEFI boot via OVMF
- **A64-virt**: ARM64 (`qemu-system-aarch64 -machine virt -cpu cortex-a72 -smp 2 -m 1G -kernel kernel.elf -nographic`)
- **NET-capture**: Packet leak tests (`-object filter-dump,id=f0,netdev=n0,file=n0.pcap`)

---

## 3. Part A: Make everything real (A1 to A21)
- **A1**: Remove every fake network and Tor output (do first)
- **A2**: Stop the data-loss bug (vault open versus format)
- **A3**: Real key hierarchy: passphrase first, TPM second
- **A4**: Real TPM 2.0 driver (TIS first, CRB second)
- **A5**: Measured boot, sealing and anti-rollback
- **A6**: Real TCP/IP with smoltcp
- **A7**: NIC drivers: real, many, tested
- **A8**: TLS and HTTPS
- **A9**: Real IOMMU (Intel VT-d now; AMD-Vi and ARM SMMU later)
- **A10**: Move out of Ring 0: real user-space services (M1 to M9)
- **A11**: SMP and scheduler
- **A12**: Persistent filesystem and disk layout
- **A13**: USB: xHCI, HID and mass storage
- **A14**: UEFI boot, Secure Boot and a loader that measures
- **A15**: Storage drivers: NVMe, hardened AHCI, SD/MMC
- **A16**: Display (double-buffering, dirty rects, virtio-gpu 2D)
- **A17**: ACPI, power and platform (real shutdown/reboot, AML interpreter)
- **A18**: Make the UI honest and connected to real services
- **A19**: libc, Rust std and a POSIX layer (kash-rt, relibc adaptation)
- **A20**: Re-verify the old audit and finish hardening
- **A21**: Status registry from real probes; docs that match; CI that blocks fakes

---

## 4. Part B: Kash Kernel 2.0 (seL4-Class Microkernel in Rust)
- Full seL4 capability model: Untyped, Retype, CNode, Endpoint, Notification, TCB, SchedContext (MCS), Reply, Frame, PageTable, VSpace, AsidPool, IrqControl, IoPortControl, IoSpace, Vcpu.
- Invariants I1 to I7 checked at runtime and verified with Verus.
- Milestones B0 to B17.

---

## 5. Part C: Finish the OS (Userland, Real Tor, Apps, Hardware)
- C1 to C14: Package manager, Installer, Real Tor (Arti via user service), Real Browser (NetSurf/Linux VM/Servo), Wi-Fi (NetVM), Audio, GPU, Accounts, Self-hosting.
