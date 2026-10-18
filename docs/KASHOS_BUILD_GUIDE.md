# KashOS Build Guide v2: the Reality Pass

Date of audit: 18 Oct 2026. Audited: GitHub `CodeRiper/KashOS` (commit `118b12e`) and `KashOS_v0_1_0_Complete_Release.zip` (same source, plus prebuilt kernel and ISO). Replaces: `docs/KASHOS_BUILD_GUIDE.md` (guide v1, "make it real, secure and fast").
Audience: the AI coding agent that builds KashOS, and the human who reviews it.

## What was and was not checked by the author of this guide
- **READ in full or in the relevant parts**: README, CLAIMS, both reports, `driver.rs`, `process.rs`, `tpm.rs`, `kms.rs`, `csprng.rs`, `vtd.rs`, `kapp.rs`, `apic.rs`, `input.rs` (xHCI part), `boot.S` (EFER part), `sync.rs`, `selftest.rs` (T13, T18-T20), CI workflow, Cargo manifests, the ISO contents.
- **RUN**: `cargo test` for `kcore` and `kvault` on a host (42 tests passed, with some dependencies pinned to older versions because the audit machine had an old compiler).
- **NOT RUN**: the kernel itself. Nobody has booted it in this audit. Every statement about boot output (T1..T43) is unconfirmed until your CI boots it with the harness in section 7.
- Anything marked "(not traced)" was not followed to the end. Treat it as a question, not a finding.

---

## 0. How to use this document
1. Save it as `docs/KASHOS_BUILD_GUIDE.md` (replace v1).
2. The agent reads sections 1 to 3 every session, then works from the task list in section 6, one task card at a time (section 11).
3. A human (or a second, independent agent using the verifier prompt in section 12) signs off every gate. The builder agent never signs off its own gate.
4. Do not redesign the UI. `kash-ui` (the glass desktop, dock, lock screen, settings panes, Files, Terminal) stays as it is. The job is to make everything behind it real, and to label anything that is not real as "not available" or "demo". Where a pane or app has no real backend yet, it stays visible but is clearly marked (section 8).

---

## 1. The rules

### 1.1 Original 10 rules (kept from v1)
1. **No simulation**: never print or hardcode anything that looks like system state.
2. **No fake `[OK]`**: success is printed only by `status.rs`, only after the thing was just checked.
3. **"Done" = code exists + reachable from a normal boot + a test proves it + status registry says `Real`**.
4. **Every security claim has a row in `docs/CLAIMS.md` with evidence.** No evidence, no claim.
5. **Fail closed on hardware that is missing (IOMMU, RNG, TPM)**: say so, disable the dependent feature, do not pretend.
6. **Dead code is wired in or deleted** (no blanket `#![allow(dead_code)]`).
7. **Every setting in the GUI is backed by a real service API.**
8. **Phases in order**: gate of phase N passes before phase N+1 starts.
9. **Every `unsafe` has a `// SAFETY:` comment** stating the invariant.
10. **Never write "verified", "proven" or "mathematically"** without a machine-checked proof in CI.

### 1.2 New rules (v2). These exist because v1's rules were satisfied on paper while the code stayed unreal
11. **Independent evidence.** A test counts as evidence for an isolation or security claim only if it observes the system from outside the code under test: the host-side harness (section 7) watching QEMU, or a hostile user-mode program. A function inside the kernel that calls another function inside the kernel ("simulate a crash", "simulate DMA") is a unit test at best. It may exist, but it never raises a claim above evidence level E2 (section 2.2).
12. **No gate tampering.** The agent must not edit, weaken, skip, or delete: gate scripts, `tools/claims_lint.py`, the harness, tests tagged `#[gate]` / located in `tests/gates/`, or CI workflow files, unless the task card explicitly says so AND a human approves. If a gate fails, fix the product, not the gate. If the gate itself is wrong, stop and report.
13. **Real means separate.** "Service", "driver", "process", "domain", "sandbox", "TPM", "IOMMU", "signature" have fixed definitions (section 2.1). A thing that does not meet the definition may not be called by that name in code, docs, boot output, GUI or the ISO.
14. **Everything shipped is consumed.** Every file in the ISO, every config key and every manifest field must be read by code that is tested. Decorative files (a `security.conf` nobody parses, a signature file containing text) are bugs. Delete them or implement their reader.
15. **No placeholder security material.** No fake signatures, no sample keys, no all-zero seeds, no `TODO` keys in any shipped artifact. A missing key means the feature reports `NotAvailable`.
16. **Fail closed means fail closed in the code, not only in the log.** Printing "refusing to ..." and continuing is a failure. The dependent operation must return an error and the caller must propagate it (see F-01 for the current counter-example).
17. **Boot on the baseline machine, always.** The OS must boot and be usable on hardware tier T0 (section 3). A security feature the T0 machine lacks (RDRAND, AES-NI, IOMMU, TPM) is reported unavailable and the OS falls back to a documented weaker mode. It must never refuse to boot, and must never silently weaken keys.
18. **Reproducible, not committed.** Binaries and ISOs are built by CI from source and are not stored in git. Release builds contain no personal paths, no debug info, no usernames.
19. **Small tasks.** One task card = one branch = one reviewable diff, aim for under 600 changed lines and under 15 files. Large tasks are split before work starts.
20. **Report the red.** Every report ends with a section "Still false / still partial / not done". An empty section is suspicious and will be audited.

---

## 2. Definitions

### 2.1 What "real" means
- **Process**: Own page tables (own CR3), runs at CPL 3, has its own kernel stack and capability space, created by the kernel from an ELF file that is not linked into the kernel image.
- **Service / driver**: A process (above) built as a separate crate/binary, not a dependency of the `kernel` crate, started from the initrd by `init` / `svcmgr`. The kernel contains no code that performs that device's I/O on its behalf (it may only validate and grant MMIO/IRQ/DMA capabilities). A crash is a hardware fault in that process handled by the fault handler; the supervisor re-spawns it from its ELF with a new process identity.
- **Domain / compartment**: A set of processes with one label in the policy engine, enforced on every IPC and capability grant, with a memory/CPU/object quota. The label shown by the compositor comes from the kernel's record, never from the app.
- **TPM feature**: Talks TPM 2.0 commands over TIS or CRB to a real or emulated TPM (`swtpm` in CI). PCR values equal what `tpm2_pcrread` on the host reports for the same TPM state. A sealed blob lives on disk and survives reboot. A software array of PCRs is a model: allowed only under `cfg(test)`, and the type is named `TpmModel`.
- **IOMMU feature**: Root and context tables are built in memory the hardware reads, translation is enabled in hardware, and a real DMA-capable device model is blocked and logged by the hardware (QEMU `intel-iommu` + `edu` device). Software walk functions are unit tests.
- **Signature**: Public-key signature (Ed25519) checked against a trust-root public key compiled into or stored with the verifier, over the exact bytes being trusted. A file that contains text, or a hash, is not a signature.
- **Persistent key**: Survives power-off and reboot, and can be unlocked again by the user's passphrase (and TPM if present). A key generated fresh at every boot is a session key and may not be called a vault key.
- **Verified / proven**: A Kani/Verus/Coq proof file exists in `proofs/`, runs in CI, and the claim text links to it. Exhaustive or randomized unit tests are "tested", never "proven".

### 2.2 Evidence levels (used in `docs/CLAIMS.md`)
- **E0**: Claimed only -> What the README may say: Nothing. Delete the claim.
- **E1**: Host unit tests of a library -> "Implemented (library)"
- **E2**: In-kernel self-test (code tests itself) -> "Self-tested at boot"
- **E3**: External harness observes expected serial/QMP events in QEMU -> "Tested in QEMU"
- **E4**: Hostile program/device attacks the boundary and the harness sees it blocked -> "Isolation tested"
- **E5**: Fuzzed for the stated duration with a stated corpus -> "Fuzzed N h (target)"
- **E6**: Machine-checked proof in CI -> "Proven (property X, tool Y)"
- **E7**: Independent third-party audit published -> "Audited by Z (report link)"

*The word "secure" is allowed only next to a specific E4+ claim, never alone.*

---

## 3. Hardware targets (decide once, test always)

The author's primary machine is an old laptop: 1 CPU core, 1 GB RAM, roughly 20 years old. The repo's own low-memory test script used `-cpu core2duo -m 100M`. The OS also wants to run on newer PCs, mini PCs, Macs and ARM. So the tiers are:

| Tier | Example | CPU features you may NOT assume | Test config in CI |
| :--- | :--- | :--- | :--- |
| **T0 baseline** | 2006-2009 laptop, Core 2 class, BIOS, 1 core, 1 GiB | RDRAND/RDSEED, AES-NI, AVX, x2APIC, IOMMU/VT-d, TPM, SMEP/SMAP, xHCI (USB is UHCI/EHCI), NVMe, UEFI | `-cpu Conroe -smp 1 -m 1024` (and `-m 256`) |
| **T1** | 2010-2015 PC | IOMMU on some, TPM 1.2/2.0 on some, AES-NI yes | `-cpu Nehalem/Haswell -smp 2` |
| **T2** | 2016+ PC/laptop/mini PC, UEFI | none | `-cpu max -smp 4` plus `-device intel-iommu`, `swtpm` |
| **T3** | ARM64 (Pi class, then Apple/others), RISC-V | different boot, interrupt, IOMMU stacks | `qemu-system-aarch64 -machine virt` (aarch64 code exists in the tree) |

### Important consequences for T0:
- **Long mode check**: Core Solo/Duo (Yonah, 2006) and Pentium M are 32-bit only. The kernel is x86_64 only. The boot stub must detect "no long mode" with CPUID and print a clear message instead of triple-faulting (F-02). Confirm the author's laptop CPU supports `lm` (`grep -c ' lm ' /proc/cpuinfo` from any Linux live USB) before spending effort.
- **No RDRAND**: Entropy must come from several sources (F-01).
- **No AES-NI**: Keep XChaCha20-Poly1305 as the default cipher; do not make AES-XTS the default. (The build already forces software Poly1305/ChaCha, which is correct for T0.)
- **Argon2id memory**: Sized from detected RAM (RFC 9106 lists 64 MiB with 3 passes as its low-memory profile; do not go below about 19 MiB). Store parameters in the volume header.
- **Timers**: APIC timer needs calibration against PIT/HPET/TSC (F-03).
- **USB**: 2006 laptops use UHCI/OHCI + EHCI, not xHCI. PS/2 keyboard and touchpad cover input for the first milestone; USB host support for T0 means UHCI + EHCI drivers (Phase H).
- **Storage**: IDE/PATA and SATA in IDE-compat mode first; AHCI next.
- **Graphics**: BIOS VGA/VBE framebuffer via GRUB `gfxpayload`; software renderer.
- **Old Intel Macs**: May have 32-bit EFI with a 64-bit CPU. Out of scope until M3.

---

## 4. Verified audit of the current code (what the claims say vs what the code does)

Status words: `SOLID` = real and tested at library level. `MODEL` = real logic but not connected to hardware or to a separate process. `FALSE` = the claim is not true of the code.

### 4.1 Findings
- **V-01 (Ring-3 driver services)**: Claimed unprivileged ring 3 driver services. Code only builds capability table for hard-coded PIDs 50-53 in kernel. Verdict: `FALSE (MODEL)` -> Fix F-04.
- **V-02 (TPM, measured boot, anti-evil-maid)**: Claimed TPM 2.0 CRTM driver, PCR bank, key sealing. `tpm.rs` PCRs are an array in kernel RAM; seal copies secret in plaintext into RAM array. Verdict: `MODEL` -> Fix F-05.
- **V-03 (Vault key)**: Claimed kvault mounted as root filesystem, TPM-sealed keys. On every boot a fresh random key is generated; data encrypted in one boot cannot be opened in the next. Verdict: `FALSE` -> Fix F-06.
- **V-04 (RNG on old CPUs)**: Claimed entropy fails closed. `csprng.rs` if RDRAND missing seeds from RDTSC reading and prints success unconditionally. On T0 laptop master key is guessable. Verdict: `FALSE, SEVERE` -> Fix F-01.
- **V-05 (IOMMU)**: Claimed VT-d SLPT, rogue DMA contained. `vtd.rs::isolate_device` writes hardcoded 0x2000_0000 into root entry and enables translation. Verdict: `MODEL, RISKY` -> Fix F-07.
- **V-06 (Network stack)**: Claimed sys-net with smoltcp stack. No smoltcp dependency exists in Cargo.toml. Verdict: `FALSE` -> Fix F-08.
- **V-07 (GUI isolation)**: Claimed kash-ui is capability-isolated display service. `gui.rs` runs Desktop inside the kernel (ring 0). Verdict: `FALSE` -> Fix F-09.
- **V-08 (Formal proofs)**: Claimed machine-checked formal invariant proofs. `formal_invariants.rs` is 4 ordinary `#[test]` functions. Verdict: `FALSE wording` -> Fix F-10.
- **V-09 (Userland)**: Claimed Ring 3 user mode & ELF loader. Real ELF loader and Ring 3 entry exist, but only user programs are hand-assembled byte arrays in tests. ISO `/bin` is empty. Verdict: `PARTIAL` -> Phase U.
- **V-10 (Signed manifest)**: Claimed UEFI/manifest signature validation. `manifest.sig` is a 65-byte plain text string; `kapp.rs::verify_signature()` always returns Err. Verdict: `FALSE` -> Fix F-11.
- **V-11 (Manifest claims)**: `manifest.toml` claims XTS-AES-256 and graphene_hardened. XTS-AES is not implemented. Verdict: `FALSE` -> Fix F-11, F-12.
- **V-12 (USB)**: Claimed xHCI driver. `XhciController::init` sets `is_running = true` and pushes hardcoded string device names without touching hardware. Verdict: `FALSE` -> Fix F-13.
- **V-13 (Timer)**: APIC timer initial count fixed at 625,000 for QEMU. Real hardware tick rate will be wrong. Verdict: `PARTIAL` -> Fix F-03.
- **V-14 (Boot on old CPUs)**: `boot.S` writes EFER with no CPUID long-mode check. Verdict: `RISK` -> Fix F-02, F-03.
- **V-15 (Phase gates)**: Claimed 10 phases 100% complete and hardware-verified. CI never boots QEMU; nobody tested on hardware. Verdict: `FALSE` -> Fix F-14.
- **V-16 (Honesty gate)**: Docs use "machine-checked", "100% complete". Kernel prints ✓ lines unconditionally. Verdict: `WEAK` -> Fix F-14.
- **V-17 (Dead / model code)**: 26 files carry `allow(dead_code)`; `kash_kernel.rs` model code; shell prints "Simulating...". Verdict: `VIOLATION` -> Fix F-15.
- **V-18 (unsafe audit)**: 527 unsafe sites and 69 SAFETY comments; 28 static mut; no `docs/UNSAFE_AUDIT.md`. Verdict: `VIOLATION` -> Fix F-16.
- **V-19 (Repo hygiene)**: `isodir/boot/kash-kernel` committed; release keeps debug info with personal paths; no LICENSE file; 67 hardcoded personal links. Verdict: `HYGIENE` -> Fix F-17.
- **V-20 (Showcase apps)**: Notes, Firefox, Photos, Music, Messages are glass-chrome showcase widgets. Verdict: `DEMO` -> Section 8.3.
- **V-21 (Lock-screen passphrase)**: UI has passphrase fields; does not feed vault key. Verdict: `(not traced)` -> Fix F-06.

### 4.2 What is solid and must not be broken
- `kcore` capability space: derive, rights monotonicity, revoke (tests pass, 18 unit + 4 property tests).
- `kvault` library: Argon2id, authenticated encryption, Merkle/CoW tree, hidden volume, duress (15 + 5 tests pass).
- ELF loader with W^X segment rules; per-process page tables; Ring 3 entry via `iretq`; syscall entry with `swapgs` and kernel stack switch; user-fault containment; 16 KiB kernel stacks with guard pages; SMEP/SMAP/UMIP/WP enabled when CPU has them; interrupt-safe ticket lock; preemptive scheduler skeleton with FPU/SSE save/restore.
- ELF segments of the built kernel are properly W^X (R, R+X, R, RW, RW).
- The project's own honesty cleanup (Phase 0) and the layout into small crates.
- The glass UI (`kash-ui`) and its performance work (dirty rectangles).

---

## 5. The fix list: do these BEFORE any new feature

- **F-01 Entropy that works on T0 and never silently weakens keys (V-04)**: Build kernel entropy service (RDSEED/RDRAND if present, CPU-jitter timing, PS/2 & disk interrupt timing, RTC, virtio-rng, persisted random-seed file). Track estimated entropy-bit counter. Only allow key generation if counter > 256 bits, else return `Err(NotEnoughEntropy)`.
- **F-02 Hardware feature detection and clean refusal (V-14)**: CPUID checks in `boot.S` before touching EFER. On failure, print plain message on VGA text/serial ("This CPU lacks X; KashOS needs x86_64 with NX") and halt cleanly.
- **F-03 Timers and interrupt controller on real hardware (V-13, V-14)**: Calibrate APIC timer against PIT (and HPET/TSC). Fall back to PIC+PIT if no APIC.
- **F-04 Drivers and services as real processes (V-01)**: Delete words "user-mode driver service" from code, docs, and boot output until Phase 4 is done.
- **F-05 Real TPM or no TPM (V-02)**: Rename RAM array to `TpmModel` and move under `cfg(test)`. Report `NotAvailable` on T0.
- **F-06 A vault key that persists and is unlocked by the user (V-03, V-21)**: Key hierarchy: user passphrase -> Argon2id -> KEK -> wraps random volume master key stored in volume header.
- **F-07 Make VT-d real or turn it off (V-05)**: Never set Translation Enable unless tables are built in DMA-reachable memory and pass self-check. Report `NotAvailable` if no DMAR.
- **F-08 Network: add the stack or remove the claim (V-06)**: Status registry shows `NotAvailable` for TCP/IP; do not print "smoltcp active".
- **F-09 Move GUI out of ring 0, or label it (V-07)**: Docs state "GUI runs in the kernel (ring 0)" until Phase 9.
- **F-10 Rename "formal" tests; add real proofs later (V-08)**: Rename `formal_invariants.rs` to `capability_property_tests.rs`; remove "formal", "machine-checked", "proof" from docs.
- **F-11 Signing and the ISO manifest (V-10, V-11)**: Write `tools/ksign` (Ed25519). Delete placeholder `manifest.sig` and "PQ_VERIFIED" text.
- **F-12 Claims in shipped files must be true (V-11)**: Run claims linter; remove "XTS-AES-256" and "graphene_hardened".
- **F-13 Remove fake hardware (V-12)**: Delete hardcoded device list in `XhciController::init`. Report "not available".
- **F-14 Real CI and a claims linter that is hard to game (V-15, V-16)**: `tools/claims_lint.py`, QEMU boot test in CI.
- **F-15 Dead and simulated code (V-17)**: Remove `allow(dead_code)`; delete shell commands that print "Simulating...".
- **F-16 unsafe audit (V-18)**: Add `#![deny(clippy::undocumented_unsafe_blocks)]`; write `docs/UNSAFE_AUDIT.md`.
- **F-17 Repo and release hygiene (V-19)**: Strip debug info, add `LICENSE` (MIT), `THIRD_PARTY_NOTICES.md`, relative links, `VERSION` file.

---

## 6. Phases (re-opened) and new phases

All 10 phases from v1 are marked REOPENED. Work in this order (critical path):
1. **Stage A (days)**: F-01, F-02, F-10, F-11 (placeholder removal), F-12, F-13, F-14 (harness skeleton + CI boot), F-17.
2. **Stage B**: Phase 1 and 2 remaining items, F-03, Phase U (userland SDK).
3. **Stage C**: Phase 3, then Phase 4 one service at a time (storage first), F-06 with Phase 6, then input, display, net.
4. **Stage D**: Phase 5 (TPM), Phase 7 (network), Phase 8 (compartments), Phase 9 (GUI out of ring 0).
5. **Stage E**: Phase I (installer/update/recovery), Phase H (hardware enablement), Phase C (compat), Phase X (security toolbox), Phase 10 (proofs, fuzzing, audit).

---

## 7. The external test harness (`tools/harness/`)
- Structured events: single-line JSON events on serial: `KASH-EVT {"t":123456,"src":"kernel","ev":"proc_spawn",...}`.
- Controls: driven via QMP (`system_reset`, `quit`, `pmemsave`, `screendump`, `device_add`, `sendkey`).
- Devices: `filter-dump` pcap, `swtpm` + `tpm-tis`, `intel-iommu` + `edu`, raw disk image.
- CPU matrix: `-cpu Conroe -smp 1 -m 1024` (T0), `-cpu Conroe -m 256`, `-cpu Haswell -smp 4`, `-cpu max -smp 4`.

---

## 8. Making the existing UI real (without redesigning it)
- Each pane, app, and dock item gets a status entry in `status.rs`: `Real`, `NotAvailable(reason)` or `Demo`.
- The UI displays a small "Not available on this system" or "Demo" badge.
- Rename "Firefox" to "Browser (demo)" until a real engine runs.

---

## 9. Release engineering and repo hygiene (F-17)
- Remove `isodir/boot/kash-kernel` from git history; `.gitignore` covers build outputs.
- Pin toolchain in `rust-toolchain.toml`.
- Release profile: `debug = false`, `strip = "symbols"`, `panic = "abort"`, `--remap-path-prefix`.
- Add `LICENSE` (MIT) and `THIRD_PARTY_NOTICES.md`.
- One version source: `VERSION` file.

---

## 10. Documents the repo must contain
`docs/THREAT_MODEL.md`, `docs/CLAIMS.md`, `docs/STATUS.md`, `docs/ABI.md`, `docs/EVENTS.md`, `docs/BOOT_FLOW.md`, `docs/MEMORY_MAP.md`, `docs/KEYS.md`, `docs/UNSAFE_AUDIT.md`, `docs/HARDWARE.md`, `docs/BENCHMARKS.md`, `docs/RELEASE.md`, `docs/design/<task>.md`, `docs/EVIDENCE/<date>/`, `proofs/README.md`.

---

## 11. Agent workflow

### 11.1 Work loop
1. Read the task card, this guide's sections 1 to 3, `docs/STATUS.md`.
2. Write `docs/design/<task>.md` (one page: approach, risks, what will still be false afterwards).
3. Implement on branch `task/<task>`.
4. Add positive and negative tests; for isolation/security claims add the harness scenario.
5. Run: unit tests, clippy, claims lint, harness scenarios. Paste raw output.
6. Update `docs/CLAIMS.md` rows: raise or lower status honestly. Update docs.
7. Report in mandatory format. Stop. Do not start the next card without signoff.

### 11.2 Mandatory Report Format
```markdown
TASK: <task_id>
CHANGED: <files + line counts>
COMMANDS RUN: <exact commands>
RESULTS: <raw output excerpts, paths of evidence bundle>
CLAIMS CHANGED: <row, old status -> new status>
STILL FALSE / PARTIAL / NOT DONE: <list, never empty>
QUESTIONS FOR HUMAN: <list>
```

### 11.3 Stop conditions
- A gate fails and the fix would require changing the gate.
- A task touches the crypto format, ABI, or boot protocol unexpectedly.
- The agent cannot make something real on the available hardware (mark `NotAvailable`).
- A dependency is needed that is not in `Cargo.lock`.
- Anything that would delete a large component or user-facing feature.

---

## Appendix A: claims linter (`tools/claims_lint.py`)
Fail CI if any of the following appears in README, `docs/**`, shipped manifests, GUI string tables, or binary strings without linked proof/evidence:
`formally verified`, `formal verification`, `machine-checked`, `mathematically`, `proven`, `proof` (outside `proofs/`), `verified` (unless signature verified), `guaranteed`, `unbreakable`, `unhackable`, `military-grade`, `100%` next to security or complete, `hardware-verified`, `post-quantum` / `PQ` / `ML-KEM` (until implemented), `seL4` (unless real seL4), `GrapheneOS`, `TCG MOR` (unless implemented), `XTS` (until implemented), `Tor` (unless client runs), `smoltcp` (unless in dependency tree), `ring 3 driver` (unless F-04 passed), `[OK]` or check mark in `kprintln!` outside `status.rs`.

---

## Appendix C: realistic milestones
- **M0 Honest prototype**: Stage A. "Research OS prototype; ring-0 kernel with a verified status table; boots in QEMU on a Core 2 model."
- **M1 Real kernel**: Phases 1, 2, 3, U. "Preemptive multitasking, user-mode init and shell, capability-checked IPC, externally tested."
- **M2 Usable VM desktop**: Phases 4 (virtio, IDE/AHCI, PS/2), 6, 9, I. "Boots from an installed encrypted disk in QEMU/VirtualBox with a user-mode GUI whose settings work."
- **M3 Real hardware**: Phase 4 (rest), 5, 7, H. "Runs on the listed laptops with networking, TPM where present, and measured boot."
- **M4 Hardened release**: Phases 8, C, X, 10. "Fuzzed, partly proven (named properties), externally reviewed."
