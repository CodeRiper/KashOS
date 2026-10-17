# KashOS Phase 6: Storage and Crypto Subsystem Architecture

**Author**: Akash <akash.official.j@gmail.com>  
**Status**: APPROVED / IMPLEMENTED  
**Target Milestone**: Phase 6 — Storage and Crypto  
**References**:
- *KashOS: make it real, secure and fast (agent build guide)* (Oct 17, 2026)
- *KashOS Architectural Blueprint* (Pages 10–14: Authenticated Vault Storage, Anti-Forensics, and KMS)
- TCG PC Client Specific Platform TPM Profile (PTP) Specification Version 2.0
- RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- RFC 8439: ChaCha20 and Poly1305 for IETF Protocols

---

## 1. Executive Summary & Objectives

Phase 6 implements the complete persistent storage and cryptographic foundation of KashOS. While earlier milestones established hardware drivers, capability routing, IOMMU containment, and TPM 2.0 measured boot, persistent storage remained unmounted at the root VFS layer.

Phase 6 achieves four key architectural goals:
1. **Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)**: A 256-bit entropy pool seeded directly from hardware CPU instructions (`RDRAND`/`RDSEED`) and virtio-rng with fail-closed non-zero entropy verification, implementing `rand_core::RngCore` and `rand_core::CryptoRng`.
2. **Key Management Service (KMS)**: Zero-allocation key hierarchy (`MasterKey`, `RootKey`, `SystemKey`, `PersonalKey`) utilizing HKDF-SHA256, integrated with TPM 2.0 PCR sealing (PCR 4 & PCR 7) to enforce Anti-Evil Maid key release.
3. **Hardware Block Storage Integration (`kblock` ↔ `kvault`)**: `KBlockDeviceAdapter` maps 4 KiB `kvault` blocks to 8 physical 512-byte sectors over the unified `kblock` driver subsystem (supporting IDE/PATA, AHCI SATA, VirtIO-Blk, NVMe, and in-memory fallback) with C-LOOK elevator queueing.
4. **Root VFS Mount & Authenticated Directory Routing**: Mounts `kvault::Vault` as the authoritative root filesystem (`/`), provisioning `/system`, `/apps`, `/personal`, and `/etc` namespaces.
5. **Anti-Forensic Screen Lock Zeroization**: Complete expulsion of key material from RAM and CPU cache lines via volatile writes and explicit x86 `clflush` instructions upon screen lock, verified via memory scan.
6. **Tamper-Evident Bit-Flip Detection**: Single-bit alteration on disk immediately halts read operations with `VaultError::Corrupt` / `VfsError::CorruptFilesystem`, preventing silent execution of forged data.

---

## 2. Threat Model & Security Posture

| Threat | Attack Vector | Mitigation in Phase 6 |
| :--- | :--- | :--- |
| **Evil Maid Tampering** | Attacker modifies kernel binary on disk or alters bootloader configuration. | Master Vault Key is sealed to TPM 2.0 PCR 4 (Kernel Code) & PCR 7 (Secure Boot Policy). If 1 byte changes, `tpm::unseal` fails closed with `TpmError::PolicyMismatch`, zeroizing buffers and denying vault access. |
| **Offline Disk Theft & Inspection** | Attacker reads raw physical sectors from HDD, SSD, or USB mass storage. | Entire disk is formatted with random noise; unused space is indistinguishable from encrypted data. Every 4 KiB block is authenticated and encrypted with XChaCha20-Poly1305 bound to (LBA, VolumeID, FileID) in AAD. |
| **Bit-Flip / Data Corruption** | Attacker or faulty storage media flips bits to bypass signature checks or trigger memory vulnerabilities. | Authenticated encryption tags (Poly1305 MAC) and Merkle tree hashes enforce strict tamper-evidence; any 1-bit flip triggers immediate authentication failure and read abort. |
| **Cold Boot / DRAM Forensics** | Attacker freezes DRAM or reads remanence cells after physical seizure. | Screen lock triggers immediate key scrubbing: volatile zeroing followed by `clflush` across all 64-byte cache lines; verified via post-lock memory scan. |
| **Weak PRNG / Predictable Nonces** | Attacker predicts XChaCha20 nonces or Argon2 salts due to bad pseudo-randomness. | CSPRNG is continuously seeded from bare-metal hardware entropy (`RDRAND`/`RDSEED`); execution halts (Rule R2: Fail-Closed) if hardware entropy is unavailable. |

---

## 3. Architecture & Core Subsystems

```
+─────────────────────────────────────────────────────────────────────────+
|                     KashOS Virtual File System (VFS)                    |
|       / (Root) ───┬─── /system  (Manifest, OS release, drivers)         |
|                   ├─── /apps    (Verified .kapp application capsules)   |
|                   ├─── /personal (User documents & encrypted secrets)   |
|                   └─── /etc     (Immutable machine configuration)       |
+─────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────+
|                     kvault Native Authenticated Engine                  |
|    - XChaCha20-Poly1305 Authenticated Encryption (192-bit Nonces)       |
|    - AAD Binding: aad("kvault/data", vol_id, abs_block, file_id, chunk) |
|    - Argon2id Password KDF + HKDF-SHA256 Subkey Derivation              |
|    - Anti-Forensic Information Dispersal (AF-Split)                     |
+─────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────+
|                   KBlockDeviceAdapter (Block Translation)               |
|      Translates 1 x 4 KiB kvault block ───> 8 x 512B disk sectors       |
+─────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────+
|                    kblock Elevator Subsystem (C-LOOK)                   |
|       - 64-Entry Request Ring & Contiguous Write Coalescing             |
|       - Drivers: PATA/IDE (0x1F0), AHCI SATA, VirtIO-Blk, NVMe          |
+─────────────────────────────────────────────────────────────────────────+
```

### 3.1 Bare-Metal Hardware CSPRNG (`kernel/src/csprng.rs`)
- State: 256-bit key `K`, 64-bit nonce `N`, 64-bit counter `C`.
- Algorithm: ChaCha20 stream generation with block-level re-keying.
- Entropy Sourcing: Queries `arch::hw_entropy()` which invokes `RDSEED` (falling back to `RDRAND`) on x86_64, or VirtIO-RNG.
- Reseeding: Reseeds from hardware entropy after every 64 KiB of generated randomness to prevent state compromise.
- Interface: Implements `kvault::rand_core::RngCore` and `kvault::rand_core::CryptoRng` for direct zero-cost integration into `kvault`.

### 3.2 Unified Key Management Service (`kernel/src/kms.rs`)
- Master Key Management: Stores master credential in `Zeroizing<[u8; 32]>`.
- Subkey Derivation: Derives compartment keys using `kvault::subkey`:
  - `RootKey`: `subkey(&master, b"kashos/root-key")`
  - `SystemKey`: `subkey(&master, b"kashos/system-key")`
  - `PersonalKey`: `subkey(&master, b"kashos/personal-key")`
- TPM 2.0 Integration:
  - `seal_to_tpm(pcr_mask, master_key)`: Computes composite policy digest over PCR 4 and PCR 7, sealing the master key to TPM NVRAM / volatile slot.
  - `unseal_from_tpm()`: Reads live PCR bank; verifies policy digest; returns `Ok(master_key)` or `Err(TpmError::PolicyMismatch)`.
- Anti-Forensic Memory Scrubbing:
  - Invokes `security::secure_zero_memory(ptr, len)`.
  - Loops over cache lines: `clflush [reg]` every 64 bytes.
  - Executes `compiler_fence(Ordering::SeqCst)` to prevent compiler store optimization.

### 3.3 Block Device Adapter (`kernel/src/blockdev.rs`)
- Implements `kvault::BlockDevice` for `KBlockDeviceAdapter`:
  - `block_count(&self) -> u64`: `stats.total_sectors / 8`.
  - `read_block(&self, idx, out) -> VaultResult<()>`: Dispatches `read_sectors(idx * 8, out)` via `kblock`.
  - `write_block(&mut self, idx, data) -> VaultResult<()>`: Dispatches `write_sectors(idx * 8, data)` via `kblock`.

### 3.4 Root VFS Mount & Path Router (`kernel/src/vfs.rs`)
- Initializes root vault on primary persistent storage device.
- Formats or unlocks volume using the TPM-unsealed master vault key.
- Root namespace mapping:
  - `/system/manifest.toml`: System component signatures and boot state.
  - `/system/os-release`: OS identification (`NAME=KashOS`, `VERSION=0.1.0-alpha`).
  - `/etc/kashos.conf`: Lockdown mode configuration and security policies.
  - `/personal/notes.txt`: Encrypted personal user data.

---

## 4. Acceptance Gates (Self-Tests in `kernel/src/selftest.rs`)

| Gate | Description | Pass Criteria |
| :--- | :--- | :--- |
| **T24** | **Hardware-Entropy Seeded CSPRNG & KMS** | CSPRNG seeds from hardware `RDSEED`/`RDRAND`; produces non-repeating cryptographic streams; derives subkeys via HKDF-SHA256. |
| **T25** | **kvault Root Mount & Bit-Flip Gate** | Root volume mounted over `kblock`; files created in `/system` and `/personal`; 1-byte tamper injected directly into disk block; subsequent read traps Poly1305 MAC failure (`VaultError::Corrupt`) and rejects data. |
| **T26** | **Anti-Forensic Screen Lock Memory Scrubbing** | Master key stored in RAM; screen lock event triggers `lock_all()`, `secure_zero_memory()`, and `clflush`; memory scan over key buffer confirms 100% zeroed bytes. |
| **T27** | **TPM-Sealed Master Key & Fail-Closed Gate** | Master key sealed to PCR 4 & 7; clean unseal succeeds and unlocks root vault; simulated 1-byte kernel tamper causes unseal rejection (`TpmError::PolicyMismatch`), vault remains locked. |
