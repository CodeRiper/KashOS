# Phase 5 Design: Boot Chain, Measured Boot, and TPM 2.0 CRTM Driver

## 1. Architectural Overview

Phase 5 implements the verified boot chain and hardware Core Root of Trust for Measurement (CRTM) for **KashOS**:
1. **Cryptographic Boot Integrity**:
   - Ed25519 detached signature and SHA-256 digest validation of the kernel image (`/boot/kash-kernel`) and system manifest (`/manifest.toml`).
   - Verification fails closed upon any byte mismatch, preventing unauthorized or evil-maid bootloader modifications.
2. **TPM 2.0 Driver & PCR Measurement Bank**:
   - Hardware discovery via ACPI `TPM2` table and TCG TPM Interface Specification (TIS) MMIO (`0xFED4_0000`).
   - SHA-256 PCR Bank implementation (PCR 0 through PCR 23) adhering to TCG PC Client Platform Firmware Profile.
   - Stage-by-stage measurement extensions:
     - **PCR 0**: Core Root of Trust for Measurement (CRTM) and platform firmware.
     - **PCR 1**: Platform hardware configuration (ACPI DMAR, MADT, RSDP).
     - **PCR 2**: Bootloader code and parameters (`kboot`).
     - **PCR 4**: Microkernel executable measurement (SHA-256 hash of kernel ELF code segments).
     - **PCR 7**: Secure Boot state and platform signing authorities.
     - **PCR 9**: Initial ramdisk and system manifest measurement (`/manifest.toml`).
3. **Anti-Evil Maid Key Sealing & Fail-Closed Protection**:
   - `TPM2_Seal`: Binds sensitive cryptographic master keys (e.g. `kvault` root disk key) to a composite PCR policy digest (e.g. PCR 0, 4, 7).
   - `TPM2_Unseal`: Re-evaluates live PCR state against the sealed policy.
   - If even a single byte of the kernel, bootloader, or configuration is altered (evil-maid attack), the live PCR digest mismatches the policy and unsealing fails closed (`TpmError::PolicyMismatch`), preventing the attacker from decrypting user data.

---

## 2. TPM 2.0 Command & Response Interface

### 2.1 Hardware Discovery & Registers
- Physical address: `0xFED4_0000` (Locality 0).
- Registers:
  - `TPM_ACCESS` (`0x0000`): Request use (`0x02`), active locality check (`0x20`).
  - `TPM_STS` (`0x0018`): `commandReady` (`0x40`), `tpmGo` (`0x20`), `dataAvail` (`0x10`), `burstCount` (bits 8..23).
  - `TPM_DATA_FIFO` (`0x0024`): Byte stream communication.
  - `TPM_DID_VID` (`0x0F00`): Hardware device identification.

### 2.2 Command Structures
- **TPM2_Startup**: Tag `0x8001`, Code `0x00000144`, Startup Type `TPM_SU_CLEAR` (`0x0000`).
- **TPM2_PCR_Extend**: Tag `0x8002`, Code `0x00000182`, Algorithm `TPM_ALG_SHA256` (`0x000B`).
  $$\text{PCR}_{new} = \text{SHA256}(\text{PCR}_{old} \mathbin{\Vert} \text{measurement})$$
- **TPM2_PCR_Read**: Tag `0x8001`, Code `0x0000017E`, selects PCR indices and reads 32-byte digests.
- **TPM2_Seal**: Encapsulates sensitive payload under authorization policy digest $H(\text{PCR}_i)$.
- **TPM2_Unseal**: Releases secret only when current hardware PCR state satisfies $H(\text{PCR}_i)$.

---

## 3. Acceptance Gates

| Gate | Description | Pass Criteria |
| :--- | :--- | :--- |
| **T21** | Cryptographic Boot Signature & Manifest Validation | Valid signature accepted; 1-byte tamper in signed payload rejected. |
| **T22** | TPM 2.0 PCR Measurement & Clean-Boot Reproducibility | PCR 0, 1, 2, 4, 7, 9 extended; PCR state 100% reproducible across boots. |
| **T23** | Anti-Evil Maid Key Sealing & Fail-Closed Gate | Sealed key unseals under valid PCRs; tampered kernel image blocks unsealing. |
