#!/usr/bin/env python3
"""Ensure unvalidated production TPM APIs remain explicitly unavailable."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TPM = (ROOT / "kernel/src/arch/x86_64/tpm.rs").read_text(encoding="utf-8")
ARCH = (ROOT / "kernel/src/arch/x86_64/mod.rs").read_text(encoding="utf-8")
KASH = (ROOT / "kernel/src/kash.rs").read_text(encoding="utf-8")
UI_LOCK = (ROOT / "kash-ui/crates/kash-ui/src/shell/lock.rs").read_text(encoding="utf-8")
UI_FILES = (ROOT / "kash-ui/crates/kash-ui/src/apps/files.rs").read_text(encoding="utf-8")


def body(source: str, signature: str, next_signature: str) -> str:
    start = source.index(signature)
    end = source.index(next_signature, start)
    return source[start:end]


probe = body(TPM, "pub fn probe(&mut self)", "/// Issues TPM2_Startup.")
checks = [
    ("TPM probe selects no hardware interface", "self.interface = TpmInterface::None" in probe),
    ("TPM probe leaves hardware absent", "self.hardware_present = false" in probe),
    ("TPM probe does not access guessed MMIO", "read_volatile" not in probe and "write_volatile" not in probe),
    ("TIS executor has no raw MMIO side effects", "pub fn tis_execute_command(&self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, TpmError> {\n        let _ = (self, cmd, resp);\n        Err(TpmError::NotPresent)" in TPM),
    ("TPM module contains no volatile MMIO transport operations", "read_volatile" not in TPM and "write_volatile" not in TPM),
    ("CRB command path cannot return synthetic success", "TpmInterface::Crb => Err(TpmError::NotPresent)" in TPM),
    ("Production TPM status is unavailable", '"NOT AVAILABLE (TPM transport disabled' in TPM),
    ("Global PCR extend fails closed", "pub fn pcr_extend(pcr_idx: usize, digest: &[u8; 32]) -> Result<[u8; 32], TpmError> {\n    let _ = (pcr_idx, digest);\n    Err(TpmError::NotPresent)" in TPM),
    ("Global key sealing fails closed", "pub fn seal_key(pcr_mask: u32, secret: &[u8]) -> Result<u32, TpmError> {\n    let _ = (pcr_mask, secret);\n    Err(TpmError::NotPresent)" in TPM),
    ("Global measured-stage API fails closed", "pub fn measure_stage(pcr_idx: usize, data: &[u8]) -> Result<[u8; 32], TpmError> {\n    let _ = (pcr_idx, data);\n    Err(TpmError::NotPresent)" in TPM),
    ("TPM NV anti-rollback does not update RAM state as hardware", "pub fn verify_and_ratify_epoch(candidate: u64) -> Result<(), kboot::RollbackError> {\n    let _ = candidate;\n    Err(kboot::RollbackError::NvStorageError)" in TPM),
    ("PCR console no longer prints model as live PCRs", "PCR report unavailable: hardware transport is disabled" in TPM),
    ("UEFI metadata is not reported as TPM attestation", "TPM-backed measured-boot attestation is unavailable" in ARCH),
    ("Vault status does not claim TPM key sealing", "Master Vault Key sealed to TPM" not in KASH),
    ("GUI POST reports measured boot unavailable", '(1.55, "Measured boot (TPM 2.0)", "unavailable")' in UI_LOCK),
    ("GUI does not list a nonexistent TPM driver", '"tpm2.drv"' not in UI_FILES),
]

for label, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}: {label}")
failures = [label for label, ok in checks if not ok]
if failures:
    print(f"{len(failures)} TPM honesty regression(s) detected.", file=sys.stderr)
    raise SystemExit(1)
print(f"All {len(checks)} TPM fail-closed checks passed.")
