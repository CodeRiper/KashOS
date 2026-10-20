#!/usr/bin/env python3
"""Keep public readiness and threat-model docs aligned with current limits."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8").lower()
THREAT = (ROOT / "docs/THREAT_MODEL.md").read_text(encoding="utf-8").lower()
CLAIMS = (ROOT / "docs/CLAIMS.md").read_text(encoding="utf-8").lower()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")
    print(f"PASS: {message}")


require("not ready for daily or security-sensitive use" in README,
        "README clearly says the OS is not ready for sensitive use")
require("development and qemu testing only" in README,
        "README restricts current use to development and QEMU testing")
require("external network access is unavailable" in README,
        "README states external networking is unavailable")
require("only the bootstrap processor is active" in README,
        "README states that only the BSP is active")
require("hardware tpm" in README and "unavailable" in README,
        "README does not imply production TPM support")
require("vt-d" in README and "dma containment is unavailable" in README,
        "README does not imply hardware DMA isolation")

for phrase in (
    "user-mode network service",
    "fail-closed network kill switch halting egress upon tor",
    "smp bring-up from acpi madt",
    "tpm 2.0 driver extending pcrs",
    "hardware cSPRNG mac address randomization".lower(),
):
    require(phrase not in README, f"README removes unsupported claim: {phrase}")

require("network stack isolated in its own user-mode service" not in THREAT,
        "threat model does not assume a nonexistent isolated network service")
require("current implementation status" in CLAIMS,
        "claims registry marks its current implementation scope")
require("software-model test results do not establish hardware isolation" in CLAIMS,
        "claims registry distinguishes software tests from hardware guarantees")
require(not re.search(r"\*\*status today.*\*\*tested\*\*", CLAIMS),
        "claims matrix no longer marks every listed model as implemented")

print("All public readiness honesty checks passed.")
