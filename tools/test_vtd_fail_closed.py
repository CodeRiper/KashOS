#!/usr/bin/env python3
"""Guard the hardware VT-d path until real DMA tables and ACS exist."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
VTD = (ROOT / "kernel/src/arch/x86_64/vtd.rs").read_text(encoding="utf-8")
SHELL = (ROOT / "kernel/src/shell.rs").read_text(encoding="utf-8")
CPUID = (ROOT / "kernel/src/arch/x86_64/cpuid.rs").read_text(encoding="utf-8")


def body(source: str, start: str, end: str) -> str:
    first = source.index(start)
    return source[first:source.index(end, first)]


def main() -> int:
    init_start = VTD.rindex("pub fn init()")
    probe = VTD[init_start:VTD.index("pub fn get_iommu_status()", init_start)]
    hardware_init = body(VTD, "pub fn init_hardware(", "    /// Bind a device in the in-memory policy model")
    enable = body(VTD, "impl IommuController for IntelVtdUnit", "// ── Global IOMMU State")
    acs = body(VTD, "pub fn probe_acs(", "    }")
    checks = [
        ("VT-d hardware initialization fails closed", "self.is_enabled = false" in hardware_init and "Err(\"VT-d activation is disabled" in hardware_init),
        ("VT-d hardware initialization performs no MMIO writes", "write_volatile" not in hardware_init and "VTD_GCMD" not in hardware_init),
        ("DMA mapping rejects inactive VT-d", "if !self.is_enabled" in body(VTD, "pub fn map_device_dma(", "    /// Unmap peripheral")),
        ("IOMMU controller enable does not fabricate success", "fn enable_dma_remapping(&self) -> Result<(), ()> {\n        Err(())" in enable),
        ("ACS reports unavailable instead of hardened presets", "PcieAcsFlags::hardened" not in acs and "false" in acs),
        ("PCI probe does not activate VT-d", "scan_pci()" not in probe and "init_hardware()" not in probe),
        ("Runtime DMAR probe is disabled until bounded ACPI mapping exists", "find_acpi_dmar" not in VTD and "DMAR probing and translation are disabled" in probe),
        ("Registry reports the VT-d implementation as a stub", "ComponentStatus::Stub" in probe and "ComponentStatus::Real" not in probe),
        ("Selftest cannot promote the VT-d status", "s.vtd_iommu = crate::status::ComponentStatus::Stub" in (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")),
        ("Selftest labels translation checks as a software model", "in-memory policy model test only" in (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")),
        ("Shell avoids claiming DMA containment", "Unavailable (VT-d not active)" in SHELL and "Probe unavailable (not checked)" in SHELL and "Rogue bus-mastering blocked by SLPT" not in SHELL),
        ("Hardware tier requires active VT-d units", "iommu_units > 0" in CPUID),
    ]
    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    if failed:
        print(f"{len(failed)} VT-d fail-closed regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} VT-d fail-closed checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
