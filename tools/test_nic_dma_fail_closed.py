#!/usr/bin/env python3
"""Guard NIC activation until DMA buffers and IOMMU isolation are real."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
NIC = (ROOT / "kernel/src/arch/x86_64/nic.rs").read_text(encoding="utf-8")


def body(start: str, end: str) -> str:
    first = NIC.index(start)
    return NIC[first:NIC.index(end, first)]


def main() -> int:
    probe_start = NIC.rindex("pub fn init()")
    probe = NIC[probe_start:NIC.index("pub fn transmit(", probe_start)]
    checks = [
        ("PCI bus mastering is not enabled by NIC code", "enable_bus_mastering()" not in NIC),
        ("e1000 initialization returns unavailable", 'Err("e1000 DMA is disabled' in body("impl E1000Device {", "    /// Transmits")),
        ("VirtIO initialization returns unavailable", 'Err("VirtIO-Net DMA is disabled' in body("impl VirtioNetDevice {", "    pub fn transmit_frame")),
        ("RTL8139 initialization returns unavailable", 'Err("RTL8139 DMA is disabled' in body("impl Rtl8139Device {", "    pub fn transmit_frame")),
        ("e1000 TX rejects inactive device", "if !self.is_up || frame.len() > TX_BUFFER_SIZE" in body("    pub fn transmit_frame", "    /// Polls for an incoming")),
        ("e1000 RX rejects inactive device", "if !self.is_up" in body("    pub fn receive_frame", "    pub fn is_link_up")),
        ("VirtIO TX rejects inactive device", "if !self.is_up" in body("    pub fn transmit_frame", "    pub fn receive_frame")),
        ("VirtIO RX rejects inactive device", "if !self.is_up" in body("    pub fn receive_frame", "    pub fn is_link_up")),
        ("RTL8139 TX rejects inactive device", "if !self.is_up || frame.len() > TX_BUFFER_SIZE" in body("    pub fn transmit_frame", "    pub fn receive_frame")),
        ("RTL8139 RX rejects inactive device", "if !self.is_up" in body("    pub fn receive_frame", "    pub fn is_link_up")),
        ("NIC probe does not touch PCI hardware", "scan_pci()" not in probe),
        ("NIC status cannot claim a real driver", "ComponentStatus::Real" not in probe),
        ("NIC status records disabled driver stubs", "ComponentStatus::Stub" in probe),
    ]
    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    if failed:
        print(f"{len(failed)} NIC DMA fail-closed regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} NIC DMA fail-closed checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
