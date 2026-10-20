#!/usr/bin/env python3
"""Regression guard: unfinished remote networking must never fabricate success."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
NET = (ROOT / "kernel/src/net.rs").read_text(encoding="utf-8")
BROWSER = (ROOT / "kernel/src/browser.rs").read_text(encoding="utf-8")
SETTINGS = (ROOT / "kash-ui/crates/kash-ui/src/apps/settings.rs").read_text(encoding="utf-8")


def method_body(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def main() -> int:
    checks = []
    http_get = method_body(NET, "pub fn http_get(", "pub fn get_socket_table(")
    checks.append(("HTTP GET returns NotAvailable", "Err(NetError::NotAvailable)" in http_get))
    for forbidden in (
        "tcp_send(",
        "build_tls13_client_hello(",
        "wrap_tls_application_data(",
        "unwrap_or(",
        "Connected securely",
    ):
        checks.append((f"HTTP GET excludes {forbidden}", forbidden not in http_get))

    init = method_body(NET, "pub fn init()", "pub fn rotate_mac()")
    checks.append(("Network init does not mark gateway Up", "GatewayStatus::Up" not in init))
    checks.append(("Network initialization uses the disabled profile", "AnonProfile::Disabled" in NET))
    checks.append(("Runtime cannot force the gateway Up", "pub fn set_gateway_status" not in NET))
    checks.append(("Socket table has no fabricated Tor listener", "Tor Anonymity Daemon" not in NET))
    checks.append(("Socket table has no fabricated DNS listener", "Encrypted DNS Proxy" not in NET))
    for claim in (
        "100% Trackers Blocked",
        "Zero Google/Telemetry",
        "Zero Canvas Fingerprinting",
        "TLS 1.3 HTTPS Client",
        "seL4 Guarded",
    ):
        checks.append((f"Browser excludes unimplemented claim: {claim}", claim not in BROWSER))

    for claim in (
        "Native Ethernet (e1000/virtio-net)",
        "Active (Fail-closed drop on disconnect)",
        "Active (knet RingDevice)",
        "Hardware NICs are bound via smoltcp ring buffers",
        "Tor anonymity routing is handled via user-space daemon",
    ):
        checks.append((f"Network settings excludes unverified claim: {claim}", claim not in SETTINGS))
    for status in (
        "Unavailable (no active NIC service)",
        "Unavailable (no verified protocol path)",
        "Policy helper only (not NIC-integrated)",
    ):
        checks.append((f"Network settings reports: {status}", status in SETTINGS))

    failed = [name for name, passed in checks if not passed]
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'}: {name}")
    if failed:
        print(f"{len(failed)} network honesty regression(s) detected.", file=sys.stderr)
        return 1
    print(f"All {len(checks)} network honesty regression checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
