#!/usr/bin/env python3
"""Regression guard: unfinished remote networking must never fabricate success."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
NET = (ROOT / "kernel/src/net.rs").read_text(encoding="utf-8")
BROWSER = (ROOT / "kernel/src/browser.rs").read_text(encoding="utf-8")
SETTINGS = (ROOT / "kash-ui/crates/kash-ui/src/apps/settings.rs").read_text(encoding="utf-8")
SELFTEST = (ROOT / "kernel/src/selftest.rs").read_text(encoding="utf-8")


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
    send_packet = method_body(NET, "pub fn send_packet(", "pub fn create_socket(")
    receive = method_body(NET, "pub fn receive(", "pub fn socket(")
    tcp_connect = method_body(NET, "pub fn tcp_connect(", "pub fn tcp_send(")
    tcp_send = method_body(NET, "pub fn tcp_send(", "pub fn tcp_recv(")
    tcp_recv = method_body(NET, "pub fn tcp_recv(", "pub fn resolve(")
    dhcp = method_body(NET, "pub fn dhcp_status()", "pub fn tcp_connect(")
    poll = NET[NET.index("pub fn poll("):]
    checks.append(("Network init does not mark gateway Up", "GatewayStatus::Up" not in init))
    checks.append(("No gateway profile can be enabled by the kernel service", "GatewayStatus" not in NET and "AnonymityGateway" not in NET))
    checks.append(("Runtime cannot force the gateway Up", "pub fn set_gateway_status" not in NET))
    checks.append(("Network service state is not externally mutable", "pub static NET_SERVICE" not in NET and "pub struct NetworkService" not in NET))
    checks.append(("No smoltcp device is instantiated as a live kernel service", "SmolNetStack::new" not in NET))
    checks.append(("Egress always returns the kill-switch result", "Err(NetError::KillSwitchBlocked)" in send_packet and "nic_transmit" not in send_packet))
    checks.append(("Ingress does not bypass policy through the NIC", "Err(NetError::NotAvailable)" in receive and "nic_receive" not in receive))
    checks.append(("Remote TCP connect remains unavailable", "Err(NetError::NotAvailable)" in tcp_connect))
    checks.append(("TCP send remains unavailable", "Err(NetError::NotAvailable)" in tcp_send))
    checks.append(("TCP receive remains unavailable", "Err(NetError::NotAvailable)" in tcp_recv))
    checks.append(("DHCP reports no lease without an adapter", "None" in dhcp))
    checks.append(("Network poll does not run a disconnected stack", "service.smol.poll" not in poll))
    checks.append(("Socket table marks its rows as model state", "Socket-state model only; no live transport" in NET and "MODEL_SYN_SENT" in NET))
    checks.append(("T31 self-test expects the explicit model-only socket label", 'entry.state == "MODEL_SYN_SENT"' in SELFTEST and 'entry.state == "SYN_SENT"' not in SELFTEST))
    checks.append(("T31 self-test reports no live network transport", "no live transport or packets are claimed" in SELFTEST))
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
