# KashOS Phase 7: Network & Privacy Design Document

**Status**: Implementation Design  
**Author**: Akash <akash.official.j@gmail.com>  
**Date**: October 17, 2026  
**Target Milestone**: Phase 7 (Network & Privacy)

---

## 1. Architectural Objectives

Grounded in the KashOS Threat Model (`docs/THREAT_MODEL.md`) and the 10 Non-Negotiable Rules (`docs/KASHOS_BUILD_GUIDE.md`):

1. **User-Mode Network Service**:
   - Encapsulate all network protocol processing within an isolated network domain (`sys-net`, Domain 1).
   - App VMs hold **only** IPC endpoints (`NetworkEndpointId`) to the network proxy; they possess zero direct access to the physical NIC MMIO or DMA rings.
2. **Default-Deny Packet Filter & Firewall**:
   - Enforce strict default-deny firewall policy for all ingress and egress packets.
   - Drop unsolicited inbound connection attempts, drop banned egress ports (e.g., plaintext Telnet 23), and normalize TCP/IP packet fingerprints (TTL=64, window=65535, strip TCP timestamps) to eliminate OS passive fingerprinting.
3. **Fail-Closed Network Kill Switch**:
   - When the anonymity gateway (Tor/WireGuard) status transitions to `GatewayStatus::Down`, the kill switch engages instantly: `Verdict::Drop` is returned for 100% of packets, ensuring zero plaintext packets escape.
4. **Hardware-Entropy Seeded MAC Randomization**:
   - Rotate layer-2 MAC address on boot and network reconnection using bare-metal CSPRNG (`knet::MacAddr::locally_administered`), ensuring hardware burned-in manufacturer OUIs are never leaked over local Wi-Fi or Ethernet switches.
5. **Reliable Socket Transport & Loopback**:
   - Maintain a deterministic TCP/IP socket state machine (`TcpIpStack`) supporting TCP/UDP connections, loopback IPC packet exchange, and ARP/ICMP packet dispatching.

---

## 2. Component Design

### 2.1 Layer-2 Network Architecture (`knet` + `kernel/src/net.rs`)

```
+---------------------------------------------------------+
|                  Client Application / Shell             |
|                 (NetworkEndpointId Handle)              |
+---------------------------------------------------------+
                             |  kipc Rendezvous (Badged)
                             v
+---------------------------------------------------------+
|               Packet Inspection Proxy & Filter          |
|  - Default-Deny Policy (`FilterTable`)                  |
|  - TCP Fingerprint Normalizer (`FingerprintNorm`)       |
|  - Fail-Closed Kill Switch (`BlockAllIfGatewayDown`)    |
+---------------------------------------------------------+
                             |  Verdict == Allow
                             v
+---------------------------------------------------------+
|                  Anonymity Gateway (sys-net)            |
|  - Tor Stream Isolation / WireGuard Tunnel Gateway      |
|  - Dynamic MAC Rotation (`NetworkIdentity`)             |
+---------------------------------------------------------+
                             |  SPSC Lock-Free Ring
                             v
+---------------------------------------------------------+
|            Physical NIC Driver (Intel e1000 / VirtIO)   |
|  - TX/RX DMA Descriptors, Hardware Checksum             |
+---------------------------------------------------------+
```

### 2.2 Acceptance Gates for Phase 7

- **T28: Default-Deny Firewall & PacketFilter Gate**:
  - Ingress and egress evaluation against `FilterTable`.
  - Blocks unauthorized ports (Port 23) and malicious SNI domains with `Verdict::DropAlert`.
  - Normalizes fingerprint fields: TTL set to 64, TCP timestamp option stripped.
- **T29: Fail-Closed Network Kill Switch Gate**:
  - Simulates sudden failure of anonymity gateway (`GatewayStatus::Down`).
  - Evaluates egress packets through proxy; 100% of packets are dropped (`Verdict::Drop`).
  - Verifies zero bytes escape to physical interface when the kill switch triggers.
- **T30: Hardware-Entropy Seeded MAC Randomization Gate**:
  - Derives locally administered MAC addresses from bare-metal CSPRNG.
  - Verifies IEEE 802.3 bit 1 is set (locally administered) and bit 0 is clear (unicast).
  - Confirms no burned-in physical OUI is exposed on network reconnection.
- **T31: smoltcp Network Service & Loopback Socket Transport Gate**:
  - Establishes a TCP socket connection over `TcpIpStack`.
  - Transmits payload across loopback queue with checksum validation.
  - Verifies socket transition from `Listen` -> `SynSent` -> `Established`.
