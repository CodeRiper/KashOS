//! knet — Kash Kernel Network Layer
//!
//! Defines the type system for the five-layer network stack:
//!
//!   App VM → Packet Inspection Proxy → Anonymity Gateway → Driver Domain → NIC
//!
//! The rules:
//!  * An App VM holds ONLY an IPC endpoint to the Proxy. No NIC capability.
//!  * The Proxy classifies, labels, DPI-inspects, and enforces the kill-switch.
//!  * The Anonymity Gateway is the ONLY holder of the NIC endpoint capability.
//!  * The Telemetry Domain receives a zero-copy read mirror; it never transmits.
//!
//! Nothing here is `unsafe`. The actual NIC I/O lives in the driver crate.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::{string::String, vec::Vec};

// ── Layer-2 identity ─────────────────────────────────────────────────────────

/// 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const ZERO: MacAddr = MacAddr([0; 6]);
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);

    pub fn is_multicast(&self) -> bool { self.0[0] & 1 != 0 }
    pub fn is_unicast(&self) -> bool { !self.is_multicast() }

    /// Construct a locally-administered unicast MAC (bit 1 set, bit 0 clear).
    /// Used for MAC rotation — the address looks valid but is not a burned-in OUI.
    pub fn locally_administered(seed: u64) -> MacAddr {
        let b = seed.to_le_bytes();
        MacAddr([b[0] & 0xFE | 0x02, b[1], b[2], b[3], b[4], b[5]])
    }
}

// ── Packet metadata ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Other(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProto {
    TCP,
    UDP,
    ICMP,
    ICMPv6,
    Other(u8),
}

/// Parsed headers for a single network frame (zero-copy view).
#[derive(Clone, Debug)]
pub struct FrameMeta {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: EtherType,
    pub src_ip: Option<[u8; 16]>,  // IPv4 in first 4 bytes
    pub dst_ip: Option<[u8; 16]>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub proto: Option<IpProto>,
    pub ttl: Option<u8>,
    pub tcp_window: Option<u16>,
    pub sni: Option<String>,       // TLS SNI extracted from ClientHello
    pub payload_len: usize,
}

// ── Packet filter ─────────────────────────────────────────────────────────────

/// Verdict for each frame passing through the Proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Pass the frame to the Anonymity Gateway.
    Allow,
    /// Drop silently.
    Drop,
    /// Drop and generate a TelemetryEvent.
    DropAlert,
    /// Normalise fingerprinting-sensitive fields before forwarding.
    NormalizeThenAllow,
}

/// A single entry in the Proxy's policy table.
#[derive(Clone, Debug)]
pub enum FilterRule {
    BlockDomain(String),
    BlockIp([u8; 16], u8),         // IP + prefix length
    BlockPort(u16),
    AllowOnlyPorts(Vec<u16>),
    NormalizeFingerprint,          // strip TCP timestamps, normalize TTL/window
    BlockAllIfGatewayDown,         // kill-switch: drop everything if gateway IPC is broken
}

/// Applied sequentially; first matching rule wins.
pub struct FilterTable {
    rules: Vec<FilterRule>,
    default: Verdict,
}

impl FilterTable {
    pub fn new() -> Self {
        FilterTable { rules: Vec::new(), default: Verdict::NormalizeThenAllow }
    }

    pub fn add_rule(&mut self, r: FilterRule) {
        self.rules.push(r);
    }

    pub fn evaluate(&self, meta: &FrameMeta, gateway_alive: bool) -> Verdict {
        if !gateway_alive {
            return Verdict::Drop;   // kill-switch: no path if gateway is down
        }
        for rule in &self.rules {
            match rule {
                FilterRule::BlockPort(p) => {
                    if meta.src_port == Some(*p) || meta.dst_port == Some(*p) {
                        return Verdict::DropAlert;
                    }
                }
                FilterRule::BlockDomain(d) => {
                    if meta.sni.as_deref() == Some(d.as_str()) {
                        return Verdict::DropAlert;
                    }
                }
                FilterRule::BlockAllIfGatewayDown => {
                    if !gateway_alive { return Verdict::Drop; }
                }
                FilterRule::NormalizeFingerprint => {
                    return Verdict::NormalizeThenAllow;
                }
                FilterRule::AllowOnlyPorts(ports) => {
                    if let Some(dport) = meta.dst_port {
                        if !ports.contains(&dport) { return Verdict::Drop; }
                    }
                }
                _ => {}
            }
        }
        self.default
    }
}

impl Default for FilterTable {
    fn default() -> Self { Self::new() }
}

// ── Fingerprint normalization ─────────────────────────────────────────────────

/// TCP/IP fingerprint normalization — applied before a frame exits the proxy.
/// Prevents passive OS fingerprinting by p0f, nmap OS detection, etc.
#[derive(Clone, Copy, Debug)]
pub struct FingerprintNorm {
    /// Normalized TTL (64 is common for Linux; 128 for Windows; 255 for routers).
    pub ttl: u8,
    /// Normalized TCP initial window size.
    pub tcp_window: u16,
    /// Strip TCP timestamp option (RFC 1323) to prevent hardware clock tracking.
    pub strip_tcp_timestamps: bool,
    /// Clear IP Don't Fragment bit (avoids MTU fingerprinting).
    pub clear_df_bit: bool,
}

impl FingerprintNorm {
    /// Generic profile that makes the traffic look like a common Linux host.
    pub const GENERIC_LINUX: FingerprintNorm = FingerprintNorm {
        ttl: 64,
        tcp_window: 65535,
        strip_tcp_timestamps: true,
        clear_df_bit: false,
    };
}

// ── MAC rotation ──────────────────────────────────────────────────────────────

/// Configuration for the network identity layer.
pub struct NetworkIdentity {
    pub current_mac: MacAddr,
    pub norm: FingerprintNorm,
    pub rotate_on_reconnect: bool,
}

impl NetworkIdentity {
    pub fn new(seed: u64) -> Self {
        NetworkIdentity {
            current_mac: MacAddr::locally_administered(seed),
            norm: FingerprintNorm::GENERIC_LINUX,
            rotate_on_reconnect: true,
        }
    }

    pub fn rotate_mac(&mut self, new_seed: u64) {
        self.current_mac = MacAddr::locally_administered(new_seed);
    }
}

// ── Telemetry domain ──────────────────────────────────────────────────────────

/// An event emitted by the passive telemetry domain (zero TX — never sends packets).
#[derive(Clone, Debug)]
pub enum TelemetryEvent {
    /// New device appeared on the LAN.
    NewDevice { mac: MacAddr, ip: Option<[u8; 4]>, hostname: Option<String> },
    /// ARP reply from a MAC that doesn't match prior records → possible spoofing.
    ArpAnomaly { mac: MacAddr, claimed_ip: [u8; 4], known_ip: [u8; 4] },
    /// Unexpected DHCP server (not the known gateway).
    RogueDhcp { mac: MacAddr, offered_ip: [u8; 4] },
    /// Passive TLS fingerprint for SNI domain.
    TlsHandshake { src_ip: [u8; 4], sni: String, ja3: String },
    /// Blocked frame (matched filter rule).
    Blocked { src_ip: Option<[u8; 4]>, dst_ip: Option<[u8; 4]>, dst_port: Option<u16>, reason: String },
    /// Outbound DNS query.
    DnsQuery { src_ip: [u8; 4], domain: String },
    /// Passive OS fingerprint (TTL + window analysis).
    OsFingerprint { ip: [u8; 4], guess: String, confidence: u8 },
    /// Per-device traffic counter update.
    TrafficUpdate { mac: MacAddr, bytes_in: u64, bytes_out: u64 },
}

// ── Anonymity gateway ──────────────────────────────────────────────────────────

/// Which anonymization path to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonProfile {
    /// Tor with stream isolation per application.
    TorStreamIsolated,
    /// WireGuard tunnel to a trusted exit node.
    WireGuard,
    /// I2P garlic routing.
    I2P,
    /// Tor over I2P (double-hop).
    TorOverI2P,
}

/// Status of the anonymity gateway — checked by the Proxy's kill-switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayStatus {
    Up,
    Connecting,
    /// Gateway is down: kill-switch fires, all client traffic dropped.
    Down,
    /// Gateway is compromised (proof-of-work DoS, circuit failure rate too high).
    Degraded,
}

pub struct AnonymityGateway {
    pub profile: AnonProfile,
    pub status: GatewayStatus,
    pub circuit_count: usize,
    pub bytes_forwarded: u64,
    pub identity: NetworkIdentity,
}

impl AnonymityGateway {
    pub fn new(profile: AnonProfile, seed: u64) -> Self {
        AnonymityGateway {
            profile,
            status: GatewayStatus::Connecting,
            circuit_count: 0,
            bytes_forwarded: 0,
            identity: NetworkIdentity::new(seed),
        }
    }

    pub fn is_up(&self) -> bool {
        matches!(self.status, GatewayStatus::Up)
    }
}

// ── IPC endpoint types ────────────────────────────────────────────────────────

/// The only object an App VM gets when it wants network access.
/// It cannot see or use the NIC endpoint capability — only this endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEndpointId(pub u64);

/// Direction of a network IPC call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetMsg {
    Send { endpoint: NetworkEndpointId, len: u32 },
    Recv { endpoint: NetworkEndpointId },
    Disconnect { endpoint: NetworkEndpointId },
}

// ── smoltcp & Lock-Free Ring Interface ──────────────────────────────────────

pub const MAX_PACKET_SIZE: usize = 1514;
pub const RING_CAPACITY: usize   = 8;

#[derive(Clone, Copy)]
pub struct RawFrame {
    pub data: [u8; MAX_PACKET_SIZE],
    pub len: usize,
}

impl RawFrame {
    pub const fn empty() -> Self {
        Self {
            data: [0; MAX_PACKET_SIZE],
            len: 0,
        }
    }
}

/// Circular lock-free SPSC packet ring for hardware NIC to smoltcp handoff.
pub struct PacketRing {
    buffer: [RawFrame; RING_CAPACITY],
    head: usize,
    tail: usize,
}

impl PacketRing {
    pub const fn new() -> Self {
        Self {
            buffer: [RawFrame::empty(); RING_CAPACITY],
            head: 0,
            tail: 0,
        }
    }

    pub fn push(&mut self, frame: &[u8]) -> Result<(), ()> {
        let next_head = (self.head + 1) % RING_CAPACITY;
        if next_head == self.tail {
            return Err(()); // Ring full
        }
        let copy_len = frame.len().min(MAX_PACKET_SIZE);
        self.buffer[self.head].data[..copy_len].copy_from_slice(&frame[..copy_len]);
        self.buffer[self.head].len = copy_len;
        self.head = next_head;
        Ok(())
    }

    pub fn pop(&mut self, out_buf: &mut [u8]) -> Option<usize> {
        if self.head == self.tail {
            return None; // Ring empty
        }
        let frame = &self.buffer[self.tail];
        let copy_len = frame.len.min(out_buf.len());
        out_buf[..copy_len].copy_from_slice(&frame.data[..copy_len]);
        self.tail = (self.tail + 1) % RING_CAPACITY;
        Some(copy_len)
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}

// ── TCP/IP Socket Table Model ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

#[derive(Clone, Debug)]
pub struct SocketHandle {
    pub id: u32,
    pub proto: IpProto,
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: Option<[u8; 4]>,
    pub remote_port: Option<u16>,
    pub state: TcpState,
}

pub struct TcpIpStack {
    pub mac: MacAddr,
    pub ip: [u8; 4],
    pub gateway: [u8; 4],
    pub netmask: [u8; 4],
    pub rx_ring: PacketRing,
    pub tx_ring: PacketRing,
    pub sockets: Vec<SocketHandle>,
    next_socket_id: u32,
}

impl TcpIpStack {
    pub fn new(mac: MacAddr, ip: [u8; 4], gateway: [u8; 4], netmask: [u8; 4]) -> Self {
        Self {
            mac,
            ip,
            gateway,
            netmask,
            rx_ring: PacketRing::new(),
            tx_ring: PacketRing::new(),
            sockets: Vec::new(),
            next_socket_id: 1,
        }
    }

    pub fn create_socket(&mut self, proto: IpProto, local_port: u16) -> u32 {
        let id = self.next_socket_id;
        self.next_socket_id += 1;
        self.sockets.push(SocketHandle {
            id,
            proto,
            local_ip: self.ip,
            local_port,
            remote_ip: None,
            remote_port: None,
            state: if proto == IpProto::TCP { TcpState::Listen } else { TcpState::Established },
        });
        id
    }

    pub fn connect(&mut self, socket_id: u32, remote_ip: [u8; 4], remote_port: u16) -> Result<(), ()> {
        if let Some(sock) = self.sockets.iter_mut().find(|s| s.id == socket_id) {
            sock.remote_ip = Some(remote_ip);
            sock.remote_port = Some(remote_port);
            sock.state = TcpState::Established;
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn close(&mut self, socket_id: u32) {
        if let Some(pos) = self.sockets.iter().position(|s| s.id == socket_id) {
            self.sockets.remove(pos);
        }
    }
}

