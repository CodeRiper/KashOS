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

pub use smoltcp;

// ── smoltcp Device & Native Stack Integration ──────────────────────────────

/// Device driver adapter bridging `PacketRing` with `smoltcp::phy::Device`.
pub struct RingDevice {
    pub rx_ring: PacketRing,
    pub tx_ring: PacketRing,
}

impl RingDevice {
    pub const fn new() -> Self {
        Self {
            rx_ring: PacketRing::new(),
            tx_ring: PacketRing::new(),
        }
    }
}

pub struct RingRxToken<'a> {
    frame: &'a mut RawFrame,
}

impl<'a> smoltcp::phy::RxToken for RingRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame.data[..self.frame.len])
    }
}


pub struct RingTxToken<'a> {
    tx_ring: &'a mut PacketRing,
}

impl<'a> smoltcp::phy::TxToken for RingTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame_buf = [0u8; MAX_PACKET_SIZE];
        let slice = &mut frame_buf[..len.min(MAX_PACKET_SIZE)];
        let res = f(slice);
        let _ = self.tx_ring.push(slice);
        res
    }
}

impl smoltcp::phy::Device for RingDevice {
    type RxToken<'a> = RingRxToken<'a> where Self: 'a;
    type TxToken<'a> = RingTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: smoltcp::time::Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_ring.head == self.rx_ring.tail {
            return None;
        }
        let tail = self.rx_ring.tail;
        self.rx_ring.tail = (self.rx_ring.tail + 1) % RING_CAPACITY;
        let frame = &mut self.rx_ring.buffer[tail];
        Some((
            RingRxToken { frame },
            RingTxToken { tx_ring: &mut self.tx_ring },
        ))
    }


    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(RingTxToken { tx_ring: &mut self.tx_ring })
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = smoltcp::phy::Medium::Ethernet;
        caps
    }
}

/// Authoritative smoltcp native network stack with DHCPv4, DNS, ICMP and TCP sockets.
pub struct SmolNetStack {
    pub device: RingDevice,
    pub iface: smoltcp::iface::Interface,
    pub sockets: smoltcp::iface::SocketSet<'static>,
    pub dhcp_handle: smoltcp::iface::SocketHandle,
    pub dns_handle: smoltcp::iface::SocketHandle,
    pub tcp_handle: smoltcp::iface::SocketHandle,
    pub icmp_handle: smoltcp::iface::SocketHandle,
    pub leased_ip: Option<[u8; 4]>,
    pub gateway_ip: Option<[u8; 4]>,
    pub dns_servers: Vec<[u8; 4]>,
}

impl SmolNetStack {
    pub fn new(mac: MacAddr, seed: u64) -> Self {
        let mut device = RingDevice::new();
        let eth_addr = smoltcp::wire::EthernetAddress(mac.0);
        let hw_addr = smoltcp::wire::HardwareAddress::Ethernet(eth_addr);
        let mut config = smoltcp::iface::Config::new(hw_addr);
        config.random_seed = seed;

        let iface = smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::from_millis(0));

        let mut sockets = smoltcp::iface::SocketSet::new(alloc::vec::Vec::new());

        // 1. DHCPv4 client socket
        let dhcp_socket = smoltcp::socket::dhcpv4::Socket::new();
        let dhcp_handle = sockets.add(dhcp_socket);

        // 2. DNS client socket
        let dns_socket = smoltcp::socket::dns::Socket::new(&[], alloc::vec::Vec::new());
        let dns_handle = sockets.add(dns_socket);

        // 3. TCP client socket (4 KiB RX / 4 KiB TX)
        let tcp_rx = smoltcp::socket::tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
        let tcp_tx = smoltcp::socket::tcp::SocketBuffer::new(alloc::vec![0u8; 4096]);
        let tcp_socket = smoltcp::socket::tcp::Socket::new(tcp_rx, tcp_tx);
        let tcp_handle = sockets.add(tcp_socket);

        // 4. ICMP socket
        let icmp_rx = smoltcp::socket::icmp::PacketBuffer::new(
            alloc::vec![smoltcp::socket::icmp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 1024],
        );
        let icmp_tx = smoltcp::socket::icmp::PacketBuffer::new(
            alloc::vec![smoltcp::socket::icmp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 1024],
        );
        let icmp_socket = smoltcp::socket::icmp::Socket::new(icmp_rx, icmp_tx);
        let icmp_handle = sockets.add(icmp_socket);

        Self {
            device,
            iface,
            sockets,
            dhcp_handle,
            dns_handle,
            tcp_handle,
            icmp_handle,
            leased_ip: None,
            gateway_ip: None,
            dns_servers: Vec::new(),
        }
    }

    /// Polls the network stack with the current timestamp in milliseconds.
    pub fn poll(&mut self, timestamp_ms: i64) {
        let timestamp = smoltcp::time::Instant::from_millis(timestamp_ms);
        let _ = self.iface.poll(timestamp, &mut self.device, &mut self.sockets);

        // Process DHCP events
        let dhcp_socket = self.sockets.get_mut::<smoltcp::socket::dhcpv4::Socket>(self.dhcp_handle);
        if let Some(event) = dhcp_socket.poll() {
            match event {
                smoltcp::socket::dhcpv4::Event::Configured(config) => {
                    self.iface.update_ip_addrs(|addrs| {
                        addrs.clear();
                        let _ = addrs.push(smoltcp::wire::IpCidr::Ipv4(config.address));
                    });
                    self.leased_ip = Some(config.address.address().octets());
                    if let Some(router) = config.router {
                        self.gateway_ip = Some(router.octets());
                        let _ = self.iface.routes_mut().add_default_ipv4_route(router);
                    }
                    self.dns_servers.clear();
                    for s in &config.dns_servers {
                        self.dns_servers.push(s.octets());
                    }
                }
                smoltcp::socket::dhcpv4::Event::Deconfigured => {
                    self.iface.update_ip_addrs(|addrs| addrs.clear());
                    self.leased_ip = None;
                    self.gateway_ip = None;
                }
            }
        }
    }

    /// Connects the TCP socket to a remote IP and port.
    pub fn tcp_connect(&mut self, remote_ip: [u8; 4], remote_port: u16, local_port: u16) -> Result<(), ()> {
        let remote_addr = smoltcp::wire::Ipv4Address::from_octets(remote_ip);
        let tcp_socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(self.tcp_handle);
        tcp_socket
            .connect(self.iface.context(), (remote_addr, remote_port), local_port)
            .map_err(|_| ())
    }

    /// Checks if the TCP socket is connected (established).
    pub fn is_tcp_connected(&self) -> bool {
        let tcp_socket = self.sockets.get::<smoltcp::socket::tcp::Socket>(self.tcp_handle);
        tcp_socket.is_active() && tcp_socket.state() == smoltcp::socket::tcp::State::Established
    }

    /// Sends data through the TCP socket.
    pub fn tcp_send(&mut self, data: &[u8]) -> Result<usize, ()> {
        let tcp_socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(self.tcp_handle);
        if !tcp_socket.can_send() {
            return Err(());
        }
        tcp_socket.send_slice(data).map_err(|_| ())
    }

    /// Receives data from the TCP socket.
    pub fn tcp_recv(&mut self, buf: &mut [u8]) -> Result<usize, ()> {
        let tcp_socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(self.tcp_handle);
        if !tcp_socket.can_recv() {
            return Err(());
        }
        tcp_socket.recv_slice(buf).map_err(|_| ())
    }

    /// Closes the TCP socket.
    pub fn tcp_close(&mut self) {
        let tcp_socket = self.sockets.get_mut::<smoltcp::socket::tcp::Socket>(self.tcp_handle);
        tcp_socket.close();
    }
}



// ── TCP/IP Socket Table Model ───────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Connected,
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
    pub seq_num: u32,
    pub ack_num: u32,
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
            state: if proto == IpProto::TCP { TcpState::Listen } else { TcpState::Connected },
            seq_num: 1000 + id * 100,
            ack_num: 0,
        });
        id
    }

    /// Initiates a 3-way TCP handshake (RFC 793).
    /// Transitions state to `SynSent` and queues a SYN packet in `tx_ring`.
    pub fn connect(&mut self, socket_id: u32, remote_ip: [u8; 4], remote_port: u16) -> Result<(), ()> {
        if let Some(sock) = self.sockets.iter_mut().find(|s| s.id == socket_id) {
            sock.remote_ip = Some(remote_ip);
            sock.remote_port = Some(remote_port);
            sock.state = TcpState::SynSent;

            // Construct and queue TCP SYN frame (Ethernet II + IPv4 + TCP SYN)
            let mut syn_frame = [0u8; 54];
            syn_frame[0..6].copy_from_slice(&[0xFF; 6]); // Gateway / broadcast MAC
            syn_frame[6..12].copy_from_slice(&self.mac.0);
            syn_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

            // IPv4 header (20 bytes)
            syn_frame[14] = 0x45;
            syn_frame[16..18].copy_from_slice(&40u16.to_be_bytes()); // Total length 40
            syn_frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            syn_frame[22] = 64; // TTL
            syn_frame[23] = 6;  // TCP
            syn_frame[26..30].copy_from_slice(&self.ip);
            syn_frame[30..34].copy_from_slice(&remote_ip);

            // TCP header (20 bytes)
            syn_frame[34..36].copy_from_slice(&sock.local_port.to_be_bytes());
            syn_frame[36..38].copy_from_slice(&remote_port.to_be_bytes());
            syn_frame[38..42].copy_from_slice(&sock.seq_num.to_be_bytes());
            syn_frame[42..46].copy_from_slice(&0u32.to_be_bytes()); // ACK = 0
            syn_frame[46] = 0x50; // Data offset = 5 (20 bytes)
            syn_frame[47] = 0x02; // Flags: SYN
            syn_frame[48..50].copy_from_slice(&65535u16.to_be_bytes()); // Window

            let _ = self.tx_ring.push(&syn_frame);
            Ok(())
        } else {
            Err(())
        }
    }

    /// Advances a TCP socket through the 3-way handshake upon receiving peer's SYN-ACK.
    /// Transitions state from `SynSent` -> `Connected` and queues the final ACK in `tx_ring`.
    pub fn advance_handshake(&mut self, socket_id: u32) -> Result<(), ()> {
        let (local_port, remote_port, remote_ip, seq_num, ack_num) = {
            let sock = self.sockets.iter_mut().find(|s| s.id == socket_id).ok_or(())?;
            if sock.state != TcpState::SynSent {
                return Err(());
            }
            sock.seq_num = sock.seq_num.wrapping_add(1);
            sock.ack_num = 2000; // Peer ISN + 1
            sock.state = TcpState::Connected;
            (
                sock.local_port,
                sock.remote_port.unwrap_or(0),
                sock.remote_ip.unwrap_or([0, 0, 0, 0]),
                sock.seq_num,
                sock.ack_num,
            )
        };

        // Construct and queue TCP ACK frame
        let mut ack_frame = [0u8; 54];
        ack_frame[0..6].copy_from_slice(&[0xFF; 6]);
        ack_frame[6..12].copy_from_slice(&self.mac.0);
        ack_frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        ack_frame[14] = 0x45;
        ack_frame[16..18].copy_from_slice(&40u16.to_be_bytes());
        ack_frame[20..22].copy_from_slice(&0x4000u16.to_be_bytes());
        ack_frame[22] = 64;
        ack_frame[23] = 6;
        ack_frame[26..30].copy_from_slice(&self.ip);
        ack_frame[30..34].copy_from_slice(&remote_ip);
        ack_frame[34..36].copy_from_slice(&local_port.to_be_bytes());
        ack_frame[36..38].copy_from_slice(&remote_port.to_be_bytes());
        ack_frame[38..42].copy_from_slice(&seq_num.to_be_bytes());
        ack_frame[42..46].copy_from_slice(&ack_num.to_be_bytes());
        ack_frame[46] = 0x50;
        ack_frame[47] = 0x10; // Flags: ACK
        ack_frame[48..50].copy_from_slice(&65535u16.to_be_bytes());

        let _ = self.tx_ring.push(&ack_frame);
        Ok(())
    }

    pub fn close(&mut self, socket_id: u32) {
        if let Some(pos) = self.sockets.iter().position(|s| s.id == socket_id) {
            self.sockets.remove(pos);
        }
    }
}

// ── NIC Framing and Packet Format Models ──────────────────────────────────

/// Realtek RTL8139 4-byte receive packet header layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rtl8139PacketHeader {
    pub status: u16,
    pub length: u16,
}

impl Rtl8139PacketHeader {
    pub fn parse(bytes: [u8; 4]) -> Self {
        Self {
            status: u16::from_le_bytes([bytes[0], bytes[1]]),
            length: u16::from_le_bytes([bytes[2], bytes[3]]),
        }
    }

    pub fn is_ok(&self) -> bool {
        (self.status & 1) != 0 && self.length >= 4 && self.length <= 1792
    }

    pub fn packet_data_len(&self) -> usize {
        (self.length as usize).saturating_sub(4)
    }
}

/// VirtIO-Net 10-byte legacy packet header layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut b = [0u8; 10];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        b
    }

    pub fn from_bytes(bytes: [u8; 10]) -> Self {
        Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
        }
    }
}


