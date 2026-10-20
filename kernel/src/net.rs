//! Network service scaffolding for KashOS.
//!
//! Remote HTTP(S), DNS, and anonymity routing are unavailable until complete
//! protocol implementations and end-to-end tests exist. The service therefore
//! starts with its egress gate closed and must not claim a tunnel is active.

#![forbid(unsafe_code)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct SocketInfo {
    pub id: u32,
    pub proto: &'static str,
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub remote_ip: Option<[u8; 4]>,
    pub remote_port: Option<u16>,
    pub state: &'static str,
    pub trust_domain: &'static str,
}
use crate::csprng::Csprng;
use crate::sync::SpinLock;
use knet::{IpProto, MacAddr, NetworkIdentity, TcpIpStack, TcpState};
use kvault::rand_core::RngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    NotInitialized,
    NotAvailable,
    KillSwitchBlocked,
    PacketFiltered,
    BufferOverflow,
    SocketNotFound,
    ConnectionFailed,
    InvalidUrl,
    IoError,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NetStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub packets_dropped: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub killswitch_drops: u64,
}

/// Kernel socket-state placeholder. No NIC transport is connected here.
struct NetworkService {
    stack: TcpIpStack,
    identity: NetworkIdentity,
    stats: NetStats,
}

impl NetworkService {
    pub fn new(seed: u64) -> Self {
        let identity = NetworkIdentity::new(seed);
        let mac = identity.current_mac;
        // This legacy socket table is a state model only. Keep it explicitly
        // unconfigured so it cannot imply a DHCP lease or live route.
        let ip = [0; 4];
        let gateway_ip = [0; 4];
        let netmask = [0; 4];

        let stack = TcpIpStack::new(mac, ip, gateway_ip, netmask);
        Self {
            stack,
            identity,
            stats: NetStats::default(),
        }
    }

    /// Rotates the local Layer-2 MAC address using a fresh cryptographic hardware seed.
    pub fn rotate_mac(&mut self, new_seed: u64) -> MacAddr {
        self.identity.rotate_mac(new_seed);
        self.stack.mac = self.identity.current_mac;
        self.identity.current_mac
    }

    /// Fails closed while no filtered NIC transport is integrated.
    pub fn send_packet(
        &mut self,
        dest_mac: MacAddr,
        proto: IpProto,
        src_port: u16,
        dst_port: u16,
        sni: Option<&str>,
        payload: &[u8],
    ) -> Result<usize, NetError> {
        let _ = (dest_mac, proto, src_port, dst_port, sni, payload);
        // The filter and gateway are policy models, not an integrated NIC
        // transport. Never emit a frame until the full ingress/egress path is
        // connected and verified.
        self.stats.packets_dropped += 1;
        self.stats.killswitch_drops += 1;
        Err(NetError::KillSwitchBlocked)
    }

    /// Creates a local socket-state model entry, not a live socket.
    pub fn create_socket(&mut self, proto: IpProto, local_port: u16) -> u32 {
        self.stack.create_socket(proto, local_port)
    }

    /// Records a connection attempt in the local state model only.
    pub fn connect_socket(
        &mut self,
        socket_id: u32,
        remote_ip: [u8; 4],
        remote_port: u16,
    ) -> Result<(), NetError> {
        self.stack
            .connect(socket_id, remote_ip, remote_port)
            .map_err(|_| NetError::ConnectionFailed)
    }

    /// Advances the local TCP state model without processing a peer packet.
    pub fn advance_handshake(&mut self, socket_id: u32) -> Result<(), NetError> {
        self.stack
            .advance_handshake(socket_id)
            .map_err(|_| NetError::ConnectionFailed)
    }

    /// Closes a socket handle.
    pub fn close_socket(&mut self, socket_id: u32) {
        self.stack.close(socket_id);
    }

    /// Sends an ICMP Echo Request and receives an Echo Reply, measuring RTT.
    pub fn ping(&mut self, target_ip: [u8; 4], seq: u16) -> Result<u64, NetError> {
        let _ = (target_ip, seq);
        Err(NetError::NotAvailable)
    }

    /// Resolves domain names to IPv4 addresses.
    pub fn dns_resolve(&mut self, host: &str) -> Option<[u8; 4]> {
        // Direct IPv4 parser (e.g. "192.168.1.1", "127.0.0.1")
        Self::parse_ipv4(host)
    }

    /// Parse a dotted-decimal IPv4 string (e.g. "192.168.1.1")
    pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let b0 = parts[0].parse::<u8>().ok()?;
        let b1 = parts[1].parse::<u8>().ok()?;
        let b2 = parts[2].parse::<u8>().ok()?;
        let b3 = parts[3].parse::<u8>().ok()?;
        let ip = [b0, b1, b2, b3];
        Some(ip)
    }

    /// Remote web access is unavailable until real DNS, TCP, and TLS are integrated.
    pub fn http_get(&mut self, url: &str) -> Result<String, NetError> {
        let _ = url;
        Err(NetError::NotAvailable)
    }

    /// Returns local socket-state model entries, not active connections.
    pub fn get_socket_table(&self) -> Vec<SocketInfo> {
        let mut list = Vec::new();
        for sock in &self.stack.sockets {
            let proto_str = match sock.proto {
                IpProto::TCP => "tcp",
                IpProto::UDP => "udp",
                IpProto::ICMP => "icmp",
                _ => "raw",
            };
            let state_str = match sock.state {
                TcpState::Listen => "MODEL_LISTEN",
                TcpState::Connected => "MODEL_CONNECTED",
                TcpState::SynSent => "MODEL_SYN_SENT",
                TcpState::Closed => "MODEL_CLOSED",
                _ => "MODEL_TIME_WAIT",
            };
            list.push(SocketInfo {
                id: sock.id + 10,
                proto: proto_str,
                local_ip: sock.local_ip,
                local_port: sock.local_port,
                remote_ip: sock.remote_ip,
                remote_port: sock.remote_port,
                state: state_str,
                trust_domain: "Socket-state model only; no live transport",
            });
        }
        list
    }
}

static NET_SERVICE: SpinLock<Option<Box<NetworkService>>> = SpinLock::new(None);

/// Initializes network scaffolding with remote egress disabled.
pub fn init() {
    let mut net_lock = NET_SERVICE.lock();
    if net_lock.is_none() {
        crate::kprintln!("[net] Initializing network scaffolding with remote egress disabled...");

        // Obtain a seed from the kernel CSPRNG for the local network identity.
        let mut rng = Csprng::new();
        let seed = rng.next_u64();

        let service = Box::new(NetworkService::new(seed));
        let mac = service.identity.current_mac;
        crate::kprintln!(
            "[net] Network scaffolding initialized; remote egress disabled. MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
        );
        crate::kprintln!("[net] Remote HTTP(S), DNS, and anonymity routing are unavailable; outbound traffic is blocked.");

        *net_lock = Some(service);
    }
}

/// Rotates MAC address using fresh hardware entropy.
pub fn rotate_mac() -> Result<MacAddr, NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    let mut rng = Csprng::new();
    let seed = rng.next_u64();
    Ok(service.rotate_mac(seed))
}

/// Rejects outbound packets until a filtered NIC-to-stack path is connected.
pub fn send(
    dest_mac: MacAddr,
    proto: IpProto,
    src_port: u16,
    dst_port: u16,
    sni: Option<&str>,
    payload: &[u8],
) -> Result<usize, NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.send_packet(dest_mac, proto, src_port, dst_port, sni, payload)
}

/// Ingress is unavailable until NIC frames pass through the network policy path.
pub fn receive(out_buf: &mut [u8]) -> Result<Option<usize>, NetError> {
    let _ = out_buf;
    Err(NetError::NotAvailable)
}

/// Creates a new socket handle.
pub fn socket(proto: IpProto, local_port: u16) -> Result<u32, NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    Ok(service.create_socket(proto, local_port))
}

/// Connects a socket to remote destination.
pub fn connect(socket_id: u32, remote_ip: [u8; 4], remote_port: u16) -> Result<(), NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.connect_socket(socket_id, remote_ip, remote_port)
}

/// Advances a socket through 3-way TCP handshake upon receiving SYN-ACK.
pub fn advance_handshake(socket_id: u32) -> Result<(), NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.advance_handshake(socket_id)
}

/// Closes a socket.
pub fn close(socket_id: u32) -> Result<(), NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.close_socket(socket_id);
    Ok(())
}

/// Returns snapshot of network performance and security statistics.
pub fn get_stats() -> Result<NetStats, NetError> {
    let net_lock = NET_SERVICE.lock();
    let service = net_lock.as_ref().ok_or(NetError::NotInitialized)?;
    Ok(service.stats)
}

/// Returns current MAC address.
pub fn get_mac() -> Result<MacAddr, NetError> {
    let net_lock = NET_SERVICE.lock();
    let service = net_lock.as_ref().ok_or(NetError::NotInitialized)?;
    Ok(service.stack.mac)
}

/// Sends ICMP Echo Request and receives reply, returning round-trip time in microseconds.
pub fn ping(target: [u8; 4], seq: u16) -> Result<u64, NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.ping(target, seq)
}

/// Resolves a domain name to IPv4 address.
pub fn dns_resolve(host: &str) -> Result<[u8; 4], NetError> {
    if let Some(ip) = NetworkService::parse_ipv4(host) {
        return Ok(ip);
    }
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.dns_resolve(host).ok_or(NetError::NotAvailable)
}

/// Remote HTTP GET is unavailable until a verified protocol path exists.
pub fn http_get(url: &str) -> Result<String, NetError> {
    let mut net_lock = NET_SERVICE.lock();
    let service = net_lock.as_mut().ok_or(NetError::NotInitialized)?;
    service.http_get(url)
}

/// Returns socket-state model entries, not live network connections.
pub fn list_sockets() -> Result<Vec<SocketInfo>, NetError> {
    let net_lock = NET_SERVICE.lock();
    let service = net_lock.as_ref().ok_or(NetError::NotInitialized)?;
    Ok(service.get_socket_table())
}

/// DHCP is unavailable until the stack is connected to the physical NIC.
pub fn dhcp_status() -> Option<[u8; 4]> {
    None
}

/// Remote TCP is unavailable until smoltcp is connected to the physical NIC.
pub fn tcp_connect(remote_ip: [u8; 4], remote_port: u16, local_port: u16) -> Result<(), NetError> {
    let _ = (remote_ip, remote_port, local_port);
    Err(NetError::NotAvailable)
}

/// TCP send is unavailable until smoltcp is connected to the physical NIC.
pub fn tcp_send(data: &[u8]) -> Result<usize, NetError> {
    let _ = data;
    Err(NetError::NotAvailable)
}

/// TCP receive is unavailable until filtered NIC ingress is connected.
pub fn tcp_recv(buf: &mut [u8]) -> Result<usize, NetError> {
    let _ = buf;
    Err(NetError::NotAvailable)
}

/// Resolves a domain name to an IPv4 address (Task A6 API).
pub fn resolve(host: &str) -> Result<[u8; 4], NetError> {
    dns_resolve(host)
}

/// Network polling is disabled until the NIC adapter and policy path are integrated.
pub fn poll(now_ms: i64) {
    let _ = now_ms;
}
