use knet::*;

#[test]
fn mac_address_locally_administered_invariants() {
    let seed = 0x1234_5678_9ABC_DEF0u64;
    let mac = MacAddr::locally_administered(seed);

    // Bit 1 of byte 0 must be 1 (locally administered)
    assert_eq!(mac.0[0] & 0x02, 0x02);
    // Bit 0 of byte 0 must be 0 (unicast)
    assert_eq!(mac.0[0] & 0x01, 0x00);
    assert!(mac.is_unicast());
    assert!(!mac.is_multicast());
}

#[test]
fn packet_filter_rules_evaluation() {
    let mut table = FilterTable::new();
    table.add_rule(FilterRule::BlockPort(23)); // Telnet banned
    table.add_rule(FilterRule::BlockDomain("malicious.tracker.org".into()));
    table.add_rule(FilterRule::NormalizeFingerprint);

    let meta_clean = FrameMeta {
        src_mac: MacAddr::ZERO,
        dst_mac: MacAddr::ZERO,
        ether_type: EtherType::IPv4,
        src_ip: Some([0; 16]),
        dst_ip: Some([0; 16]),
        src_port: Some(54321),
        dst_port: Some(443), // HTTPS
        proto: Some(IpProto::TCP),
        ttl: Some(128),
        tcp_window: Some(8192),
        sni: Some("clean.domain.org".into()),
        payload_len: 100,
    };

    assert_eq!(table.evaluate(&meta_clean, true), Verdict::NormalizeThenAllow);

    // Test port blocking
    let mut meta_telnet = meta_clean.clone();
    meta_telnet.dst_port = Some(23);
    assert_eq!(table.evaluate(&meta_telnet, true), Verdict::DropAlert);

    // Test SNI domain blocking
    let mut meta_tracker = meta_clean.clone();
    meta_tracker.sni = Some("malicious.tracker.org".into());
    assert_eq!(table.evaluate(&meta_tracker, true), Verdict::DropAlert);
}

#[test]
fn fail_closed_kill_switch_drops_all_packets_when_gateway_down() {
    let table = FilterTable::new();

    let meta = FrameMeta {
        src_mac: MacAddr::ZERO,
        dst_mac: MacAddr::ZERO,
        ether_type: EtherType::IPv4,
        src_ip: Some([0; 16]),
        dst_ip: Some([0; 16]),
        src_port: Some(12345),
        dst_port: Some(443),
        proto: Some(IpProto::TCP),
        ttl: Some(64),
        tcp_window: Some(65535),
        sni: Some("safe.org".into()),
        payload_len: 64,
    };

    // When gateway is alive -> Allowed
    assert_eq!(table.evaluate(&meta, /* gateway_alive = */ true), Verdict::NormalizeThenAllow);

    // When gateway is down -> Kill switch fires closed!
    assert_eq!(table.evaluate(&meta, /* gateway_alive = */ false), Verdict::Drop);
}

#[test]
fn packet_ring_spsc_fifo_ordering() {
    let mut ring = PacketRing::new();
    assert!(ring.is_empty());

    let packet1 = b"Ethernet Frame 1 Payload";
    let packet2 = b"Ethernet Frame 2 Payload";

    assert!(ring.push(packet1).is_ok());
    assert!(ring.push(packet2).is_ok());
    assert!(!ring.is_empty());

    let mut buf = [0u8; 1514];
    let len1 = ring.pop(&mut buf).expect("pop packet1 failed");
    assert_eq!(&buf[..len1], packet1);

    let len2 = ring.pop(&mut buf).expect("pop packet2 failed");
    assert_eq!(&buf[..len2], packet2);

    assert!(ring.is_empty());
}

#[test]
fn tcp_ip_stack_socket_lifecycle() {
    let mac = MacAddr([0x02, 0x4B, 0x41, 0x53, 0x48, 0x01]);
    let ip = [192, 168, 1, 100];
    let gateway = [192, 168, 1, 1];
    let netmask = [255, 255, 255, 0];

    let mut stack = TcpIpStack::new(mac, ip, gateway, netmask);

    let sock_id = stack.create_socket(IpProto::TCP, 8080);
    assert_eq!(stack.sockets.len(), 1);
    assert_eq!(stack.sockets[0].state, TcpState::Listen);

    // Initiating connection must transition to SynSent, NOT immediately Established
    assert!(stack.connect(sock_id, [192, 168, 1, 50], 443).is_ok());
    assert_eq!(stack.sockets[0].state, TcpState::SynSent);
    assert_eq!(stack.sockets[0].remote_port, Some(443));

    // Receiving peer SYN-ACK completes the 3-way handshake to Connected
    assert!(stack.advance_handshake(sock_id).is_ok());
    assert_eq!(stack.sockets[0].state, TcpState::Connected);

    stack.close(sock_id);
    assert_eq!(stack.sockets.len(), 0);
}

#[test]
fn smol_net_stack_device_and_socket_test() {
    let mac = MacAddr([0x02, 0x4B, 0x41, 0x53, 0x48, 0x02]);
    let mut stack = SmolNetStack::new(mac, 0xDEADBEEF);

    assert_eq!(stack.leased_ip, None);
    assert_eq!(stack.gateway_ip, None);
    assert!(!stack.is_tcp_connected());

    // Initially tx_ring is empty
    assert!(stack.device.tx_ring.is_empty());

    // Assign IP address to interface (simulating DHCP lease)
    stack.iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(smoltcp::wire::IpCidr::new(
            smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(10, 0, 2, 15)),
            24,
        ));
    });

    // Connect TCP socket towards remote server
    let res = stack.tcp_connect([10, 0, 2, 2], 80, 49152);
    assert!(res.is_ok());


    // Polling triggers SYN transmission into tx_ring
    stack.poll(10);
    assert!(!stack.device.tx_ring.is_empty());

    let mut tx_frame = [0u8; 1514];
    let tx_len = stack.device.tx_ring.pop(&mut tx_frame).expect("expected SYN packet");
    assert!(tx_len >= 54); // Ethernet (14) + IP (20) + TCP (20)
    assert_eq!(&tx_frame[6..12], &mac.0); // Source MAC equals stack MAC
    assert_eq!(&tx_frame[12..14], &0x0800u16.to_be_bytes()); // IPv4 EtherType
}

