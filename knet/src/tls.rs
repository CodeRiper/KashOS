//! TLS 1.3 Client Record Layer & HTTPS Client (RFC 8446) for KashOS.
//!
//! Provides `#![no_std]` TLS 1.3 ClientHello serialization with SNI,
//! SupportedVersions, KeyShare extensions, TLS Record Layer framing,
//! and HTTP/1.1 request/response parsing.

extern crate alloc;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// TLS Record Layer Content Type (RFC 8446 Section 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TlsContentType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// TLS 1.3 Handshake Type (RFC 8446 Section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

/// 5-byte TLS Record Layer Header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsRecordHeader {
    pub content_type: TlsContentType,
    pub legacy_version: u16,
    pub length: u16,
}

impl TlsRecordHeader {
    pub const HEADER_LEN: usize = 5;

    pub fn new(content_type: TlsContentType, length: u16) -> Self {
        Self {
            content_type,
            legacy_version: 0x0303, // TLS 1.2 legacy wire compatibility (RFC 8446 Section 5.1)
            length,
        }
    }

    pub fn serialize(&self) -> [u8; 5] {
        let mut buf = [0u8; 5];
        buf[0] = self.content_type as u8;
        buf[1..3].copy_from_slice(&self.legacy_version.to_be_bytes());
        buf[3..5].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::HEADER_LEN {
            return None;
        }
        let content_type = TlsContentType::from_u8(bytes[0])?;
        let legacy_version = u16::from_be_bytes([bytes[1], bytes[2]]);
        let length = u16::from_be_bytes([bytes[3], bytes[4]]);
        Some(Self {
            content_type,
            legacy_version,
            length,
        })
    }
}

/// Encapsulates application data into a TLS ApplicationData record.
pub fn wrap_tls_application_data(data: &[u8]) -> Vec<u8> {
    let header = TlsRecordHeader::new(TlsContentType::ApplicationData, data.len() as u16);
    let mut record = Vec::with_capacity(TlsRecordHeader::HEADER_LEN + data.len());
    record.extend_from_slice(&header.serialize());
    record.extend_from_slice(data);
    record
}

/// Decapsulates a TLS ApplicationData record, returning the inner payload.
pub fn unwrap_tls_application_data(record: &[u8]) -> Option<&[u8]> {
    let header = TlsRecordHeader::parse(record)?;
    if header.content_type != TlsContentType::ApplicationData {
        return None;
    }
    let data_len = header.length as usize;
    if record.len() >= TlsRecordHeader::HEADER_LEN + data_len {
        Some(&record[TlsRecordHeader::HEADER_LEN..TlsRecordHeader::HEADER_LEN + data_len])
    } else {
        None
    }
}

/// Constructs a compliant TLS 1.3 ClientHello record with SNI, SupportedVersions,
/// KeyShare, and SupportedGroups extensions.
pub fn build_tls13_client_hello(host: &str, random: &[u8; 32], client_public_key: &[u8; 32]) -> Vec<u8> {
    let mut extensions = Vec::new();

    // 1. Server Name Indication (SNI) Extension (Type 0x0000)
    let host_bytes = host.as_bytes();
    let sni_list_len = (host_bytes.len() + 3) as u16;
    let mut sni_data = Vec::new();
    sni_data.extend_from_slice(&sni_list_len.to_be_bytes());
    sni_data.push(0); // HostName type
    sni_data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(host_bytes);

    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // Type 0 (SNI)
    extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_data);

    // 2. Supported Versions Extension (Type 0x002B) -> TLS 1.3 (0x0304)
    extensions.extend_from_slice(&0x002Bu16.to_be_bytes());
    extensions.extend_from_slice(&3u16.to_be_bytes()); // length: 3 bytes
    extensions.push(2); // 2 bytes of versions
    extensions.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3

    // 3. Supported Groups Extension (Type 0x000A) -> X25519 (0x001D)
    extensions.extend_from_slice(&0x000Au16.to_be_bytes());
    extensions.extend_from_slice(&4u16.to_be_bytes());
    extensions.extend_from_slice(&2u16.to_be_bytes()); // list length: 2 bytes
    extensions.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519

    // 4. Key Share Extension (Type 0x0033) -> X25519 Client Share (32 bytes key)
    let mut key_share_data = Vec::new();
    let client_shares_len = (2 + 2 + 32) as u16;
    key_share_data.extend_from_slice(&client_shares_len.to_be_bytes());
    key_share_data.extend_from_slice(&0x001Du16.to_be_bytes()); // Group: X25519
    key_share_data.extend_from_slice(&32u16.to_be_bytes()); // Key exchange length
    key_share_data.extend_from_slice(client_public_key);

    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    extensions.extend_from_slice(&(key_share_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share_data);

    // 5. Signature Algorithms Extension (Type 0x000D)
    extensions.extend_from_slice(&0x000Du16.to_be_bytes());
    extensions.extend_from_slice(&8u16.to_be_bytes());
    extensions.extend_from_slice(&6u16.to_be_bytes()); // List length: 6 bytes
    extensions.extend_from_slice(&0x0807u16.to_be_bytes()); // ed25519
    extensions.extend_from_slice(&0x0804u16.to_be_bytes()); // rsa_pss_rsae_sha256
    extensions.extend_from_slice(&0x0403u16.to_be_bytes()); // ecdsa_secp256r1_sha256

    // Construct ClientHello Body
    let mut ch_body = Vec::new();
    ch_body.extend_from_slice(&0x0303u16.to_be_bytes()); // Legacy Client Version: 0x0303
    ch_body.extend_from_slice(random); // 32 bytes client random
    ch_body.push(32); // Legacy session id length = 32
    ch_body.extend_from_slice(random); // Echo random as session id for middlebox compatibility

    // Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    ch_body.extend_from_slice(&4u16.to_be_bytes()); // Cipher suites length: 4 bytes
    ch_body.extend_from_slice(&0x1301u16.to_be_bytes());
    ch_body.extend_from_slice(&0x1303u16.to_be_bytes());

    // Legacy Compression Methods: 1 byte (0x00)
    ch_body.push(1);
    ch_body.push(0);

    // Extensions length + extensions
    ch_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&extensions);

    // Handshake Header: Type = 1 (ClientHello), Length (3 bytes)
    let mut handshake_msg = Vec::new();
    handshake_msg.push(TlsHandshakeType::ClientHello as u8);
    let ch_len = ch_body.len() as u32;
    handshake_msg.push(((ch_len >> 16) & 0xFF) as u8);
    handshake_msg.push(((ch_len >> 8) & 0xFF) as u8);
    handshake_msg.push((ch_len & 0xFF) as u8);
    handshake_msg.extend_from_slice(&ch_body);

    // Record Layer Header: Type = 22 (Handshake), Version = 0x0303, Length
    let record_header = TlsRecordHeader::new(TlsContentType::Handshake, handshake_msg.len() as u16);
    let mut full_record = Vec::with_capacity(5 + handshake_msg.len());
    full_record.extend_from_slice(&record_header.serialize());
    full_record.extend_from_slice(&handshake_msg);
    full_record
}

// ── HTTP / HTTPS Client Framing ─────────────────────────────────────────────

/// Parsed URL components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedUrl<'a> {
    pub is_https: bool,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
}

/// Parses an HTTP or HTTPS URL into its constituent components.
pub fn parse_url(url: &str) -> Option<ParsedUrl<'_>> {
    let (is_https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        (true, url) // Default to HTTPS
    };

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = match host_port.find(':') {
        Some(idx) => {
            let host = &host_port[..idx];
            let port_str = &host_port[idx + 1..];
            let port = port_str.parse::<u16>().ok()?;
            (host, port)
        }
        None => {
            let port = if is_https { 443 } else { 80 };
            (host_port, port)
        }
    };

    if host.is_empty() {
        return None;
    }

    Some(ParsedUrl {
        is_https,
        host,
        port,
        path,
    })
}

/// Constructs a standard, privacy-preserving HTTP/1.1 GET request.
pub fn build_http_get_request(host: &str, path: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: KashOS-Browser/0.2.0 (ELinks; Microkernel; +https://kashos.org)\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Connection: close\r\n\r\n",
        path, host
    )
}

/// Parsed HTTP/1.1 response structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

/// Parses raw HTTP/1.1 response bytes into an `HttpResponse`.
pub fn parse_http_response(raw: &str) -> Option<HttpResponse> {
    let (headers_part, body_part) = match raw.find("\r\n\r\n") {
        Some(idx) => (&raw[..idx], &raw[idx + 4..]),
        None => match raw.find("\n\n") {
            Some(idx) => (&raw[..idx], &raw[idx + 2..]),
            None => (raw, ""),
        },
    };

    let mut lines = headers_part.lines();
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next()?;
    let code_str = parts.next()?;
    let status_code = code_str.parse::<u16>().ok()?;
    let status_text = parts.next().unwrap_or("").to_string();

    let mut headers = Vec::new();
    for line in lines {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_string();
            let val = line[idx + 1..].trim().to_string();
            headers.push((key, val));
        }
    }

    Some(HttpResponse {
        status_code,
        status_text,
        headers,
        body: body_part.to_string(),
    })
}
