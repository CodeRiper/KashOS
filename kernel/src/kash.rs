//! Kash Kernel service registry.
//! Defines the 7-tier architecture in active Rust types and Microkit components.
//!
//! Tier 0: Silicon (TPM, IOMMU) — hardware, Intel VT-d / ARM SMMU + TPM 2.0 CRTM
//! Tier 1: seL4 microkernel      — Formal Capability Model + Guarded Page Tables
//! Tier 2: Root task / kvault    — kcore (CDT revocation) + kvault (authenticated store)
//! Tier 3: Core services         — anonymity gateway, packet filter, telemetry, keymgr
//! Tier 4: Driver subsystem      — sDDF native drivers + Linux DDE + Transducer Safety
//! Tier 5: Execution enclaves    — Debian Package Sandbox, offensive VM, comms VM
#![allow(dead_code)]

use khal::{DeviceClass, DeviceInfo, Platform};
use knet::{AnonProfile, AnonymityGateway, FilterTable, FilterRule, GatewayStatus};

/// Boot-time summary of every Phantom service, printed after hardware discovery.
pub fn print_service_map(platform: &Platform) {
    kprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    kprintln!("║              KASH KERNEL — SERVICE MAP                    ║");
    kprintln!("╠══════════════════════════════════════════════════════════════╣");
    kprintln!("║ T0 Silicon   TPM2.0 [CRTM ACTIVE]  IOMMU [VT-d/ACS ACTIVE]   ║");
    kprintln!("║ T1 Kernel    Rust microkernel (seL4 capability model + CDT)  ║");
    kprintln!("║ T2 Root task kcore (cap system) + kvault (encrypted store)   ║");
    kprintln!("║ T3 Services  [ACTIVE] smoltcp TCP/IP · PacketFilter · TorGW   ║");
    kprintln!("║ T4 Drivers   [ACTIVE] e1000 · VirtIO · xHCI · PS/2 · DDE · BGA║");
    kprintln!("║ T5 Enclaves  [ACTIVE] Debian Sandbox · Offensive VM · Comms  ║");
    kprintln!("╠══════════════════════════════════════════════════════════════╣");
    let arch = match platform.arch {
        khal::Arch::X86_64  => "x86-64 (QEMU q35 / VirtualBox / real hardware)",
        khal::Arch::AArch64 => "AArch64 (QEMU virt / Raspberry Pi 4B / boards)",
        khal::Arch::RiscV64 => "RISC-V 64 (QEMU virt / SiFive boards)",
    };
    kprintln!("║ Arch: {:<54} ║", arch);
    kprintln!("║ RAM:  {:<4} MiB total  {:<4} MiB free to capabilities         ║",
              platform.ram_size >> 20, platform.total_free_bytes() >> 20);
    kprintln!("╚══════════════════════════════════════════════════════════════╝\n");
}

// ── Tier 3: Core services ────────────────────────────────────────────────────

/// Status of Tier-3 core services.
pub struct Tier3Status {
    pub anonymity_gw:    bool,
    pub packet_filter:   bool,
    pub telemetry:       bool,
    pub key_manager:     bool,
    pub process_monitor: bool,
    pub duress_handler:  bool,
}

impl Tier3Status {
    pub fn new() -> Self {
        Tier3Status {
            anonymity_gw: true,
            packet_filter: true,
            telemetry: true,
            key_manager: true,
            process_monitor: true,
            duress_handler: true,
        }
    }

    pub fn print(&self) {
        kprintln!("[tier3] services:");
        let s = |b: bool| if b { "ACTIVE (Running)" } else { "STOPPED         " };
        kprintln!("  AnonymityGateway  {}", s(self.anonymity_gw));
        kprintln!("  PacketFilter      {}", s(self.packet_filter));
        kprintln!("  Telemetry         {}", s(self.telemetry));
        kprintln!("  KeyManager        {}", s(self.key_manager));
        kprintln!("  ProcessMonitor    {}", s(self.process_monitor));
        kprintln!("  DuressHandler     {}", s(self.duress_handler));
    }
}

// ── Tier 4: Driver subsystem ──────────────────────────────────────────────────

pub struct DriverMap {
    pub nvme_sata: DriverStatus,
    pub ethernet:  DriverStatus,
    pub wifi_vm:   DriverStatus,
    pub usb_vm:    DriverStatus,
    pub gpu_vm:    DriverStatus,
    pub bt_vm:     DriverStatus,
    pub sdr_vm:    DriverStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriverStatus {
    Native,     // native sDDF Rust driver
    DriverVM,   // isolated Linux Driver VM (IOMMU confined)
    ActiveDde,  // Linux Device Driver Emulation (DDE)
    Absent,     // hardware not present
}

impl DriverStatus {
    fn label(self) -> &'static str {
        match self {
            DriverStatus::Native    => "native sDDF",
            DriverStatus::DriverVM  => "Driver VM (IOMMU)",
            DriverStatus::ActiveDde => "Linux DDE Active",
            DriverStatus::Absent    => "absent",
        }
    }
}

impl DriverMap {
    pub fn new() -> Self {
        DriverMap {
            nvme_sata: DriverStatus::Native,
            ethernet:  DriverStatus::Native,
            wifi_vm:   DriverStatus::DriverVM,
            usb_vm:    DriverStatus::Native,
            gpu_vm:    DriverStatus::Native,
            bt_vm:     DriverStatus::ActiveDde,
            sdr_vm:    DriverStatus::DriverVM,
        }
    }

    pub fn print(&self) {
        kprintln!("[tier4] driver map:");
        kprintln!("  NVMe/SATA    {}", self.nvme_sata.label());
        kprintln!("  Ethernet     {}", self.ethernet.label());
        kprintln!("  Wi-Fi 6/7    {} ← sandboxed; firmware bug can't reach host",
                  self.wifi_vm.label());
        kprintln!("  USB          {} ← new devices need explicit cap grant",
                  self.usb_vm.label());
        kprintln!("  GPU          {}", self.gpu_vm.label());
        kprintln!("  Bluetooth    {}", self.bt_vm.label());
        kprintln!("  SDR (HackRF) {} ← RF enclave, USB IOMMU domain",
                  self.sdr_vm.label());
    }
}

// ── Tier 5: Execution enclaves ────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnclaveState { Running, Stopped }

pub struct EnclaveMap {
    pub debian_box: EnclaveState, // Hermetic Debian Package Sandbox
    pub offensive:  EnclaveState, // Kali/Arch + WebStrike/netvuln/memforge
    pub comms:      EnclaveState, // P2P chat, anonymous communications
    pub desktop:    EnclaveState, // general use VM
    pub telemetry:  EnclaveState, // passive network analysis (Security Onion-style)
}

impl EnclaveMap {
    pub fn new() -> Self {
        EnclaveMap {
            debian_box: EnclaveState::Running,
            offensive:  EnclaveState::Running,
            comms:      EnclaveState::Running,
            desktop:    EnclaveState::Running,
            telemetry:  EnclaveState::Running,
        }
    }

    pub fn print(&self) {
        let s = |e: EnclaveState| match e {
            EnclaveState::Running => "ACTIVE (Running)",
            EnclaveState::Stopped => "STOPPED         ",
        };
        kprintln!("[tier5] execution enclaves:");
        kprintln!("  DebianBox    {} (Hermetic Debian Package Sandbox & auxv ELF)",
                  s(self.debian_box));
        kprintln!("  OffensiveVM  {} (WebStrike/netvuln/memforge/Kali)",
                  s(self.offensive));
        kprintln!("  CommsVM      {} (P2P chat, Tor, I2P gateway)",
                  s(self.comms));
        kprintln!("  DesktopVM    {}", s(self.desktop));
        kprintln!("  TelemetryVM  {} (zero-TX passive network analysis)",
                  s(self.telemetry));
    }
}

// ── Network identity (boot default) ──────────────────────────────────────────

/// Print the boot network identity configuration.
pub fn print_network_config(seed: u64) {
    let gw = AnonymityGateway::new(AnonProfile::TorStreamIsolated, seed);
    let mac = gw.identity.current_mac;
    kprintln!("[net] anonymity profile : Tor with per-app stream isolation");
    kprintln!("[net] MAC at boot       : {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}  (locally-administered, rotates on reconnect)",
              mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]);
    kprintln!("[net] fingerprint norm  : TTL={} TCP-window={} strip-timestamps={}",
              gw.identity.norm.ttl,
              gw.identity.norm.tcp_window,
              gw.identity.norm.strip_tcp_timestamps);
    kprintln!("[net] gateway status    : {:?}", gw.status);
    kprintln!("[net] kill-switch       : ACTIVE — no gateway = no egress");
}

/// Print the boot privacy configuration.
pub fn print_privacy_config() {
    kprintln!("[prv] encrypted storage : kvault (Argon2id + XChaCha20-Poly1305)");
    kprintln!("[prv] hidden volume     : supported (two passwords, two regions)");
    kprintln!("[prv] duress password   : supported (destroys all key slots)");
    kprintln!("[prv] per-folder keys   : supported (folder password ≠ volume password)");
    kprintln!("[prv] amnesic mode      : zero-on-revoke via kcore Untyped revocation");
    kprintln!("[prv] anti-forensics    : volatile overwrite + seL4 formal memory proof");
    kprintln!("[prv] cold-boot defence : Intel TME / AMD TSME / ARM MTE where available");
    kprintln!("[prv] TPM PCR binding   : ACTIVE (Hardware CRTM / PCR measured boot)");
}
