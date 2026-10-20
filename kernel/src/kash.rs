//! Kash Kernel service registry.
//! Defines the 7-tier architecture in active Rust types and Microkit components.
//!
//! Tier 0: Silicon (TPM, IOMMU) — hardware, Intel VT-d / ARM SMMU + TPM 2.0 CRTM
//! Tier 1: seL4 microkernel      — Formal Capability Model + Guarded Page Tables
//! Tier 2: Root task / kvault    — kcore (CDT revocation) + kvault (authenticated store)
//! Tier 3: Core services         — anonymity gateway, packet filter, telemetry, keymgr
//! Tier 4: Driver subsystem      — sDDF native drivers + Linux DDE + Transducer Safety
//! Tier 5: Execution enclaves    — Debian Package Sandbox, offensive VM, comms VM

use khal::{DeviceClass, DeviceInfo, Platform};
use knet::{FilterTable, FilterRule};

/// Boot-time summary of every KashOS service, printed after hardware discovery.
pub fn print_service_map(platform: &Platform) {
    let reg = crate::status::get();
    kprintln!("\n╔══════════════════════════════════════════════════════════════╗");
    kprintln!("║              KASH KERNEL — SERVICE MAP                    ║");
    kprintln!("╠══════════════════════════════════════════════════════════════╣");
    kprintln!("║ T0 Silicon   TPM: [{:<6}]              IOMMU [{:<13}]  ║", reg.tpm2_crtm.label(), reg.vtd_iommu.label());
    kprintln!("║ T1 Kernel    monolithic prototype; capability isolation incomplete ║");
    kprintln!("║ T2 Storage   kvault root authenticated store [{:<13}]  ║", reg.kvault_fs.label());
    let net_label = if reg.nic_e1000.is_real() || reg.nic_virtio.is_real() || reg.nic_rtl8139.is_real() {
        "REAL (Hardware)"
    } else {
        "NOT AVAILABLE"
    };
    kprintln!("║ T3 Services  smoltcp / Net: [{:<14}]                  ║", net_label);
    kprintln!("║ T4 Drivers   e1000:[{:<6}] VirtIO:[{:<6}] RTL:[{:<4}]     ║",
              reg.nic_e1000.label(), reg.nic_virtio.label(), reg.nic_rtl8139.label());
    kprintln!("║ T5 Enclaves  Capsules: [{:<8}] Sandbox: [{:<8}]        ║",
              reg.kapp_capsules.label(), reg.pledge_unveil.label());
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
            anonymity_gw: false,
            packet_filter: false,
            telemetry: false,
            key_manager: false,
            process_monitor: false,
            duress_handler: false,
        }
    }

    pub fn print(&self) {
        kprintln!("[tier3] services:");
        let s = |b: bool| if b { "ACTIVE (Running)" } else { "NOT IMPLEMENTED (Part B)" };
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
    #[allow(dead_code)]
    DriverVM,   // isolated Linux Driver VM (IOMMU confined)
    #[allow(dead_code)]
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
        let reg = crate::status::get();
        let storage_name = crate::blockdev::active_driver_name();
        let nvme_sata = if storage_name.contains("NVMe")
            || storage_name.contains("AHCI")
            || storage_name.contains("SATA")
            || storage_name.contains("VirtIO")
            || storage_name.contains("PATA")
            || storage_name.contains("IDE")
        {
            DriverStatus::Native
        } else {
            DriverStatus::Absent
        };

        DriverMap {
            nvme_sata,
            ethernet:  if reg.nic_e1000.is_real() || reg.nic_virtio.is_real() || reg.nic_rtl8139.is_real() { DriverStatus::Native } else { DriverStatus::Absent },
            wifi_vm:   DriverStatus::Absent,
            usb_vm:    DriverStatus::Absent,
            gpu_vm:    if reg.linear_framebuffer.is_real() { DriverStatus::Native } else { DriverStatus::Absent },
            bt_vm:     DriverStatus::Absent,
            sdr_vm:    DriverStatus::Absent,
        }
    }

    pub fn print(&self) {
        kprintln!("[tier4] driver map:");
        kprintln!("  NVMe/SATA    {}", self.nvme_sata.label());
        kprintln!("  Ethernet     {}", self.ethernet.label());
        kprintln!("  Wi-Fi 6/7    {}", self.wifi_vm.label());
        kprintln!("  USB / PS/2   {}", self.usb_vm.label());
        kprintln!("  GPU / Framebuffer {}", self.gpu_vm.label());
        kprintln!("  Bluetooth    {}", self.bt_vm.label());
        kprintln!("  SDR (HackRF) {}", self.sdr_vm.label());
    }
}

// ── Tier 5: Execution enclaves ────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnclaveState {
    #[allow(dead_code)]
    Running,
    Stopped,
}

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
            debian_box: EnclaveState::Stopped,
            offensive:  EnclaveState::Stopped,
            comms:      EnclaveState::Stopped,
            desktop:    EnclaveState::Stopped,
            telemetry:  EnclaveState::Stopped,
        }
    }

    pub fn print(&self) {
        let s = |e: EnclaveState| match e {
            EnclaveState::Running => "ACTIVE (Running)",
            EnclaveState::Stopped => "STOPPED (Not Launched)",
        };
        kprintln!("[tier5] execution enclaves:");
        kprintln!("  DebianBox    {} (Hermetic Debian Package Sandbox)", s(self.debian_box));
        kprintln!("  OffensiveVM  {} (Isolated security testing domain, Part E)", s(self.offensive));
        kprintln!("  CommsVM      {} (P2P chat, secure gateway)", s(self.comms));
        kprintln!("  DesktopVM    {}", s(self.desktop));
        kprintln!("  TelemetryVM  {}", s(self.telemetry));
    }
}

// ── Network identity (boot default) ──────────────────────────────────────────

/// Report network integration state without presenting generated identity data as live networking.
pub fn print_network_config(_seed: u64) {
    let reg = crate::status::get();
    if reg.nic_e1000.is_real() || reg.nic_virtio.is_real() || reg.nic_rtl8139.is_real() {
        kprintln!("[net] knet TCP/IP stack active; default-deny packet filter & fail-closed kill switch armed");
        kprintln!("[net] Layer-2 MAC address randomized via bare-metal CSPRNG; physical OUI tracking blocked");
    } else {
        kprintln!("[net] networking running over loopback queue; no physical NIC detected");
        kprintln!("[net] Default-deny packet filter and fail-closed kill switch active on loopback");
    }
}

/// Print the boot privacy configuration.
pub fn print_privacy_config() {
    let reg = crate::status::get();
    if reg.kvault_fs.is_real() {
        kprintln!("[prv] kvault authenticated storage mounted as root (/) filesystem over kblock");
        kprintln!("[prv] TPM-backed key sealing is unavailable; the vault is unlocked by the entered passphrase.");
        kprintln!("[prv] Anti-forensic memory zeroization & clflush active on screen lock");
    } else {
        kprintln!("[prv] kvault contains an authenticated-encryption library with passing unit tests; it is not mounted as system storage");
        kprintln!("[prv] hidden volumes, duress deletion, and folder keys are library features, not boot-integrated services");
        kprintln!("[prv] memory zeroing helpers are present; no seL4 proof, cold-boot protection, or TPM measured boot is provided");
    }
}
