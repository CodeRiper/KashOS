//! Central Subsystem Status Registry (Rule R1: Single Source of Truth).
//!
//! Enforces:
//! - R1: No unproven claims. Never print [OK] / active / verified / ready unless the code just checked it.
//! - One status registry (Real / Partial / Stub / NotAvailable) that boot banners, shell, and docs read from.
//! - R3: No invented output. If a feature isn't implemented, report STUB / NOT IMPLEMENTED.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ComponentStatus {
    /// Fully implemented and verified by live hardware/software checks.
    Real,
    /// Partially implemented; specific limitations or caveats exist.
    Partial,
    /// Interface or stub defined; underlying logic is NOT implemented.
    Stub,
    /// Hardware feature or peripheral requested but not detected on this machine.
    NotAvailable,
}

impl ComponentStatus {
    pub fn label(&self) -> &'static str {
        match self {
            ComponentStatus::Real => "[OK]",
            ComponentStatus::Partial => "[PARTIAL]",
            ComponentStatus::Stub => "[STUB]",
            ComponentStatus::NotAvailable => "[NOT AVAILABLE]",
        }
    }

    pub fn is_real(&self) -> bool {
        matches!(self, ComponentStatus::Real)
    }
}

/// Global registry recording conservative implementation state for KashOS components.
#[derive(Copy, Clone, Debug)]
pub struct StatusRegistry {
    pub wx_paging: ComponentStatus,
    pub gdt_tss: ComponentStatus,
    pub idt_interrupts: ComponentStatus,
    pub apic_timer: ComponentStatus,
    pub kcore_caps: ComponentStatus,
    pub linear_framebuffer: ComponentStatus,
    pub hw_entropy: ComponentStatus,
    pub tresor_debug_regs: ComponentStatus,
    pub vtd_iommu: ComponentStatus,
    pub nic_e1000: ComponentStatus,
    pub nic_virtio: ComponentStatus,
    pub nic_rtl8139: ComponentStatus,
    pub ps2_input: ComponentStatus,
    pub xhci_usb: ComponentStatus,
    pub uefi_boot: ComponentStatus,
    pub bios_pvh_boot: ComponentStatus,
    pub pledge_unveil: ComponentStatus,
    pub zero_trust_powerbox: ComponentStatus,
    pub dde_linux: ComponentStatus,
    pub apple_safety_dsp: ComponentStatus,
    pub flask_mac: ComponentStatus,
    pub kapp_capsules: ComponentStatus,
    pub multilang_runtimes: ComponentStatus,
    pub wayland_compositor: ComponentStatus,
    pub liquid_glass_gui: ComponentStatus,
    pub kvault_fs: ComponentStatus,
    pub spec_mitigations: ComponentStatus,
    pub lockdown_mode: ComponentStatus,
    pub security_toolkit: ComponentStatus,
    pub kscheduler_preempt: ComponentStatus,
    pub smp_multicore: ComponentStatus,
    pub quota_frames: ComponentStatus,
    pub user_mode_ring3: ComponentStatus,
    pub elf_loader: ComponentStatus,
    pub sync_ipc: ComponentStatus,
    pub user_drivers: ComponentStatus,
    pub tpm2_crtm: ComponentStatus,
    pub measured_boot: ComponentStatus,
}

impl StatusRegistry {
    pub const fn new() -> Self {
        Self {
            wx_paging: ComponentStatus::Partial,
            gdt_tss: ComponentStatus::Partial,
            idt_interrupts: ComponentStatus::Partial,
            apic_timer: ComponentStatus::Partial,
            kcore_caps: ComponentStatus::Partial,
            linear_framebuffer: ComponentStatus::NotAvailable,
            hw_entropy: ComponentStatus::NotAvailable,
            tresor_debug_regs: ComponentStatus::Partial,
            vtd_iommu: ComponentStatus::NotAvailable,
            nic_e1000: ComponentStatus::NotAvailable,
            nic_virtio: ComponentStatus::NotAvailable,
            nic_rtl8139: ComponentStatus::NotAvailable,
            ps2_input: ComponentStatus::Partial,
            xhci_usb: ComponentStatus::Stub,
            uefi_boot: ComponentStatus::Stub,
            bios_pvh_boot: ComponentStatus::Partial,
            pledge_unveil: ComponentStatus::Stub,
            zero_trust_powerbox: ComponentStatus::Partial,
            dde_linux: ComponentStatus::Stub,
            apple_safety_dsp: ComponentStatus::NotAvailable,
            flask_mac: ComponentStatus::Partial,
            kapp_capsules: ComponentStatus::Partial,
            multilang_runtimes: ComponentStatus::Stub,
            wayland_compositor: ComponentStatus::Stub,
            liquid_glass_gui: ComponentStatus::Partial,
            kvault_fs: ComponentStatus::Partial,
            spec_mitigations: ComponentStatus::Partial,
            lockdown_mode: ComponentStatus::Partial,
            security_toolkit: ComponentStatus::Stub,
            kscheduler_preempt: ComponentStatus::Partial,
            smp_multicore: ComponentStatus::Partial,
            quota_frames: ComponentStatus::Partial,
            user_mode_ring3: ComponentStatus::Stub,
            elf_loader: ComponentStatus::Stub,
            sync_ipc: ComponentStatus::Stub,
            user_drivers: ComponentStatus::Stub,
            tpm2_crtm: ComponentStatus::Stub,
            measured_boot: ComponentStatus::Stub,
        }
    }
}

use crate::blockdev::SpinLock;

static REGISTRY: SpinLock<StatusRegistry> = SpinLock::new(StatusRegistry::new());

/// Retrieve a copy of the current system status registry safely without unsafe data races.
pub fn get() -> StatusRegistry {
    *REGISTRY.lock()
}

/// Mutate status of a component based on real hardware/self-test outcome under thread-safe spinlock.
pub fn update<F: FnOnce(&mut StatusRegistry)>(f: F) {
    let mut guard = REGISTRY.lock();
    f(&mut *guard);
}

/// Print the official boot banner strictly reading from the status registry.
/// Never prints [OK] unless status == ComponentStatus::Real.
pub fn print_boot_banner() {
    let reg = get();
    crate::kprintln!();
    crate::kprintln!("+==============================================================================+");
    crate::kprintln!("|                    KASH OS COMPONENT STATUS REGISTRY                         |");
    crate::kprintln!("|                    (development build; conservative status)                  |");
    crate::kprintln!("+==============================================================================+");

    let entries = [
        ("W^X Paging & Memory Protection", reg.wx_paging, "kernel page tables; no proof claim"),
        ("GDT + TSS Stack Handling", reg.gdt_tss, "TSS RSP0 & IST stacks active"),
        ("IDT & Interrupt / Exception Handlers", reg.idt_interrupts, "kernel exception handling"),
        ("Timer & RTC", reg.apic_timer, "platform timer and RTC support varies"),
        ("Preemptive QoS Scheduler", reg.kscheduler_preempt, "3-band timer preemption"),
        ("SMP Multicore Processor Cores", reg.smp_multicore, "ACPI MADT multi-core discovery"),
        ("Physical Frame Domain Quotas", reg.quota_frames, "per-domain frame quotas"),
        ("Ring 3 User Mode & Syscalls", reg.user_mode_ring3, "Ring 3 isolation & fault containment"),
        ("ELF64 Loader & W^X Enforcement", reg.elf_loader, "validates ELF64 and enforces W^X"),
        ("Capability Engine", reg.kcore_caps, "handles, CSpace, revocation & IPC"),
        ("Synchronous Rendezvous IPC", reg.sync_ipc, "badged endpoints & cap transfer"),
        ("Linear Framebuffer Desktop Shell", reg.linear_framebuffer, "Liquid-Glass GUI compositor surface"),
        ("Hardware Cryptographic Entropy", reg.hw_entropy, "RDRAND / RDSEED / VirtIO-RNG"),
        ("Register Key Staging", reg.tresor_debug_regs, "experimental; not a hardware security claim"),
        ("Intel VT-d IOMMU DMA Containment", reg.vtd_iommu, "ACPI DMAR table & SLPT translation"),
        ("Intel e1000 Gigabit NIC Driver", reg.nic_e1000, "PCI 82540EM/82545GB DMA rings"),
        ("VirtIO-Net Paravirtualized NIC", reg.nic_virtio, "VirtIO split virtqueue driver"),
        ("Realtek RTL-8139 Fast Ethernet", reg.nic_rtl8139, "PCI RTL8139 100Mbps ring buffer"),
        ("PS/2 Keyboard & Mouse Driver", reg.ps2_input, "legacy input support; hardware varies"),
        ("USB xHCI Controller Driver", reg.xhci_usb, "xHCI host controller & HID parser"),
        ("BIOS / PVH Bootloader Chain", reg.bios_pvh_boot, "boot path depends on target and firmware"),
        ("UEFI BOOTX64.EFI Secure Loader", reg.uefi_boot, "UEFI PE32+ loader (Part B15)"),
        ("Pledge / Unveil-style Restrictions", reg.pledge_unveil, "no user process syscall enforcement"),
        ("Zero-Trust Powerbox Broker", reg.zero_trust_powerbox, "Out-of-process mediator"),
        ("Linux Device Driver Environment (DDE)", reg.dde_linux, "DDE-Linux C driver container"),
        ("Apple Transducer Safety Engine", reg.apple_safety_dsp, "TAS2764 speakersafetyd DSP"),
        ("FLASK Mandatory Access Control", reg.flask_mac, "Type enforcement & security IDs"),
        ("Capability Capsules (.kapp)", reg.kapp_capsules, "Ed25519 signature verified or rejected"),
        ("Multi-Language ELF Runtimes", reg.multilang_runtimes, "Userspace relibc / Musl layer"),
        ("Smithay-Style Wayland Compositor", reg.wayland_compositor, "External Wayland client protocol"),
        ("Kash UI Desktop", reg.liquid_glass_gui, "direct framebuffer renderer; app services incomplete"),
        ("kvault Authenticated Storage", reg.kvault_fs, "root VFS mount & tamper gate"),
        ("Speculative Execution Mitigations", reg.spec_mitigations, "best-effort CPU controls; not independently verified"),
        ("Strict Security Lockdown Mode", reg.lockdown_mode, "W^X violation blocks & port gating"),
        ("Security Diagnostic Toolkit", reg.security_toolkit, "Sandboxed security testing capsule (Part E)"),
        ("User Driver Services & Resilience", reg.user_drivers, "Ring 3 storage, net, input, display"),
        ("TPM 2.0 Hardware & CRTM Engine", reg.tpm2_crtm, "TCG TIS MMIO & SHA-256 PCR bank"),
        ("Anti-Evil Maid Measured Boot", reg.measured_boot, "PCR policy sealing & fail-closed key release"),
    ];

    for (name, status, detail) in entries {
        let tag = match status {
            ComponentStatus::Real => "[OK]       ",
            ComponentStatus::Partial => "[PARTIAL]  ",
            ComponentStatus::Stub => "[NOT IMPL] ",
            ComponentStatus::NotAvailable => "[NOT AVAIL]",
        };
        crate::kprintln!("| {:<11} {:<36} : {:<22} |", tag, name, detail);
    }
    crate::kprintln!("+==============================================================================+");
}
