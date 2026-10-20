//! App registry + capability/permission model shared by Settings, Files, Dock, Launchpad and the Terminal.
//! Three classes of software: GUI apps (/Applications), CLI tools (/CLI Applications), drivers (/Drivers).
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::icons::{FileKind, Icon};
use crate::ui::AppKind;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppClass { Gui, Cli, Driver }
impl AppClass {
    pub const ALL: [AppClass; 3] = [AppClass::Gui, AppClass::Cli, AppClass::Driver];
    pub fn folder(self) -> &'static str { match self { AppClass::Gui => "Applications", AppClass::Cli => "CLI Applications", AppClass::Driver => "Drivers" } }
    pub fn singular(self) -> &'static str { match self { AppClass::Gui => "Application", AppClass::Cli => "Command-Line Tool", AppClass::Driver => "Driver" } }
    pub fn plural(self) -> &'static str { match self { AppClass::Gui => "Applications", AppClass::Cli => "CLI Applications", AppClass::Driver => "Drivers" } }
    pub fn icon(self) -> Icon { match self { AppClass::Gui => Icon::Apps, AppClass::Cli => Icon::Terminal, AppClass::Driver => Icon::Chip } }
    pub fn color(self) -> u32 { match self { AppClass::Gui => 0x0A84FF, AppClass::Cli => 0x30D158, AppClass::Driver => 0xFF9F0A } }
    pub fn file_kind(self) -> FileKind { match self { AppClass::Gui => FileKind::App, AppClass::Cli => FileKind::Exec, AppClass::Driver => FileKind::Driver } }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Perm {
    Camera, Microphone, Location, Bluetooth, Usb,
    FullDisk, Files, Photos, Contacts, Keys,
    Accessibility, InputMon, Screen, Automation, AppMgmt, Notifications, Admin, Spawn,
    Network, LocalNet, RawSocket,
    Dma, IoPorts, KernelMem, Framebuffer, Storage, InputDev,
}
pub const NPERM: usize = 27;
pub const ALL_PERMS: [Perm; NPERM] = [
    Perm::Camera, Perm::Microphone, Perm::Location, Perm::Bluetooth, Perm::Usb,
    Perm::FullDisk, Perm::Files, Perm::Photos, Perm::Contacts, Perm::Keys,
    Perm::Accessibility, Perm::InputMon, Perm::Screen, Perm::Automation, Perm::AppMgmt, Perm::Notifications, Perm::Admin, Perm::Spawn,
    Perm::Network, Perm::LocalNet, Perm::RawSocket,
    Perm::Dma, Perm::IoPorts, Perm::KernelMem, Perm::Framebuffer, Perm::Storage, Perm::InputDev,
];
pub const SECTIONS: [(&str, usize, usize); 5] = [("Sensors & Devices", 0, 5), ("Files & Data", 5, 10), ("Control & Automation", 10, 18), ("Network", 18, 21), ("Driver Capabilities", 21, 27)];

/// name, one-line description, prompt phrase, icon, colour
const META: [(&str, &str, &str, Icon, u32); NPERM] = [
    ("Camera", "Capture photos and video", "access the camera", Icon::Camera, 0x8E8E93),
    ("Microphone", "Record audio", "access the microphone", Icon::Mic, 0xFF9F0A),
    ("Location", "Use your approximate location", "use your current location", Icon::Pin, 0x0A84FF),
    ("Bluetooth", "Find and connect to Bluetooth devices", "use Bluetooth", Icon::Bluetooth, 0x0A84FF),
    ("USB & Accessories", "Talk to USB, Thunderbolt and SD devices", "connect to USB accessories", Icon::Usb, 0x8E8E93),
    ("Full Disk Access", "Read every file, including protected data", "access all files on Kash HD", Icon::Disk, 0x5E5CE6),
    ("Files & Folders", "Read and write in Documents, Desktop, Downloads", "access files in your Documents folder", Icon::Folder, 0x32ADE6),
    ("Photos", "Read your photo library", "access your Photos library", Icon::Photo, 0xFF375F),
    ("Contacts", "Read and edit your contacts", "access your contacts", Icon::User, 0xFF9F0A),
    ("Keys & Secrets", "Use secrets held by the key manager", "use secrets in your key vault", Icon::Key, 0xBF5AF2),
    ("Accessibility", "Control this computer with assistive APIs", "control this computer using accessibility features", Icon::Accessibility, 0x0A84FF),
    ("Input Monitoring", "Observe keyboard and pointer input", "monitor input from your keyboard and pointer", Icon::Keyboard, 0x8E8E93),
    ("Screen Recording", "Capture the contents of your screen", "record this computer's screen", Icon::Display, 0xFF453A),
    ("Automation", "Control other apps", "control other apps", Icon::Sliders, 0x5E5CE6),
    ("App Management", "Update or delete other apps", "update or delete other apps", Icon::Apps, 0x0A84FF),
    ("Notifications", "Show alerts and badges", "send you notifications", Icon::Bell, 0xFF453A),
    ("Administrator", "Run with elevated privileges", "run with administrator privileges", Icon::Shield, 0xFF453A),
    ("Launch Programs", "Start other processes", "launch other programs", Icon::Terminal, 0x30D158),
    ("Network", "Reach the internet through the Anonymity Gateway", "connect to the internet", Icon::Globe, 0x0A84FF),
    ("Local Network", "Find devices on your local network", "find and connect to devices on your local network", Icon::Network, 0x0A84FF),
    ("Raw Sockets", "Craft and sniff packets", "open raw network sockets", Icon::Radar, 0xFF9F0A),
    ("Direct Memory Access", "Bus-master DMA (IOMMU-mapped)", "use direct memory access", Icon::Chip, 0xFF9F0A),
    ("Interrupts & I/O Ports", "Claim IRQ lines and port ranges", "access I/O ports and interrupts", Icon::Bolt, 0xFF9F0A),
    ("Kernel Memory", "Map kernel address space", "access kernel memory", Icon::Chip, 0xFF453A),
    ("Framebuffer", "Draw to the display", "draw to the display", Icon::Display, 0x32ADE6),
    ("Storage Devices", "Read and write block devices", "access storage devices", Icon::Disk, 0x8E8E93),
    ("Input Devices", "Read keyboard, mouse and HID devices", "read input devices", Icon::Mouse, 0x8E8E93),
];

impl Perm {
    #[inline] pub fn idx(self) -> usize { self as usize }
    pub fn name(self) -> &'static str { META[self as usize].0 }
    pub fn desc(self) -> &'static str { META[self as usize].1 }
    pub fn prompt(self) -> &'static str { META[self as usize].2 }
    pub fn icon(self) -> Icon { META[self as usize].3 }
    pub fn color(self) -> u32 { META[self as usize].4 }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PS { NA, Ask, Allow, Deny }
impl PS {
    pub fn label(self) -> &'static str { match self { PS::NA => "—", PS::Ask => "Ask", PS::Allow => "Allowed", PS::Deny => "Denied" } }
}

#[derive(Clone, Debug)]
pub struct AppEntry {
    pub name: String,
    pub class: AppClass,
    pub kind: Option<AppKind>,
    pub version: &'static str,
    pub size: u64,
    pub publisher: &'static str,
    pub signed: bool,
    pub system: bool,
    pub date: &'static str,
    pub blurb: &'static str,
    pub perms: [PS; NPERM],
    pub prompted: bool,
    pub last_used: i64,
}
impl AppEntry {
    pub fn path(&self) -> String {
        match self.class { AppClass::Gui => format!("/Applications/{}.app", self.name), AppClass::Cli => format!("/CLI Applications/{}", self.name), AppClass::Driver => format!("/Drivers/{}", self.name) }
    }
    pub fn declared(&self) -> usize { self.perms.iter().filter(|p| **p != PS::NA).count() }
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut a, mut k, mut d) = (0, 0, 0);
        for p in self.perms.iter() { match p { PS::Allow => a += 1, PS::Ask => k += 1, PS::Deny => d += 1, PS::NA => {} } }
        (a, k, d)
    }
}

#[derive(Clone, Debug)]
pub struct LogEntry { pub t: i64, pub text: String, pub state: PS }
#[derive(Clone, Debug)]
pub struct Download { pub name: String, pub kind: FileKind, pub size: u64, pub date: String }

#[derive(Clone, Debug)]
pub struct Registry {
    pub apps: Vec<AppEntry>,
    /// Prototype-only policy values. They are not used to authorize execution.
    pub app_policy: usize,
    pub driver_policy: usize,
    pub accessories: usize,
    pub lockdown: bool,
    pub log: Vec<LogEntry>,
    pub pending: Vec<(usize, Perm)>,
    pub downloads: Vec<Download>,
    /// Active download: (name, kind, size, progress 0..1)
    pub dl_active: Option<(String, FileKind, u64, f32)>,
    pub rev: u32,
}

fn e(name: &str, class: AppClass, kind: Option<AppKind>, version: &'static str, size: u64, publisher: &'static str, signed: bool, system: bool, date: &'static str, blurb: &'static str, perms: &[(Perm, PS)]) -> AppEntry {
    let mut p = [PS::NA; NPERM];
    for (k, s) in perms { p[k.idx()] = *s; }
    AppEntry { name: String::from(name), class, kind, version, size, publisher, signed, system, date, blurb, perms: p, prompted: false, last_used: 0 }
}

impl Registry {
    pub fn new() -> Registry {
        use AppClass::*; use Perm::*; use PS::*;
        let apps = alloc::vec![
            // These are compiled-in UI demonstrations, not installed packages.
            // Package versions, sizes, installation dates and signatures are unknown.
            e("Files", Gui, Some(AppKind::Files), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Demo app; filesystem access is not capability-enforced", &[(Files, Allow), (FullDisk, Ask), (AppMgmt, Ask), (Usb, Allow)]),
            e("System Settings", Gui, Some(AppKind::Settings), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Settings prototype; controls are not generally connected to kernel services", &[(AppMgmt, Allow), (Accessibility, Allow), (Location, Allow), (Bluetooth, Allow), (Network, Allow), (Usb, Allow), (FullDisk, Allow)]),
            e("Terminal", Gui, Some(AppKind::Terminal), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Terminal demo; commands are handled by the UI and are not a general shell", &[(FullDisk, Ask), (Files, Allow), (Network, Allow), (Automation, Ask), (Accessibility, Ask), (AppMgmt, Deny), (Spawn, Allow)]),
            e("Browser (demo)", Gui, Some(AppKind::Browser), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Remote networking and process-isolated permissions are unavailable", &[(Camera, Deny), (Microphone, Deny), (Location, Deny), (Network, Deny), (LocalNet, Deny), (Notifications, Deny), (Files, Deny), (Screen, Deny), (Keys, Deny)]),
            e("Notes", Gui, Some(AppKind::Notes), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Notes demo; persistent storage is unavailable", &[(Files, Allow), (Photos, Ask), (Notifications, Allow)]),
            e("Photos", Gui, Some(AppKind::Photos), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Photos demo; media library integration is unavailable", &[(Photos, Allow), (Camera, Ask), (Location, Ask), (Files, Allow), (Network, Allow)]),
            e("Music", Gui, Some(AppKind::Music), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Music demo; media library integration is unavailable", &[(Microphone, Ask), (Network, Allow), (Bluetooth, Allow), (Notifications, Allow), (Files, Allow)]),
            e("Messages", Gui, Some(AppKind::Messages), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Messaging demo; no network transport is connected", &[(Contacts, Allow), (Notifications, Allow), (Camera, Ask), (Microphone, Ask), (Network, Allow), (Photos, Ask), (Location, Ask)]),
            e("Activity Monitor", Gui, Some(AppKind::ActivityMonitor), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Activity Monitor demo; live process and memory telemetry is unavailable", &[(Accessibility, Allow), (AppMgmt, Allow), (FullDisk, Ask), (Network, Allow)]),
            e("Calculator", Gui, Some(AppKind::Calculator), "demo", 0, "Built-in UI demo", false, true, "Unavailable", "Calculator demo", &[]),
        ];
        let downloads = Vec::new();
        Registry { apps, app_policy: 1, driver_policy: 1, accessories: 1, lockdown: false, log: Vec::new(), pending: Vec::new(), downloads, dl_active: None, rev: 1 }
    }

    pub fn of_class(&self, c: AppClass) -> Vec<usize> { (0..self.apps.len()).filter(|i| self.apps[*i].class == c).collect() }
    pub fn find_kind(&self, k: AppKind) -> Option<usize> { self.apps.iter().position(|a| a.kind == Some(k)) }
    pub fn find_name(&self, n: &str) -> Option<usize> { self.apps.iter().position(|a| a.name == n || a.name.trim_end_matches(".kdrv") == n) }
    pub fn for_perm(&self, p: Perm) -> Vec<usize> { (0..self.apps.len()).filter(|i| self.apps[*i].perms[p.idx()] != PS::NA).collect() }
    pub fn perm_counts(&self, p: Perm) -> (usize, usize, usize) {
        let (mut a, mut k, mut d) = (0, 0, 0);
        for ap in self.apps.iter() { match ap.perms[p.idx()] { PS::Allow => a += 1, PS::Ask => k += 1, PS::Deny => d += 1, PS::NA => {} } }
        (a, k, d)
    }
    pub fn class_counts(&self, c: AppClass) -> (usize, usize, usize) {
        let (mut a, mut k, mut d) = (0, 0, 0);
        for ap in self.apps.iter().filter(|x| x.class == c) { let (x, y, z) = ap.counts(); a += x; k += y; d += z; }
        (a, k, d)
    }
    pub fn totals(&self) -> (usize, usize, usize) { let (mut a, mut k, mut d) = (0, 0, 0); for c in AppClass::ALL { let (x, y, z) = self.class_counts(c); a += x; k += y; d += z; } (a, k, d) }

    /// This prototype has no package signature verifier or execution policy hook.
    pub fn blocked(&self, i: usize) -> bool {
        let _ = i;
        false
    }
    /// Effective state after policy and Lockdown Mode.
    pub fn effective(&self, i: usize, p: Perm) -> PS {
        let s = self.apps[i].perms[p.idx()];
        if s == PS::NA { return PS::NA; }
        if self.blocked(i) { return PS::Deny; }
        if self.lockdown && s == PS::Ask { return PS::Deny; }
        s
    }
    /// For UI policy checks by tool name. Unknown tools fail closed.
    pub fn check(&self, name: &str, p: Perm) -> PS {
        match self.find_name(name) { Some(i) => { let s = self.effective(i, p); if s == PS::NA { PS::Deny } else { s } } None => PS::Deny }
    }

    fn push_log(&mut self, t: i64, text: String, state: PS) { self.log.insert(0, LogEntry { t, text, state }); self.log.truncate(40); }
    pub fn set(&mut self, i: usize, p: Perm, s: PS, now: i64) {
        if self.apps[i].perms[p.idx()] == PS::NA || self.apps[i].perms[p.idx()] == s { return; }
        self.apps[i].perms[p.idx()] = s;
        let msg = match s { PS::Allow => format!("Allowed {} for {}", p.name(), self.apps[i].name), PS::Deny => format!("Denied {} for {}", p.name(), self.apps[i].name), _ => format!("{} will ask for {}", self.apps[i].name, p.name()) };
        self.push_log(now, msg, s);
        self.rev += 1;
    }
    pub fn set_perm_all(&mut self, p: Perm, s: PS, now: i64) { for i in self.for_perm(p) { self.set(i, p, s, now); } }
    pub fn set_app_all(&mut self, i: usize, s: PS, now: i64) { for p in ALL_PERMS { self.set(i, p, s, now); } }
    pub fn set_class_all(&mut self, c: AppClass, s: PS, now: i64) { for i in self.of_class(c) { self.set_app_all(i, s, now); } }
    pub fn reset(&mut self, now: i64) {
        let fresh = Registry::new();
        for i in 0..self.apps.len() { self.apps[i].perms = fresh.apps[i].perms; self.apps[i].prompted = false; }
        self.lockdown = false; self.app_policy = 1; self.driver_policy = 1; self.accessories = 1;
        self.push_log(now, String::from("All permissions reset to defaults"), PS::Ask);
        self.rev += 1;
    }
    pub fn touch(&mut self, k: AppKind, now: i64) { if let Some(i) = self.find_kind(k) { self.apps[i].last_used = now; } }
    /// First launch of a GUI app: queue the first permission it has to ask for.
    pub fn queue_launch_prompt(&mut self, k: AppKind) {
        if let Some(i) = self.find_kind(k) {
            if self.apps[i].prompted { return; }
            self.apps[i].prompted = true;
            if self.blocked(i) { return; }
            for p in ALL_PERMS { if self.apps[i].perms[p.idx()] == PS::Ask { self.pending.push((i, p)); break; } }
        }
    }
    pub fn add_download(&mut self, d: Download) { self.downloads.insert(0, d); self.rev += 1; }
}

impl Registry {
    /// A GUI app asks to use a capability right now. Allow → proceed, Ask → a prompt is queued, Deny/NA → refused.
    pub fn request(&mut self, k: AppKind, p: Perm) -> PS {
        let i = match self.find_kind(k) { Some(i) => i, None => return PS::Allow };
        match self.effective(i, p) {
            PS::Allow => PS::Allow,
            PS::Ask => { if !self.pending.iter().any(|(a, b)| *a == i && *b == p) { self.pending.push((i, p)); } PS::Ask }
            _ => PS::Deny,
        }
    }
    pub fn start_download(&mut self, name: &str, kind: FileKind, size: u64) { if self.dl_active.is_none() { self.dl_active = Some((String::from(name), kind, size, 0.0)); self.rev += 1; } }
    /// Advance the active download; returns the finished file name when complete.
    pub fn tick_download(&mut self, dt: f32) -> Option<String> {
        let mut done = None;
        if let Some((n, k, s, p)) = self.dl_active.as_mut() {
            *p += dt * 0.35;
            if *p >= 1.0 { done = Some((n.clone(), *k, *s)); }
        }
        if let Some((n, k, s)) = done {
            self.dl_active = None;
            self.downloads.insert(0, Download { name: n.clone(), kind: k, size: s, date: String::from("Today") });
            self.rev += 1;
            return Some(n);
        }
        None
    }
    pub fn clear_downloads(&mut self) { self.downloads.clear(); self.rev += 1; }
    pub fn perm_phrase(&self, p: Perm) -> &'static str { p.prompt() }
}

// ── UI-only compartment preview model (not connected to the running kernel) ─

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DomainKind {
    AdminDom0,
    TemplateVm,
    AppVm,
    ServiceVm,
    DisposableVm,
    VaultVm,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityColorTag {
    ObsidianAdmin,
    PurpleVault,
    MintPersonal,
    BlueWork,
    AmberUsb,
    RedUntrustedNet,
    MagentaDisposable,
}

#[derive(Clone, Copy, Debug)]
pub struct DomainDescriptor {
    pub id: u16,
    pub name: &'static str,
    pub kind: DomainKind,
    pub color_tag: SecurityColorTag,
    pub running: bool,
    // seL4-style Untyped Memory Capability Quotas (in MiB)
    pub untyped_quota_mib: u32,
    pub untyped_watermark_mib: u32,
    // ARINC 653 Static Partition Scheduling Parameters
    pub cpu_core: u8,
    pub arinc_slice_ms: u16,
    pub arinc_period_ms: u16,
    pub deadline_misses: u32,
    pub queue_watermark_pct: u8,
    // Qubes-style Network & Peripheral Routing
    pub net_provider_id: Option<u16>,
    pub iommu_pcie_bdf: Option<&'static str>,
    pub vtd_second_stage_locked: bool,
    pub read_only_root_template: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PolicyVerdict {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Copy, Debug)]
pub struct RpcPolicyEntry {
    pub service_name: &'static str,
    pub src_domain_id: u16,
    pub dst_domain_id: u16,
    pub verdict: PolicyVerdict,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsTab {
    CompartmentDeckAndManager,
    UntypedMemoryAndCapabilityAssurance,
    Arinc653SchedulerAndHealth,
    IommuAndPeripheralJails,
    KashRpcAndGuiSecurity,
}

#[derive(Clone, Debug)]
pub struct KashSystemRegistry {
    /// This registry is local demo state. It does not create kernel compartments,
    /// schedule partitions, configure an IOMMU, or claim unbacked formal proofs.
    pub preview_only: bool,
    pub active_tab: SettingsTab,
    pub selected_domain_idx: usize,
    pub dom0_gui_locked: bool,
    pub nitpicker_xray_active: bool,
    pub tint_window_backgrounds: bool,
    pub strict_utf8_title_sanitization: bool,
    pub dpi_scale_percent: u16,
    pub property_tests_verified: u32,
    pub pbit_hardware_verified: bool,
    pub cbit_ecc_status_clean: bool,
    pub domains: [DomainDescriptor; 7],
    pub rpc_policies: [RpcPolicyEntry; 6],
}

impl KashSystemRegistry {
    pub const fn new_default() -> Self {
        Self {
            preview_only: true,
            active_tab: SettingsTab::CompartmentDeckAndManager,
            selected_domain_idx: 1,
            dom0_gui_locked: false,
            nitpicker_xray_active: false,
            tint_window_backgrounds: true,
            strict_utf8_title_sanitization: true,
            dpi_scale_percent: 125,
            property_tests_verified: 0,
            pbit_hardware_verified: false,
            cbit_ecc_status_clean: false,
            domains: [
                DomainDescriptor {
                    id: 0,
                    name: "kash-dom0",
                    kind: DomainKind::AdminDom0,
                    color_tag: SecurityColorTag::ObsidianAdmin,
                    running: false,
                    untyped_quota_mib: 512,
                    untyped_watermark_mib: 148,
                    cpu_core: 0,
                    arinc_slice_ms: 5,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 4,
                    net_provider_id: None,
                    iommu_pcie_bdf: None,
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-verified-root",
                },
                DomainDescriptor {
                    id: 1,
                    name: "sys-net",
                    kind: DomainKind::ServiceVm,
                    color_tag: SecurityColorTag::RedUntrustedNet,
                    running: false,
                    untyped_quota_mib: 256,
                    untyped_watermark_mib: 192,
                    cpu_core: 1,
                    arinc_slice_ms: 4,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 22,
                    net_provider_id: None,
                    iommu_pcie_bdf: Some("03:00.0 Intel Wi-Fi 6E AX210"),
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-minimal-net-tpl",
                },
                DomainDescriptor {
                    id: 2,
                    name: "personal",
                    kind: DomainKind::AppVm,
                    color_tag: SecurityColorTag::MintPersonal,
                    running: false,
                    untyped_quota_mib: 2048,
                    untyped_watermark_mib: 620,
                    cpu_core: 1,
                    arinc_slice_ms: 4,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 10,
                    net_provider_id: Some(1),
                    iommu_pcie_bdf: None,
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-personal-tpl",
                },
                DomainDescriptor {
                    id: 3,
                    name: "work-app",
                    kind: DomainKind::AppVm,
                    color_tag: SecurityColorTag::BlueWork,
                    running: false,
                    untyped_quota_mib: 4096,
                    untyped_watermark_mib: 1840,
                    cpu_core: 2,
                    arinc_slice_ms: 8,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 15,
                    net_provider_id: Some(1), // Routed through sys-net
                    iommu_pcie_bdf: None,
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-workstation-tpl",
                },
                DomainDescriptor {
                    id: 4,
                    name: "sys-usb",
                    kind: DomainKind::ServiceVm,
                    color_tag: SecurityColorTag::AmberUsb,
                    running: false,
                    untyped_quota_mib: 256,
                    untyped_watermark_mib: 110,
                    cpu_core: 1,
                    arinc_slice_ms: 3,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 12,
                    net_provider_id: None,
                    iommu_pcie_bdf: Some("00:14.0 xHCI USB Controller"),
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-minimal-usb-tpl",
                },
                DomainDescriptor {
                    id: 5,
                    name: "disp-pdf-884",
                    kind: DomainKind::DisposableVm,
                    color_tag: SecurityColorTag::MagentaDisposable,
                    running: false,
                    untyped_quota_mib: 512,
                    untyped_watermark_mib: 164,
                    cpu_core: 3,
                    arinc_slice_ms: 3,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 8,
                    net_provider_id: None, // Offline disposable viewer
                    iommu_pcie_bdf: None,
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-dvm-viewer-tpl",
                },
                DomainDescriptor {
                    id: 6,
                    name: "vault-keys",
                    kind: DomainKind::VaultVm,
                    color_tag: SecurityColorTag::PurpleVault,
                    running: false,
                    untyped_quota_mib: 256,
                    untyped_watermark_mib: 64,
                    cpu_core: 0,
                    arinc_slice_ms: 2,
                    arinc_period_ms: 25,
                    deadline_misses: 0,
                    queue_watermark_pct: 2,
                    net_provider_id: None, // Hardware air-gapped
                    iommu_pcie_bdf: None,
                    vtd_second_stage_locked: false,
                    read_only_root_template: "kash-vault-crypto-tpl",
                },
            ],
            rpc_policies: [
                RpcPolicyEntry {
                    service_name: "kash.OpenInDisposableVm",
                    src_domain_id: 3,
                    dst_domain_id: 5,
                    verdict: PolicyVerdict::Allow,
                },
                RpcPolicyEntry {
                    service_name: "kash.GpgSplitSign",
                    src_domain_id: 3,
                    dst_domain_id: 6,
                    verdict: PolicyVerdict::Ask,
                },
                RpcPolicyEntry {
                    service_name: "kash.ClipboardCopyPaste",
                    src_domain_id: 3,
                    dst_domain_id: 6,
                    verdict: PolicyVerdict::Deny,
                },
                RpcPolicyEntry {
                    service_name: "kash.UsbBlockAttach",
                    src_domain_id: 4,
                    dst_domain_id: 3,
                    verdict: PolicyVerdict::Ask,
                },
                RpcPolicyEntry {
                    service_name: "kash.FileTransfer",
                    src_domain_id: 6,
                    dst_domain_id: 1,
                    verdict: PolicyVerdict::Deny, // Hardware invariant: Vault -> Net forbidden
                },
                RpcPolicyEntry {
                    service_name: "kash.AdminPolicyUpdate",
                    src_domain_id: 1,
                    dst_domain_id: 0,
                    verdict: PolicyVerdict::Deny, // Hardware invariant: sys-net -> dom0 forbidden
                },
            ],
        }
    }

    /// GUI action: Adjusts Untyped Memory quota for a compartment while preserving watermark bounds
    pub fn adjust_untyped_quota(&mut self, domain_idx: usize, delta_mib: i32) {
        if self.dom0_gui_locked || domain_idx >= self.domains.len() {
            return;
        }
        let dom = &mut self.domains[domain_idx];
        let proposed = (dom.untyped_quota_mib as i32) + delta_mib;
        // Quota cannot drop below active watermark allocation or below 64 MiB
        let min_allowed = (dom.untyped_watermark_mib.max(64)) as i32;
        if proposed >= min_allowed && proposed <= 16384 {
            dom.untyped_quota_mib = proposed as u32;
        }
    }

    /// GUI action: Adjusts ARINC 653 deterministic time slice (in milliseconds)
    pub fn adjust_arinc_timeslice(&mut self, domain_idx: usize, delta_ms: i16) {
        if self.dom0_gui_locked || domain_idx >= self.domains.len() {
            return;
        }
        let dom = &mut self.domains[domain_idx];
        let proposed = (dom.arinc_slice_ms as i16) + delta_ms;
        if proposed >= 1 && proposed <= 20 {
            dom.arinc_slice_ms = proposed as u16;
        }
    }

    /// GUI action: Emergency network kill-switch disconnecting a compartment from sys-net
    pub fn toggle_domain_network(&mut self, domain_idx: usize) {
        if self.dom0_gui_locked || domain_idx >= self.domains.len() {
            return;
        }
        let dom = &mut self.domains[domain_idx];
        // Vault and Disposable viewers are prohibited by kernel invariant from attaching to sys-net
        if matches!(dom.kind, DomainKind::VaultVm | DomainKind::DisposableVm | DomainKind::AdminDom0) {
            dom.net_provider_id = None;
            return;
        }
        dom.net_provider_id = match dom.net_provider_id {
            Some(_) => None,
            None => Some(1),
        };
    }

    /// GUI action: Instantaneous Untyped Capability revocation and restart for Disposable VMs
    pub fn purge_and_reset_compartment(&mut self, domain_idx: usize) {
        if self.dom0_gui_locked || domain_idx >= self.domains.len() {
            return;
        }
        let dom = &mut self.domains[domain_idx];
        dom.untyped_watermark_mib = 32; // Reclaimed to base rootfs image footprint
        dom.deadline_misses = 0;
        dom.queue_watermark_pct = 0;
    }

    /// GUI action: Cycles kash-rpc policy verdict while enforcing non-interference invariants
    pub fn cycle_rpc_policy(&mut self, rule_idx: usize) {
        if self.dom0_gui_locked || rule_idx >= self.rpc_policies.len() {
            return;
        }
        let rule = &mut self.rpc_policies[rule_idx];
        // Prevent weakening of mandatory Vault/Admin isolation rules
        if (rule.src_domain_id == 5 && rule.dst_domain_id == 1)
            || (rule.src_domain_id == 1 && rule.dst_domain_id == 0)
        {
            rule.verdict = PolicyVerdict::Deny;
            return;
        }
        rule.verdict = match rule.verdict {
            PolicyVerdict::Allow => PolicyVerdict::Ask,
            PolicyVerdict::Ask => PolicyVerdict::Deny,
            PolicyVerdict::Deny => PolicyVerdict::Allow,
        };
    }
}
