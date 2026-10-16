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
    /// 0 = KashOS-signed only · 1 = identified developers · 2 = anywhere
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
        let ks = "KashOS";
        let apps = alloc::vec![
            e("Files", Gui, Some(AppKind::Files), "27.0", 18_400_000, ks, true, true, "Oct 9", "Browse and organise files", &[(Files, Allow), (FullDisk, Ask), (AppMgmt, Ask), (Usb, Allow)]),
            e("System Settings", Gui, Some(AppKind::Settings), "27.0", 42_100_000, ks, true, true, "Oct 9", "Configure KashOS", &[(AppMgmt, Allow), (Accessibility, Allow), (Location, Allow), (Bluetooth, Allow), (Network, Allow), (Usb, Allow), (FullDisk, Allow)]),
            e("Terminal", Gui, Some(AppKind::Terminal), "27.0", 9_800_000, ks, true, true, "Oct 9", "Command line for the Phantom kernel", &[(FullDisk, Ask), (Files, Allow), (Network, Allow), (Automation, Ask), (Accessibility, Ask), (AppMgmt, Deny), (Spawn, Allow)]),
            e("Browser", Gui, Some(AppKind::Browser), "27.0", 128_000_000, ks, true, true, "Oct 9", "Anonymity-gateway web browser", &[(Camera, Ask), (Microphone, Ask), (Location, Ask), (Network, Allow), (LocalNet, Ask), (Notifications, Ask), (Files, Allow), (Screen, Deny), (Keys, Ask)]),
            e("Notes", Gui, Some(AppKind::Notes), "27.0", 14_200_000, ks, true, true, "Oct 9", "Quick notes", &[(Files, Allow), (Photos, Ask), (Notifications, Allow)]),
            e("Photos", Gui, Some(AppKind::Photos), "27.0", 61_000_000, ks, true, true, "Oct 9", "Your photo library", &[(Photos, Allow), (Camera, Ask), (Location, Ask), (Files, Allow), (Network, Allow)]),
            e("Music", Gui, Some(AppKind::Music), "27.0", 54_000_000, ks, true, true, "Oct 9", "Play your music", &[(Microphone, Ask), (Network, Allow), (Bluetooth, Allow), (Notifications, Allow), (Files, Allow)]),
            e("Messages", Gui, Some(AppKind::Messages), "27.0", 22_000_000, ks, true, true, "Oct 9", "Chat over the Anonymity Gateway", &[(Contacts, Allow), (Notifications, Allow), (Camera, Ask), (Microphone, Ask), (Network, Allow), (Photos, Ask), (Location, Ask)]),
            e("Activity Monitor", Gui, Some(AppKind::ActivityMonitor), "27.0", 11_600_000, ks, true, true, "Oct 12", "Processes, memory and capabilities", &[(Accessibility, Allow), (AppMgmt, Allow), (FullDisk, Ask), (Network, Allow)]),
            e("Calculator", Gui, Some(AppKind::Calculator), "27.0", 3_900_000, ks, true, true, "Oct 12", "Everyday maths", &[]),
            // ── CLI tools ──
            e("ssh", Cli, None, "9.8", 2_400_000, "KashOS", true, true, "Oct 3", "Secure shell client", &[(Network, Allow), (Files, Ask), (Keys, Ask), (Spawn, Allow)]),
            e("curl", Cli, None, "8.9", 1_100_000, "KashOS", true, true, "Oct 3", "Transfer data over URLs", &[(Network, Allow), (Files, Allow)]),
            e("nmap", Cli, None, "7.95", 6_300_000, "Nmap Project", true, false, "Sep 28", "Network discovery and security scanner", &[(Network, Allow), (RawSocket, Ask), (LocalNet, Ask), (Admin, Deny)]),
            e("tcpdump", Cli, None, "4.99", 1_700_000, "The Tcpdump Group", true, false, "Sep 28", "Packet analyzer", &[(RawSocket, Ask), (Admin, Ask), (Files, Ask)]),
            e("kvault", Cli, None, "0.2", 2_900_000, ks, true, true, "Oct 8", "Encrypted vault client", &[(FullDisk, Allow), (Files, Allow), (Keys, Allow), (Admin, Ask)]),
            e("git", Cli, None, "2.46", 4_800_000, "Git Project", true, false, "Sep 20", "Distributed version control", &[(Network, Allow), (Files, Allow), (Spawn, Allow)]),
            e("cargo", Cli, None, "1.90", 38_000_000, "Rust Foundation", true, false, "Sep 20", "Rust package manager and build tool", &[(Files, Allow), (Network, Ask), (Spawn, Allow)]),
            e("phantom-ctl", Cli, None, "0.2", 3_200_000, ks, true, true, "Oct 8", "Control the Phantom kernel services", &[(Admin, Allow), (Spawn, Allow), (KernelMem, Deny), (Network, Ask)]),
            // ── drivers ──
            e("kash-nic.kdrv", Driver, None, "0.2", 410_000, ks, true, true, "Oct 8", "Network interface controller", &[(Dma, Allow), (IoPorts, Allow), (Network, Allow)]),
            e("kash-fb.kdrv", Driver, None, "0.2", 220_000, ks, true, true, "Oct 8", "Linear framebuffer", &[(Framebuffer, Allow), (Dma, Allow), (IoPorts, Allow)]),
            e("kash-usb-hid.kdrv", Driver, None, "0.2", 190_000, ks, true, true, "Oct 8", "USB keyboard and mouse", &[(Usb, Allow), (InputDev, Allow), (IoPorts, Allow)]),
            e("kash-nvme.kdrv", Driver, None, "0.2", 340_000, ks, true, true, "Oct 8", "NVMe storage controller", &[(Storage, Allow), (Dma, Allow), (IoPorts, Allow)]),
            e("kash-ps2.kdrv", Driver, None, "0.2", 40_000, ks, true, true, "Oct 8", "PS/2 input", &[(InputDev, Allow), (IoPorts, Allow)]),
            e("kash-bt.kdrv", Driver, None, "0.1", 260_000, ks, true, true, "Oct 8", "Bluetooth controller", &[(Bluetooth, Allow), (Usb, Allow), (IoPorts, Allow)]),
            e("kash-hda.kdrv", Driver, None, "0.1", 180_000, ks, true, true, "Oct 8", "HD audio codec", &[(Microphone, Ask), (Dma, Allow), (IoPorts, Allow)]),
            e("rtl8821-wifi.kdrv", Driver, None, "5.2", 1_200_000, "Community (unsigned)", false, false, "Oct 11", "Third-party Wi-Fi adapter", &[(Dma, Ask), (Network, Ask), (KernelMem, Ask), (IoPorts, Ask)]),
        ];
        let downloads = alloc::vec![
            Download { name: String::from("phantom-kernel.iso"), kind: FileKind::Iso, size: 11_300_000, date: String::from("Today") },
            Download { name: String::from("tools.zip"), kind: FileKind::Archive, size: 220_000_000, date: String::from("Oct 9") },
            Download { name: String::from("wordlists.zip"), kind: FileKind::Archive, size: 1_400_000_000, date: String::from("Sep 28") },
            Download { name: String::from("kali-nethunter.iso"), kind: FileKind::Iso, size: 3_800_000_000, date: String::from("Sep 5") },
        ];
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

    /// Unsigned software is blocked when the matching policy only allows signed code.
    pub fn blocked(&self, i: usize) -> bool {
        let a = &self.apps[i];
        if a.signed { return false; }
        match a.class { AppClass::Driver => self.driver_policy < 2, _ => self.app_policy < 1 }
    }
    /// Effective state after policy and Lockdown Mode.
    pub fn effective(&self, i: usize, p: Perm) -> PS {
        let s = self.apps[i].perms[p.idx()];
        if s == PS::NA { return PS::NA; }
        if self.blocked(i) { return PS::Deny; }
        if self.lockdown && s == PS::Ask { return PS::Deny; }
        s
    }
    /// For CLI enforcement by tool name. Unknown tools are allowed.
    pub fn check(&self, name: &str, p: Perm) -> PS {
        match self.find_name(name) { Some(i) => { let s = self.effective(i, p); if s == PS::NA { PS::Deny } else { s } } None => PS::Allow }
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
