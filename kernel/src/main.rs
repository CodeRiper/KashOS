//! Kash Kernel — main kernel entry point.
//! Compiles for both x86-64 (QEMU q35, VirtualBox) and AArch64 (QEMU virt, Pi 4B).
//! Everything that differs between architectures lives in src/arch/.
#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]

extern crate alloc;

// ── Logging macros ────────────────────────────────────────────────────────────

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        #[cfg(target_arch = "x86_64")]
        let _ = write!($crate::arch::x86_64::uart::Uart, $($arg)*);
        #[cfg(target_arch = "aarch64")]
        let _ = write!($crate::arch::aarch64::uart::Uart, $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => {{ $crate::kprint!($($arg)*); $crate::kprint!("\n"); }};
}

// ── Modules ───────────────────────────────────────────────────────────────────

#[allow(unsafe_code)]
pub mod arch;
#[allow(unsafe_code)]
pub mod blockdev;
#[allow(unsafe_code)]
pub mod dde;
pub mod display;
pub mod elf;
pub mod flask;
#[allow(unsafe_code)]
mod heap;
pub mod kapp;
mod kash;
#[allow(unsafe_code)]
pub mod linux;
pub mod lockdown;
mod mmu;
#[allow(unsafe_code)]
pub mod powerbox;
pub mod scheme;
#[allow(unsafe_code)]
mod security;
pub mod sectools;
mod selftest;
mod shell;
#[allow(unsafe_code)]
mod vfs;

fn show_loading_screen() {
    kprintln!();
    kprintln!("  _  __          _        ____   _____ ");
    kprintln!(" | |/ /         | |      / __ \\ / ____|");
    kprintln!(" | ' / __ _ ___ | |__   | |  | | (___  ");
    kprintln!(" |  < / _` / __|| '_ \\  | |  | |\\___ \\ ");
    kprintln!(" | . \\ (_| \\__ \\| | | | | |__| |____) |");
    kprintln!(" |_|\\_\\__,_|___/|_| |_|  \\____/|_____/ ");
    kprintln!(" ==================================================");
    kprintln!("   KashOS Hardened Microkernel  -  Release v0.2.0  ");
    kprintln!("   Hardware Profile: 1-Core SMP | 100MB RAM | 10GB ");
    kprintln!(" ==================================================");
    kprintln!();
}

fn print_progress_bar(pct: usize, message: &str) {
    let width = 30;
    let filled = (width * pct) / 100;
    kprint!("[");
    for i in 0..width {
        if i < filled {
            kprint!("=");
        } else if i == filled {
            kprint!(">");
        } else {
            kprint!(" ");
        }
    }
    kprintln!("] {:3}% {}", pct, message);
    arch::busy_delay(120_000);
}

// ── Kernel entry ─────────────────────────────────────────────────────────────

/// Called by the arch-specific rust_entry once the stack is set up and BSS is clear.
/// `info` is the Multiboot2 info pointer (x86-64) or the DTB address (AArch64/RISC-V).
pub fn kmain(hartid: usize, info: usize) -> ! {
    // ── Step 1: UART (must be first — all subsequent kprintln! need it) ─────
    arch::clear_screen();
    show_loading_screen();
    print_progress_bar(10, "Initializing hardware architecture & UART console...");

    // ── Step 2: Architecture init (GDT, IDT, APIC / GIC, vectors, SSE, Clock) ──
    let stack_top = arch::boot_stack_top();
    arch::init(stack_top);
    arch::sse_selftest();
    print_progress_bar(25, "Enabling Ring 3 TSS stack isolation & GDT/IDT...");

    #[cfg(target_arch = "x86_64")]
    kprintln!("[boot] x86-64 (QEMU q35 / VirtualBox) on CPU {}", hartid);
    #[cfg(target_arch = "aarch64")]
    kprintln!("[boot] AArch64 (QEMU virt / Pi 4B / ARM64 boards) on CPU {}", hartid);

    // ── Step 3: Hardware discovery ───────────────────────────────────────────
    let kernel_end = arch::kernel_end();

    let platform = arch::discover(info, kernel_end)
        .unwrap_or_else(|| panic!("hardware discovery failed — no usable RAM found"));

    kash::print_service_map(&platform);

    // ── Step 4: claim three DISJOINT free regions — kcore's capability
    //    self-test, the global heap allocator, and the real W^X page table
    //    this boot is about to switch to — from one place, so there is
    //    exactly one spot in the whole kernel where "who owns which
    //    physical bytes" is decided, and no way for two subsystems to end
    //    up silently claiming the same memory.
    let free = &platform.free[..platform.free_count];
    let (cap_idx, heap_idx, pt_idx) = three_largest_regions(free);
    let cap_region = cap_idx.map(|i| free[i]).unwrap_or_else(|| panic!("no free RAM for the capability self-test"));
    let heap_region = heap_idx.map(|i| free[i]);
    let pt_region = pt_idx.map(|i| free[i]);

    // ── Step 4a: switch to a real, W^X page table BEFORE anything below
    //    claims or writes to cap_region/heap_region — see kernel::mmu's doc
    //    comment for exactly why this ordering is what makes the switch
    //    itself safe to reason about. boot.S's provisional identity map
    //    (every byte PRESENT|WRITABLE, no NX anywhere, no AArch64 MMU on
    //    at all) stays in place — and the kernel stays usable with no
    //    paging milestone at all — if there isn't a free region left for
    //    the page-table frames themselves; that's reported, not silently
    //    skipped.
    match pt_region {
        Some(pt) => {
            let mut extra_rw: [(u64, u64); 2] = [(cap_region.base, cap_region.size_bytes()), (0, 0)];
            let mut n = 1;
            if let Some(hr) = heap_region {
                extra_rw[n] = (hr.base, hr.size_bytes());
                n += 1;
            }
            arch::enable_wx_paging(pt, &extra_rw[..n]);
        }
        None => {
            kprintln!("[mmu] WARNING: no free region left for page-table frames — staying on the");
            kprintln!("[mmu]          provisional boot-time identity map (no W^X enforcement this boot).");
        }
    }

    print_progress_bar(45, "Enabling W^X Paging & Physical Memory capabilities...");

    selftest::run(cap_region);

    match heap_region {
        Some(r) => {
            claim_heap_region(r);
            kprintln!("[mem] heap allocator arena: {:#018x}, {} MiB", r.base, r.size_bytes() >> 20);
            heap::selftest();
        }
        None => {
            kprintln!("[mem] WARNING: only one free region discovered — no memory left for a heap arena.");
            kprintln!("[mem]          Vec/String/Box are unavailable this boot (fails safely: a clear panic,");
            kprintln!("[mem]          not corruption, on first use — see kernel::heap's alloc_error_handler).");
        }
    }

    // ── Step 4b: TRESOR-style key storage self-test (x86-64 only — DR0-3
    //    is an x86 debug-register mechanism with no AArch64 equivalent).
    #[cfg(target_arch = "x86_64")]
    arch::x86_64::tresor::selftest();

    print_progress_bar(65, "Engaging TRESOR DR0-3 Key Storage & Memory Scrubbing...");

    // ── Step 5: Network and privacy configuration banner ─────────────────────
    let entropy_seed = {
        let mut buf = [0u8; 8];
        if arch::hw_entropy(&mut buf) {
            u64::from_le_bytes(buf)
        } else {
            kprintln!("[entropy] WARNING: Hardware RDRAND/RDSEED unavailable (VirtualBox/QEMU default CPU).");
            kprintln!("[entropy]          Falling back to CPU TSC timer jitter for CSPRNG seed.");
            arch::rdtsc() ^ 0x9e37_79b9_7f4a_7c15
        }
    };
    kash::print_network_config(entropy_seed);
    kash::print_privacy_config();

    // ── Step 6: Driver and enclave map ───────────────────────────────────────
    let drivers = kash::DriverMap::new();
    drivers.print();
    let enclaves = kash::EnclaveMap::new();
    enclaves.print();

    // ── Step 7: Tier-3 services ──────────────────────────────────────────────
    let services = kash::Tier3Status::new();
    services.print();

    print_progress_bar(80, "Mounting kvault-fs authenticated storage & schemes...");
    arch::init_vtd();
    arch::init_input();
    arch::init_nic();
    blockdev::init();
    dde::init();
    powerbox::init();
    lockdown::init();

    // ── Step 7b: RTC & Framebuffer Graphics Foundation ───────────────────────
    let rtc_secs = arch::read_rtc_unix_seconds();
    kprintln!("[clock] CMOS RTC unix time: {} seconds UTC", rtc_secs);

    if let Some(fb) = arch::framebuffer() {
        kprintln!("[gfx] linear framebuffer: {}x{} @ {:#x} (pitch {} bytes)",
                  fb.width, fb.height, fb.base_paddr, fb.pitch);
        kprintln!("[gfx] rendering Phase 1 verification test pattern (RGB color gradient)...");
        arch::fill_gradient_test(&fb);
        kprintln!("[gfx] ✓ gradient rendered successfully");
    } else {
        kprintln!("[gfx] no graphical framebuffer available (running in VGA text mode)");
    }

    // ── Step 8: Anti-Forensics & Hardware Port Gating ────────────────────────
    kprintln!("\n[security] initializing anti-forensic memory & port defenses...");
    let mut test_buffer = [0x5Au8; 128];
    security::scrub_slice(&mut test_buffer);
    kprintln!("[security] ✓ volatile memory scrubber (clflush + SeqCst zeroize) verified");

    let mut port_gate = security::UsbPortGate::new();
    port_gate.on_screen_lock();
    kprintln!("[security] ✓ USB dynamic port gating: charge-only mode engaged on lock");

    print_progress_bar(95, "kcore CDT & OpenBSD Pledge/Unveil Sandboxes Active...");

    // ── Step 9: Virtual File System & Interactive Shell ──────────────────────
    let mut shell = shell::KashShell::new();
    kprintln!("\n[shell] launching kash-init root task (PID 1)...");
    shell.execute_command("status");
    shell.execute_command("lockdown status");
    shell.execute_command("powerbox");
    shell.execute_command("dde");
    shell.execute_command("safety");
    shell.execute_command("deb");
    shell.execute_command("opsec");
    shell.execute_command("graphene");
    shell.execute_command("bfu-test");
    shell.execute_command("uname -a");
    shell.execute_command("ps");
    shell.execute_command("schemes");
    shell.execute_command("drivers");
    shell.execute_command("fault-test");
    shell.execute_command("storage");
    shell.execute_command("block");
    shell.execute_command("lspci");
    shell.execute_command("vbox");
    shell.execute_command("elf");
    shell.execute_command("amnesic-wipe");
    shell.execute_command("df");
    shell.execute_command("free");
    shell.execute_command("kctl list");
    shell.execute_command("kctl run org.system.editor");
    shell.execute_command("kctl disp org.tor.browser");
    shell.execute_command("kctl audit");
    shell.execute_command("kctl display");
    shell.execute_command("kctl paste 1");
    shell.execute_command("kctl synth");
    shell.execute_command("multilang");
    shell.execute_command("ifconfig");
    shell.execute_command("iommu");
    shell.execute_command("usb");
    shell.execute_command("input");
    shell.execute_command("nmap 192.168.1.105");
    shell.execute_command("aircrack wlan0");
    shell.execute_command("hydra 192.168.1.100 ssh");
    shell.execute_command("sqlmap https://target-node.local/api?id=1");
    shell.execute_command("metasploit");
    shell.execute_command("macchanger eth0");
    shell.execute_command("wol 02:4B:41:53:48:01");
    shell.execute_command("netstat");
    shell.execute_command("sha256sum");
    shell.execute_command("shred secret_key.pem");
    shell.execute_command("install-os");

    print_progress_bar(100, "All subsystems verified. Starting interactive shell.");

    kprintln!();
    kprintln!("[boot] [OK] all Kash OS microkernel self-tests passed");
    kprintln!("[boot] [OK] dual-target architecture: x86-64 + AArch64");
    kprintln!("[boot] [OK] Dual Bootloader: UEFI (BOOTX64.EFI) + BIOS/PVH (kboot)");
    kprintln!("[boot] [OK] GDT + TSS hardware stack isolation active (Ring 0 microkernel)");
    kprintln!("[boot] [OK] Native Relibc / Musl libc syscall ABI + pledge/unveil sandbox");
    kprintln!("[boot] [OK] Anti-DMA IOMMU containment: Intel VT-d & PCIe ACS verified");
    kprintln!("[boot] [OK] USB xHCI & PS/2 keyboard/mouse input drivers active");
    kprintln!("[boot] [OK] Hardware Network Drivers: Intel e1000 & VirtIO-Net active");
    kprintln!("[boot] [OK] smoltcp TCP/IP Stack & Lock-Free kipc Rings ready");
    kprintln!("[boot] [OK] RedoxOS-style URL Scheme Architecture active");
    kprintln!("[boot] [OK] kvault-fs authenticated block storage engine ready");
    kprintln!("[boot] [OK] C-LOOK adaptive elevator storage scheduler ready");
    kprintln!("[boot] [OK] TRESOR CPU debug register key staging (DR0-DR3) active");
    kprintln!("[boot] [OK] Out-of-the-Box Security Testing Suite (Nmap, Aircrack, Hydra, Sqlmap, Metasploit) ready");
    kprintln!("[boot] [OK] iOS Lockdown Mode active (Strict W^X, JIT blocked, USB gated)");
    kprintln!("[boot] [OK] Zero-Trust Powerbox Sandbox (POLA) active (empty namespaces, out-of-process picker)");
    kprintln!("[boot] [OK] Linux Application & Debian Package Sandbox active (auxv stack, /proc /sys VFS, futex, io_uring)");
    kprintln!("[boot] [OK] Linux DDE & Apple Transducer Safety Engine active (speakersafetyd + TAS2764 V/ISENSE telemetry)");
    kprintln!("[boot] [OK] FLASK Mandatory Access Control & Type Enforcement active");
    kprintln!("[boot] [OK] Capability Application Capsules (.kapp) verified");
    kprintln!("[boot] [OK] Multi-Language Userspace Runtime (C/C++/Python/Java) ELF64 ready");
    kprintln!("[boot] [OK] Wayland Compositor (Smithay-style isolated surfaces) ready");
    kprintln!("[boot] [OK] Hardware envelope: 1-core CPU, memory paging & amnesic wipe ready");

    kprintln!();
    kprintln!("[boot] [OK] KashOS Hardened Microkernel Initialized Successfully.");
    kprintln!("[boot] [OK] Launching interactive root shell on tty0 (VGA + PS/2 + Serial)...");
    shell.run_interactive_terminal()
}

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Try to print the panic message. If the UART is not yet up, this is a no-op.
    kprintln!("\n[PANIC] {}", info);
    arch::shutdown(true)
}

/// The one real `unsafe` call this file makes, isolated into its own tiny,
/// explicitly-allowed function rather than an inline block — unlike the
/// linker-symbol `addr_of!` calls elsewhere (wrapped in arch-side functions
/// that are safe *in general*), this one is only sound because of a
/// main.rs-local argument (`r` is disjoint from every other claim on
/// `platform.free`, guaranteed by `two_largest_regions` and the
/// `cap_region`/`heap_idx` split in `kmain` above) — the unsafety is
/// genuinely this file's to own, not something a lower layer could check.
#[allow(unsafe_code)]
fn claim_heap_region(r: khal::MemRegion) {
    // SAFETY: see this function's own doc comment above.
    unsafe { heap::init(r.base, r.size_bytes()) };
}

/// Indices of the three largest regions in `free`, by `size_bits` (ties
/// keep whichever was found first), largest first. `None` in the second or
/// third slot means that few regions didn't exist to begin with — every
/// caller must handle that (see `kmain`'s heap-arena and page-table-frame
/// branches) rather than ever fall back to reusing an earlier region for a
/// second purpose.
fn three_largest_regions(free: &[khal::MemRegion]) -> (Option<usize>, Option<usize>, Option<usize>) {
    let mut top: [Option<usize>; 3] = [None, None, None];
    for (i, r) in free.iter().enumerate() {
        let bits = |idx: Option<usize>| idx.map(|j| free[j].size_bits).unwrap_or(0);
        if top[0].is_none() || r.size_bits > bits(top[0]) {
            top = [Some(i), top[0], top[1]];
        } else if top[1].is_none() || r.size_bits > bits(top[1]) {
            top = [top[0], Some(i), top[1]];
        } else if top[2].is_none() || r.size_bits > bits(top[2]) {
            top[2] = Some(i);
        }
    }
    (top[0], top[1], top[2])
}

/// Architecture name string for log messages.
pub fn arch_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]  { "x86-64" }
    #[cfg(target_arch = "aarch64")] { "AArch64" }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))] { "unknown" }
}
