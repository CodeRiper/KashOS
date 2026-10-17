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
pub mod cap;
#[allow(unsafe_code)]
pub mod dde;
pub mod display;
#[allow(unsafe_code)]
pub mod driver;
pub mod elf;
pub mod flask;
#[allow(unsafe_code)]
pub mod gui;
#[allow(unsafe_code)]
mod heap;
#[allow(unsafe_code)]
pub mod ipc;
pub mod kapp;
mod kash;
pub mod kash_kernel;
#[allow(unsafe_code)]
pub mod linux;
pub mod lockdown;
mod mmu;
#[allow(unsafe_code)]
pub mod powerbox;
#[allow(unsafe_code)]
pub mod process;
pub mod scheme;
#[allow(unsafe_code)]
mod security;
pub mod sectools;
#[allow(unsafe_code)]
mod selftest;
#[allow(unsafe_code)]
pub mod status;
#[allow(unsafe_code)]
pub mod sync;
#[allow(unsafe_code)]
pub mod task;
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
    kprintln!("   KashOS experimental kernel build 0.1.0  ");
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
    print_progress_bar(25, "Installing architecture tables, exception vectors & timer...");

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
    //    at all) must never remain active after this point. If we cannot
    //    reserve page-table memory, stop booting rather than claim a secure
    //    boot with the permissive provisional map still installed.
    match pt_region {
        Some(pt) => {
            let mut extra_rw: [(u64, u64); 3] = [
                (cap_region.base, cap_region.size_bytes()),
                (pt.base, pt.size_bytes()),
                (0, 0),
            ];
            let mut n = 2;
            if let Some(hr) = heap_region {
                extra_rw[n] = (hr.base, hr.size_bytes());
                n += 1;
            }
            arch::enable_wx_paging(pt, &extra_rw[..n]);
        }
        None => panic!("mmu: no disjoint free RAM region for mandatory W^X page tables; refusing insecure boot"),
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

    print_progress_bar(65, "Applying available kernel memory and key handling...");

    // ── Step 5: Network and privacy configuration banner ─────────────────────
    let mut entropy_seed = 0u64;
    let mut buf = [0u8; 8];
    if arch::hw_entropy(&mut buf) {
        entropy_seed = u64::from_le_bytes(buf);
        status::update(|s| s.hw_entropy = crate::status::ComponentStatus::Real);
    } else {
        kprintln!("[entropy] ERROR: Hardware RDRAND/RDSEED/virtio-rng unavailable (Rule R2: Fail-Closed).");
        kprintln!("[entropy] Refusing to seed cryptographic keys from insecure TSC timer.");
        status::update(|s| s.hw_entropy = crate::status::ComponentStatus::NotAvailable);
    }
    kash::print_network_config(entropy_seed);
    kash::print_privacy_config();

    // ── Step 5b: Speculative execution mitigations (A12) ──────────────────────
    security::SpeculativeMitigations::apply();
    status::update(|s| s.spec_mitigations = crate::status::ComponentStatus::Partial);

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
    driver::init();
    powerbox::init();
    lockdown::init();

    // ── Step 7b: RTC & Framebuffer Graphics Foundation ───────────────────────
    let rtc_secs = arch::read_rtc_unix_seconds();
    kprintln!("[clock] CMOS RTC unix time: {} seconds UTC", rtc_secs);

    if let Some(fb) = arch::framebuffer() {
        kprintln!("[gfx] linear framebuffer: {}x{} @ {:#x} (pitch {} bytes)",
                  fb.width, fb.height, fb.base_paddr, fb.pitch);
        arch::clear_framebuffer(&fb, 0xFF0A0F1D);
        kprintln!("[gfx] linear framebuffer initialized & cleared to dark slate");
        status::update(|s| s.linear_framebuffer = crate::status::ComponentStatus::Real);
    } else {
        kprintln!("[gfx] no graphical framebuffer available (running in VGA text mode)");
        status::update(|s| s.linear_framebuffer = crate::status::ComponentStatus::NotAvailable);
    }

    // ── Step 8: Anti-Forensics & Hardware Port Gating ────────────────────────
    kprintln!("\n[security] initializing anti-forensic memory & port defenses...");
    let mut test_buffer = [0x5Au8; 128];
    security::scrub_slice(&mut test_buffer);
    kprintln!("[security] temporary buffer zeroing helper checked");

    let mut port_gate = security::UsbPortGate::new();
    port_gate.on_screen_lock();
    kprintln!("[security] USB port-gating policy helper checked; no USB controller gating is integrated");

    print_progress_bar(95, "Finalizing kernel services...");

    // ── Step 9: Virtual File System & Interactive Shell / UI ─────────────────
    let mut shell = shell::KashShell::new();
    print_progress_bar(100, "Kernel initialization complete. Starting kernel shell or desktop.");

    // Rule R1: Print the single source-of-truth status registry banner
    status::print_boot_banner();

    if let Some(fb) = arch::framebuffer() {
        kprintln!("[boot] Linear Framebuffer active ({}x{} @ {:#x}). Launching Kash UI desktop shell...",
                  fb.width, fb.height, fb.base_paddr);
        gui::run(fb);
    } else {
        kprintln!("[boot] Launching the kernel shell on the available console...");
        shell.run_interactive_terminal()
    }
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
