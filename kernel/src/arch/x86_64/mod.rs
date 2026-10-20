//! x86-64 architecture module.
//! Public facade for boot, UART, GDT, IDT, APIC, CPUID, hardware discovery.
#![allow(unsafe_code)]

pub mod apic;
pub mod boot;
pub mod cpuid;
pub mod gdt;
pub mod idt;
pub mod pci;
pub mod syscall;
pub mod tresor;
pub mod uart;
pub mod vbox;
pub mod vtd;
pub mod input;
pub mod nic;
pub mod fpu;
pub mod clock;
pub mod fb;
pub mod acpi;
pub mod smp;
pub mod tpm;
pub mod virtio_gpu;

pub use cpuid::{detect as detect_cpu, CpuFeatures, HardwareTier, detect_hardware_tier, print_hardware_report};
pub use pci::{scan_bus as scan_pci, PciDevice, find_ahci, find_nvme, find_nic, find_audio, find_virtio_gpu};
pub use vbox::{probe_environment as probe_vbox, VirtualBoxProfile, VBoxBgaDisplay, VBoxAtaDriver, AtaDriveInfo};
pub use vtd::{init as init_vtd, get_iommu_status, IntelVtdUnit, PcieAcsVerifier};
pub use tpm::{init as init_tpm, get_tpm_status, Tpm2Device, TpmError, print_pcr_report, print_tcg_event_log, print_anti_rollback_status, verify_and_ratify_epoch};
pub use input::{get_xhci_status, init as init_input, poll_input_event, Ps2Controller, XhciController};
pub use nic::{init as init_nic, transmit as nic_transmit, receive as nic_receive, get_mac_address as nic_mac};
pub use fb::{get_framebuffer as framebuffer, fill_gradient_test, clear_framebuffer};
pub use clock::{calibrate_tsc, elapsed_seconds, read_rtc_unix_seconds, tsc_frequency_hz};
pub use fpu::{enable_sse, selftest as sse_selftest, FpuState};
pub use smp::{cpu_count, PerCpuData, broadcast_tlb_shootdown};

use khal::{Arch, MemRegion, Platform, MAX_MEM_REGIONS};
use kpaging::{FrameAllocator as _, X86_64};

// ── Logging macros (arch-private re-export, used by idt.rs) ─────────────────
// The top-level kernel/src/main.rs defines kprint!/kprintln! globally.

extern "C" {
    static _boot_stack_top: u8;
    static _boot_stack_guard: u8;
    static _boot_magic: u64;
    static __kernel_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
}

/// Safe wrapper around the one linker-symbol address-of read this arch needs.
pub fn boot_stack_top() -> u64 {
    core::ptr::addr_of!(_boot_stack_top) as u64
}

/// Safe read of the bootloader magic.
pub fn boot_magic() -> u32 {
    unsafe { (core::ptr::addr_of!(_boot_magic) as *const u64).read_volatile() as u32 }
}

/// The kernel's own section boundaries, straight from the linker script —
/// what `kernel::mmu::build` maps with real, differentiated permissions.
pub fn kernel_sections() -> crate::mmu::KernelSections {
    crate::mmu::KernelSections {
        text_start: core::ptr::addr_of!(__text_start) as u64,
        text_end: core::ptr::addr_of!(__text_end) as u64,
        rodata_start: core::ptr::addr_of!(__rodata_start) as u64,
        rodata_end: core::ptr::addr_of!(__rodata_end) as u64,
        data_start: core::ptr::addr_of!(__data_start) as u64,
        kernel_end: core::ptr::addr_of!(__kernel_end) as u64,
    }
}

/// First address after the kernel image (page aligned by the linker script).
pub fn kernel_end() -> u64 {
    core::ptr::addr_of!(__kernel_end) as u64
}

// ── Shutdown & Reboot ────────────────────────────────────────────────────────
pub fn shutdown(failure: bool) -> ! {
    acpi::poweroff(failure)
}

pub fn reboot() -> ! {
    acpi::reboot()
}

pub fn clear_screen() {
    uart::clear_screen();
}

pub fn busy_delay(cycles: u64) {
    uart::busy_delay(cycles);
}

pub fn get_char() -> Option<u8> {
    uart::get_char()
}

// ── Multiboot information structure ──────────────────────────────────────────
const MB2_TAG_END:         u32 = 0;
const MB2_TAG_MMAP:        u32 = 6;   // memory map
const MB2_TAG_FRAMEBUFFER: u32 = 8;   // linear framebuffer

const MMAP_AVAILABLE: u32 = 1;

/// Walk the Multiboot1 / Multiboot2 info starting at `mb_ptr`.
/// Returns a `Platform` struct with free RAM regions ready to become capabilities.
pub fn discover(mb_ptr: usize, kernel_end: u64) -> Option<Platform> {
    if mb_ptr == 0 {
        return None;
    }

    let features = cpuid::detect();
    let vendor = core::str::from_utf8(&features.vendor).unwrap_or("???");
    let brand_raw = &features.brand;
    let brand = core::str::from_utf8(brand_raw)
        .unwrap_or("unknown")
        .trim_matches('\0')
        .trim();
    kprintln!("[hw] CPU vendor={} phys={}bit virt={}bit",
              vendor, features.max_phys_bits, features.max_virt_bits);
    kprintln!("[hw] CPU {}", brand);
    kprintln!("[hw] features: NX={} RDRAND={} RDSEED={} VT-x={} SMEP={} SMAP={} TME={}",
              features.has_nx as u8, features.has_rdrand as u8,
              features.has_rdseed as u8, features.has_vmx as u8,
              features.has_smep as u8, features.has_smap as u8,
              features.has_tme as u8);

    let boot_magic64 = unsafe { *(mb_ptr as *const u64) };
    if boot_magic64 == kboot::KASH_BOOT_MAGIC {
        let boot_info = unsafe { &*(mb_ptr as *const kboot::KashBootInfo) };
        kprintln!("[hw] Booted via KashBoot (Dual UEFI / Measured Boot) @ {:#x}", mb_ptr);
        kprintln!("[hw] Boot source: {:?}", boot_info.boot_source);
        if boot_info.framebuffer.is_valid() {
            fb::set_framebuffer(boot_info.framebuffer);
            kprintln!("[hw] GOP Framebuffer: {}x{} @ {:#x}",
                      boot_info.framebuffer.width, boot_info.framebuffer.height, boot_info.framebuffer.base_paddr);
        }
        kprintln!("[security] UEFI boot metadata received; TPM-backed measured-boot attestation is unavailable.");
        if boot_info.boot_source == kboot::BootSource::Uefi {
            crate::status::update(|s| {
                s.uefi_boot = crate::status::ComponentStatus::Real;
            });
        }
    }

    let pvh_magic = unsafe { *(mb_ptr as *const u32) };
    if pvh_magic == 0x336ec578 || pvh_magic == 0x336ec531 {
        kprintln!("[hw] Booted via PVH protocol (QEMU direct ELF64) @ {:#x}", mb_ptr);
        crate::status::update(|s| s.bios_pvh_boot = crate::status::ComponentStatus::Real);
        let memmap_paddr = unsafe { *((mb_ptr + 40) as *const u64) } as usize;
        let memmap_entries = unsafe { *((mb_ptr + 48) as *const u32) } as usize;
        let mut ram_base: u64 = 0;
        let mut ram_size: u64 = 0;
        let mut free = [MemRegion::EMPTY; MAX_MEM_REGIONS];
        let mut free_count = 0usize;

        let mut curr = memmap_paddr;
        for _ in 0..memmap_entries {
            let base = unsafe { *(curr as *const u64) };
            let len  = unsafe { *((curr + 8) as *const u64) };
            let typ  = unsafe { *((curr + 16) as *const u32) };
            if typ == 1 && len > 0 {
                kprintln!("[hw] RAM {:#018x}..{:#018x} ({} MiB)",
                          base, base + len, len >> 20);
                if len > ram_size { ram_base = base; ram_size = len; }
                khal::carve_free_regions(base.max(kernel_end), base + len, &mut free, &mut free_count);
            }
            curr += 24;
        }

        if ram_size == 0 {
            return None;
        }

        kprintln!("[hw] {} free region(s) for the capability system:", free_count);
        let mut total = 0u64;
        for r in &free[..free_count] {
            kprintln!("[mem]  base={:#018x} size=2^{} ({} MiB)",
                      r.base, r.size_bits, r.size_bytes() >> 20);
            total += r.size_bytes();
        }
        kprintln!("[mem]  {} MiB total handed to kcore", total >> 20);

        if fb::get_framebuffer().is_none() {
            if let Some(bga_fb) = fb::acquire_bga_fallback(1024, 768) {
                kprintln!("[hw] BGA Hardware Framebuffer (PVH fallback): {}x{} @ {:#x} (pitch {} bytes)",
                          bga_fb.width, bga_fb.height, bga_fb.base_paddr, bga_fb.pitch);
            }
        }

        return Some(Platform {
            arch: Arch::X86_64,
            ram_base,
            ram_size,
            cpu_count: smp::cpu_count(),
            free,
            free_count,
        });
    }

    let magic = boot_magic();
    if magic == 0x2badb002 {
        kprintln!("[hw] Booted via Multiboot 1 (QEMU / BIOS direct) @ {:#x}", mb_ptr);
        crate::status::update(|s| s.bios_pvh_boot = crate::status::ComponentStatus::Real);
        let flags = unsafe { *(mb_ptr as *const u32) };
        let mut ram_base: u64 = 0;
        let mut ram_size: u64 = 0;
        let mut free = [MemRegion::EMPTY; MAX_MEM_REGIONS];
        let mut free_count = 0usize;

        if flags & (1 << 6) != 0 {
            let mmap_length = unsafe { *((mb_ptr + 44) as *const u32) } as usize;
            let mmap_addr = unsafe { *((mb_ptr + 48) as *const u32) } as usize;
            let mut curr = mmap_addr;
            let end = mmap_addr + mmap_length;
            while curr < end {
                let size = unsafe { *(curr as *const u32) } as usize;
                let base = unsafe { *((curr + 4) as *const u64) };
                let len  = unsafe { *((curr + 12) as *const u64) };
                let typ  = unsafe { *((curr + 20) as *const u32) };
                if typ == 1 && len > 0 {
                    kprintln!("[hw] RAM {:#018x}..{:#018x} ({} MiB)",
                              base, base + len, len >> 20);
                    if len > ram_size { ram_base = base; ram_size = len; }
                    khal::carve_free_regions(base.max(kernel_end), base + len, &mut free, &mut free_count);
                }
                curr += size + 4;
            }
        } else if flags & 1 != 0 {
            let mem_upper = unsafe { *((mb_ptr + 8) as *const u32) } as u64;
            let base = 0x100000u64;
            let len = mem_upper * 1024;
            kprintln!("[hw] RAM {:#018x}..{:#018x} ({} MiB)", base, base + len, len >> 20);
            ram_base = base;
            ram_size = len;
            khal::carve_free_regions(base.max(kernel_end), base + len, &mut free, &mut free_count);
        }

        if ram_size == 0 {
            return None;
        }

        kprintln!("[hw] {} free region(s) for the capability system:", free_count);
        let mut total = 0u64;
        for r in &free[..free_count] {
            kprintln!("[mem]  base={:#018x} size=2^{} ({} MiB)",
                      r.base, r.size_bits, r.size_bytes() >> 20);
            total += r.size_bytes();
        }
        kprintln!("[mem]  {} MiB total handed to kcore", total >> 20);

        return Some(Platform {
            arch: Arch::X86_64,
            ram_base,
            ram_size,
            cpu_count: smp::cpu_count(),
            free,
            free_count,
        });
    }

    // Multiboot 2 tag list (8-byte aligned)
    let total_size = unsafe { *(mb_ptr as *const u32) } as usize;
    kprintln!("[hw] Multiboot2 info @ {:#x}  size={} bytes", mb_ptr, total_size);

    let mut pos = mb_ptr + 8;
    let end = mb_ptr + total_size;
    let mut ram_base: u64 = 0;
    let mut ram_size: u64 = 0;
    let mut free = [MemRegion::EMPTY; MAX_MEM_REGIONS];
    let mut free_count = 0usize;

    while pos < end {
        let tag_type  = unsafe { *(pos as *const u32) };
        let tag_size  = unsafe { *((pos + 4) as *const u32) } as usize;
        if tag_type == MB2_TAG_END { break; }

        if tag_type == MB2_TAG_MMAP {
            // Memory map: entries start at offset 16 from tag start.
            let entry_size = unsafe { *((pos + 8) as *const u32) } as usize;
            let mut e = pos + 16;
            while e + entry_size <= pos + tag_size {
                let base = unsafe { *(e as *const u64) };
                let len  = unsafe { *((e + 8) as *const u64) };
                let typ  = unsafe { *((e + 16) as *const u32) };
                if typ == MMAP_AVAILABLE && len > 0 {
                    kprintln!("[hw] RAM {:#018x}..{:#018x} ({} MiB)",
                              base, base + len, len >> 20);
                    if len > ram_size { ram_base = base; ram_size = len; }
                    // Carve every free region above kernel_end from this
                    // range — not just one (see khal::carve_free_regions's
                    // doc comment for the real bug this fixed: the previous
                    // single-region version here silently discarded most of
                    // a 512 MiB boot's RAM).
                    khal::carve_free_regions(base.max(kernel_end), base + len, &mut free, &mut free_count);
                }
                e += entry_size;
            }
        } else if tag_type == MB2_TAG_FRAMEBUFFER {
            let fb_addr   = unsafe { *((pos + 8) as *const u64) };
            let fb_pitch  = unsafe { *((pos + 16) as *const u32) };
            let fb_width  = unsafe { *((pos + 20) as *const u32) };
            let fb_height = unsafe { *((pos + 24) as *const u32) };
            let fb_bpp    = unsafe { *((pos + 28) as *const u8) };
            if fb_bpp == 32 || fb_bpp == 24 {
                let fb_info = kboot::FramebufferInfo {
                    base_paddr: fb_addr,
                    size_bytes: (fb_pitch as u64) * (fb_height as u64),
                    width: fb_width,
                    height: fb_height,
                    pitch: fb_pitch,
                    bits_per_pixel: fb_bpp,
                    red_mask_size: 8,
                    green_mask_size: 8,
                    blue_mask_size: 8,
                };
                fb::set_framebuffer(fb_info);
                kprintln!("[hw] Multiboot2 Framebuffer: {}x{}x{} @ {:#x} (pitch {} bytes)",
                          fb_width, fb_height, fb_bpp, fb_addr, fb_pitch);
            }
        }

        // Advance to next tag (8-byte aligned).
        pos += (tag_size + 7) & !7;
    }

    if fb::get_framebuffer().is_none() {
        if let Some(bga_fb) = fb::acquire_bga_fallback(1024, 768) {
            kprintln!("[hw] BGA Hardware Framebuffer (fallback): {}x{} @ {:#x} (pitch {} bytes)",
                      bga_fb.width, bga_fb.height, bga_fb.base_paddr, bga_fb.pitch);
        }
    }

    if ram_size == 0 {
        return None;
    }

    kprintln!("[hw] {} free region(s) for the capability system:", free_count);
    let mut total = 0u64;
    for r in &free[..free_count] {
        kprintln!("[mem]  base={:#018x} size=2^{} ({} MiB)",
                  r.base, r.size_bits, r.size_bytes() >> 20);
        total += r.size_bytes();
    }
    kprintln!("[mem]  {} MiB total handed to kcore", total >> 20);

    Some(Platform {
        arch: Arch::X86_64,
        ram_base,
        ram_size,
        cpu_count: smp::cpu_count(),
        free,
        free_count,
    })
}

/// Zero `len` bytes at physical address `start` (identity-mapped).
pub fn zero_phys(start: u64, len: u64) {
    debug_assert!(start % 8 == 0 && len % 8 == 0);
    let mut addr = start;
    while addr < start + len {
        unsafe {
            core::ptr::write_volatile(addr as *mut u64, 0);
        }
        addr += 8;
    }
}

/// End-of-interrupt to the Local APIC.
#[inline]
pub fn irq_eoi() {
    apic::eoi();
}

/// Read hardware or physical entropy. Used by kvault at init and by the kernel PRNG.
pub fn hw_entropy(buf: &mut [u8]) -> bool {
    if cpuid::fill_entropy(buf) {
        return true;
    }
    // Fallback for T0: extract from multi-source physical entropy pool if verified >= 256 bits
    if crate::entropy::is_cryptographically_secure() {
        let mut seed = [0u8; 32];
        if crate::entropy::extract_seed(&mut seed).is_ok() {
            let take = buf.len().min(32);
            buf[..take].copy_from_slice(&seed[..take]);
            return true;
        }
    }
    false
}

/// Initialise all x86-64 hardware: UART → GDT → IDT → APIC → FPU/SSE → Clock.
/// Must be called from `kmain` before enabling interrupts.
pub fn init(kernel_stack_top: u64) {
    uart::init();
    fpu::enable_sse();
    gdt::init(kernel_stack_top);
    idt::init();
    apic::init();
    clock::calibrate_tsc();
    vtd::early_init();
    tpm::early_init();
    smp::init(apic::bsp_id());
    syscall::init();

    // Report discovered CPUs but keep APs parked until their local execution state exists.
    let mut kernel_cr3: u64 = 0;
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) kernel_cr3, options(nostack));
    }
    smp::boot_secondary_cores(kernel_cr3);

    // Initialize preemptive task manager with initial kernel stack
    crate::task::init(kernel_stack_top);

    // Enable hardware interrupts via sti (Part A9)
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }
}

/// Local APIC default MMIO base — the one piece of MMIO this kernel touches
/// on x86-64 today (the UART is I/O-port based, not memory-mapped).
const APIC_MMIO_BASE: u64 = 0xFEE0_0000;
const APIC_MMIO_LEN: u64 = 0x1000;

/// Build and install the real, W^X-correct page table, replacing
/// `boot.S`'s provisional 4 GiB identity map. See `kernel::mmu`'s doc
/// comment for why this runs before anything claims the regions it's
/// handed, and `boot.S`'s EFER-setup comment for why `EFER.NXE` is already
/// on by the time this matters.
///
/// Also enables SMEP and SMAP (CR4 bits 20/21) when the CPU supports them
/// (checked via CPUID — Core 2 Duo-class CPUs in this project's own
/// old-hardware testing do not, and setting an unsupported CR4 bit faults).
/// The Ring 3 process mechanism is exercised by a boot self-test, but normal
/// UI and service paths remain in Ring 0. These mitigations do not establish
/// isolation for those kernel-resident paths.
pub fn enable_wx_paging(
    pt_region: MemRegion,
    extra_rw_regions: &[(u64, u64)],
) {
    use crate::mmu::{self, BumpFrameAllocator, MmioRegion};

    // SAFETY: `pt_region` is a region `kmain` picked specifically for this
    // purpose, disjoint (by construction in `two_largest_regions`/its
    // caller) from every other region this boot claims.
    let mut frames = unsafe { BumpFrameAllocator::new(pt_region.base, pt_region.size_bytes()) };
    let root = frames.allocate_frame().unwrap_or_else(|e| panic!("mmu: couldn't allocate root PML4: {e:?}"));

    let sections = kernel_sections();
    let mut mmio = [
        MmioRegion::uncached(APIC_MMIO_BASE, APIC_MMIO_LEN),
        MmioRegion::uncached(0xB8000, 0x8000),
        MmioRegion::uncached(0xE0000, 0x20000), // BIOS / ACPI tables
        MmioRegion::uncached(0xFED4_0000, 0x5000), // TPM 2.0 TIS MMIO (Localities 0..4)
        MmioRegion::uncached(0xFEBC_0000, 0x20000), // PCI e1000 Gigabit NIC MMIO BAR
        MmioRegion::uncached(0xFEB8_0000, 0x20000), // Alternate PCI MMIO aperture
        MmioRegion::write_combining(0, 0),
        MmioRegion::write_combining(0, 0),
    ];
    let mut mmio_count = 6;
    if let Some(fb_info) = fb::get_framebuffer() {
        mmio[6] = MmioRegion::write_combining(fb_info.base_paddr, fb_info.size_bytes);
        mmio_count = 7;
    }
    let mut vs = mmu::build::<X86_64>(frames, root, &sections, extra_rw_regions, &mmio[..mmio_count]);
    let guard_paddr = core::ptr::addr_of!(_boot_stack_guard) as u64;
    let _ = vs.unmap_4k(guard_paddr);

    kprintln!("[mmu] new page table built: .text RX [{:#x}..{:#x}) .rodata RO [{:#x}..{:#x}) .data+ RW [{:#x}..{:#x})",
              sections.text_start, sections.text_end,
              sections.rodata_start, sections.rodata_end,
              sections.data_start, sections.kernel_end);

    // SAFETY: `vs.root_paddr` is a fully-built, live PML4 whose mappings
    // cover everything execution is about to touch next — the kernel's own
    // code/data (so the instructions right after this write, and the stack,
    // keep working), the Local APIC (already in use for the timer), and the
    // regions about to become the kcore self-test's and the heap's arenas
    // (not yet written to, by the ordering guarantee in `kmain`). Loading a
    // PML4 that was missing any of those would fault on the very next
    // instruction fetch or stack push with no handler able to help.
    unsafe {
        core::arch::asm!("mov cr3, {0}", in(reg) vs.root_paddr, options(nostack));
    }
    kprintln!("[mmu] CR3 switched — W^X now enforced kernel-wide");

    // Enable CR0.WP (bit 16): Write Protect supervisor access to read-only pages
    let mut cr0: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr0", out(reg) cr0, options(nostack, preserves_flags));
        cr0 |= 1 << 16;
        core::arch::asm!("mov cr0, {0}", in(reg) cr0, options(nostack));
    }
    let cr0_check: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr0", out(reg) cr0_check, options(nostack, preserves_flags));
    }
    kprintln!("[mmu] CR0.WP supervisor write-protect active: cr0={:#x} (WP={})", cr0_check, (cr0_check >> 16) & 1);

    // SMEP/SMAP/UMIP: checked individually via CPUID before being added to CR4
    let f = cpuid::detect();
    let mut cr4: u64;
    unsafe { core::arch::asm!("mov {0}, cr4", out(reg) cr4, options(nostack, preserves_flags)) };
    if f.has_smep {
        cr4 |= 1 << 20;
    }
    if f.has_smap {
        cr4 |= 1 << 21;
    }
    if f.has_umip {
        cr4 |= 1 << 11;
    }
    if f.has_smep || f.has_smap || f.has_umip {
        unsafe { core::arch::asm!("mov cr4, {0}", in(reg) cr4, options(nostack)) };
    }
    kprintln!(
        "[mmu] WP=on SMEP={} SMAP={} UMIP={}",
        if f.has_smep { "on" } else { "unsupported, skipped" },
        if f.has_smap { "on" } else { "unsupported, skipped" },
        if f.has_umip { "on" } else { "unsupported, skipped" }
    );
}

pub fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack));
    }
    ((high as u64) << 32) | (low as u64)
}
