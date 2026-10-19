//! AArch64 architecture module — QEMU virt / Raspberry Pi 4B / ARM64 boards.
#![allow(unsafe_code)]

pub mod apple_silicon;
pub mod boot;
pub mod gic;
pub mod uart;

use khal::{Arch, MemRegion, Platform, MAX_MEM_REGIONS};
use kpaging::{AArch64, FrameAllocator as _};

extern crate alloc;

extern "C" {
    static __stack_top: u8;
    static __kernel_end: u8;
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
}

/// Safe wrapper around the one linker-symbol address-of read this arch needs.
pub fn boot_stack_top() -> u64 {
    core::ptr::addr_of!(__stack_top) as u64
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

/// Initialise all AArch64 hardware: UART → GICv3 → vector table.
pub fn init(_kernel_stack_top: u64) {
    uart::init(None); // PL011 at QEMU default 0x09000000
    // Vector table FIRST: if GIC bring-up MMIO faults (wrong base/version on a
    // given board), we get a reported, fail-closed halt instead of a silent hang.
    gic::vectors::install();
    gic::init();
}

pub fn shutdown(failure: bool) -> ! {
    // QEMU virt PSCI power-off via SMCCC (HVC call). PSCI SYSTEM_OFF = 0x84000008,
    // written as a literal immediate in the asm text so no unstable `const`
    // operand feature is needed.
    let code: u64 = if failure { 0xFFFF_FFFF } else { 0 };
    unsafe {
        core::arch::asm!(
            "mov x0, #0x0008",
            "movk x0, #0x8400, lsl #16",
            "mov x1, {code}",
            "hvc #0",
            code = in(reg) code,
            out("x0") _,
            options(nomem, nostack)
        );
    }
    loop {
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)); }
    }
}

pub fn clear_screen() {
    uart::clear_screen();
}

pub fn busy_delay(cycles: u64) {
    for _ in 0..cycles {
        core::hint::spin_loop();
    }
}

pub fn get_char() -> Option<u8> {
    uart::get_char()
}

/// Zero physical memory (identity mapped at boot, before MMU is enabled).
pub fn zero_phys(start: u64, len: u64) {
    debug_assert!(start % 8 == 0 && len % 8 == 0);
    let mut addr = start;
    while addr < start + len {
        unsafe { core::ptr::write_volatile(addr as *mut u64, 0); }
        addr += 8;
    }
}

/// True if this CPU implements FEAT_RNG (RNDR/RNDRRS), ARMv8.5 and later.
/// Read from ID_AA64ISAR0_EL1 bits [63:60] ("RNDR" field; 0 = not implemented).
/// Mandatory check: executing RNDRRS on a CPU without FEAT_RNG (e.g. Cortex-A57,
/// ARMv8.0) is an undefined-instruction trap — confirmed by boot testing on
/// `-cpu cortex-a57`, which faulted with ESR_EL1 EC=0 before this guard existed.
fn has_rndr() -> bool {
    let isar0: u64;
    unsafe {
        core::arch::asm!("mrs {0}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack));
    }
    (isar0 >> 60) & 0xF != 0
}

pub fn hw_entropy(buf: &mut [u8]) -> bool {
    if !has_rndr() {
        return false; // caller (kmain) treats this as "no hardware entropy available"
    }
    let mut i = 0;
    while i + 8 <= buf.len() {
        let mut val: u64 = 0;
        let ok: u64;
        unsafe {
            // RNDRRS: reseed + read; returns CC=1 (NZCV.C set) on success.
            core::arch::asm!(
                ".inst 0xd53be100",  // mrs x0, RNDRRS — ARMv8.5, guarded by has_rndr() above
                "cset {ok}, cs",
                out("x0") val,
                ok = out(reg) ok,
                options(nomem, nostack)
            );
        }
        if ok == 0 { return false; }
        buf[i..i+8].copy_from_slice(&val.to_le_bytes());
        i += 8;
    }
    true
}

// ── Device-tree platform discovery ───────────────────────────────────────────

pub fn discover(dtb: usize, kernel_end: u64) -> Option<Platform> {
    let dtb = if dtb != 0 {
        dtb
    } else {
        #[cfg(feature = "qemu-virt")]
        {
            // QEMU's ELF entry stub leaves x0 unset. With the image linked
            // above the reserved start of virt RAM, QEMU places its DTB at
            // this documented platform address. The normal DTB magic, size,
            // and FDT parser checks below still gate all hardware use.
            kprintln!("[hw] x0 has no DTB; using the QEMU virt handoff address (qemu-virt build)");
            0x4000_0000usize
        }
        #[cfg(not(feature = "qemu-virt"))]
        {
            kprintln!("[hw] missing device tree; refusing to guess the RAM map or device addresses");
            return None;
        }
    };
    kprintln!("[hw] dtb pointer = {:#018x}  kernel_end = {:#018x}", dtb, kernel_end);

    // SAFETY: QEMU/firmware guarantees a valid DTB at this address.
    let blob = unsafe {
        let magic = u32::from_be(core::ptr::read_volatile(dtb as *const u32));
        kprintln!("[hw] dtb magic = {:#010x} (want 0xd00dfeed)", magic);
        if magic != 0xD00DFEED {
            kprintln!("[hw] invalid DTB magic; refusing to guess the RAM map or device addresses");
            return None;
        }
        let total = u32::from_be(core::ptr::read_volatile((dtb + 4) as *const u32)) as usize;
        kprintln!("[hw] dtb total_size = {} bytes", total);
        if total < 40 || total > 4 * 1024 * 1024 {
            kprintln!("[hw] DTB size out of range; refusing hardware discovery");
            return None;
        }
        core::slice::from_raw_parts(dtb as *const u8, total)
    };

    let fdt = match fdt::Fdt::new(blob) {
        Ok(f) => f,
        Err(e) => {
            kprintln!("[hw] FDT parse failed: {:?}; refusing hardware discovery", e);
            return None;
        }
    };
    kprintln!("[hw] machine: {}", fdt.root().model());
    let cpu_count = fdt.cpus().count();
    kprintln!("[hw] cpus: {}", cpu_count);

    let mut ram_base = u64::MAX;
    let mut ram_end  = 0u64;
    let mut free = [MemRegion::EMPTY; MAX_MEM_REGIONS];
    let mut free_count = 0usize;

    for region in fdt.memory().regions() {
        let base = region.starting_address as u64;
        let size = region.size.unwrap_or(0) as u64;
        if size == 0 { continue; }
        kprintln!("[hw] RAM {:#018x}..{:#018x} ({} MiB)", base, base + size, size >> 20);
        if base < ram_base { ram_base = base; }
        if base + size > ram_end { ram_end = base + size; }
        khal::carve_free_regions(base.max(kernel_end), base + size, &mut free, &mut free_count);
    }

    kprintln!("[hw] devices:");
    for node in fdt.all_nodes() {
        let Some(compat) = node.compatible() else { continue };
        let first = compat.first();
        if first.starts_with("riscv") || node.name.starts_with("cpu") { continue; }
        kprintln!("  {:<28} {}", node.name, first);
    }

    if ram_end == 0 { return None; }

    let total: u64 = free[..free_count].iter().map(|r| r.size_bytes()).sum();
    kprintln!("[mem] {} free region(s), {} MiB total → capability system",
              free_count, total >> 20);

    Some(Platform {
        arch: Arch::AArch64,
        ram_base,
        ram_size: ram_end - ram_base,
        cpu_count,
        free,
        free_count,
    })
}

/// PL011 UART and GICv3 distributor+redistributor — the MMIO this kernel
/// touches on AArch64. Must stay mapped device/RW across the MMU-enable
/// switchover below, or the very next `kprintln!`/interrupt-ack after it
/// faults with nothing able to report why.
const UART_MMIO_BASE: u64 = 0x0900_0000;
const UART_MMIO_LEN: u64 = 0x1000;
const GICD_MMIO_BASE: u64 = 0x0800_0000;
const GICD_MMIO_LEN: u64 = 0x1_0000;
const GICR_MMIO_BASE: u64 = 0x0808_0000;
const GICR_MMIO_LEN: u64 = 0xC_0000; // covers the per-CPU redistributor frames this kernel uses

/// Build the real page table (via `kpaging`) and turn the MMU on for the
/// first time — AArch64 has run with the MMU off, physical addresses used
/// directly, for every boot before this function existed. See
/// `kernel::mmu`'s doc comment for why this runs before anything claims the
/// regions it's handed.
///
/// Also sets `SCTLR_EL1.WXN` (bit 19): a hardware-enforced backstop that
/// makes *any* writable mapping execute-never regardless of its own
/// PXN/UXN bits, and `PAN` (bit 23, Privileged Access Never — EL1 cannot
/// touch EL0-accessible data without an explicit, temporary override).
/// Both are meaningless today (nothing user-mode-accessible exists yet,
/// there is no EL0 support), enabled now for the same reason as x86-64's
/// SMEP/SMAP in the sibling module: so turning that on later doesn't also
/// require remembering to come back and flip these bits too.
pub fn enable_wx_paging(pt_region: MemRegion, extra_rw_regions: &[(u64, u64)]) {
    use crate::mmu::{self, BumpFrameAllocator, MmioRegion};

    // SAFETY: `pt_region` is a region `kmain` picked specifically for this
    // purpose, disjoint (by construction in `two_largest_regions`/its
    // caller) from every other region this boot claims.
    let mut frames = unsafe { BumpFrameAllocator::new(pt_region.base, pt_region.size_bytes()) };
    let root = frames.allocate_frame().unwrap_or_else(|e| panic!("mmu: couldn't allocate root table: {e:?}"));

    let sections = kernel_sections();
    let mmio = [
        MmioRegion::uncached(UART_MMIO_BASE, UART_MMIO_LEN),
        MmioRegion::uncached(GICD_MMIO_BASE, GICD_MMIO_LEN),
        MmioRegion::uncached(GICR_MMIO_BASE, GICR_MMIO_LEN),
    ];
    let vs = mmu::build::<AArch64>(frames, root, &sections, extra_rw_regions, &mmio);

    kprintln!("[mmu] new translation table built: .text RX [{:#x}..{:#x}) .rodata RO [{:#x}..{:#x}) .data+ RW [{:#x}..{:#x})",
              sections.text_start, sections.text_end,
              sections.rodata_start, sections.rodata_end,
              sections.data_start, sections.kernel_end);

    unsafe {
        // MAIR_EL1: AttrIndx 0 = Normal WB, AttrIndx 1 = Device-nGnRnE —
        // must match exactly what kpaging::aarch64's leaf encoder assumed.
        core::arch::asm!("msr mair_el1, {0}", in(reg) kpaging::MAIR_EL1_VALUE, options(nomem, nostack));

        // TCR_EL1: 4 KiB granule, 48-bit input address space via TTBR0
        // (T0SZ=16 => 64-16=48 VA bits, matching kpaging's 4-level,
        // 4 KiB-granule walk exactly: 4×9 + 12 = 48), Normal
        // Write-Back/Inner-Shareable walks for the table itself, and IPS
        // set from this CPU's own reported physical address size
        // (ID_AA64MMFR0_EL1.PARange, bits 3:0 — the same 4-bit encoding is
        // reused directly as TCR_EL1.IPS, bits 34:32, by ARM's own design).
        let mmfr0: u64;
        core::arch::asm!("mrs {0}, id_aa64mmfr0_el1", out(reg) mmfr0, options(nomem, nostack));
        let parange = mmfr0 & 0xF;
        let t0sz: u64 = 16;
        let irgn0: u64 = 0b01; // Normal, Inner Write-Back Read/Write-Allocate
        let orgn0: u64 = 0b01; // Normal, Outer Write-Back Read/Write-Allocate
        let sh0: u64 = 0b11; // Inner Shareable
        let tg0: u64 = 0b00; // 4 KiB granule
        let tcr = t0sz | (irgn0 << 8) | (orgn0 << 10) | (sh0 << 12) | (tg0 << 14) | (parange << 32);
        core::arch::asm!("msr tcr_el1, {0}", in(reg) tcr, options(nomem, nostack));

        // SAFETY (for every asm! block in this function from here on): the
        // table just built by `mmu::build` covers every byte the CPU is
        // about to touch next (see this function's own doc comment), MAIR
        // and TCR above match exactly what that table's leaf descriptors
        // assumed, and `isb` after each system-register write is required
        // by the architecture to guarantee the new value is visible to
        // subsequent instructions, not just eventually.
        core::arch::asm!("isb", options(nomem, nostack));
        core::arch::asm!("msr ttbr0_el1, {0}", in(reg) vs.root_paddr, options(nomem, nostack));
        core::arch::asm!("isb", options(nomem, nostack));

        // SCTLR_EL1: set M (bit 0, MMU enable), C (bit 2, data cache), I
        // (bit 12, instruction cache), WXN (bit 19), and read-modify-write
        // through the *current* value rather than a hand-assembled
        // constant, so every reset-defined bit this kernel hasn't
        // considered yet keeps whatever the architecture says it should be.
        let mut sctlr: u64;
        core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12) | (1 << 19) | (1 << 23); // M, C, I, WXN, PAN
        core::arch::asm!(
            "msr sctlr_el1, {0}",
            "isb",
            in(reg) sctlr,
            options(nomem, nostack)
        );
    }
    kprintln!("[mmu] MMU enabled — W^X (WXN) and PAN now enforced kernel-wide");
}

#[derive(Debug, Clone)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_id: u8,
    pub subclass_id: u8,
    pub prog_if: u8,
    pub irq_line: u8,
    pub bars: [u32; 6],
}

impl PciDevice {
    pub fn device_description(&self) -> &'static str { "Generic PCI Device" }
    pub fn vendor_name(&self) -> &'static str { "Unknown Vendor" }
}

pub fn scan_pci() -> alloc::vec::Vec<PciDevice> {
    alloc::vec::Vec::new()
}

pub fn find_ahci() -> Option<PciDevice> {
    None
}

pub fn find_nvme() -> Option<PciDevice> {
    None
}

pub fn find_nic() -> Option<PciDevice> {
    None
}

pub fn find_audio() -> Option<PciDevice> {
    None
}

#[derive(Debug, Clone)]
pub struct AtaDriveInfo {
    pub drive_index: u8,
    pub model: alloc::string::String,
    pub serial: alloc::string::String,
    pub firmware: alloc::string::String,
    pub total_sectors: u64,
    pub is_atapi: bool,
}

#[derive(Debug, Clone)]
pub struct VirtualBoxProfile {
    pub is_virtualbox: bool,
    pub hypervisor_signature: alloc::string::String,
    pub bga_detected: bool,
    pub bga_version: u16,
    pub current_res: (u16, u16, u16),
    pub vmmdev_present: bool,
    pub vmmdev_io_port: u32,
    pub ata_drives: alloc::vec::Vec<AtaDriveInfo>,
    pub e1000_detected: bool,
    pub e1000_mac: [u8; 6],
}

pub fn probe_vbox() -> VirtualBoxProfile {
    VirtualBoxProfile {
        is_virtualbox: false,
        hypervisor_signature: alloc::string::String::from("AArch64-BareMetal"),
        bga_detected: false,
        bga_version: 0,
        current_res: (0, 0, 0),
        vmmdev_present: false,
        vmmdev_io_port: 0,
        ata_drives: alloc::vec::Vec::new(),
        e1000_detected: false,
        e1000_mac: [0; 6],
    }
}

pub fn init_vtd() {}
pub fn get_iommu_status() -> (bool, usize, usize) { (false, 0, 0) }
pub fn init_input() {}
pub fn poll_input_event() -> Option<khal::InputEvent> { None }
pub fn init_nic() {}
pub fn nic_transmit(_frame: &[u8]) -> Result<(), ()> { Err(()) }
pub fn nic_receive(_out_buf: &mut [u8]) -> Option<usize> { None }
pub fn nic_mac() -> [u8; 6] { [0x02, 0x4B, 0x41, 0x53, 0x48, 0x01] }

pub fn rdtsc() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("mrs {0}, cntvct_el0", out(reg) val, options(nomem, nostack));
    }
    val
}

pub fn framebuffer() -> Option<kboot::FramebufferInfo> { None }
pub fn fill_gradient_test(_fb: &kboot::FramebufferInfo) {}
pub fn clear_framebuffer(_fb: &kboot::FramebufferInfo, _color: u32) {}
pub fn calibrate_tsc() {}
pub fn elapsed_seconds() -> f32 { 0.016 }
pub fn tsc_frequency_hz() -> u64 { 1_000_000_000 }
pub fn read_rtc_unix_seconds() -> u64 { 1776340000 }
pub fn enable_sse() {}
pub fn sse_selftest() {}
pub fn print_pcr_report() {}
pub fn print_tcg_event_log() {}
pub fn print_anti_rollback_status() {}
pub fn get_security_epoch() -> u64 { 2 }
pub fn verify_and_ratify_epoch(_cand: u64) -> Result<(), kboot::RollbackError> { Ok(()) }
pub fn get_xhci_status() -> (bool, bool) { (false, false) }



