//! khal — Hardware Abstraction Layer
//!
//! Pure traits. All `unsafe` lives in the arch modules inside `kernel/`.
//! This crate is `no_std` and has no dependencies.
#![no_std]
#![forbid(unsafe_code)]

// ── Console ──────────────────────────────────────────────────────────────────

/// A write-only byte stream to a hardware console (UART, VGA, etc.).
/// The kernel's `kprint!` macro goes through this.
pub trait Console: Send {
    fn put_byte(&self, b: u8);

    fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                self.put_byte(b'\r');
            }
            self.put_byte(b);
        }
    }
}

// ── Hardware entropy ─────────────────────────────────────────────────────────

/// Raw entropy from a hardware source.
/// x86-64: RDSEED (preferred) → RDRAND
/// ARM64: RNDRRS (ARMv8.5-RNG) → TRNG access via SMCCC
/// RISC-V: seed CSR (Zks extension)
pub trait HwRng {
    /// Fill `buf` with hardware-sourced random bytes.
    /// Returns `Ok(())` if all bytes were filled, `Err(())` if the source is dry.
    fn fill_entropy(&self, buf: &mut [u8]) -> Result<(), ()>;
}

/// Fallback: hardware-seeded PRNG (ChaCha8 in the kernel, seeded at boot).
pub trait KernelRng {
    fn fill_bytes(&self, buf: &mut [u8]);
    fn next_u64(&self) -> u64;
}

// ── Timer ────────────────────────────────────────────────────────────────────

/// A monotonic hardware timer (Local APIC on x86-64, ARM Generic Timer on AArch64).
pub trait Timer {
    /// Frequency in Hz.
    fn frequency_hz(&self) -> u64;

    /// Ticks since boot.
    fn ticks(&self) -> u64;

    /// Microseconds since boot.
    fn micros(&self) -> u64 {
        self.ticks() * 1_000_000 / self.frequency_hz()
    }
}

// ── Interrupt controller ─────────────────────────────────────────────────────

/// IRQ numbers are kernel-internal (not raw hardware vectors).
pub type IrqId = u32;

/// A hardware interrupt controller (Local APIC / GICv3).
pub trait IrqController {
    fn init(&self);
    fn mask(&self, irq: IrqId);
    fn unmask(&self, irq: IrqId);
    fn ack(&self, irq: IrqId);
    fn send_eoi(&self, irq: IrqId);
    fn set_target_cpu(&self, irq: IrqId, cpu: u32);
}

// ── Platform summary ─────────────────────────────────────────────────────────

/// Maximum number of free RAM regions the HAL will report.
pub const MAX_MEM_REGIONS: usize = 16;

/// One naturally-aligned power-of-two chunk of free RAM.
#[derive(Clone, Copy, Debug)]
pub struct MemRegion {
    pub base: u64,
    pub size_bits: u8,  // region size = 1 << size_bits (≥ 12)
}

impl MemRegion {
    pub const EMPTY: MemRegion = MemRegion { base: 0, size_bits: 0 };
    pub const fn size_bytes(&self) -> u64 { 1u64 << self.size_bits }
}

/// Architecture-detected platform information.
#[derive(Debug)]
pub struct Platform {
    pub arch: Arch,
    pub ram_base: u64,
    pub ram_size: u64,
    pub cpu_count: usize,
    pub free: [MemRegion; MAX_MEM_REGIONS],
    pub free_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    AArch64,
    RiscV64,
}

impl Platform {
    pub fn total_free_bytes(&self) -> u64 {
        self.free[..self.free_count].iter().map(|r| r.size_bytes()).sum()
    }
}

/// Carve naturally-aligned, power-of-two free regions out of `[start, end)`,
/// greedily taking the largest chunk that is both small enough to fit the
/// remaining space *and* aligned to its own size, then repeating on
/// whatever is left — looping until nothing 4 KiB-or-larger remains or
/// `out` is full.
///
/// Shared by every architecture's hardware discovery so there is exactly
/// one implementation of "how do we turn a raw available-memory range into
/// capability-sized regions" to get right. It matters: an earlier,
/// separately-written x86-64 version of this logic computed a region's
/// *size* correctly but then placed only one such region per available
/// range, silently discarding everything between the range's start and
/// that one region's rounded-up-to-aligned start — on a 512 MiB QEMU boot,
/// that threw away roughly 255 MiB of real, usable RAM without any error
/// or warning. AArch64's independently-written version of this same logic
/// never had that bug. One shared function is what keeps that kind of
/// divergence from being possible to reintroduce later on just one side.
pub fn carve_free_regions(mut start: u64, end: u64, out: &mut [MemRegion; MAX_MEM_REGIONS], count: &mut usize) {
    start = (start + 0xFFF) & !0xFFF; // round up to 4 KiB
    while start < end && *count < MAX_MEM_REGIONS {
        let avail = end - start;
        let size_bits = 63 - avail.leading_zeros();
        let align_bits = start.trailing_zeros();
        let bits = size_bits.min(align_bits);
        if bits < 12 {
            break; // smaller than one page: nothing more worth carving here
        }
        if let Some(slot) = out.get_mut(*count) {
            *slot = MemRegion { base: start, size_bits: bits as u8 };
        }
        *count += 1;
        start += 1u64 << bits;
    }
}

// ── Device classes ───────────────────────────────────────────────────────────

/// Device class detected from ACPI/DeviceTree, for the boot banner.
#[derive(Clone, Copy, Debug)]
pub enum DeviceClass {
    Storage,
    NIC,
    WiFi,
    USB,
    GPU,
    SerialUART,
    InterruptController,
    Timer,
    RTC,
    TPM,
    IOMMU,
    Other,
}

#[derive(Debug)]
pub struct DeviceInfo {
    pub name: &'static str,
    pub class: DeviceClass,
    pub mmio_base: Option<u64>,
    pub mmio_size: Option<u64>,
    pub irq: Option<u32>,
}

// ── IOMMU & DMA Remapping (Intel VT-d / ARM SMMU) ──────────────────────────

/// PCI Bus/Device/Function identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PciBdf {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
}

impl PciBdf {
    pub const fn new(bus: u8, dev: u8, func: u8) -> Self {
        Self { bus, dev, func }
    }

    pub const fn to_raw(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.dev as u16) << 3) | (self.func as u16)
    }
}

/// PCIe Access Control Services (ACS) capability flags (PCI-SIG spec).
/// Enforces DMA isolation between downstream PCIe ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcieAcsFlags {
    pub source_validation: bool,       // SV: Validates requester ID matches device
    pub translation_blocking: bool,    // TB: Blocks untranslated DMA requests from bypassing IOMMU
    pub p2p_request_redirect: bool,    // RR: Redirects peer-to-peer DMA requests to root complex
    pub p2p_completion_redirect: bool, // CR: Redirects peer-to-peer completions to root complex
    pub upstream_forwarding: bool,     // UF: Forwards peer-to-peer memory transactions upstream
    pub p2p_egress_control: bool,      // EC: Hardware egress filters on downstream ports
    pub direct_translated_p2p: bool,   // DT: Controls direct translated P2P DMA
}

impl PcieAcsFlags {
    pub const fn hardened() -> Self {
        Self {
            source_validation: true,
            translation_blocking: true,
            p2p_request_redirect: true,
            p2p_completion_redirect: true,
            upstream_forwarding: true,
            p2p_egress_control: true,
            direct_translated_p2p: false,
        }
    }

    /// Returns true if all critical ACS DMA isolation flags are enabled.
    pub const fn is_dma_isolated(&self) -> bool {
        self.source_validation && self.translation_blocking && self.p2p_request_redirect
    }
}

/// Intel VT-d / ARM SMMU DMA Remapping Controller Trait.
pub trait IommuController {
    /// Enable DMA remapping translation.
    fn enable_dma_remapping(&self) -> Result<(), ()>;

    /// Disable DMA remapping translation.
    fn disable_dma_remapping(&self);

    /// Check if PCIe Access Control Services (ACS) is enforced for device.
    fn check_pcie_acs(&self, bdf: PciBdf) -> bool;

    /// Map a physical memory region for peripheral device DMA under an isolated domain.
    fn map_device_dma(
        &self,
        bdf: PciBdf,
        domain_id: u16,
        guest_phys: u64,
        host_phys: u64,
        size: usize,
        read: bool,
        write: bool,
    ) -> Result<(), ()>;

    /// Unmap peripheral device DMA region.
    fn unmap_device_dma(&self, bdf: PciBdf, guest_phys: u64, size: usize) -> Result<(), ()>;
}

// ── Input Subsystem (PS/2 Keyboard/Mouse + USB xHCI HID) ───────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCode {
    Unknown,
    A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z,
    Num0, Num1, Num2, Num3, Num4, Num5, Num6, Num7, Num8, Num9,
    Enter, Escape, Backspace, Tab, Space,
    Minus, Equal, LeftBracket, RightBracket, Backslash, Semicolon, Quote, Grave,
    Comma, Period, Slash,
    CapsLock, F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
    LeftShift, RightShift, LeftCtrl, RightCtrl, LeftAlt, RightAlt,
    Up, Down, Left, Right,
    Delete, Insert, Home, End, PageUp, PageDown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputEvent {
    KeyDown(KeyCode),
    KeyUp(KeyCode),
    MouseMove { dx: i32, dy: i32 },
    MouseButtonDown { left: bool, right: bool, middle: bool },
    MouseButtonUp { left: bool, right: bool, middle: bool },
    MouseWheel { dx: i32, dy: i32 },
}

pub trait InputDevice {
    fn poll_event(&mut self) -> Option<InputEvent>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_wheel_event_invariants() {
        let ev = InputEvent::MouseWheel { dx: 0, dy: 1 };
        assert_eq!(ev, InputEvent::MouseWheel { dx: 0, dy: 1 });
        assert_ne!(ev, InputEvent::MouseWheel { dx: 0, dy: -1 });
    }

    #[test]
    fn intellimouse_standard_wheel_delta_decoding() {
        // Standard IntelliMouse byte 4 is signed 8-bit dz
        let up_byte: u8 = 1;
        let down_byte: u8 = 0xFF; // -1 in 2's complement
        let dz_up = (up_byte as i8) as i32;
        let dz_down = (down_byte as i8) as i32;
        assert_eq!(dz_up, 1);
        assert_eq!(dz_down, -1);
    }

    #[test]
    fn intellimouse_5button_wheel_delta_decoding() {
        // 5-button mouse byte 4 lower 4 bits are 2's complement (-8..+7)
        let raw_up: u8 = 0x01;
        let raw_down: u8 = 0x0F; // -1 in 4-bit signed
        let decode = |b: u8| -> i32 {
            let r = (b & 0x0F) as i8;
            if (r & 0x08) != 0 {
                (r | -16) as i32
            } else {
                r as i32
            }
        };
        assert_eq!(decode(raw_up), 1);
        assert_eq!(decode(raw_down), -1);
    }

    #[test]
    fn natural_vs_traditional_scroll_direction() {
        let dy = -1; // rolling wheel down towards user
        let mult = 1.0f32;
        let traditional_sign = -1.0f32;
        let natural_sign = 1.0f32;

        let trad_scroll = (dy as f32) * mult * traditional_sign;
        let nat_scroll = (dy as f32) * mult * natural_sign;

        // In traditional scrolling, rolling down yields positive content offset (scrolling down the page)
        assert!(trad_scroll > 0.0);
        // In natural scrolling, content tracks finger/wheel movement (negative offset)
        assert!(nat_scroll < 0.0);
    }

    #[test]
    fn apic_timer_calibration_and_pit_fallback_calculations() {
        // 1. PIT countdown for 10 ms calibration window:
        // PIT input clock is 1,193,182 Hz. 10 ms = 0.010 s * 1,193,182 = 11,931.82 -> 11,932 counts.
        let pit_10ms_counts = 11_932u16;
        let pit_low = (pit_10ms_counts & 0xFF) as u8;
        let pit_high = ((pit_10ms_counts >> 8) & 0xFF) as u8;
        assert_eq!(pit_low, 0x9C);
        assert_eq!(pit_high, 0x2E);

        // 2. APIC calibration over 10 ms at 1.0 GHz bus (QEMU model):
        let ticks_10ms_qemu = 625_000u64;
        let bus_mhz_qemu = ((ticks_10ms_qemu * 16 * 100) / 1_000_000) as u32;
        assert_eq!(bus_mhz_qemu, 1000); // 1000 MHz
        let icr_100hz_qemu = ticks_10ms_qemu as u32;
        assert_eq!(icr_100hz_qemu, 625_000);

        // 3. APIC calibration over 10 ms on Core 2 Duo (200 MHz Front Side Bus):
        let ticks_10ms_c2d = 125_000u64;
        let bus_mhz_c2d = ((ticks_10ms_c2d * 16 * 100) / 1_000_000) as u32;
        assert_eq!(bus_mhz_c2d, 200); // 200 MHz
        let icr_100hz_c2d = ticks_10ms_c2d as u32;
        assert_eq!(icr_100hz_c2d, 125_000);

        // 4. Fallback 8254 PIT Channel 0 divisor for 100 Hz scheduling:
        let pit_divisor = (1_193_182u32 / 100) as u16;
        assert_eq!(pit_divisor, 11_931);
        let effective_rate = 1_193_182.0 / (pit_divisor as f64);
        assert!((effective_rate - 100.0).abs() < 0.01);
    }
}

