//! x86-64 CPUID: detect hardware features needed by Kash Kernel.
//! Checks for: NX/XD (required), RDRAND, RDSEED, TME, VT-x, VT-d presence.
#![allow(unsafe_code)]

#[derive(Debug)]
pub struct CpuFeatures {
    /// Brand string, e.g. "Intel(R) Core(TM) i7-..."
    pub brand: [u8; 48],
    pub vendor: [u8; 12],
    pub has_nx:      bool,  // No-Execute / Execute-Disable
    pub has_aesni:   bool,  // AES-NI hardware instruction acceleration
    pub has_rdrand:  bool,  // RDRAND instruction
    pub has_rdseed:  bool,  // RDSEED instruction (higher-quality entropy)
    pub has_vmx:     bool,  // Intel VT-x (hardware virtualisation)
    pub has_smep:    bool,  // Supervisor Mode Execution Protection
    pub has_smap:    bool,  // Supervisor Mode Access Protection
    pub has_umip:    bool,  // User-Mode Instruction Prevention
    pub has_tme:     bool,  // Intel TME (Total Memory Encryption)
    pub has_fsgsbase: bool, // FSGSBASE instructions
    pub has_pcid:    bool,  // Process-Context Identifiers (TLB tags)
    pub has_ibrs:    bool,  // Speculation control MSR (IA32_SPEC_CTRL) / IBRS
    pub has_stibp:   bool,  // Single Thread Indirect Branch Predictor
    pub has_l1d_flush: bool, // IA32_FLUSH_CMD (L1D cache flush)
    pub has_ssbd:    bool,  // Speculative Store Bypass Disable
    pub has_apic:    bool,  // On-chip Local APIC present (CPUID.01H:EDX[9])
    pub has_tsc:     bool,  // Time Stamp Counter present (CPUID.01H:EDX[4])
    pub has_invariant_tsc: bool, // Invariant TSC across P/C-states (CPUID.80000007H:EDX[8])
    pub max_phys_bits: u8,
    pub max_virt_bits: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HardwareTier {
    T0Legacy,       // 1 core, < 1 GB RAM, BIOS only, no VT-x, no IOMMU, no TPM
    T1BasicModern,  // 2+ cores, 4 GB RAM, VT-x, no TPM
    T2SecureModern, // 4+ cores, 8 GB RAM, VT-x + VT-d/AMD-Vi, TPM 2.0, UEFI Secure Boot
    T3HighEnd,      // Multi-core, 16+ GB RAM, CET, SMEP/SMAP, PKU
}

impl Default for CpuFeatures {
    fn default() -> Self {
        CpuFeatures {
            brand: [0; 48],
            vendor: [0; 12],
            has_nx: false, has_aesni: false, has_rdrand: false, has_rdseed: false, has_vmx: false,
            has_smep: false, has_smap: false, has_umip: false, has_tme: false, has_fsgsbase: false,
            has_pcid: false, has_ibrs: false, has_stibp: false, has_l1d_flush: false,
            has_ssbd: false, has_apic: false, has_tsc: false, has_invariant_tsc: false,
            max_phys_bits: 0, max_virt_bits: 0,
        }
    }
}

#[inline]
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    unsafe {
        // RBX is reserved by LLVM (base pointer in PIC code generation), so it
        // cannot appear as a direct asm! operand — save/restore it by hand
        // around the single instruction that clobbers it.
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            inout("ecx") sub => ecx,
            out("edx") edx,
            ebx_out = out(reg) ebx,
            options(preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

pub fn detect() -> CpuFeatures {
    let mut f = CpuFeatures::default();

    // Vendor string (leaf 0)
    let (_, vb, vc, vd) = cpuid(0, 0);
    let vendor_words = [vb, vd, vc]; // GenuineIntel / AuthenticAMD ordering
    for (i, &w) in vendor_words.iter().enumerate() {
        f.vendor[i*4..i*4+4].copy_from_slice(&w.to_le_bytes());
    }

    // Standard features (leaf 1)
    let (_, _, ecx1, edx1) = cpuid(1, 0);
    f.has_rdrand    = ecx1 & (1 << 30) != 0;
    f.has_vmx       = ecx1 & (1 << 5)  != 0;
    f.has_pcid      = ecx1 & (1 << 17) != 0;
    f.has_tsc       = edx1 & (1 << 4)  != 0; // Time Stamp Counter
    f.has_apic      = edx1 & (1 << 9)  != 0; // On-chip APIC Hardware

    // Extended features (leaf 7, sub 0)
    let (_, ebx7, ecx7, edx7) = cpuid(7, 0);
    f.has_smep      = ebx7 & (1 << 7)  != 0;
    f.has_smap      = ebx7 & (1 << 20) != 0;
    f.has_umip      = ecx7 & (1 << 2)  != 0;
    f.has_rdseed    = ebx7 & (1 << 18) != 0;
    f.has_fsgsbase  = ebx7 & (1 << 0)  != 0;
    f.has_tme       = ecx7 & (1 << 13) != 0;
    f.has_ibrs      = edx7 & (1 << 26) != 0; // IBRS / IBPB
    f.has_stibp     = edx7 & (1 << 27) != 0; // STIBP
    f.has_l1d_flush = edx7 & (1 << 28) != 0; // IA32_FLUSH_CMD
    f.has_ssbd      = edx7 & (1 << 31) != 0; // SSBD

    // Extended CPUID limit
    let (max_ext, _, _, _) = cpuid(0x8000_0000, 0);

    // Extended CPUID (leaf 0x80000001) — NX bit
    if max_ext >= 0x8000_0001 {
        let (_, _, _, edx_ext) = cpuid(0x8000_0001, 0);
        f.has_nx = edx_ext & (1 << 20) != 0;
    }

    // Invariant TSC (leaf 0x80000007, EDX bit 8)
    if max_ext >= 0x8000_0007 {
        let (_, _, _, edx_pm) = cpuid(0x8000_0007, 0);
        f.has_invariant_tsc = edx_pm & (1 << 8) != 0;
    }

    // Address size (leaf 0x80000008)
    if max_ext >= 0x8000_0008 {
        let (eax_as, _, _, _) = cpuid(0x8000_0008, 0);
        f.max_phys_bits = (eax_as & 0xFF) as u8;
        f.max_virt_bits = ((eax_as >> 8) & 0xFF) as u8;
    }

    // CPU brand string (leaves 0x80000002..0x80000004)
    if max_ext >= 0x8000_0004 {
        for i in 0..3u32 {
            let (a, b, c, d) = cpuid(0x8000_0002 + i, 0);
            let off = i as usize * 16;
            f.brand[off..off+4].copy_from_slice(&a.to_le_bytes());
            f.brand[off+4..off+8].copy_from_slice(&b.to_le_bytes());
            f.brand[off+8..off+12].copy_from_slice(&c.to_le_bytes());
            f.brand[off+12..off+16].copy_from_slice(&d.to_le_bytes());
        }
    }

    f
}

/// Try RDSEED first, fall back to RDRAND, return None if neither works.
///
/// Mandatory feature check before executing either instruction — not an
/// optimisation, a correctness requirement. RDSEED/RDRAND "failing" (CPU
/// has the instruction but entropy isn't ready yet) sets the carry flag to
/// 0, which is what the loop below already handles. That is a completely
/// different situation from the instruction *not existing at all*: RDSEED
/// is Ivy-Bridge-and-later-only and RDRAND is Ivy-Bridge/Bulldozer-and-later
/// only, and on any older CPU the opcode is simply undefined — executing it
/// raises #UD and halts the kernel. Confirmed by booting this kernel under
/// `-cpu core2duo` (a pre-RDRAND model QEMU can emulate): without this
/// guard, hardware-entropy collection crashed the kernel on exactly the
/// kind of older hardware this project aims to support. The AArch64 side
/// of this file's sibling module hit the identical class of bug with
/// RNDRRS on `-cpu cortex-a57` earlier in this project — same lesson,
/// same fix shape, this time on the x86-64 side.
pub fn hw_rand64() -> Option<u64> {
    let f = detect();
    let mut val: u64;
    let mut ok: u8;
    if f.has_rdseed {
        unsafe {
            core::arch::asm!(
                "rdseed {0}",
                "setc   {1}",
                out(reg) val,
                out(reg_byte) ok,
                options(nomem, nostack)
            );
        }
        if ok != 0 {
            return Some(val);
        }
    }
    if f.has_rdrand {
        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc   {1}",
                out(reg) val,
                out(reg_byte) ok,
                options(nomem, nostack)
            );
        }
        if ok != 0 {
            return Some(val);
        }
    }
    None
}

/// Fill a buffer with hardware entropy. Returns false if the source is dry.
pub fn fill_entropy(buf: &mut [u8]) -> bool {
    let mut i = 0;
    while i + 8 <= buf.len() {
        match hw_rand64() {
            Some(v) => { buf[i..i+8].copy_from_slice(&v.to_le_bytes()); i += 8; }
            None => return false,
        }
    }
    if i < buf.len() {
        match hw_rand64() {
            Some(v) => {
                let b = v.to_le_bytes();
                let remaining = buf.len() - i;
                buf[i..].copy_from_slice(&b[..remaining]);
            }
            None => return false,
        }
    }
    true
}

impl HardwareTier {
    pub fn name(&self) -> &'static str {
        match *self {
            HardwareTier::T0Legacy => "T0 Legacy (Vintage PC / Core 2 Duo Class)",
            HardwareTier::T1BasicModern => "T1 Basic Modern (Multi-Core / Virtualization)",
            HardwareTier::T2SecureModern => "T2 Secure Modern (IOMMU + TPM + Secure Boot)",
            HardwareTier::T3HighEnd => "T3 High End (Hardware Security Extension / CET)",
        }
    }
}

pub fn detect_hardware_tier() -> HardwareTier {
    let f = detect();
    let (iommu_active, _, _) = super::vtd::get_iommu_status();
    let tpm_status = super::tpm::get_tpm_status();

    if f.has_vmx && iommu_active && tpm_status.contains("Active") && f.has_smep && f.has_smap {
        HardwareTier::T2SecureModern
    } else if f.has_vmx {
        HardwareTier::T1BasicModern
    } else {
        HardwareTier::T0Legacy
    }
}

pub fn print_hardware_report() {
    let f = detect();
    let tier = detect_hardware_tier();
    let (iommu_active, _, _) = super::vtd::get_iommu_status();
    let tpm_status = super::tpm::get_tpm_status();
    let cpus = super::smp::cpu_count();

    crate::kprintln!("\n╔══════════════════════════════════════════════════════════════════════╗");
    crate::kprintln!("║            KASH-OS HARDWARE COMPLIANCE & SECURITY REPORT             ║");
    crate::kprintln!("╠══════════════════════════════════════════════════════════════════════╣");
    let vendor_str = core::str::from_utf8(&f.vendor).unwrap_or("Unknown");
    crate::kprintln!("║ CPU Vendor / Cores    : {:<20} ({} active cores)        ║", vendor_str, cpus);
    crate::kprintln!("║ Detected Platform Tier: {:<45}║", tier.name());
    crate::kprintln!("╠──────────────────────────────────────────────────────────────────────╣");
    crate::kprintln!("║ HARDWARE SECURITY CAPABILITY AUDIT (NO SILENT DOWNGRADES):           ║");
    crate::kprintln!("║   * Hardware W^X / NX Execution Protection: [{:<12}]               ║", if f.has_nx { "ACTIVE" } else { "NOT AVAILABLE" });
    crate::kprintln!("║   * SMEP (Supervisor Mode Execution Prev) : [{:<12}]               ║", if f.has_smep { "ACTIVE" } else { "NOT AVAILABLE" });
    crate::kprintln!("║   * SMAP (Supervisor Mode Access Prev)    : [{:<12}]               ║", if f.has_smap { "ACTIVE" } else { "NOT AVAILABLE" });
    crate::kprintln!("║   * Intel VT-x Hardware Virtualization    : [{:<12}]               ║", if f.has_vmx { "ACTIVE" } else { "NOT AVAILABLE" });
    crate::kprintln!("║   * IOMMU / VT-d DMA Bus-Master Remapping : [{:<12}]               ║", if iommu_active { "ACTIVE" } else { "REDUCED (T0)" });
    crate::kprintln!("║   * Hardware TPM 2.0 Cryptographic Root   : [{:<12}]               ║", if tpm_status.contains("ACTIVE") { "ACTIVE" } else { "NOT AVAILABLE" });
    crate::kprintln!("║   * AES-NI Hardware Crypto Acceleration   : [{:<12}]               ║", if f.has_aesni { "ACTIVE" } else { "SOFTWARE (XChaCha20)" });
    crate::kprintln!("║   * RDRAND / RDSEED Hardware Entropy      : [{:<12}]               ║", if f.has_rdrand { "ACTIVE" } else { "FALLBACK (Jitter)" });
    crate::kprintln!("╠──────────────────────────────────────────────────────────────────────╣");
    crate::kprintln!("║ COMPENSATING POLICIES FOR DETECTED TIER:                             ║");
    if tier == HardwareTier::T0Legacy {
        crate::kprintln!("║   - Vault Key Derivation  : Memory-Hard Argon2id (OWASP Low-RAM)     ║");
        crate::kprintln!("║   - Stream Cipher         : XChaCha20-Poly1305 (Fast in software)    ║");
        crate::kprintln!("║   - DMA Port Isolation    : USB deny-by-default, Whitelisted HID only║");
        crate::kprintln!("║   - Browser Sandbox       : Lightweight Single-Pass Execution Engine ║");
    } else {
        crate::kprintln!("║   - Vault Key Derivation  : Argon2id (256 MiB, t=12, p=1) Full Spec  ║");
        crate::kprintln!("║   - Stream Cipher         : Post-Quantum ML-KEM + 4000-Stripe Split  ║");
        crate::kprintln!("║   - DMA Bus Isolation     : Hardware IOMMU Fencing for all devices   ║");
        crate::kprintln!("║   - VM Containment        : Hardware-Assisted VT-x Domain Separation ║");
    }
    crate::kprintln!("╚══════════════════════════════════════════════════════════════════════╝\n");
}
