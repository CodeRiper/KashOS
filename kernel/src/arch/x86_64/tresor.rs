//! TRESOR-style key storage: hold sensitive key material in CPU debug
//! registers (DR0–DR3) instead of RAM, so a cold-boot attack (dumping DRAM
//! within the few minutes its contents can survive after power loss) finds
//! nothing — the key was never in DRAM in the first place.
//!
//! This is the "legacy hardware, no TPM" path the architecture audit asked
//! for specifically; TPM 2.0 PCR-sealed keys are the modern-hardware
//! equivalent and are **not** implemented here — see this module's
//! limitations section below for exactly why, rather than a half-working
//! TPM2 command driver masquerading as one.
//!
//! DR0–DR3 are each a 64-bit "debug address" register, normally used to set
//! hardware breakpoint addresses. TRESOR's technique (Müller, Freiling &
//! Dewald, 2011) repurposes them as plain scratch storage: writing a value
//! into DR0 does not, by itself, do anything — a debug-address register
//! only triggers a trap if the matching enable bits in DR7 are also set.
//! This module never touches DR7, so DR0–DR3 holding key material here has
//! no side effect on debugging or exception behaviour; it only matters
//! that the CPU, not DRAM, is where the bits physically live.
//!
//! # Limitations (read before relying on this for anything real)
//! - **32 bytes only.** Four 64-bit registers is one AES-256 key, with no
//!   room left over for anything else — this is a hard ceiling, not a
//!   tuning parameter.
//! - **Lost across a context switch that doesn't know to preserve it, and
//!   always lost on any reset.** There is no scheduler yet in this kernel,
//!   so that caveat is currently theoretical, but it stops being
//!   theoretical the moment one exists — whatever eventually calls
//!   `store`/`load` needs to be the *only* thing that ever touches DR0–DR3
//!   for the lifetime the key needs to survive, or a future context-switch
//!   routine needs to know to save/restore them like any other register.
//! - **A debugger (including a hypervisor's) can simply read these
//!   registers too** — this defeats a cold-boot DRAM dump, not a live
//!   debugger or hypervisor with EL1/ring-0-equivalent access to the CPU
//!   state. It is one specific, real mitigation for one specific, real
//!   attack, not a general "now the key is safe" claim.
#![allow(unsafe_code)]

/// Store a 32-byte key into DR0–DR3 (8 bytes each, little-endian), zeroing
/// the Rust-side buffer it came from — the whole point is that the only
/// remaining copy is inside the CPU, not in RAM.
///
/// # Safety
/// Caller must not already be relying on DR0–DR3 for real hardware
/// breakpoints — this overwrites them unconditionally.
pub unsafe fn store(key: &mut [u8; 32]) {
    let w = |bytes: &[u8]| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
    let (d0, d1, d2, d3) = (w(&key[0..8]), w(&key[8..16]), w(&key[16..24]), w(&key[24..32]));
    // SAFETY: DR0–DR3 are freely writable from ring 0 (CPL=0, which the
    // kernel always runs at — there is no ring 3 support yet); this
    // function's own doc comment covers the "don't also need them for real
    // breakpoints" precondition the caller must uphold.
    unsafe {
        core::arch::asm!("mov dr0, {0}", in(reg) d0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov dr1, {0}", in(reg) d1, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov dr2, {0}", in(reg) d2, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov dr3, {0}", in(reg) d3, options(nomem, nostack, preserves_flags));
    }
    // The only remaining copy is now inside the CPU — scrub the one that
    // was in RAM a moment ago. A plain assignment could be optimised away
    // by the compiler since `key` isn't read again in its caller's eyes;
    // volatile writes can't be.
    for b in key.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
}

/// Read the 32-byte key back out of DR0–DR3.
///
/// # Safety
/// Caller must only call this after a matching `store`, with nothing else
/// having touched DR0–DR3 in between.
pub unsafe fn load() -> [u8; 32] {
    let (d0, d1, d2, d3): (u64, u64, u64, u64);
    // SAFETY: pure reads of CPU state, no side effects of their own.
    unsafe {
        core::arch::asm!("mov {0}, dr0", out(reg) d0, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {0}, dr1", out(reg) d1, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {0}, dr2", out(reg) d2, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov {0}, dr3", out(reg) d3, options(nomem, nostack, preserves_flags));
    }
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&d0.to_le_bytes());
    out[8..16].copy_from_slice(&d1.to_le_bytes());
    out[16..24].copy_from_slice(&d2.to_le_bytes());
    out[24..32].copy_from_slice(&d3.to_le_bytes());
    out
}

/// Zero DR0–DR3. Call this when the key is no longer needed — e.g. on the
/// same panic/duress/chassis-intrusion path that already zeroes RAM-held
/// secrets elsewhere in this project's design.
pub fn clear() {
    // SAFETY: writing a fixed, non-secret value (zero); no precondition beyond CPL=0.
    unsafe {
        core::arch::asm!("mov dr0, {0}", in(reg) 0u64, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov dr1, {0}", in(reg) 0u64, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov dr2, {0}", in(reg) 0u64, options(nomem, nostack, preserves_flags));
        core::arch::asm!("mov dr3, {0}", in(reg) 0u64, options(nomem, nostack, preserves_flags));
    }
}

/// Real round-trip test, run live at boot (not just in a host test — DR0–DR3
/// are privileged, ring-0-only registers, so this can only genuinely be
/// exercised inside the booting kernel, the same reasoning as every other
/// privileged-instruction test in this project).
pub fn selftest() {
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(0x9B).wrapping_add(0x5A); // arbitrary, non-trivial pattern
    }
    let expected = key;

    // SAFETY: nothing else in this kernel uses DR0–DR3 (no debugger, no
    // breakpoints are ever set), satisfying `store`/`load`'s preconditions.
    unsafe {
        store(&mut key);
    }
    if key != [0u8; 32] {
        panic!("tresor selftest: RAM copy was not scrubbed after store");
    }

    let round_tripped = unsafe { load() };
    if round_tripped != expected {
        panic!("tresor selftest: key read back from DR0-3 does not match what was stored");
    }

    clear();
    let after_clear = unsafe { load() };
    if after_clear != [0u8; 32] {
        panic!("tresor selftest: DR0-3 did not actually clear");
    }

    kprintln!("[selftest] TRESOR key storage (DR0-3): ok (32-byte round trip verified, RAM copy scrubbed, clear verified)");
}
