//! Tiny f32 math layer on top of `libm` so the whole crate stays `no_std`.
#![allow(dead_code)]

#[inline] pub fn sqrt(x: f32) -> f32 { libm::sqrtf(x) }
#[inline] pub fn floor(x: f32) -> f32 { libm::floorf(x) }
#[inline] pub fn ceil(x: f32) -> f32 { libm::ceilf(x) }
#[inline] pub fn powf(x: f32, y: f32) -> f32 { libm::powf(x, y) }
#[inline] pub fn exp(x: f32) -> f32 { libm::expf(x) }
#[inline] pub fn sin(x: f32) -> f32 { libm::sinf(x) }
#[inline] pub fn cos(x: f32) -> f32 { libm::cosf(x) }
#[inline] pub fn tan(x: f32) -> f32 { libm::tanf(x) }
#[inline] pub fn atan(x: f32) -> f32 { libm::atanf(x) }
#[inline] pub fn asin(x: f32) -> f32 { libm::asinf(x) }
#[inline] pub fn atan2(y: f32, x: f32) -> f32 { libm::atan2f(y, x) }
#[inline] pub fn fabs(x: f32) -> f32 { if x < 0.0 { -x } else { x } }
#[inline] pub fn clamp(x: f32, lo: f32, hi: f32) -> f32 { if x < lo { lo } else if x > hi { hi } else { x } }
#[inline] pub fn saturate(x: f32) -> f32 { clamp(x, 0.0, 1.0) }
#[inline] pub fn lerp(a: f32, b: f32, t: f32) -> f32 { a + (b - a) * t }
#[inline] pub fn smoothstep(e0: f32, e1: f32, x: f32) -> f32 {
    let t = saturate((x - e0) / (e1 - e0));
    t * t * (3.0 - 2.0 * t)
}
#[inline] pub fn round(x: f32) -> f32 { libm::roundf(x) }
#[inline] pub fn fract(x: f32) -> f32 { x - floor(x) }
pub const PI: f32 = core::f32::consts::PI;
pub const TAU: f32 = core::f32::consts::TAU;

/// Cheap deterministic hash noise in [0,1).
#[inline]
pub fn hash2(x: i32, y: i32, seed: u32) -> f32 {
    let mut h = (x as u32).wrapping_mul(0x27d4_eb2d) ^ (y as u32).wrapping_mul(0x1656_67b1) ^ seed.wrapping_mul(0x9e37_79b9);
    h ^= h >> 15; h = h.wrapping_mul(0x85eb_ca6b); h ^= h >> 13; h = h.wrapping_mul(0xc2b2_ae35); h ^= h >> 16;
    (h & 0x00ff_ffff) as f32 / 16_777_216.0
}

/// Smooth value noise.
pub fn vnoise(x: f32, y: f32, seed: u32) -> f32 {
    let xi = floor(x); let yi = floor(y);
    let xf = x - xi; let yf = y - yi;
    let (xi, yi) = (xi as i32, yi as i32);
    let u = xf * xf * (3.0 - 2.0 * xf);
    let v = yf * yf * (3.0 - 2.0 * yf);
    let a = hash2(xi, yi, seed);
    let b = hash2(xi + 1, yi, seed);
    let c = hash2(xi, yi + 1, seed);
    let d = hash2(xi + 1, yi + 1, seed);
    lerp(lerp(a, b, u), lerp(c, d, u), v)
}

pub fn fbm(mut x: f32, mut y: f32, oct: u32, seed: u32) -> f32 {
    let mut amp = 0.5; let mut sum = 0.0; let mut norm = 0.0;
    for i in 0..oct {
        sum += amp * vnoise(x, y, seed.wrapping_add(i * 31));
        norm += amp;
        x *= 2.03; y *= 2.03; amp *= 0.5;
    }
    sum / norm
}

// ── Deterministic Fixed-Point Layout & Graph Geometry Helpers ───────────────

#[inline(always)]
pub const fn clamp_u32(val: u32, min_val: u32, max_val: u32) -> u32 {
    if val < min_val {
        min_val
    } else if val > max_val {
        max_val
    } else {
        val
    }
}

/// Calculates fill width in pixels for Untyped Memory watermark and ARINC 653 bars
#[inline(always)]
pub const fn percentage_bar_width(used: u32, total: u32, bar_max_px: u32) -> u32 {
    if total == 0 {
        return 0;
    }
    let scaled = (used as u64 * bar_max_px as u64) / (total as u64);
    clamp_u32(scaled as u32, 0, bar_max_px)
}

