//! Colours. Canvas pixels are `0x00RRGGBB`; `Color` carries straight (non-premultiplied) alpha.
use crate::mathf::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Color { pub r: u8, pub g: u8, pub b: u8, pub a: u8 }

impl Color {
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color { Color { r, g, b, a } }
    pub const fn rgb(r: u8, g: u8, b: u8) -> Color { Color { r, g, b, a: 255 } }
    pub const fn hex(h: u32) -> Color { Color { r: (h >> 16) as u8, g: (h >> 8) as u8, b: h as u8, a: 255 } }
    pub const WHITE: Color = Color::rgb(255, 255, 255);
    pub const BLACK: Color = Color::rgb(0, 0, 0);
    pub const CLEAR: Color = Color::rgba(0, 0, 0, 0);
    /// Multiply alpha by `f` in 0..1.
    pub fn fade(self, f: f32) -> Color { Color { a: (self.a as f32 * saturate(f) + 0.5) as u8, ..self } }
    pub fn alpha(self, a: f32) -> Color { Color { a: (saturate(a) * 255.0 + 0.5) as u8, ..self } }
    pub fn pix(self) -> u32 { ((self.r as u32) << 16) | ((self.g as u32) << 8) | self.b as u32 }
    pub fn from_pix(p: u32) -> Color { Color::rgb((p >> 16) as u8, (p >> 8) as u8, p as u8) }
    pub fn mix(self, o: Color, t: f32) -> Color {
        let t = saturate(t);
        let m = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t + 0.5) as u8;
        Color { r: m(self.r, o.r), g: m(self.g, o.g), b: m(self.b, o.b), a: m(self.a, o.a) }
    }
    pub fn lighten(self, t: f32) -> Color { self.mix(Color::rgba(255, 255, 255, self.a), t) }
    pub fn darken(self, t: f32) -> Color { self.mix(Color::rgba(0, 0, 0, self.a), t) }
    pub fn luma(self) -> f32 { (0.2126 * self.r as f32 + 0.7152 * self.g as f32 + 0.0722 * self.b as f32) / 255.0 }
}

/// Source-over blend of (r,g,b,a) onto an opaque 0x00RRGGBB pixel.
#[inline(always)]
pub fn blend(dst: u32, r: u32, g: u32, b: u32, a: u32) -> u32 {
    if a == 0 { return dst; }
    if a >= 255 { return (r << 16) | (g << 8) | b; }
    let ia = 255 - a;
    let dr = (dst >> 16) & 255; let dg = (dst >> 8) & 255; let db = dst & 255;
    let nr = (r * a + dr * ia + 127) / 255;
    let ng = (g * a + dg * ia + 127) / 255;
    let nb = (b * a + db * ia + 127) / 255;
    (nr << 16) | (ng << 8) | nb
}

#[inline(always)]
pub fn blend_c(dst: u32, c: Color, cov: u32) -> u32 {
    let a = if cov >= 255 { c.a as u32 } else { (c.a as u32 * cov + 127) / 255 };
    blend(dst, c.r as u32, c.g as u32, c.b as u32, a)
}

#[inline(always)]
pub fn mix_pix(a: u32, b: u32, t256: u32) -> u32 {
    // SWAR: two channels per multiply (bit-identical to the per-channel `(a*(256-t) + b*t) >> 8`).
    let t = t256.min(256);
    let it = 256 - t;
    let rb = (((a & 0x00FF_00FF) * it + (b & 0x00FF_00FF) * t) >> 8) & 0x00FF_00FF;
    let g = (((a & 0x0000_FF00) * it + (b & 0x0000_FF00) * t) >> 8) & 0x0000_FF00;
    rb | g
}

/// HSV (h in 0..360, s,v in 0..1) → Color.
pub fn hsv(h: f32, s: f32, v: f32) -> Color {
    let h = (h % 360.0 + 360.0) % 360.0 / 60.0;
    let i = floor(h); let f = h - i;
    let p = v * (1.0 - s); let q = v * (1.0 - s * f); let t = v * (1.0 - s * (1.0 - f));
    let (r, g, b) = match i as i32 { 0 => (v, t, p), 1 => (q, v, p), 2 => (p, v, t), 3 => (p, q, v), 4 => (t, p, v), _ => (v, p, q) };
    Color::rgb((r * 255.0 + 0.5) as u8, (g * 255.0 + 0.5) as u8, (b * 255.0 + 0.5) as u8)
}
