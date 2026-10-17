//! Liquid Glass: backdrop blur + saturation + edge refraction (convex-squircle bezel, Snell's law)
//! + dual-light specular rim. Everything is computed on the CPU, per frame, on the live backdrop.
use alloc::vec::Vec;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::mathf::*;

/// Kash UI look: no inner white glow — brightness of the top sheen and of the inner specular rim (0 = off).
pub const SHEEN: f32 = 0.0;
pub const RIM: f32 = 0.0;

#[derive(Clone, Copy, Debug)]
pub struct GlassStyle {
    pub radius: f32,
    /// Gaussian sigma of the backdrop blur, px.
    pub blur: f32,
    pub tint: Color,
    pub saturation: f32,
    /// Additive brightness, -1..1.
    pub brightness: f32,
    /// Width of the refractive bezel in px (0 disables refraction).
    pub bezel: f32,
    /// Refraction strength multiplier (1 = physically plausible glass, n = 1.5).
    pub refraction: f32,
    /// Specular rim strength 0..1.
    pub spec: f32,
    pub dark: bool,
}

impl GlassStyle {
    pub fn new(radius: f32) -> GlassStyle {
        GlassStyle { radius, blur: 10.0, tint: Color::rgba(255, 255, 255, 40), saturation: 1.5, brightness: 0.0, bezel: 10.0, refraction: 1.0, spec: 0.8, dark: false }
    }
}

fn box_h(src: &[u8], dst: &mut [u8], w: usize, h: usize, r: usize) {
    let div = (2 * r + 1) as u32;
    let inv = 65536 / div;
    for y in 0..h {
        let row = &src[y * w * 3..(y + 1) * w * 3];
        let out = &mut dst[y * w * 3..(y + 1) * w * 3];
        let mut s = [0u32; 3];
        for i in -(r as i32)..=(r as i32) {
            let xi = i.clamp(0, w as i32 - 1) as usize;
            s[0] += row[xi * 3] as u32; s[1] += row[xi * 3 + 1] as u32; s[2] += row[xi * 3 + 2] as u32;
        }
        for x in 0..w {
            out[x * 3] = ((s[0] * inv + 32768) >> 16) as u8;
            out[x * 3 + 1] = ((s[1] * inv + 32768) >> 16) as u8;
            out[x * 3 + 2] = ((s[2] * inv + 32768) >> 16) as u8;
            let a = (x as i32 + r as i32 + 1).clamp(0, w as i32 - 1) as usize;
            let b = (x as i32 - r as i32).clamp(0, w as i32 - 1) as usize;
            s[0] = s[0] + row[a * 3] as u32 - row[b * 3] as u32;
            s[1] = s[1] + row[a * 3 + 1] as u32 - row[b * 3 + 1] as u32;
            s[2] = s[2] + row[a * 3 + 2] as u32 - row[b * 3 + 2] as u32;
        }
    }
}

fn box_v(src: &[u8], dst: &mut [u8], w: usize, h: usize, r: usize) {
    let div = (2 * r + 1) as u32;
    let inv = 65536 / div;
    for x in 0..w {
        let mut s = [0u32; 3];
        for i in -(r as i32)..=(r as i32) {
            let yi = i.clamp(0, h as i32 - 1) as usize;
            let o = (yi * w + x) * 3;
            s[0] += src[o] as u32; s[1] += src[o + 1] as u32; s[2] += src[o + 2] as u32;
        }
        for y in 0..h {
            let o = (y * w + x) * 3;
            dst[o] = ((s[0] * inv + 32768) >> 16) as u8;
            dst[o + 1] = ((s[1] * inv + 32768) >> 16) as u8;
            dst[o + 2] = ((s[2] * inv + 32768) >> 16) as u8;
            let a = ((y as i32 + r as i32 + 1).clamp(0, h as i32 - 1) as usize * w + x) * 3;
            let b = ((y as i32 - r as i32).clamp(0, h as i32 - 1) as usize * w + x) * 3;
            s[0] = s[0] + src[a] as u32 - src[b] as u32;
            s[1] = s[1] + src[a + 1] as u32 - src[b + 1] as u32;
            s[2] = s[2] + src[a + 2] as u32 - src[b + 2] as u32;
        }
    }
}

/// Reusable scratch to avoid per-frame allocation churn.
#[derive(Default)]
pub struct GlassScratch { a: Vec<u8>, b: Vec<u8> }

#[inline]
fn bilinear_q(lo: &[u8], lw: usize, lh: usize, fxq: i32, fyq: i32) -> (i32, i32, i32) {
    let fxq = fxq.clamp(0, ((lw as i32 - 1) * 256 - 1).max(0));
    let fyq = fyq.clamp(0, ((lh as i32 - 1) * 256 - 1).max(0));
    let x0 = (fxq >> 8) as usize; let y0 = (fyq >> 8) as usize;
    let x1 = (x0 + 1).min(lw - 1); let y1 = (y0 + 1).min(lh - 1);
    let tx = fxq & 255; let ty = fyq & 255;
    let i00 = (y0 * lw + x0) * 3; let i10 = (y0 * lw + x1) * 3; let i01 = (y1 * lw + x0) * 3; let i11 = (y1 * lw + x1) * 3;
    let c = |o: usize| -> i32 {
        let top = lo[i00 + o] as i32 * (256 - tx) + lo[i10 + o] as i32 * tx;
        let bot = lo[i01 + o] as i32 * (256 - tx) + lo[i11 + o] as i32 * tx;
        (top * (256 - ty) + bot * ty) >> 16
    };
    (c(0), c(1), c(2))
}

/// Inward refraction displacement LUT over normalised bezel depth t ∈ [0,1] (edge→flat).
/// Convex squircle height profile y=(1-(1-t)^4)^(1/4); Snell's law with n=1.5.
fn displacement_lut(bezel: f32, strength: f32, out: &mut [f32; 33]) {
    let thickness = bezel * 0.9;
    let n = 1.5f32;
    for i in 0..=32 {
        let t = (i as f32 / 32.0).max(0.004);
        let u = 1.0 - t;
        let u4 = u * u * u * u;
        let y = powf(1.0 - u4, 0.25);
        let dy = powf(1.0 - u4, -0.75) * u * u * u;
        let slope = thickness * dy / bezel;
        let th1 = atan(slope);
        let s2 = sin(th1) / n;
        let th2 = asin(clamp(s2, -1.0, 1.0));
        let disp = (thickness * y + bezel * 0.4) * tan(th1 - th2);
        out[i] = clamp(disp * strength, 0.0, bezel * 1.6);
    }
    out[32] = 0.0;
}

impl Canvas {
    pub fn glass(&mut self, rect: Rect, st: &GlassStyle, scratch: &mut GlassScratch) {
        if rect.w < 2.0 || rect.h < 2.0 { return; }
        let r = st.radius.min(rect.w * 0.5).min(rect.h * 0.5).max(0.0);
        let bb = IRect::from_rect_outer(&rect).intersect(&self.clip());
        if bb.is_empty() { return; }
        let bezel = st.bezel.max(0.0);
        let mut lut = [0f32; 33];
        if bezel > 0.5 { displacement_lut(bezel, st.refraction, &mut lut); }
        let mut maxdisp = 0.0f32;
        for v in lut.iter() { maxdisp = maxdisp.max(*v); }
        let margin = ceil(st.blur * 2.0 + maxdisp + 3.0) as i32;
        let full = IRect::from_rect_outer(&rect);
        let src = IRect::new(full.x0 - margin, full.y0 - margin, full.x1 + margin, full.y1 + margin).intersect(&self.bounds());
        if src.is_empty() { return; }
        let k: i32 = if st.blur < 2.5 { 1 } else if st.blur < 9.0 { 2 } else { 4 };
        let lw = ((src.w() + k - 1) / k) as usize; let lh = ((src.h() + k - 1) / k) as usize;
        if lw == 0 || lh == 0 { return; }
        scratch.a.clear(); scratch.a.resize(lw * lh * 3, 0);
        scratch.b.clear(); scratch.b.resize(lw * lh * 3, 0);
        // 1) downsample backdrop (box average)
        let dsh: u32 = match k { 1 => 0, 2 => 2, _ => 4 };
        for ly in 0..lh {
            for lx in 0..lw {
                let (mut sr, mut sg, mut sb) = (0u32, 0u32, 0u32);
                let y0 = src.y0 + ly as i32 * k; let x0 = src.x0 + lx as i32 * k;
                for yy in 0..k {
                    let y = (y0 + yy).min(src.y1 - 1);
                    for xx in 0..k {
                        let x = (x0 + xx).min(src.x1 - 1);
                        let p = self.px[(y * self.w + x) as usize];
                        sr += (p >> 16) & 255; sg += (p >> 8) & 255; sb += p & 255;
                    }
                }
                let o = (ly * lw + lx) * 3;
                scratch.a[o] = (sr >> dsh) as u8; scratch.a[o + 1] = (sg >> dsh) as u8; scratch.a[o + 2] = (sb >> dsh) as u8;
            }
        }
        // 2) blur (box passes ≈ gaussian)
        let sigma_lo = st.blur / k as f32;
        if sigma_lo >= 0.45 {
            let rb = (sigma_lo * 0.95).max(1.0) as usize;
            let passes = if sigma_lo >= 3.0 { 3 } else { 2 };
            for _ in 0..passes {
                box_h(&scratch.a, &mut scratch.b, lw, lh, rb);
                box_v(&scratch.b, &mut scratch.a, lw, lh, rb);
            }
        }
        // saturation + tint are affine → apply once at low-res
        {
            let satq = (st.saturation * 256.0) as i32;
            let ta = st.tint.a as i32;
            let (tr, tg, tb) = (st.tint.r as i32, st.tint.g as i32, st.tint.b as i32);
            for p in scratch.a.chunks_exact_mut(3) {
                let (mut rr, mut gg, mut bl) = (p[0] as i32, p[1] as i32, p[2] as i32);
                let lum = (77 * rr + 150 * gg + 29 * bl) >> 8;
                rr = lum + (((rr - lum) * satq) >> 8); gg = lum + (((gg - lum) * satq) >> 8); bl = lum + (((bl - lum) * satq) >> 8);
                if ta > 0 { rr += ((tr - rr) * ta) >> 8; gg += ((tg - gg) * ta) >> 8; bl += ((tb - bl) * ta) >> 8; }
                p[0] = rr.clamp(0, 255) as u8; p[1] = gg.clamp(0, 255) as u8; p[2] = bl.clamp(0, 255) as u8;
            }
        }
        let lo = &scratch.a;

        // ── flat fast path: no bezel, square corners, no specular → pure bilinear upsample of the blurred backdrop
        if bezel < 0.5 && r < 0.5 && st.spec == 0.0 && lw >= 2 && lh >= 2 {
            let ks: i32 = match k { 1 => 0, 2 => 1, _ => 2 };
            let bright = (st.brightness * 255.0) as i32;
            let mut tmp = alloc::vec![0i32; lw * 3];
            let maxy = (lh as i32 - 1) * 256 - 1; let maxx = (lw as i32 - 1) * 256 - 1;
            for y in bb.y0..bb.y1 {
                let fyq = ((((y - src.y0) << 8) + 128) >> ks) - 128;
                let fyq = fyq.clamp(0, maxy);
                let (y0, ty) = ((fyq >> 8) as usize, fyq & 255);
                let (r0, r1) = (&lo[y0 * lw * 3..(y0 + 1) * lw * 3], &lo[(y0 + 1) * lw * 3..(y0 + 2) * lw * 3]);
                for i in 0..lw * 3 { tmp[i] = (r0[i] as i32 * (256 - ty) + r1[i] as i32 * ty) >> 8; }
                let v = saturate((y as f32 + 0.5 - rect.y) / rect.h);
                let add = bright + ((1.0 - v) * SHEEN * st.spec) as i32;
                let row = (y * self.w) as usize;
                for x in bb.x0..bb.x1 {
                    let fxq = (((((x - src.x0) << 8) + 128) >> ks) - 128).clamp(0, maxx);
                    let (x0, tx) = ((fxq >> 8) as usize * 3, fxq & 255);
                    let rr = ((tmp[x0] * (256 - tx) + tmp[x0 + 3] * tx) >> 8) + add;
                    let gg = ((tmp[x0 + 1] * (256 - tx) + tmp[x0 + 4] * tx) >> 8) + add;
                    let bl = ((tmp[x0 + 2] * (256 - tx) + tmp[x0 + 5] * tx) >> 8) + add;
                    self.px[row + x as usize] = ((rr.clamp(0, 255) as u32) << 16) | ((gg.clamp(0, 255) as u32) << 8) | bl.clamp(0, 255) as u32;
                }
            }
            return;
        }
        let (cx, cy, hw, hh) = (rect.cx(), rect.cy(), rect.w * 0.5, rect.h * 0.5);
        let inner = rect.inset(bezel.max(r) + 1.0);
        let (ix0, ix1, iy0, iy1) = (ceil(inner.x) as i32, floor(inner.right()) as i32, ceil(inner.y) as i32, floor(inner.bottom()) as i32);
        let bright = (st.brightness * 255.0) as i32;
        let (lx, ly) = (-0.5f32, -0.866f32);
        let rim_w = (bezel * 0.22).max(1.2);
        let ks: i32 = match k { 1 => 0, 2 => 1, _ => 2 };
        let hl_col: i32 = if st.dark { 235 } else { 255 };
        let hl_gain = st.spec * if st.dark { 0.75 } else { 1.0 };
        let mut rim_lut = [0f32; 160]; let mut edge_lut = [0f32; 160];
        for i in 0..160 {
            let d = i as f32 * 0.25;
            rim_lut[i] = 0.65 * exp(-(d / rim_w) * (d / rim_w)) + 0.35 * exp(-(d / (rim_w * 3.0)) * (d / (rim_w * 3.0)));
            edge_lut[i] = exp(-(d / 0.9) * (d / 0.9));
        }
        let mut hl_lut = [0f32; 129];
        for i in 0..129 {
            let a = (i as f32 - 64.0) / 64.0;
            hl_lut[i] = if a > 0.0 { powf(a, 1.3) } else { 0.5 * powf(-a, 1.3) };
        }
        let sheen_amp = SHEEN * st.spec;
        let band = bezel + rim_w * 3.0;

        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            let row = (y * self.w) as usize;
            let v = saturate((yc - rect.y) / rect.h);
            let sheen = (1.0 - v) * sheen_amp;
            let add = bright + sheen as i32;
            let fyq_base = ((((y - src.y0) << 8) + 128) >> ks) - 128;
            for x in bb.x0..bb.x1 {
                let interior = x >= ix0 && x < ix1 && y >= iy0 && y < iy1;
                let mut fxq = ((((x - src.x0) << 8) + 128) >> ks) - 128;
                let mut fyq = fyq_base;
                let mut cov = 255u32;
                let mut hl256 = 0i32;
                if !interior {
                    let xc = x as f32 + 0.5;
                    let dx = xc - cx; let dy = yc - cy;
                    let qx = fabs(dx) - (hw - r); let qy = fabs(dy) - (hh - r);
                    let (sd, nx, ny);
                    if qx > 0.0 && qy > 0.0 {
                        let l = sqrt(qx * qx + qy * qy).max(0.0001);
                        sd = l - r;
                        nx = qx / l * if dx < 0.0 { -1.0 } else { 1.0 };
                        ny = qy / l * if dy < 0.0 { -1.0 } else { 1.0 };
                    } else if qx > qy {
                        sd = qx - r; nx = if dx < 0.0 { -1.0 } else { 1.0 }; ny = 0.0;
                    } else {
                        sd = qy - r; nx = 0.0; ny = if dy < 0.0 { -1.0 } else { 1.0 };
                    }
                    if sd > 0.5 { continue; }
                    cov = (saturate(0.5 - sd) * 255.0 + 0.5) as u32;
                    let d = if sd < 0.0 { -sd } else { 0.0 };
                    if d < band {
                        if d < bezel && bezel > 0.5 {
                            let t = saturate(d / bezel) * 32.0;
                            let i0 = t as usize; let f = t - i0 as f32;
                            let disp = lut[i0] + (lut[(i0 + 1).min(32)] - lut[i0]) * f;
                            let sx = xc - nx * disp; let sy = yc - ny * disp;
                            fxq = ((((sx - src.x0 as f32) * 256.0) as i32 + 128) >> ks) - 128;
                            fyq = ((((sy - src.y0 as f32) * 256.0) as i32 + 128) >> ks) - 128;
                        }
                        let a = nx * lx + ny * ly;
                        let hl = hl_lut[((a * 64.0 + 64.5) as usize).min(128)];
                        let di = ((d * 4.0) as usize).min(159);
                        let spec = hl * rim_lut[di] * hl_gain;
                        let edge_line = edge_lut[di] * (0.16 + 0.34 * saturate(hl)) * st.spec.min(1.0);
                        hl256 = (saturate((spec * 0.75 + edge_line) * RIM) * 256.0) as i32;
                    }
                }
                let (mut rr, mut gg, mut bl) = if k == 1 && interior {
                    let o = ((y - src.y0) as usize * lw + (x - src.x0) as usize) * 3;
                    (lo[o] as i32, lo[o + 1] as i32, lo[o + 2] as i32)
                } else { bilinear_q(lo, lw, lh, fxq, fyq) };
                rr += add; gg += add; bl += add;
                if hl256 > 0 {
                    rr += ((hl_col - rr) * hl256) >> 8; gg += ((hl_col - gg) * hl256) >> 8; bl += ((hl_col - bl) * hl256) >> 8;
                }
                let o = ((rr.clamp(0, 255) as u32) << 16) | ((gg.clamp(0, 255) as u32) << 8) | bl.clamp(0, 255) as u32;
                let i = row + x as usize;
                self.px[i] = if cov >= 255 { o } else { mix_pix(self.px[i], o, (cov * 256 / 255).min(256)) };
            }
        }
    }
}

// ── Nitpicker-Inspired Frosted Glass Surface & Unforgeable 4px Security Border ──

use crate::registry::SecurityColorTag;
use crate::theme::{theme_for_tag, RgbaColor};

pub struct GlassSurface {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub border_thickness: u32,
}

impl GlassSurface {
    /// Renders an unforgeable security border and optional domain-tinted glass background
    /// directly into the hardware framebuffer. Client VMs cannot draw over `border_thickness`.
    pub fn composite_secure_frame(
        &self,
        framebuffer: &mut [u32],
        fb_stride: u32,
        tag: SecurityColorTag,
        apply_background_tint: bool,
        xray_overlay_mode: bool,
    ) {
        let theme = theme_for_tag(tag);
        let border_px = self.border_thickness.max(4); // Mandatory minimum 4px security border
        let border_argb = theme.primary_border.to_argb32();
        let bg_color = if apply_background_tint {
            theme.subtle_window_tint
        } else {
            RgbaColor::new(20, 22, 26, 240)
        };

        for row in 0..self.height {
            let py = self.y + row;
            for col in 0..self.width {
                let px = self.x + col;
                let idx = (py * fb_stride + px) as usize;

                if idx >= framebuffer.len() {
                    continue;
                }

                let is_security_border = row < border_px
                    || row >= self.height.saturating_sub(border_px)
                    || col < border_px
                    || col >= self.width.saturating_sub(border_px)
                    || row < 28; // Mandatory 28px unforgeable Nitpicker title bar

                if is_security_border {
                    framebuffer[idx] = border_argb;
                } else if xray_overlay_mode {
                    // Nitpicker X-Ray mode dims client content and highlights domain ownership
                    framebuffer[idx] = Self::blend_pixel(framebuffer[idx], theme.primary_border, 96);
                } else {
                    framebuffer[idx] = Self::blend_pixel(framebuffer[idx], bg_color, bg_color.a);
                }
            }
        }
    }

    #[inline(always)]
    fn blend_pixel(dst: u32, src: RgbaColor, alpha: u8) -> u32 {
        let inv_a = (255 - alpha) as u32;
        let a = alpha as u32;
        let dst_r = (dst >> 16) & 0xFF;
        let dst_g = (dst >> 8) & 0xFF;
        let dst_b = dst & 0xFF;

        let out_r = ((src.r as u32 * a) + (dst_r * inv_a)) >> 8;
        let out_g = ((src.g as u32 * a) + (dst_g * inv_a)) >> 8;
        let out_b = ((src.b as u32 * a) + (dst_b * inv_a)) >> 8;

        0xFF00_0000 | (out_r << 16) | (out_g << 8) | out_b
    }
}

