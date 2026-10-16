//! Software canvas: anti-aliased SDF primitives, polygons, shadows.
//! Pixel format is `0x00RRGGBB` (matches a GRUB/UEFI BGRX linear framebuffer on little-endian).
use alloc::vec::Vec;
use alloc::vec;
use crate::color::*;
use crate::geom::*;
use crate::mathf::*;

#[derive(Clone, Copy, Debug)]
pub enum Paint {
    Solid(Color),
    VGrad { y0: f32, y1: f32, c0: Color, c1: Color },
    Linear { p0: Pt, p1: Pt, c0: Color, c1: Color },
    Radial { c: Pt, r: f32, c0: Color, c1: Color },
}

impl Paint {
    #[inline]
    pub fn at(&self, x: f32, y: f32) -> Color {
        match *self {
            Paint::Solid(c) => c,
            Paint::VGrad { y0, y1, c0, c1 } => c0.mix(c1, (y - y0) / (y1 - y0).max(0.001)),
            Paint::Linear { p0, p1, c0, c1 } => {
                let dx = p1.x - p0.x; let dy = p1.y - p0.y;
                let t = ((x - p0.x) * dx + (y - p0.y) * dy) / (dx * dx + dy * dy).max(0.001);
                c0.mix(c1, t)
            }
            Paint::Radial { c, r, c0, c1 } => {
                let dx = x - c.x; let dy = y - c.y;
                c0.mix(c1, sqrt(dx * dx + dy * dy) / r.max(0.001))
            }
        }
    }
}
impl From<Color> for Paint { fn from(c: Color) -> Paint { Paint::Solid(c) } }

/// Signed distance to a rounded rectangle (negative inside).
#[inline]
pub fn rrect_sd(px: f32, py: f32, cx: f32, cy: f32, hw: f32, hh: f32, r: f32) -> f32 {
    let qx = fabs(px - cx) - (hw - r);
    let qy = fabs(py - cy) - (hh - r);
    if qx > 0.0 && qy > 0.0 { sqrt(qx * qx + qy * qy) - r } else if qx > qy { qx - r } else { qy - r }
}

#[inline] fn cov8(d: f32) -> u32 { (saturate(0.5 - d) * 255.0 + 0.5) as u32 }

pub struct Canvas {
    pub w: i32,
    pub h: i32,
    pub px: Vec<u32>,
    clip: IRect,
    stack: Vec<IRect>,
}

impl Canvas {
    pub fn new(w: i32, h: i32) -> Canvas {
        let (w, h) = (w.max(1), h.max(1));
        Canvas { w, h, px: vec![0; (w * h) as usize], clip: IRect::new(0, 0, w, h), stack: Vec::new() }
    }
    pub fn resize(&mut self, w: i32, h: i32) {
        let (w, h) = (w.max(1), h.max(1));
        if w == self.w && h == self.h { return; }
        self.w = w; self.h = h;
        self.px.clear(); self.px.resize((w * h) as usize, 0);
        self.clip = IRect::new(0, 0, w, h);
        self.stack.clear();
    }
    pub fn bounds(&self) -> IRect { IRect::new(0, 0, self.w, self.h) }
    pub fn clip(&self) -> IRect { self.clip }
    pub fn push_clip(&mut self, r: Rect) {
        self.stack.push(self.clip);
        let ir = IRect::from_rect_outer(&r);
        self.clip = self.clip.intersect(&ir);
    }
    pub fn push_clip_i(&mut self, ir: IRect) { self.stack.push(self.clip); self.clip = self.clip.intersect(&ir); }
    pub fn pop_clip(&mut self) { if let Some(c) = self.stack.pop() { self.clip = c; } }
    pub fn clear(&mut self, c: Color) { let p = c.pix(); for v in self.px.iter_mut() { *v = p; } }
    #[inline] pub fn get(&self, x: i32, y: i32) -> u32 {
        let x = x.clamp(0, self.w - 1); let y = y.clamp(0, self.h - 1);
        self.px[(y * self.w + x) as usize]
    }

    pub fn fill_rect(&mut self, rect: Rect, paint: impl Into<Paint>) { self.fill_rrect(rect, 0.0, paint) }

    pub fn fill_rrect(&mut self, rect: Rect, r: f32, paint: impl Into<Paint>) {
        let paint: Paint = paint.into();
        if rect.w <= 0.0 || rect.h <= 0.0 { return; }
        let r = r.min(rect.w * 0.5).min(rect.h * 0.5).max(0.0);
        let bb = IRect::from_rect_outer(&rect).intersect(&self.clip);
        if bb.is_empty() { return; }
        let (cx, cy, hw, hh) = (rect.cx(), rect.cy(), rect.w * 0.5, rect.h * 0.5);
        let (left, right, top, bottom) = (rect.x, rect.right(), rect.y, rect.bottom());
        let solid = if let Paint::Solid(c) = paint { Some(c) } else { None };
        let stride = self.w;
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            let edge_row = yc < top + 1.0 || yc > bottom - 1.0;
            let corner_row = r > 0.0 && (yc < top + r || yc > bottom - r);
            let (le, rs) = if corner_row { (ceil(left + r), floor(right - r)) } else { (ceil(left) + 1.0, floor(right) - 1.0) };
            let lend = (le as i32).clamp(bb.x0, bb.x1);
            let rstart = (rs as i32).clamp(lend, bb.x1);
            let row = (y * stride) as usize;
            let aa = |this: &mut Canvas, x: i32| {
                let xc = x as f32 + 0.5;
                let d = rrect_sd(xc, yc, cx, cy, hw, hh, r);
                let cv = cov8(d);
                if cv == 0 { return; }
                let c = match solid { Some(c) => c, None => paint.at(xc, yc) };
                let i = row + x as usize;
                this.px[i] = blend_c(this.px[i], c, cv);
            };
            for x in bb.x0..lend { aa(self, x); }
            if edge_row {
                for x in lend..rstart { aa(self, x); }
            } else if let Some(c) = solid {
                let sl = &mut self.px[row + lend as usize..row + rstart as usize];
                if c.a == 255 { let p = c.pix(); for v in sl.iter_mut() { *v = p; } }
                else if c.a > 0 { for v in sl.iter_mut() { *v = blend(*v, c.r as u32, c.g as u32, c.b as u32, c.a as u32); } }
            } else {
                for x in lend..rstart {
                    let c = paint.at(x as f32 + 0.5, yc);
                    let i = row + x as usize;
                    self.px[i] = blend(self.px[i], c.r as u32, c.g as u32, c.b as u32, c.a as u32);
                }
            }
            for x in rstart..bb.x1 { aa(self, x); }
        }
    }

    pub fn stroke_rrect(&mut self, rect: Rect, r: f32, width: f32, color: Color) {
        if rect.w <= 0.0 || rect.h <= 0.0 || color.a == 0 { return; }
        let r = r.min(rect.w * 0.5).min(rect.h * 0.5).max(0.0);
        let bb = IRect::from_rect_outer(&rect).intersect(&self.clip);
        if bb.is_empty() { return; }
        let (cx, cy, hw, hh) = (rect.cx(), rect.cy(), rect.w * 0.5, rect.h * 0.5);
        let (left, right, top, bottom) = (rect.x, rect.right(), rect.y, rect.bottom());
        let band = width + 1.0;
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            let full_row = yc < top + band || yc > bottom - band;
            let corner_row = r > 0.0 && (yc < top + r + 1.0 || yc > bottom - r - 1.0);
            let row = (y * self.w) as usize;
            let mut ranges: [(i32, i32); 2] = [(0, 0), (0, 0)];
            if full_row {
                ranges[0] = (bb.x0, bb.x1);
            } else {
                let wdt = if corner_row { r + 1.0 } else { band };
                ranges[0] = (bb.x0, (ceil(left + wdt) as i32).clamp(bb.x0, bb.x1));
                ranges[1] = ((floor(right - wdt) as i32).clamp(ranges[0].1, bb.x1), bb.x1);
            }
            for (xa, xb) in ranges {
                for x in xa..xb {
                    let xc = x as f32 + 0.5;
                    let d = rrect_sd(xc, yc, cx, cy, hw, hh, r);
                    let c_out = saturate(0.5 - d);
                    let c_in = saturate(0.5 - (d + width));
                    let cv = ((c_out * (1.0 - c_in)) * 255.0 + 0.5) as u32;
                    if cv == 0 { continue; }
                    let i = row + x as usize;
                    self.px[i] = blend_c(self.px[i], color, cv);
                }
            }
        }
    }

    pub fn fill_circle(&mut self, cx: f32, cy: f32, r: f32, paint: impl Into<Paint>) {
        self.fill_rrect(Rect::new(cx - r, cy - r, r * 2.0, r * 2.0), r, paint)
    }
    pub fn ring(&mut self, cx: f32, cy: f32, r: f32, width: f32, color: Color) {
        self.stroke_rrect(Rect::new(cx - r, cy - r, r * 2.0, r * 2.0), r, width, color)
    }

    /// Squircle (superellipse) used for app icons. `n` ≈ 5 matches Apple's continuous corner look.
    pub fn fill_squircle(&mut self, rect: Rect, n: f32, paint: impl Into<Paint>) {
        let paint: Paint = paint.into();
        let bb = IRect::from_rect_outer(&rect).intersect(&self.clip);
        if bb.is_empty() { return; }
        let hw = rect.w * 0.5; let hh = rect.h * 0.5;
        let (cx, cy) = (rect.cx(), rect.cy());
        let k = hw.min(hh);
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            let ny = fabs(yc - cy) / hh;
            for x in bb.x0..bb.x1 {
                let xc = x as f32 + 0.5;
                let nx = fabs(xc - cx) / hw;
                let f = powf(powf(nx, n) + powf(ny, n), 1.0 / n);
                let d = (f - 1.0) * k;
                let cv = cov8(d);
                if cv == 0 { continue; }
                let c = paint.at(xc, yc);
                let i = (y * self.w + x) as usize;
                self.px[i] = blend_c(self.px[i], c, cv);
            }
        }
    }

    /// Round-capped line segment.
    pub fn line(&mut self, a: Pt, b: Pt, width: f32, color: Color) {
        let pad = width * 0.5 + 1.0;
        let bb = IRect::from_rect_outer(&Rect::new(a.x.min(b.x) - pad, a.y.min(b.y) - pad, (a.x - b.x).abs() + 2.0 * pad, (a.y - b.y).abs() + 2.0 * pad)).intersect(&self.clip);
        if bb.is_empty() { return; }
        let dx = b.x - a.x; let dy = b.y - a.y;
        let len2 = (dx * dx + dy * dy).max(0.0001);
        let hw = width * 0.5;
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            for x in bb.x0..bb.x1 {
                let xc = x as f32 + 0.5;
                let t = saturate(((xc - a.x) * dx + (yc - a.y) * dy) / len2);
                let px = a.x + dx * t - xc; let py = a.y + dy * t - yc;
                let d = sqrt(px * px + py * py) - hw;
                let cv = cov8(d);
                if cv == 0 { continue; }
                let i = (y * self.w + x) as usize;
                self.px[i] = blend_c(self.px[i], color, cv);
            }
        }
    }

    pub fn polyline(&mut self, pts: &[Pt], width: f32, color: Color) {
        for w in pts.windows(2) { self.line(w[0], w[1], width, color); }
    }

    /// Arc centred at (cx,cy), angles in radians (0 = +x, clockwise on screen), round caps.
    pub fn arc(&mut self, cx: f32, cy: f32, r: f32, a0: f32, a1: f32, width: f32, color: Color) {
        let pad = r + width * 0.5 + 1.0;
        let bb = IRect::from_rect_outer(&Rect::new(cx - pad, cy - pad, pad * 2.0, pad * 2.0)).intersect(&self.clip);
        if bb.is_empty() { return; }
        let hw = width * 0.5;
        let (e0x, e0y) = (cx + cos(a0) * r, cy + sin(a0) * r);
        let (e1x, e1y) = (cx + cos(a1) * r, cy + sin(a1) * r);
        let span = a1 - a0;
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            for x in bb.x0..bb.x1 {
                let xc = x as f32 + 0.5;
                let dx = xc - cx; let dy = yc - cy;
                let rho = sqrt(dx * dx + dy * dy);
                let mut ang = atan2(dy, dx) - a0;
                ang = ang - floor(ang / TAU) * TAU;
                let d = if ang <= span {
                    fabs(rho - r) - hw
                } else {
                    let d0 = sqrt((xc - e0x) * (xc - e0x) + (yc - e0y) * (yc - e0y));
                    let d1 = sqrt((xc - e1x) * (xc - e1x) + (yc - e1y) * (yc - e1y));
                    d0.min(d1) - hw
                };
                let cv = cov8(d);
                if cv == 0 { continue; }
                let i = (y * self.w + x) as usize;
                self.px[i] = blend_c(self.px[i], color, cv);
            }
        }
    }

    /// Anti-aliased polygon fill (signed area accumulation).
    pub fn fill_poly(&mut self, pts: &[Pt], paint: impl Into<Paint>) {
        let paint: Paint = paint.into();
        if pts.len() < 3 { return; }
        let mut minx = f32::MAX; let mut miny = f32::MAX; let mut maxx = f32::MIN; let mut maxy = f32::MIN;
        for p in pts { minx = minx.min(p.x); miny = miny.min(p.y); maxx = maxx.max(p.x); maxy = maxy.max(p.y); }
        let ox = floor(minx) as i32 - 1; let oy = floor(miny) as i32 - 1;
        let bw = (ceil(maxx) as i32 + 1 - ox) as usize; let bh = (ceil(maxy) as i32 + 1 - oy) as usize;
        if bw * bh > 4_000_000 || bw == 0 || bh == 0 { return; }
        let stride = bw + 2;
        let mut acc = vec![0f32; stride * bh + 2];
        let n = pts.len();
        for i in 0..n {
            let p0 = pts[i]; let p1 = pts[(i + 1) % n];
            accum_line(&mut acc, stride, bh, Pt::new(p0.x - ox as f32, p0.y - oy as f32), Pt::new(p1.x - ox as f32, p1.y - oy as f32), bw as f32);
        }
        for ry in 0..bh {
            let y = oy + ry as i32;
            if y < self.clip.y0 || y >= self.clip.y1 { continue; }
            let mut a = 0.0f32;
            for rx in 0..bw {
                a += acc[ry * stride + rx];
                let x = ox + rx as i32;
                if x < self.clip.x0 || x >= self.clip.x1 { continue; }
                let cv = (saturate(fabs(a)) * 255.0 + 0.5) as u32;
                if cv == 0 { continue; }
                let c = paint.at(x as f32 + 0.5, y as f32 + 0.5);
                let i = (y * self.w + x) as usize;
                self.px[i] = blend_c(self.px[i], c, cv);
            }
        }
    }

    /// Soft shadow shaped like a rounded rect. `blur` is the half-width of the falloff in px.
    /// If `skip_inside`, the fully-opaque interior is not painted (use when the caster is opaque and drawn after).
    /// Row-span algorithm: constant-alpha spans are filled directly, only bands/corners are evaluated per pixel.
    pub fn shadow_rrect(&mut self, rect: Rect, r: f32, blur: f32, color: Color, skip_inside: bool) {
        if color.a == 0 || blur <= 0.0 { return; }
        let r = r.min(rect.w * 0.5).min(rect.h * 0.5).max(0.0);
        let bb = IRect::from_rect_outer(&rect.inset(-blur)).intersect(&self.clip);
        if bb.is_empty() { return; }
        const N: usize = 96;
        let mut lut = [0u32; N + 1];
        for i in 0..=N { let t = i as f32 / N as f32; let a = 1.0 - t * t * (3.0 - 2.0 * t); lut[i] = (a * color.a as f32 + 0.5) as u32; }
        let scale = N as f32 / (2.0 * blur);
        let alpha_of = |sd: f32| -> u32 { let t = (sd + blur) * scale; if t <= 0.0 { lut[0] } else if t >= N as f32 { 0 } else { lut[t as usize] } };
        let (cr, cg, cb) = (color.r as u32, color.g as u32, color.b as u32);
        let (cx, cy, hw, hh) = (rect.cx(), rect.cy(), rect.w * 0.5, rect.h * 0.5);
        let stride = self.w as usize;
        let full_a = lut[0];
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            let dy = fabs(yc - cy);
            let qy = dy - (hh - r);
            let row = y as usize * stride;
            let (x0, x1) = (bb.x0, bb.x1);
            // helper closures can't borrow self.px mutably twice, so inline small loops
            if qy <= 0.0 {
                let sdy = dy - hh;
                let xa = (ceil(cx - hw + blur) as i32).clamp(x0, x1);
                let xb = (floor(cx + hw - blur) as i32).clamp(x0, x1);
                let (xa, xb) = if xa >= xb { let m = (cx as i32).clamp(x0, x1); (m, m) } else { (xa, xb) };
                for x in x0..xa { let sdx = fabs(x as f32 + 0.5 - cx) - hw; let a = alpha_of(if sdx > sdy { sdx } else { sdy }); if a > 0 { let i = row + x as usize; self.px[i] = blend(self.px[i], cr, cg, cb, a); } }
                let a = alpha_of(sdy);
                if a > 0 && !(skip_inside && a >= full_a) { for p in self.px[row + xa as usize..row + xb as usize].iter_mut() { *p = blend(*p, cr, cg, cb, a); } }
                for x in xb..x1 { let sdx = fabs(x as f32 + 0.5 - cx) - hw; let a = alpha_of(if sdx > sdy { sdx } else { sdy }); if a > 0 { let i = row + x as usize; self.px[i] = blend(self.px[i], cr, cg, cb, a); } }
            } else {
                let xin0 = (ceil(cx - (hw - r)) as i32).clamp(x0, x1);
                let xin1 = (floor(cx + (hw - r)) as i32).clamp(xin0, x1);
                let sdc = qy - r;
                let ac = alpha_of(sdc);
                for x in x0..xin0 { let qx = fabs(x as f32 + 0.5 - cx) - (hw - r); let sd = if qx > 0.0 { sqrt(qx * qx + qy * qy) - r } else { sdc }; let a = alpha_of(sd); if a > 0 { let i = row + x as usize; self.px[i] = blend(self.px[i], cr, cg, cb, a); } }
                if ac > 0 { for p in self.px[row + xin0 as usize..row + xin1 as usize].iter_mut() { *p = blend(*p, cr, cg, cb, ac); } }
                for x in xin1..x1 { let qx = fabs(x as f32 + 0.5 - cx) - (hw - r); let sd = if qx > 0.0 { sqrt(qx * qx + qy * qy) - r } else { sdc }; let a = alpha_of(sd); if a > 0 { let i = row + x as usize; self.px[i] = blend(self.px[i], cr, cg, cb, a); } }
            }
        }
    }
}

/// font-rs style signed-area accumulation of one edge.
fn accum_line(a: &mut [f32], stride: usize, bh: usize, p0: Pt, p1: Pt, maxx: f32) {
    if p0.y == p1.y { return; }
    let (dir, p0, p1) = if p0.y < p1.y { (1.0f32, p0, p1) } else { (-1.0f32, p1, p0) };
    let dxdy = (p1.x - p0.x) / (p1.y - p0.y);
    let mut x = p0.x;
    let y0 = if p0.y < 0.0 { 0usize } else { p0.y as usize };
    if p0.y < 0.0 { x -= p0.y * dxdy; }
    let yend = bh.min(ceil(p1.y) as usize);
    for y in y0..yend {
        let ls = y * stride;
        let dy = ((y + 1) as f32).min(p1.y) - (y as f32).max(p0.y);
        let xnext = x + dxdy * dy;
        let d = dy * dir;
        let (xa, xb) = if x < xnext { (x, xnext) } else { (xnext, x) };
        let (xa, xb) = (clamp(xa, 0.0, maxx), clamp(xb, 0.0, maxx));
        let x0f = floor(xa); let x0i = x0f as i32;
        let x1c = ceil(xb); let x1i = x1c as i32;
        if x1i <= x0i + 1 {
            let xmf = 0.5 * (xa + xb) - x0f;
            a[ls + x0i as usize] += d - d * xmf;
            a[ls + (x0i + 1) as usize] += d * xmf;
        } else {
            let s = 1.0 / (xb - xa);
            let x0fr = xa - x0f;
            let a0 = 0.5 * s * (1.0 - x0fr) * (1.0 - x0fr);
            let x1fr = xb - x1c + 1.0;
            let am = 0.5 * s * x1fr * x1fr;
            a[ls + x0i as usize] += d * a0;
            if x1i == x0i + 2 {
                a[ls + (x0i + 1) as usize] += d * (1.0 - a0 - am);
            } else {
                let a1 = s * (1.5 - x0fr);
                a[ls + (x0i + 1) as usize] += d * (a1 - a0);
                for xi in (x0i + 2)..(x1i - 1) { a[ls + xi as usize] += d * s; }
                let a2 = a1 + (x1i - x0i - 3) as f32 * s;
                a[ls + (x1i - 1) as usize] += d * (1.0 - a2 - am);
            }
            a[ls + x1i as usize] += d * am;
        }
        x = xnext;
    }
}
