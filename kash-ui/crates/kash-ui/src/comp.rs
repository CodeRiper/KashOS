//! Layer compositing: rounded-mask blits, scaled blits (open/close), genie (minimise) warp.
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::mathf::*;

impl Canvas {
    /// 1:1 copy of `src` at integer (x,y) with a rounded-rect mask of radius `r` and global alpha (0..255).
    pub fn blit_rounded(&mut self, src: &Canvas, x: i32, y: i32, r: f32, alpha: u32) { self.blit_rounded_dim(src, x, y, r, alpha, 0); }

    /// Like `blit_rounded`, darkening the source towards black by `dim` (0..255) while copying — used for the inactive-window veil
    /// so the veil can change every frame without re-rendering the window.
    pub fn blit_rounded_dim(&mut self, src: &Canvas, x: i32, y: i32, r: f32, alpha: u32, dim: u32) {
        let clip = self.clip();
        let bb = IRect::new(x, y, x + src.w, y + src.h).intersect(&clip);
        if bb.is_empty() { return; }
        let r = r.min(src.w as f32 * 0.5).min(src.h as f32 * 0.5);
        let ri = ceil(r) as i32 + 1;
        let (cx, cy, hw, hh) = (x as f32 + src.w as f32 * 0.5, y as f32 + src.h as f32 * 0.5, src.w as f32 * 0.5, src.h as f32 * 0.5);
        for yy in bb.y0..bb.y1 {
            let sy = yy - y;
            let corner_row = sy < ri || sy >= src.h - ri;
            let drow = (yy * self.w) as usize; let srow = (sy * src.w) as usize;
            let (xa, xb) = if corner_row { ((x + ri).clamp(bb.x0, bb.x1), (x + src.w - ri).clamp(bb.x0, bb.x1)) } else { (bb.x0, bb.x1) };
            if alpha >= 255 && dim == 0 {
                if xb > xa { self.px[drow + xa as usize..drow + xb as usize].copy_from_slice(&src.px[srow + (xa - x) as usize..srow + (xb - x) as usize]); }
            } else if alpha >= 255 {
                let k = 256 - dim.min(256);
                for xx in xa..xb {
                    let p = src.px[srow + (xx - x) as usize];
                    self.px[drow + xx as usize] = ((((p >> 16) & 255) * k >> 8) << 16) | ((((p >> 8) & 255) * k >> 8) << 8) | ((p & 255) * k >> 8);
                }
            } else {
                for xx in xa..xb { let i = drow + xx as usize; self.px[i] = mix_pix(self.px[i], dim_pix(src.px[srow + (xx - x) as usize], dim), alpha * 256 / 255); }
            }
            if corner_row {
                let edge = |this: &mut Canvas, xx: i32| {
                    let sd = rrect_sd(xx as f32 + 0.5, yy as f32 + 0.5, cx, cy, hw, hh, r);
                    let cov = (saturate(0.5 - sd) * alpha as f32) as u32;
                    if cov == 0 { return; }
                    let i = drow + xx as usize;
                    this.px[i] = mix_pix(this.px[i], dim_pix(src.px[srow + (xx - x) as usize], dim), cov * 256 / 255);
                };
                for xx in bb.x0..xa.min(bb.x1) { edge(self, xx); }
                for xx in xb.max(bb.x0)..bb.x1 { edge(self, xx); }
            }
        }
    }

    /// Scaled blit of `src` into float rect `dest` (bilinear), rounded mask radius `r`.
    pub fn blit_scaled(&mut self, src: &Canvas, dest: Rect, r: f32, alpha: f32) {
        if dest.w < 1.0 || dest.h < 1.0 || alpha <= 0.0 { return; }
        let bb = IRect::from_rect_outer(&dest).intersect(&self.clip());
        if bb.is_empty() { return; }
        let r = r.min(dest.w * 0.5).min(dest.h * 0.5);
        let (cx, cy, hw, hh) = (dest.cx(), dest.cy(), dest.w * 0.5, dest.h * 0.5);
        let sxs = src.w as f32 / dest.w; let sys = src.h as f32 / dest.h;
        let a256 = (saturate(alpha) * 256.0) as u32;
        let maxx = ((src.w - 1) as i32 * 256 - 1).max(0); let maxy = ((src.h - 1) as i32 * 256 - 1).max(0);
        let sw = src.w as usize;
        // per-column source taps, computed once
        let nx = (bb.x1 - bb.x0) as usize;
        let mut taps: alloc::vec::Vec<(u32, u32, u32)> = alloc::vec::Vec::with_capacity(nx);
        for x in bb.x0..bb.x1 {
            let xc = x as f32 + 0.5;
            let fx = ((((xc - dest.x) * sxs - 0.5) * 256.0) as i32).clamp(0, maxx);
            let x0 = (fx >> 8) as u32;
            taps.push((x0, (x0 + 1).min(sw as u32 - 1), (fx & 255) as u32));
        }
        let rb = r + 1.5; // only pixels this close to a corner/edge need the exact SDF
        // horizontally-interpolated source rows are cached: consecutive dest rows share them when the scale is ~1
        let mut ha: alloc::vec::Vec<u32> = alloc::vec![0; nx];
        let mut hb: alloc::vec::Vec<u32> = alloc::vec![0; nx];
        let (mut ia, mut ib) = (usize::MAX, usize::MAX);
        let fill = |buf: &mut alloc::vec::Vec<u32>, row: usize, taps: &alloc::vec::Vec<(u32, u32, u32)>| {
            let base = row * sw;
            for (k, t) in taps.iter().enumerate() { buf[k] = mix_pix(src.px[base + t.0 as usize], src.px[base + t.1 as usize], t.2); }
        };
        for y in bb.y0..bb.y1 {
            let yc = y as f32 + 0.5;
            let fy = ((((yc - dest.y) * sys - 0.5) * 256.0) as i32).clamp(0, maxy);
            let (y0, ty) = ((fy >> 8) as usize, (fy & 255) as u32);
            let y1 = (y0 + 1).min(src.h as usize - 1);
            // make sure (ha, hb) hold rows (y0, y1)
            if ia == y0 && ib == y1 {}
            else if ib == y0 { core::mem::swap(&mut ha, &mut hb); ia = y0; fill(&mut hb, y1, &taps); ib = y1; }
            else if ia == y1 { core::mem::swap(&mut ha, &mut hb); ib = y1; fill(&mut ha, y0, &taps); ia = y0; }
            else { fill(&mut ha, y0, &taps); fill(&mut hb, y1, &taps); ia = y0; ib = y1; }
            let in_band = yc - dest.y < rb || dest.bottom() - yc < rb;
            let row = (y * self.w) as usize;
            for (k, x) in (bb.x0..bb.x1).enumerate() {
                let xc = x as f32 + 0.5;
                let cov = if in_band || xc - dest.x < rb || dest.right() - xc < rb {
                    let sd = rrect_sd(xc, yc, cx, cy, hw, hh, r);
                    if sd > 0.5 { continue; }
                    (saturate(0.5 - sd) * a256 as f32) as u32
                } else { a256 };
                let p = mix_pix(ha[k], hb[k], ty);
                let i = row + x as usize;
                self.px[i] = if cov >= 256 { p } else { mix_pix(self.px[i], p, cov) };
            }
        }
    }

    /// Genie-style minimise: rows of the window pinch toward `target` as `t` goes 0→1.
    pub fn blit_genie(&mut self, src: &Canvas, from: Rect, target: Pt, t: f32, alpha: f32) {
        if t <= 0.0 { self.blit_scaled(src, from, 24.0, alpha); return; }
        let n = src.h;
        let hgt = from.h;
        let tw = 24.0f32;
        let a256 = (saturate(alpha) * 256.0) as u32;
        let clip = self.clip();
        for sy in (0..n).rev() {
            let v = sy as f32 / (n - 1).max(1) as f32;
            let lag = 0.55;
            let tt = saturate((t - (1.0 - v) * lag) / (1.0 - lag));
            let e = tt * tt * (3.0 - 2.0 * tt);
            let y_src = from.y + v * hgt;
            let y = lerp(y_src, target.y, e);
            let sq = ease_curve(e);
            let wdt = lerp(from.w, tw, sq);
            let cxr = lerp(from.cx(), target.x, sq);
            let x0 = cxr - wdt * 0.5; let x1 = cxr + wdt * 0.5;
            let yi = y as i32;
            if yi < clip.y0 || yi >= clip.y1 { continue; }
            let xa = (floor(x0) as i32).max(clip.x0); let xb = (ceil(x1) as i32).min(clip.x1);
            if xb <= xa { continue; }
            let srow = (sy * src.w) as usize;
            let drow = (yi * self.w) as usize;
            let sw = src.w as f32;
            for x in xa..xb {
                let u = ((x as f32 + 0.5 - x0) / wdt.max(1.0) * sw) as i32;
                let u = u.clamp(0, src.w - 1) as usize;
                let cov_l = saturate(x as f32 + 1.0 - x0); let cov_r = saturate(x1 - x as f32);
                let cov = (cov_l.min(cov_r) * a256 as f32) as u32;
                let i = drow + x as usize;
                self.px[i] = mix_pix(self.px[i], src.px[srow + u], cov);
            }
        }
    }
}

fn ease_curve(e: f32) -> f32 { let u = saturate(e); u * u * (1.5 - 0.5 * u) }

#[inline]
fn dim_pix(p: u32, dim: u32) -> u32 {
    if dim == 0 { return p; }
    let k = 256 - dim.min(256);
    ((((p >> 16) & 255) * k >> 8) << 16) | ((((p >> 8) & 255) * k >> 8) << 8) | ((p & 255) * k >> 8)
}
