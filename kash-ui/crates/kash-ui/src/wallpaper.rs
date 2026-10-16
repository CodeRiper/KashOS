//! Procedural wallpapers (original artwork rendered at runtime — no image assets).
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::mathf::*;

pub const WALLPAPERS: [&str; 5] = ["Golden Hour", "Aurora", "Graphite", "Lagoon", "Ember"];

fn grad(stops: &[(f32, Color)], t: f32) -> Color {
    let t = saturate(t);
    for i in 1..stops.len() {
        if t <= stops[i].0 {
            let (t0, c0) = stops[i - 1]; let (t1, c1) = stops[i];
            return c0.mix(c1, (t - t0) / (t1 - t0).max(0.0001));
        }
    }
    stops[stops.len() - 1].1
}

pub fn paint(cv: &mut Canvas, idx: usize) {
    match idx {
        0 => golden_hour(cv),
        1 => flow(cv, 0x2C6BFF, 0x7A3CFF, 0x00D4FF, 0x0A0F3A, 11),
        2 => flow(cv, 0x4A4F5C, 0x20232B, 0x7C8498, 0x08090D, 23),
        3 => flow(cv, 0x00B8A9, 0x0B6BCB, 0x7CF7C0, 0x021B2B, 37),
        _ => flow(cv, 0xFF5E3A, 0xC2185B, 0xFFB347, 0x2A0A1E, 51),
    }
}

fn flow(cv: &mut Canvas, a: u32, b: u32, c: u32, base: u32, seed: u32) {
    let (w, h) = (cv.w, cv.h);
    let (ca, cb, cc, cbase) = (Color::hex(a), Color::hex(b), Color::hex(c), Color::hex(base));
    for y in 0..h {
        let fy = y as f32 / h as f32;
        for x in 0..w {
            let fx = x as f32 / w as f32;
            let wx = fx * 2.4 + fbm(fx * 1.6, fy * 1.6, 3, seed) * 1.6;
            let wy = fy * 2.4 + fbm(fx * 1.6 + 7.0, fy * 1.6 + 3.0, 3, seed + 1) * 1.6;
            let v1 = 0.5 + 0.5 * sin(wx * 2.2 + wy * 1.3 + seed as f32);
            let v2 = 0.5 + 0.5 * sin(wy * 2.6 - wx * 0.9 + 1.7);
            let k = fbm(fx * 3.0, fy * 3.0, 3, seed + 2);
            let mut col = cbase.mix(ca, smoothstep(0.15, 0.85, v1 * 0.8 + k * 0.4));
            col = col.mix(cb, smoothstep(0.35, 0.95, v2) * 0.85);
            col = col.mix(cc, smoothstep(0.65, 1.0, v1 * v2 + k * 0.3) * 0.75);
            let dx = fx - 0.5; let dy = fy - 0.5;
            let vg = 1.0 - saturate((dx * dx + dy * dy) * 0.9);
            let col = col.darken((1.0 - vg) * 0.35);
            cv.px[(y * w + x) as usize] = col.pix();
        }
    }
}

fn golden_hour(cv: &mut Canvas) {
    let (w, h) = (cv.w, cv.h);
    let wf = w as f32; let hf = h as f32;
    let hor = hf * 0.60;
    let sky = [
        (0.00, Color::hex(0x141C4F)), (0.30, Color::hex(0x4B3A8F)), (0.52, Color::hex(0xC25A8E)),
        (0.78, Color::hex(0xFF8A6B)), (1.00, Color::hex(0xFFC77D)),
    ];
    let sun = Pt::new(wf * 0.70, hor - hf * 0.045);
    for y in 0..h {
        let fy = y as f32;
        for x in 0..w {
            let fx = x as f32;
            let col = if fy < hor {
                let t = fy / hor;
                let mut c = grad(&sky, powf(t, 1.15));
                let d = sqrt((fx - sun.x) * (fx - sun.x) + (fy - sun.y) * (fy - sun.y) * 1.6);
                let g = exp(-d / (wf * 0.16));
                c = c.mix(Color::hex(0xFFE3A8), g * 0.75);
                let core = smoothstep(wf * 0.030, wf * 0.022, d);
                c = c.mix(Color::hex(0xFFF6DA), core);
                let n = fbm(fx / wf * 5.0, fy / hf * 14.0, 3, 5);
                c = c.mix(Color::hex(0xFFB3A0), smoothstep(0.55, 0.85, n) * (1.0 - t) * 0.35);
                c
            } else {
                let t = (fy - hor) / (hf - hor);
                let mut c = grad(&[(0.0, Color::hex(0x7A4F8F)), (0.25, Color::hex(0x3B3A78)), (1.0, Color::hex(0x0B1236))], t);
                let ripple = fbm(fx / wf * 40.0, (fy - hor) / hf * 140.0 * (0.4 + t), 2, 9);
                let colx = exp(-fabs(fx - sun.x) / (wf * (0.02 + 0.10 * t)));
                c = c.mix(Color::hex(0xFFC27A), colx * (0.25 + 0.5 * ripple) * (1.0 - t * 0.6));
                c = c.darken(ripple * 0.12 * t);
                c
            };
            cv.px[(y * w + x) as usize] = col.pix();
        }
    }
    let ridge = |cv: &mut Canvas, base: f32, amp: f32, freq: f32, seed: u32, c: Color, x_from: f32, x_to: f32| {
        for x in (x_from as i32).max(0)..(x_to as i32).min(w) {
            let fx = x as f32 / wf;
            let hgt = base - amp * fbm(fx * freq, 0.5, 4, seed) - amp * 0.6 * smoothstep(1.0, 0.0, fx * 1.6);
            let y0 = hgt as i32;
            for y in y0.max(0)..(hor as i32 + 2).min(h) {
                let a = saturate((y as f32 - hgt) + 0.5);
                let i = (y * w + x) as usize;
                cv.px[i] = mix_pix(cv.px[i], c.pix(), (a * 256.0) as u32);
            }
        }
    };
    ridge(cv, hor - hf * 0.02, hf * 0.10, 3.2, 3, Color::rgb(0x5A, 0x3F, 0x86), 0.0, wf * 0.55);
    ridge(cv, hor - hf * 0.005, hf * 0.07, 4.5, 8, Color::rgb(0x2B, 0x22, 0x59), 0.0, wf * 0.38);
    ridge(cv, hor - hf * 0.01, hf * 0.05, 5.0, 15, Color::rgb(0x4A, 0x37, 0x78), wf * 0.80, wf);
    // suspension bridge (original vector drawing)
    let vermil = Color::hex(0xD9472B);
    let vermil_d = Color::hex(0x8F2A1A);
    let deck_y = hor + hf * 0.012;
    let t1x = wf * 0.27; let t2x = wf * 0.62;
    let th = hf * 0.30; let tw = wf * 0.012;
    cv.fill_rect(Rect::new(0.0, deck_y, wf, hf * 0.006), vermil_d);
    cv.fill_rect(Rect::new(0.0, deck_y + hf * 0.006, wf, hf * 0.0025), Color::rgba(20, 14, 40, 180));
    for tx in [t1x, t2x] {
        let top = deck_y - th;
        for lx in [tx - tw * 2.2, tx + tw * 1.2] {
            cv.fill_rect(Rect::new(lx, top, tw, th + hf * 0.12), vermil);
            cv.fill_rect(Rect::new(lx + tw * 0.65, top, tw * 0.35, th + hf * 0.12), vermil_d);
        }
        for i in 0..6 { let by = top + th * (0.12 + 0.15 * i as f32); cv.fill_rect(Rect::new(tx - tw * 2.2, by, tw * 4.4, tw * 0.55), vermil); }
        cv.fill_rect(Rect::new(tx - tw * 2.4, top - tw * 0.6, tw * 4.8, tw * 0.8), vermil);
        cv.fill_rect(Rect::new(tx - tw * 3.0, deck_y + hf * 0.04, tw * 6.0, hf * 0.09), Color::rgba(18, 18, 50, 255));
    }
    let cable = |cv: &mut Canvas, x0: f32, y0: f32, x1: f32, y1: f32, sag: f32, drop_to_deck: bool| {
        let n = 80; let mut prev = Pt::new(x0, y0);
        for i in 1..=n {
            let t = i as f32 / n as f32;
            let x = lerp(x0, x1, t); let y = lerp(y0, y1, t) + sag * 4.0 * t * (1.0 - t);
            let cur = Pt::new(x, y);
            cv.line(prev, cur, (hf * 0.0032).max(1.5), vermil);
            if drop_to_deck && i % 2 == 0 { cv.line(cur, Pt::new(x, deck_y), 1.0, vermil.fade(0.8)); }
            prev = cur;
        }
    };
    let ct = deck_y - th;
    cable(cv, t1x + tw * 0.3, ct, t2x + tw * 0.3, ct, th * 0.80, true);
    cable(cv, -20.0, deck_y - hf * 0.04, t1x + tw * 0.3, ct, hf * 0.10, true);
    cable(cv, t2x + tw * 0.3, ct, wf + 20.0, deck_y - hf * 0.03, hf * 0.10, true);
    for y in (hor as i32 - (hf * 0.10) as i32)..(hor as i32 + (hf * 0.05) as i32) {
        if y < 0 || y >= h { continue; }
        for x in 0..w {
            let fx = x as f32 / wf; let fyy = (y as f32 - (hor - hf * 0.10)) / (hf * 0.15);
            let n = fbm(fx * 5.0, fyy * 2.0, 4, 77);
            let band = smoothstep(0.0, 0.5, fyy) * smoothstep(1.0, 0.45, fyy);
            let a = saturate(band * (n * 1.5 - 0.35) * 0.55);
            let i = (y * w + x) as usize;
            cv.px[i] = mix_pix(cv.px[i], 0xFFD5C0, (a * 256.0) as u32);
        }
    }
}
