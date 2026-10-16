//! Text: Inter (OFL) + DejaVu Sans Mono rasterised with fontdue, glyph-cached.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use fontdue::{Font, FontSettings};
use crate::color::*;
use crate::geom::*;
use crate::gfx::Canvas;
use crate::mathf::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Weight { Regular = 0, Medium = 1, Semibold = 2, Bold = 3, Mono = 4 }

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Align { Left, Center, Right }

struct Glyph { xmin: i32, ymin: i32, w: usize, h: usize, adv: f32, bmp: Vec<u8> }

pub struct Fonts {
    pub icons: crate::icons::IconCache,
    faces: [Font; 5],
    cache: BTreeMap<(u8, u32, u16), Glyph>,
    lut_light: [u8; 256],
    lut_dark: [u8; 256],
}

static REGULAR: &[u8] = include_bytes!("../assets/fonts/Inter-Regular.otf");
static MEDIUM: &[u8] = include_bytes!("../assets/fonts/Inter-Medium.otf");
static SEMIBOLD: &[u8] = include_bytes!("../assets/fonts/Inter-SemiBold.otf");
static BOLD: &[u8] = include_bytes!("../assets/fonts/Inter-Bold.otf");
static MONO: &[u8] = include_bytes!("../assets/fonts/DejaVuSansMono.ttf");

impl Fonts {
    pub fn new() -> Fonts {
        let mk = |d: &[u8]| Font::from_bytes(d, FontSettings { scale: 48.0, ..FontSettings::default() }).expect("font");
        let mut lut_light = [0u8; 256]; let mut lut_dark = [0u8; 256];
        for i in 0..256 {
            let c = i as f32 / 255.0;
            lut_light[i] = (powf(c, 1.18) * 255.0 + 0.5) as u8;
            lut_dark[i] = (powf(c, 0.82) * 255.0 + 0.5) as u8;
        }
        Fonts { icons: crate::icons::IconCache::new(), faces: [mk(REGULAR), mk(MEDIUM), mk(SEMIBOLD), mk(BOLD), mk(MONO)], cache: BTreeMap::new(), lut_light, lut_dark }
    }

    /// Rasterise the common ASCII glyphs at the UI's usual sizes up-front (moves the first-use hitch to boot).
    pub fn prewarm(&mut self) {
        let sizes = [11.0f32, 11.5, 12.0, 12.5, 13.0, 13.5, 14.0, 15.0, 16.0, 17.0, 18.0, 20.0, 22.0, 28.0, 30.0];
        for wt in [Weight::Regular, Weight::Medium, Weight::Semibold, Weight::Bold] {
            for sz in sizes.iter() { for c in 32u8..127 { let _ = self.glyph(wt, c as char, *sz); } }
        }
        for sz in [12.0f32, 13.0, 13.5, 14.0] { for c in 32u8..127 { let _ = self.glyph(Weight::Mono, c as char, sz); } }
    }

    fn glyph(&mut self, wt: Weight, ch: char, size: f32) -> &Glyph {
        let q = (size * 4.0 + 0.5) as u16;
        let key = (wt as u8, ch as u32, q);
        if !self.cache.contains_key(&key) {
            let px = q as f32 / 4.0;
            let (m, bmp) = self.faces[wt as usize].rasterize(ch, px);
            self.cache.insert(key, Glyph { xmin: m.xmin, ymin: m.ymin, w: m.width, h: m.height, adv: m.advance_width, bmp });
        }
        self.cache.get(&key).unwrap()
    }

    pub fn advance(&mut self, wt: Weight, ch: char, size: f32) -> f32 { self.glyph(wt, ch, size).adv }

    pub fn measure(&mut self, s: &str, size: f32, wt: Weight) -> f32 {
        let mut w = 0.0;
        for ch in s.chars() { w += self.glyph(wt, ch, size).adv; }
        w
    }

    pub fn fit(&mut self, s: &str, size: f32, wt: Weight, max_w: f32) -> String {
        if self.measure(s, size, wt) <= max_w { return String::from(s); }
        let ell = self.glyph(wt, '…', size).adv;
        let mut out = String::new(); let mut w = 0.0;
        for ch in s.chars() {
            let a = self.glyph(wt, ch, size).adv;
            if w + a + ell > max_w { break; }
            out.push(ch); w += a;
        }
        out.push('…');
        out
    }

    /// Draw with the pen starting at (x, baseline). Returns the advance width.
    pub fn draw(&mut self, cv: &mut Canvas, x: f32, baseline: f32, s: &str, size: f32, wt: Weight, color: Color) -> f32 {
        let lut = if color.luma() > 0.55 { self.lut_light } else { self.lut_dark };
        let mut pen = x;
        let clip = cv.clip();
        for ch in s.chars() {
            if ch == '\n' { continue; }
            let (xmin, ymin, w, h, adv) = { let g = self.glyph(wt, ch, size); (g.xmin, g.ymin, g.w, g.h, g.adv) };
            if w > 0 && h > 0 {
                let gx = round(pen) as i32 + xmin;
                let gy = round(baseline) as i32 - ymin - h as i32;
                if gx < clip.x1 && gx + w as i32 > clip.x0 && gy < clip.y1 && gy + h as i32 > clip.y0 {
                    let g = self.cache.get(&(wt as u8, ch as u32, (size * 4.0 + 0.5) as u16)).unwrap();
                    for yy in 0..h {
                        let py = gy + yy as i32;
                        if py < clip.y0 || py >= clip.y1 { continue; }
                        for xx in 0..w {
                            let px = gx + xx as i32;
                            if px < clip.x0 || px >= clip.x1 { continue; }
                            let c = g.bmp[yy * w + xx];
                            if c == 0 { continue; }
                            let cov = lut[c as usize] as u32;
                            let i = (py * cv.w + px) as usize;
                            cv.px[i] = blend_c(cv.px[i], color, cov);
                        }
                    }
                }
            }
            pen += adv;
        }
        pen - x
    }

    pub fn draw_in(&mut self, cv: &mut Canvas, rect: Rect, s: &str, size: f32, wt: Weight, color: Color, align: Align) {
        let t = self.fit(s, size, wt, rect.w);
        let w = self.measure(&t, size, wt);
        let x = match align { Align::Left => rect.x, Align::Center => rect.x + (rect.w - w) * 0.5, Align::Right => rect.right() - w };
        let baseline = rect.cy() + size * 0.364;
        self.draw(cv, x, baseline, &t, size, wt, color);
    }

    pub fn wrap(&mut self, s: &str, size: f32, wt: Weight, max_w: f32) -> Vec<String> {
        let mut lines = Vec::new();
        for para in s.split('\n') {
            let mut cur = String::new(); let mut cw = 0.0;
            let sp = self.glyph(wt, ' ', size).adv;
            for word in para.split(' ') {
                let ww = self.measure(word, size, wt);
                if !cur.is_empty() && cw + sp + ww > max_w { lines.push(core::mem::take(&mut cur)); cw = 0.0; }
                if !cur.is_empty() { cur.push(' '); cw += sp; }
                cur.push_str(word); cw += ww;
            }
            lines.push(cur);
        }
        lines
    }
}
