//! Mouse cursor sprites drawn as AA vector polygons (always the last thing painted).
use alloc::vec::Vec;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::mathf::*;
use crate::ui::CursorShape;

pub fn draw_cursor(cv: &mut Canvas, x: f32, y: f32, shape: CursorShape, scale: f32) {
    let full = IRect::new(0, 0, cv.w, cv.h);
    cv.push_clip_i(full);
    match shape {
        CursorShape::Arrow | CursorShape::Move => arrow(cv, x, y, scale),
        CursorShape::IBeam => ibeam(cv, x, y, scale),
        CursorShape::Hand => hand(cv, x, y, scale),
        CursorShape::ResizeEW => double_arrow(cv, x, y, 0.0, scale),
        CursorShape::ResizeNS => double_arrow(cv, x, y, PI / 2.0, scale),
        CursorShape::ResizeNWSE => double_arrow(cv, x, y, PI / 4.0, scale),
        CursorShape::ResizeNESW => double_arrow(cv, x, y, -PI / 4.0, scale),
    }
    cv.pop_clip();
}

fn arrow(cv: &mut Canvas, x: f32, y: f32, s: f32) {
    let base = [(0.0, 0.0), (0.0, 16.8), (3.7, 13.2), (6.3, 19.2), (8.9, 18.0), (6.3, 12.2), (11.4, 12.2)];
    let pts: Vec<Pt> = base.iter().map(|(a, b)| Pt::new(x + a * s, y + b * s)).collect();
    for (dx, dy, a) in [(1.0f32, 2.0f32, 28u8), (0.5, 1.2, 36)] {
        let sh: Vec<Pt> = pts.iter().map(|p| Pt::new(p.x + dx * s, p.y + dy * s)).collect();
        cv.fill_poly(&sh, Color::rgba(0, 0, 0, a));
    }
    for i in 0..pts.len() { cv.line(pts[i], pts[(i + 1) % pts.len()], 2.3 * s, Color::WHITE); }
    cv.fill_poly(&pts, Color::rgb(12, 12, 14));
}

fn ibeam(cv: &mut Canvas, x: f32, y: f32, s: f32) {
    let h = 9.0 * s;
    for (w, c) in [(3.4 * s, Color::WHITE), (1.5 * s, Color::rgb(12, 12, 14))] {
        cv.line(Pt::new(x, y - h), Pt::new(x, y + h), w, c);
        cv.line(Pt::new(x - 3.0 * s, y - h), Pt::new(x + 3.0 * s, y - h), w, c);
        cv.line(Pt::new(x - 3.0 * s, y + h), Pt::new(x + 3.0 * s, y + h), w, c);
    }
}

fn hand(cv: &mut Canvas, x: f32, y: f32, s: f32) {
    let r = |dx: f32, dy: f32, w: f32, h: f32| Rect::new(x + dx * s, y + dy * s, w * s, h * s);
    for (grow, c) in [(1.2f32, Color::rgb(12, 12, 14)), (0.0, Color::WHITE)] {
        let g = grow * s;
        let ex = |rc: Rect, rad: f32, cv: &mut Canvas| cv.fill_rrect(Rect::new(rc.x - g, rc.y - g, rc.w + 2.0 * g, rc.h + 2.0 * g), rad + g, c);
        ex(r(-1.8, 0.0, 3.8, 11.0), 1.9 * s, cv);
        ex(r(2.0, 6.0, 3.2, 8.0), 1.6 * s, cv);
        ex(r(5.0, 6.8, 3.2, 7.5), 1.6 * s, cv);
        ex(r(8.0, 8.0, 3.2, 6.5), 1.6 * s, cv);
        ex(r(-5.4, 8.0, 15.6, 11.0), 4.5 * s, cv);
    }
}

fn double_arrow(cv: &mut Canvas, x: f32, y: f32, ang: f32, s: f32) {
    let (c, sn) = (cos(ang), sin(ang));
    let p = |u: f32, v: f32| Pt::new(x + (u * c - v * sn) * s, y + (u * sn + v * c) * s);
    let shape = [p(-9.0, 0.0), p(-3.6, -4.8), p(-3.6, -1.7), p(3.6, -1.7), p(3.6, -4.8), p(9.0, 0.0), p(3.6, 4.8), p(3.6, 1.7), p(-3.6, 1.7), p(-3.6, 4.8)];
    for i in 0..shape.len() { cv.line(shape[i], shape[(i + 1) % shape.len()], 2.3 * s, Color::WHITE); }
    cv.fill_poly(&shape, Color::rgb(12, 12, 14));
}
