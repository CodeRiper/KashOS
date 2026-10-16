//! Procedural vector icons (original artwork, SF-Symbols-like monoline glyphs on a 24-unit grid,
//! plus coloured app tiles and file-type icons). No bitmap assets.
use alloc::vec::Vec;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::mathf::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Icon {
    Search, ChevL, ChevR, ChevD, ChevU, Grid, List, Columns, Gear, Wifi, Battery, Bluetooth, Sound, Moon, Sun, Display, Folder, Doc,
    Download, Desktop, Apps, Photo, Music, Trash, Home, Cloud, Lock, Shield, Bell, Globe, User, Keyboard, Mouse, Palette, Sliders,
    Plus, Minus, Check, Close, Share, Star, Tag, Network, Chip, Eye, Bolt, Power, Clock, Info, Terminal, Cursor, Airdrop, Dock, Wallpaper,
    Accessibility, Disk, Ghost, Key, Pencil, Radar, Siri, Focus, Brightness, Back, Camera, Mic, Pin, Usb, Cpu, Trash2, Rocket,
}

pub fn draw_icon(cv: &mut Canvas, ic: Icon, r: Rect, c: Color) {
    let s = r.w.min(r.h) / 24.0;
    let ox = r.cx() - 12.0 * s; let oy = r.cy() - 12.0 * s;
    let p = |x: f32, y: f32| Pt::new(ox + x * s, oy + y * s);
    let w = (1.7 * s).max(1.15);
    let ln = |cv: &mut Canvas, a: (f32, f32), b: (f32, f32), ww: f32| cv.line(p(a.0, a.1), p(b.0, b.1), ww, c);
    let rr = |x: f32, y: f32, ww: f32, hh: f32| Rect::new(ox + x * s, oy + y * s, ww * s, hh * s);
    let d2r = |d: f32| d * PI / 180.0;
    match ic {
        Icon::Search => { cv.ring(ox + 10.5 * s, oy + 10.5 * s, 6.2 * s, w, c); ln(cv, (15.2, 15.2), (20.5, 20.5), w); }
        Icon::ChevL => { cv.polyline(&[p(14.5, 5.5), p(8.0, 12.0), p(14.5, 18.5)], w * 1.15, c); }
        Icon::ChevR => { cv.polyline(&[p(9.5, 5.5), p(16.0, 12.0), p(9.5, 18.5)], w * 1.15, c); }
        Icon::ChevD => { cv.polyline(&[p(5.5, 9.0), p(12.0, 15.5), p(18.5, 9.0)], w * 1.15, c); }
        Icon::ChevU => { cv.polyline(&[p(5.5, 15.0), p(12.0, 8.5), p(18.5, 15.0)], w * 1.15, c); }
        Icon::Back => { cv.polyline(&[p(11.0, 5.0), p(4.5, 12.0), p(11.0, 19.0)], w, c); ln(cv, (5.0, 12.0), (19.5, 12.0), w); }
        Icon::Grid => { for (x, y) in [(3.5, 3.5), (13.5, 3.5), (3.5, 13.5), (13.5, 13.5)] { cv.fill_rrect(rr(x, y, 7.0, 7.0), 2.0 * s, c); } }
        Icon::List => { for y in [5.5, 12.0, 18.5] { cv.fill_circle(ox + 4.5 * s, oy + y * s, 1.3 * s, c); ln(cv, (8.5, y), (20.5, y), w); } }
        Icon::Columns => { cv.stroke_rrect(rr(3.0, 4.0, 18.0, 16.0), 3.0 * s, w, c); ln(cv, (9.0, 4.5), (9.0, 19.5), w * 0.8); ln(cv, (15.0, 4.5), (15.0, 19.5), w * 0.8); }
        Icon::Gear => {
            cv.ring(ox + 12.0 * s, oy + 12.0 * s, 6.3 * s, 3.0 * s, c);
            for i in 0..8 { let a = i as f32 * PI / 4.0; let (cx, sy) = (cos(a), sin(a)); cv.line(p(12.0 + cx * 7.6, 12.0 + sy * 7.6), p(12.0 + cx * 10.0, 12.0 + sy * 10.0), 3.2 * s, c); }
        }
        Icon::Wifi => {
            for (rad, ww) in [(4.2f32, w * 1.05), (8.2, w * 1.05), (12.2, w * 1.05)] { cv.arc(ox + 12.0 * s, oy + 19.0 * s, rad * s, d2r(228.0), d2r(312.0), ww, c); }
            cv.fill_circle(ox + 12.0 * s, oy + 18.6 * s, 1.5 * s, c);
        }
        Icon::Battery => {
            cv.stroke_rrect(rr(1.5, 6.5, 18.0, 11.0), 3.2 * s, w * 0.8, c.fade(0.6));
            cv.fill_rrect(rr(3.4, 8.4, 11.6, 7.2), 1.6 * s, c);
            cv.fill_rrect(rr(20.5, 10.2, 1.8, 3.6), 0.9 * s, c.fade(0.6));
        }
        Icon::Bluetooth => { cv.polyline(&[p(6.5, 8.0), p(17.0, 16.0), p(12.0, 20.5), p(12.0, 3.5), p(17.0, 8.0), p(6.5, 16.0)], w, c); }
        Icon::Sound => {
            cv.fill_poly(&[p(3.5, 9.5), p(7.5, 9.5), p(12.0, 5.5), p(12.0, 18.5), p(7.5, 14.5), p(3.5, 14.5)], c);
            cv.arc(ox + 12.5 * s, oy + 12.0 * s, 4.2 * s, d2r(-48.0), d2r(48.0), w, c);
            cv.arc(ox + 12.5 * s, oy + 12.0 * s, 7.6 * s, d2r(-48.0), d2r(48.0), w, c);
        }
        Icon::Moon => {
            // crescent: outer circle minus an offset inner circle
            let (c1, r1, c2, r2) = ((11.0f32, 12.5f32), 8.6f32, (16.2f32, 8.6f32), 7.4f32);
            let mut outer: alloc::vec::Vec<Pt> = alloc::vec::Vec::new();
            let mut inner: alloc::vec::Vec<Pt> = alloc::vec::Vec::new();
            for i in 0..72 {
                let a = i as f32 * (6.2831853 / 72.0);
                let (px, py) = (c1.0 + r1 * cos(a), c1.1 + r1 * sin(a));
                if (px - c2.0) * (px - c2.0) + (py - c2.1) * (py - c2.1) > r2 * r2 { outer.push(p(px, py)); }
                let (qx, qy) = (c2.0 + r2 * cos(a), c2.1 + r2 * sin(a));
                if (qx - c1.0) * (qx - c1.0) + (qy - c1.1) * (qy - c1.1) < r1 * r1 { inner.push(p(qx, qy)); }
            }
            // outer arc is contiguous but may wrap; rotate so the sequence starts after the largest angular gap
            let n = outer.len();
            if n > 2 {
                let mut start = 0; let mut best = 0.0f32;
                for i in 0..n { let a = outer[i]; let b = outer[(i + 1) % n]; let d = (a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y); if d > best { best = d; start = (i + 1) % n; } }
                outer.rotate_left(start);
                // inner arc: order so it runs from the outer's end back to its start
                let ni = inner.len();
                if ni > 2 {
                    let mut s2 = 0; let mut b2 = 0.0f32;
                    for i in 0..ni { let a = inner[i]; let b = inner[(i + 1) % ni]; let d = (a.x - b.x) * (a.x - b.x) + (a.y - b.y) * (a.y - b.y); if d > b2 { b2 = d; s2 = (i + 1) % ni; } }
                    inner.rotate_left(s2);
                    let last = outer[n - 1];
                    let e0 = (inner[0].x - last.x) * (inner[0].x - last.x) + (inner[0].y - last.y) * (inner[0].y - last.y);
                    let e1 = (inner[ni - 1].x - last.x) * (inner[ni - 1].x - last.x) + (inner[ni - 1].y - last.y) * (inner[ni - 1].y - last.y);
                    if e1 < e0 { inner.reverse(); }
                    outer.extend(inner);
                    cv.fill_poly(&outer, c);
                }
            }
        }
        Icon::Sun | Icon::Brightness => {
            cv.fill_circle(ox + 12.0 * s, oy + 12.0 * s, 4.3 * s, c);
            for i in 0..8 { let a = i as f32 * PI / 4.0; cv.line(p(12.0 + cos(a) * 7.4, 12.0 + sin(a) * 7.4), p(12.0 + cos(a) * 9.6, 12.0 + sin(a) * 9.6), w, c); }
        }
        Icon::Display | Icon::Desktop => { cv.stroke_rrect(rr(2.5, 4.5, 19.0, 12.5), 2.6 * s, w, c); ln(cv, (8.5, 20.0), (15.5, 20.0), w); ln(cv, (12.0, 17.0), (12.0, 20.0), w); }
        Icon::Dock => { cv.stroke_rrect(rr(2.5, 4.5, 19.0, 15.0), 3.0 * s, w, c); cv.fill_rrect(rr(6.0, 14.5, 12.0, 3.4), 1.7 * s, c); }
        Icon::Folder => { cv.fill_rrect(rr(2.5, 4.5, 8.5, 6.0), 2.0 * s, c); cv.fill_rrect(rr(2.5, 7.5, 19.0, 12.5), 3.0 * s, c); }
        Icon::Doc => { cv.stroke_rrect(rr(5.0, 2.8, 14.0, 18.4), 2.8 * s, w, c); ln(cv, (8.5, 9.5), (15.5, 9.5), w * 0.8); ln(cv, (8.5, 13.0), (15.5, 13.0), w * 0.8); ln(cv, (8.5, 16.5), (12.5, 16.5), w * 0.8); }
        Icon::Download => { ln(cv, (12.0, 3.5), (12.0, 15.0), w); cv.polyline(&[p(6.8, 10.2), p(12.0, 15.4), p(17.2, 10.2)], w, c); ln(cv, (4.8, 20.0), (19.2, 20.0), w); }
        Icon::Apps => { cv.stroke_rrect(rr(3.0, 3.0, 18.0, 18.0), 5.0 * s, w, c); ln(cv, (8.0, 16.0), (12.0, 7.5), w); ln(cv, (12.0, 7.5), (16.0, 16.0), w); ln(cv, (9.2, 13.0), (14.8, 13.0), w); }
        Icon::Photo => { cv.stroke_rrect(rr(2.8, 4.5, 18.4, 15.0), 3.0 * s, w, c); cv.fill_circle(ox + 8.4 * s, oy + 9.6 * s, 1.7 * s, c); cv.polyline(&[p(3.5, 17.5), p(9.5, 12.5), p(13.0, 15.5), p(15.5, 13.2), p(20.5, 17.5)], w, c); }
        Icon::Music => { cv.fill_circle(ox + 7.8 * s, oy + 17.2 * s, 3.0 * s, c); cv.fill_circle(ox + 17.2 * s, oy + 15.2 * s, 3.0 * s, c); ln(cv, (10.4, 16.8), (10.4, 5.0), w); ln(cv, (19.8, 14.8), (19.8, 3.5), w); ln(cv, (10.4, 5.5), (19.8, 3.8), w * 1.8); }
        Icon::Trash => { ln(cv, (4.0, 6.5), (20.0, 6.5), w); ln(cv, (9.2, 3.8), (14.8, 3.8), w); cv.stroke_rrect(rr(6.0, 8.5, 12.0, 12.2), 2.4 * s, w, c); ln(cv, (10.0, 11.5), (10.0, 17.5), w * 0.8); ln(cv, (14.0, 11.5), (14.0, 17.5), w * 0.8); }
        Icon::Home => { cv.polyline(&[p(3.5, 11.5), p(12.0, 4.0), p(20.5, 11.5)], w, c); cv.polyline(&[p(6.0, 10.0), p(6.0, 19.5), p(18.0, 19.5), p(18.0, 10.0)], w, c); }
        Icon::Cloud => { cv.fill_circle(ox + 8.0 * s, oy + 14.0 * s, 4.4 * s, c); cv.fill_circle(ox + 13.0 * s, oy + 10.5 * s, 5.2 * s, c); cv.fill_circle(ox + 17.5 * s, oy + 14.5 * s, 3.9 * s, c); cv.fill_rrect(rr(8.0, 13.5, 10.0, 5.0), 2.5 * s, c); }
        Icon::Lock => { cv.fill_rrect(rr(5.0, 10.5, 14.0, 10.5), 3.0 * s, c); cv.arc(ox + 12.0 * s, oy + 10.5 * s, 4.3 * s, d2r(180.0), d2r(360.0), w * 1.1, c); ln(cv, (7.7, 10.5), (7.7, 9.0), w * 1.1); ln(cv, (16.3, 10.5), (16.3, 9.0), w * 1.1); }
        Icon::Shield => { let pts = [p(12.0, 2.8), p(19.5, 5.8), p(19.0, 12.2), p(15.5, 17.8), p(12.0, 21.0), p(8.5, 17.8), p(5.0, 12.2), p(4.5, 5.8)]; cv.fill_poly(&pts, c); }
        Icon::Bell => { cv.arc(ox + 12.0 * s, oy + 10.5 * s, 5.8 * s, d2r(180.0), d2r(360.0), w * 1.2, c); ln(cv, (6.2, 10.5), (5.2, 16.5), w * 1.2); ln(cv, (17.8, 10.5), (18.8, 16.5), w * 1.2); ln(cv, (4.2, 17.0), (19.8, 17.0), w * 1.2); cv.fill_circle(ox + 12.0 * s, oy + 19.8 * s, 1.7 * s, c); }
        Icon::Globe => { cv.ring(ox + 12.0 * s, oy + 12.0 * s, 8.8 * s, w, c); ln(cv, (3.4, 12.0), (20.6, 12.0), w * 0.8); cv.arc(ox + 4.0 * s, oy + 12.0 * s, 10.0 * s, d2r(-52.0), d2r(52.0), w * 0.8, c); cv.arc(ox + 20.0 * s, oy + 12.0 * s, 10.0 * s, d2r(128.0), d2r(232.0), w * 0.8, c); }
        Icon::User => { cv.fill_circle(ox + 12.0 * s, oy + 8.0 * s, 4.2 * s, c); cv.fill_rrect(rr(4.5, 14.5, 15.0, 6.8), 3.4 * s, c); }
        Icon::Keyboard => { cv.stroke_rrect(rr(2.0, 6.0, 20.0, 12.5), 3.0 * s, w, c); for x in [6.0, 9.7, 13.4, 17.1] { cv.fill_circle(ox + x * s, oy + 10.2 * s, 0.95 * s, c); } for x in [7.8, 11.5, 15.2] { cv.fill_circle(ox + x * s, oy + 13.0 * s, 0.95 * s, c); } ln(cv, (8.0, 15.7), (16.0, 15.7), w * 0.8); }
        Icon::Mouse => { cv.stroke_rrect(rr(6.5, 2.8, 11.0, 18.4), 5.5 * s, w, c); ln(cv, (12.0, 3.5), (12.0, 10.0), w * 0.8); }
        Icon::Palette => { cv.ring(ox + 12.0 * s, oy + 12.0 * s, 8.8 * s, w, c); for (x, y) in [(8.0, 9.5), (12.0, 7.5), (16.0, 9.5), (8.0, 14.5)] { cv.fill_circle(ox + x * s, oy + y * s, 1.4 * s, c); } }
        Icon::Sliders | Icon::Focus => { for (y, x) in [(6.5, 8.0), (12.0, 16.0), (17.5, 10.0)] { ln(cv, (3.5, y), (20.5, y), w * 0.9); cv.fill_circle(ox + x * s, oy + y * s, 2.5 * s, c); } }
        Icon::Plus => { ln(cv, (12.0, 5.0), (12.0, 19.0), w * 1.1); ln(cv, (5.0, 12.0), (19.0, 12.0), w * 1.1); }
        Icon::Minus => { ln(cv, (5.0, 12.0), (19.0, 12.0), w * 1.1); }
        Icon::Check => { cv.polyline(&[p(5.0, 12.8), p(10.0, 17.5), p(19.0, 6.8)], w * 1.3, c); }
        Icon::Close => { ln(cv, (6.0, 6.0), (18.0, 18.0), w * 1.1); ln(cv, (18.0, 6.0), (6.0, 18.0), w * 1.1); }
        Icon::Share => { ln(cv, (12.0, 3.5), (12.0, 14.5), w); cv.polyline(&[p(8.0, 7.2), p(12.0, 3.2), p(16.0, 7.2)], w, c); cv.polyline(&[p(8.0, 10.5), p(5.5, 10.5), p(5.5, 20.5), p(18.5, 20.5), p(18.5, 10.5), p(16.0, 10.5)], w, c); }
        Icon::Star => { let mut pts = Vec::new(); for i in 0..10 { let a = -PI / 2.0 + i as f32 * PI / 5.0; let rad = if i % 2 == 0 { 9.5 } else { 4.1 }; pts.push(p(12.0 + cos(a) * rad, 12.4 + sin(a) * rad)); } cv.fill_poly(&pts, c); }
        Icon::Tag => { cv.fill_poly(&[p(3.5, 4.5), p(12.5, 4.5), p(21.0, 13.0), p(13.0, 21.0), p(4.5, 12.5)], c); }
        Icon::Network => { for (x, y) in [(12.0, 5.0), (5.5, 18.0), (18.5, 18.0)] { cv.fill_circle(ox + x * s, oy + y * s, 2.5 * s, c); } ln(cv, (12.0, 5.0), (5.5, 18.0), w * 0.8); ln(cv, (12.0, 5.0), (18.5, 18.0), w * 0.8); ln(cv, (5.5, 18.0), (18.5, 18.0), w * 0.8); }
        Icon::Chip => { cv.fill_rrect(rr(6.0, 6.0, 12.0, 12.0), 2.6 * s, c); for t in [8.5, 12.0, 15.5] { ln(cv, (t, 3.0), (t, 6.0), w * 0.8); ln(cv, (t, 18.0), (t, 21.0), w * 0.8); ln(cv, (3.0, t), (6.0, t), w * 0.8); ln(cv, (18.0, t), (21.0, t), w * 0.8); } }
        Icon::Eye => { cv.arc(ox + 12.0 * s, oy + 21.0 * s, 13.0 * s, d2r(240.0), d2r(300.0), w, c); cv.arc(ox + 12.0 * s, oy + 3.0 * s, 13.0 * s, d2r(60.0), d2r(120.0), w, c); cv.fill_circle(ox + 12.0 * s, oy + 12.0 * s, 3.2 * s, c); }
        Icon::Bolt => { cv.fill_poly(&[p(13.5, 2.5), p(5.5, 13.5), p(11.0, 13.5), p(9.5, 21.5), p(18.5, 9.8), p(12.5, 9.8)], c); }
        Icon::Power => { cv.arc(ox + 12.0 * s, oy + 12.5 * s, 7.6 * s, d2r(-60.0), d2r(240.0), w * 1.1, c); ln(cv, (12.0, 3.2), (12.0, 11.5), w * 1.2); }
        Icon::Clock => { cv.ring(ox + 12.0 * s, oy + 12.0 * s, 8.8 * s, w, c); ln(cv, (12.0, 7.0), (12.0, 12.0), w); ln(cv, (12.0, 12.0), (15.5, 14.0), w); }
        Icon::Info => { cv.ring(ox + 12.0 * s, oy + 12.0 * s, 8.8 * s, w, c); cv.fill_circle(ox + 12.0 * s, oy + 7.8 * s, 1.2 * s, c); ln(cv, (12.0, 11.0), (12.0, 17.0), w * 1.1); }
        Icon::Terminal => { cv.stroke_rrect(rr(2.5, 4.0, 19.0, 16.0), 3.0 * s, w, c); cv.polyline(&[p(7.0, 9.5), p(10.5, 12.0), p(7.0, 14.5)], w, c); ln(cv, (12.5, 15.0), (17.0, 15.0), w); }
        Icon::Cursor => { cv.fill_poly(&[p(6.0, 3.5), p(6.0, 19.0), p(10.2, 15.0), p(13.0, 21.0), p(15.4, 19.9), p(12.7, 14.0), p(18.5, 14.0)], c); }
        Icon::Airdrop => { for rad in [3.5f32, 7.0, 10.5] { cv.arc(ox + 12.0 * s, oy + 13.0 * s, rad * s, d2r(200.0), d2r(340.0), w, c); } cv.fill_circle(ox + 12.0 * s, oy + 13.0 * s, 1.6 * s, c); }
        Icon::Wallpaper => { cv.stroke_rrect(rr(3.0, 4.0, 18.0, 16.0), 3.0 * s, w, c); cv.polyline(&[p(3.8, 16.5), p(9.0, 11.0), p(13.0, 15.0), p(16.0, 12.5), p(20.2, 16.5)], w, c); cv.fill_circle(ox + 16.0 * s, oy + 8.5 * s, 1.5 * s, c); }
        Icon::Accessibility => { cv.ring(ox + 12.0 * s, oy + 12.0 * s, 9.0 * s, w, c); cv.fill_circle(ox + 12.0 * s, oy + 7.5 * s, 1.4 * s, c); ln(cv, (7.0, 10.5), (17.0, 10.5), w); ln(cv, (12.0, 10.5), (12.0, 14.5), w); ln(cv, (12.0, 14.5), (9.5, 18.5), w); ln(cv, (12.0, 14.5), (14.5, 18.5), w); }
        Icon::Disk => { cv.stroke_rrect(rr(3.0, 6.5, 18.0, 11.0), 3.0 * s, w, c); cv.fill_circle(ox + 17.0 * s, oy + 12.0 * s, 1.1 * s, c); ln(cv, (6.5, 12.0), (12.0, 12.0), w * 0.8); }
        Icon::Ghost => { draw_ghost(cv, r, c, Color::CLEAR); }
        Icon::Key => { cv.ring(ox + 8.0 * s, oy + 12.0 * s, 4.3 * s, w, c); ln(cv, (12.3, 12.0), (21.0, 12.0), w); ln(cv, (18.0, 12.0), (18.0, 15.5), w); ln(cv, (15.2, 12.0), (15.2, 14.6), w); }
        Icon::Pencil => { cv.fill_poly(&[p(5.0, 19.0), p(6.0, 14.5), p(16.5, 4.0), p(20.0, 7.5), p(9.5, 18.0)], c); }
        Icon::Radar => { cv.ring(ox + 12.0 * s, oy + 12.0 * s, 9.0 * s, w, c); cv.ring(ox + 12.0 * s, oy + 12.0 * s, 4.5 * s, w, c); ln(cv, (12.0, 12.0), (18.5, 5.5), w); }
        Icon::Camera => { cv.stroke_rrect(rr(3.0, 7.0, 18.0, 13.0), 3.5 * s, w, c); cv.ring(ox + 12.0 * s, oy + 13.5 * s, 3.6 * s, w, c); cv.polyline(&[p(8.5, 7.0), p(10.0, 4.5), p(14.0, 4.5), p(15.5, 7.0)], w, c); }
        Icon::Mic => { cv.stroke_rrect(rr(9.0, 3.0, 6.0, 11.0), 3.0 * s, w, c); cv.polyline(&[p(6.0, 11.0), p(6.2, 13.0), p(8.2, 16.2), p(12.0, 17.6), p(15.8, 16.2), p(17.8, 13.0), p(18.0, 11.0)], w, c); ln(cv, (12.0, 17.6), (12.0, 21.0), w); ln(cv, (9.0, 21.0), (15.0, 21.0), w); }
        Icon::Pin => { cv.ring(ox + 12.0 * s, oy + 9.5 * s, 5.6 * s, w, c); cv.polyline(&[p(7.9, 13.4), p(12.0, 21.0), p(16.1, 13.4)], w, c); cv.fill_circle(ox + 12.0 * s, oy + 9.5 * s, 1.9 * s, c); }
        Icon::Usb => { ln(cv, (12.0, 5.0), (12.0, 19.0), w); cv.fill_circle(ox + 12.0 * s, oy + 20.2 * s, 2.0 * s, c); cv.polyline(&[p(12.0, 14.5), p(7.0, 11.5), p(7.0, 9.0)], w, c); cv.polyline(&[p(12.0, 11.0), p(17.0, 8.0), p(17.0, 7.0)], w, c); cv.fill_rect(rr(5.6, 6.0, 2.8, 2.8), c); cv.fill_circle(ox + 17.0 * s, oy + 5.8 * s, 1.9 * s, c); cv.fill_poly(&[p(9.6, 5.6), p(12.0, 2.0), p(14.4, 5.6)], c); }
        Icon::Cpu => { cv.stroke_rrect(rr(6.0, 6.0, 12.0, 12.0), 2.6 * s, w, c); cv.fill_rrect(rr(9.5, 9.5, 5.0, 5.0), 1.2 * s, c); for t in [9.0, 15.0] { ln(cv, (t, 3.0), (t, 6.0), w * 0.8); ln(cv, (t, 18.0), (t, 21.0), w * 0.8); ln(cv, (3.0, t), (6.0, t), w * 0.8); ln(cv, (18.0, t), (21.0, t), w * 0.8); } }
        Icon::Trash2 => { ln(cv, (5.0, 7.0), (19.0, 7.0), w); cv.polyline(&[p(7.0, 7.0), p(8.0, 20.0), p(16.0, 20.0), p(17.0, 7.0)], w, c); ln(cv, (9.5, 7.0), (9.5, 4.5), w); ln(cv, (14.5, 7.0), (14.5, 4.5), w); ln(cv, (9.5, 4.5), (14.5, 4.5), w); }
        Icon::Rocket => { cv.fill_poly(&[p(12.0, 2.5), p(16.5, 8.0), p(15.5, 15.5), p(8.5, 15.5), p(7.5, 8.0)], c); cv.fill_poly(&[p(7.5, 11.0), p(4.0, 16.0), p(8.5, 15.0)], c); cv.fill_poly(&[p(16.5, 11.0), p(20.0, 16.0), p(15.5, 15.0)], c); cv.fill_poly(&[p(10.0, 17.0), p(12.0, 21.5), p(14.0, 17.0)], c); }
        Icon::Siri => { for (i, h) in [4.0f32, 9.0, 14.0, 9.0, 4.0].iter().enumerate() { let x = 4.5 + i as f32 * 3.8; ln(cv, (x, 12.0 - h * 0.5), (x, 12.0 + h * 0.5), 2.4 * s); } }
    }
}

/// The Phantom ghost mark. `eye` colour punches the eyes (use the tile background).
/// Legacy name kept for call sites: draws the KashOS mark in one colour.
pub fn draw_ghost(cv: &mut Canvas, r: Rect, body: Color, _eye: Color) { draw_kash_mark(cv, r, body, None); }

pub fn tile(cv: &mut Canvas, r: Rect, top: Color, bottom: Color) { tile_ex(cv, r, top, bottom, 1.0); }

/// `light` scales the top/bottom glow and rim (≈0.5 for dark-mode tiles).
pub fn tile_ex(cv: &mut Canvas, r: Rect, top: Color, bottom: Color, light: f32) {
    let n = 5.0;
    let rad = r.w * 0.225;
    let s = r.w / 64.0;
    cv.fill_squircle(r, n, Paint::VGrad { y0: r.y, y1: r.bottom(), c0: top.lighten(0.05), c1: bottom.darken(0.07) });
    // soft top light (radial, fades to nothing — no hard edge)
    cv.fill_squircle(r, n, Paint::Radial { c: Pt::new(r.cx(), r.y - r.h * 0.12), r: r.w * 0.95, c0: Color::rgba(255, 255, 255, (84.0 * light) as u8), c1: Color::rgba(255, 255, 255, 0) });
    // reflected light bouncing up from the bottom edge
    cv.fill_squircle(r, n, Paint::Radial { c: Pt::new(r.cx(), r.bottom() + r.h * 0.10), r: r.w * 0.72, c0: Color::rgba(255, 255, 255, (46.0 * light) as u8), c1: Color::rgba(255, 255, 255, 0) });
    // inner rim: bright catch-light on the top edge, soft shade on the bottom edge
    let lw = (1.15 * s).max(0.8);
    // rim light fades smoothly from bright (top) to a soft shade (bottom) in thin horizontal strips
    let strips = 10;
    for k in 0..strips {
        let t0 = k as f32 / strips as f32; let t1 = (k + 1) as f32 / strips as f32;
        let tm = (t0 + t1) * 0.5;
        let col = if tm < 0.5 { Color::rgba(255, 255, 255, (125.0 * light.min(1.0) * (1.0 - tm * 2.0)) as u8) } else { Color::rgba(0, 0, 0, (54.0 * (tm - 0.5) * 2.0) as u8) };
        cv.push_clip(Rect::new(r.x - 2.0, r.y + r.h * t0 - if k == 0 { 2.0 } else { 0.0 }, r.w + 4.0, r.h * (t1 - t0) + if k == 0 || k + 1 == strips { 2.0 } else { 0.0 }));
        cv.stroke_rrect(r.inset(lw * 0.5), rad, lw, col);
        cv.pop_clip();
    }
    cv.stroke_rrect(r.inset(lw * 1.5), rad - lw, lw * 0.8, Color::rgba(255, 255, 255, 22));
}

/// Draw a glyph with a soft 3-step drop shadow underneath (gives icons depth).
fn depth(cv: &mut Canvas, s: f32, shadow: Color, f: &dyn Fn(&mut Canvas, f32, Option<Color>)) {
    for (k, a) in [(0.8f32, 0.50f32), (1.8, 0.32), (3.0, 0.18)] { f(cv, k * s, Some(shadow.fade(a * (shadow.a as f32 / 255.0)))); }
    f(cv, 0.0, None);
}

// ───────────────────────── KashOS logo ─────────────────────────
/// The KashOS mark: a bold "K" — stem, arm and leg — whose arm ends in a ring "node" (a capability / vault handle).
/// Drawn in one colour so it works as a menu-bar glyph; `node` optionally recolours the ring.
pub fn draw_kash_mark(cv: &mut Canvas, r: Rect, c: Color, node: Option<Color>) {
    let s = r.w.min(r.h) / 64.0;
    let ox = r.cx() - 32.0 * s; let oy = r.cy() - 32.0 * s;
    let p = |x: f32, y: f32| Pt::new(ox + x * s, oy + y * s);
    let w = 9.4 * s;
    cv.line(p(20.5, 12.5), p(20.5, 51.5), w, c);          // stem
    cv.line(p(23.0, 33.0), p(41.0, 17.5), w, c);          // arm
    cv.line(p(29.5, 31.0), p(46.0, 51.5), w, c);          // leg
    let nc = node.unwrap_or(c);
    cv.ring(p(47.5, 13.0).x, p(47.5, 13.0).y, 6.2 * s, 3.4 * s, nc);   // node
}

/// App-icon style badge of the logo (used for About, boot, exports).
pub fn kash_badge(cv: &mut Canvas, r: Rect, dark: bool) {
    let s = r.w / 64.0;
    if dark { tile_ex(cv, r, Color::hex(0x24306B), Color::hex(0x0A0722), 0.55); } else { tile(cv, r, Color::hex(0x62CBFF), Color::hex(0x5A2BD2)); }
    // halo behind the mark
    cv.fill_squircle(r, 5.0, Paint::Radial { c: Pt::new(r.cx(), r.cy() - 3.0 * s), r: 30.0 * s, c0: Color::rgba(255, 255, 255, if dark { 34 } else { 70 }), c1: Color::rgba(255, 255, 255, 0) });
    let g = Rect::new(r.x + 8.0 * s, r.y + 8.0 * s, 48.0 * s, 48.0 * s);
    for (k, a) in [(0.8f32, 0.50f32), (1.8, 0.30), (3.0, 0.16)] { draw_kash_mark(cv, g.offset(0.0, k * s), Color::rgba(10, 0, 60, (255.0 * a) as u8), Some(Color::rgba(10, 0, 60, (255.0 * a) as u8))); }
    if dark { draw_kash_mark(cv, g, Color::hex(0xEAF1FF), Some(Color::hex(0x38E0FF))); }
    else { draw_kash_mark(cv, g, Color::WHITE, Some(Color::hex(0xB6F3FF))); }
}

pub fn app_icon(cv: &mut Canvas, kind: crate::ui::AppKind, r: Rect) { app_icon_t(cv, kind, r, false); }

/// App icons in light or dark appearance (dark = deep glass tiles with luminous glyphs).
pub fn app_icon_t(cv: &mut Canvas, kind: crate::ui::AppKind, r: Rect, dark: bool) {
    use crate::ui::AppKind::*;
    let s = r.w / 64.0;
    let lt = if dark { 0.55 } else { 1.0 };
    let g = |dx: f32, dy: f32, ww: f32, hh: f32| Rect::new(r.x + dx * s, r.y + dy * s, ww * s, hh * s);
    let c = |l: u32, d: u32| Color::hex(if dark { d } else { l });
    match kind {
        Files => {
            tile_ex(cv, r, c(0x86D8FF, 0x35537F), c(0x1763E6, 0x09132A), lt);
            let fr = g(11.0, 15.0, 42.0, 34.0);
            cv.shadow_rrect(fr.offset(0.0, 2.5 * s), 6.0 * s, 5.0 * s, Color::rgba(0, 30, 90, if dark { 150 } else { 90 }), false);
            cv.fill_rrect(g(11.0, 15.0, 18.0, 10.0), 4.5 * s, if dark { Color::hex(0x4DA6FF).fade(0.75) } else { Color::rgba(255, 255, 255, 170) });
            cv.fill_rrect(g(11.0, 19.5, 42.0, 29.5), 6.0 * s, if dark { Color::hex(0x3B8CFF).fade(0.8) } else { Color::rgba(255, 255, 255, 150) });
            let front = g(11.0, 24.0, 42.0, 25.0);
            cv.fill_rrect(front, 6.0 * s, Paint::VGrad { y0: front.y, y1: front.bottom(), c0: c(0xFFFFFF, 0x9CE0FF), c1: c(0xD3E6FF, 0x3F8CFF) });
            cv.fill_rect(Rect::new(front.x + 4.0 * s, front.y + 0.4 * s, front.w - 8.0 * s, 1.0 * s), Color::rgba(255, 255, 255, if dark { 150 } else { 255 }));
        }
        Settings => {
            tile_ex(cv, r, c(0xE3E7EE, 0x4A505C), c(0x7D8594, 0x14161C), lt);
            let gr = g(9.0, 9.0, 46.0, 46.0);
            if dark {
                draw_icon(cv, Icon::Gear, gr.offset(0.0, -1.0 * s), Color::rgba(255, 255, 255, 40));
                depth(cv, s, Color::rgba(0, 0, 0, 200), &|cv, off, col| { if let Some(cc) = col { draw_icon(cv, Icon::Gear, gr.offset(0.0, off), cc); } });
                draw_icon(cv, Icon::Gear, gr, Color::hex(0xD5DAE4));
                cv.fill_circle(r.cx(), r.cy(), 6.2 * s, Paint::VGrad { y0: r.cy() - 6.0 * s, y1: r.cy() + 6.0 * s, c0: Color::hex(0x5A606D), c1: Color::hex(0x23262D) });
                cv.ring(r.cx(), r.cy(), 6.2 * s, 0.9 * s, Color::rgba(255, 255, 255, 50));
            } else {
                draw_icon(cv, Icon::Gear, gr.offset(0.0, 1.3 * s), Color::rgba(255, 255, 255, 190));
                depth(cv, s, Color::rgba(0, 0, 0, 120), &|cv, off, col| { if let Some(cc) = col { draw_icon(cv, Icon::Gear, gr.offset(0.0, off), cc); } });
                draw_icon(cv, Icon::Gear, gr, Color::hex(0x3B404B));
                cv.fill_circle(r.cx(), r.cy(), 6.2 * s, Paint::VGrad { y0: r.cy() - 6.0 * s, y1: r.cy() + 6.0 * s, c0: Color::hex(0xCDD2DB), c1: Color::hex(0x8A92A1) });
                cv.ring(r.cx(), r.cy(), 6.2 * s, 0.9 * s, Color::rgba(0, 0, 0, 70));
            }
        }
        Terminal => {
            tile_ex(cv, r, c(0x3B404D, 0x2A2E39), c(0x08090C, 0x040507), lt);
            for (k, col) in [0xFF5F57u32, 0xFEBC2E, 0x28C840].iter().enumerate() { cv.fill_circle(r.x + (12.0 + k as f32 * 6.4) * s, r.y + 11.5 * s, 2.1 * s, Color::hex(*col).fade(0.9)); }
            let p = |x: f32, y: f32| Pt::new(r.x + x * s, r.y + y * s);
            let green = Color::hex(0x5BF29B);
            cv.polyline(&[p(16.0, 26.0), p(28.0, 35.0), p(16.0, 44.0)], 9.0 * s, green.fade(0.16));
            cv.line(p(33.0, 45.0), p(47.0, 45.0), 9.0 * s, green.fade(0.16));
            cv.polyline(&[p(16.0, 26.0), p(28.0, 35.0), p(16.0, 44.0)], 4.4 * s, green);
            cv.line(p(33.0, 45.0), p(47.0, 45.0), 4.4 * s, green);
        }
        Browser => {
            tile_ex(cv, r, c(0x7AD9FF, 0x1F3F70), c(0x1558E0, 0x050D20), lt);
            let (cx, cy) = (r.cx(), r.cy());
            let ring = if dark { Color::hex(0x7CC2FF) } else { Color::rgba(255, 255, 255, 240) };
            cv.fill_circle(cx, cy, 23.0 * s, Paint::VGrad { y0: cy - 23.0 * s, y1: cy + 23.0 * s, c0: Color::rgba(255, 255, 255, if dark { 30 } else { 52 }), c1: Color::rgba(255, 255, 255, 6) });
            cv.ring(cx, cy, 22.0 * s, 2.6 * s, ring);
            for k in 0..24 {
                let a = k as f32 * PI / 12.0; let major = k % 6 == 0;
                let (r0, r1) = (if major { 15.5 } else { 17.8 }, 19.6);
                cv.line(Pt::new(cx + cos(a) * r0 * s, cy + sin(a) * r0 * s), Pt::new(cx + cos(a) * r1 * s, cy + sin(a) * r1 * s), (if major { 1.7 } else { 0.9 }) * s, ring.fade(if major { 0.95 } else { 0.55 }));
            }
            let ux = 0.7071f32;
            let tip_r = Pt::new(cx + 12.5 * s, cy - 12.5 * s); let tip_w = Pt::new(cx - 12.5 * s, cy + 12.5 * s);
            let sd = Pt::new(5.2 * s * ux, 5.2 * s * ux);
            let (a1, a2) = (Pt::new(cx - sd.x, cy - sd.y), Pt::new(cx + sd.x, cy + sd.y));
            cv.fill_poly(&[Pt::new(tip_r.x, tip_r.y + 1.6 * s), Pt::new(a1.x, a1.y + 1.6 * s), Pt::new(a2.x, a2.y + 1.6 * s)], Color::rgba(0, 20, 80, 90));
            cv.fill_poly(&[tip_r, a1, a2], Color::hex(0xFF453A));
            cv.fill_poly(&[tip_w, a1, a2], Color::rgba(255, 255, 255, 245));
            cv.fill_circle(cx, cy, 2.2 * s, Color::hex(0xE8EEF8)); cv.ring(cx, cy, 2.2 * s, 0.7 * s, Color::rgba(0, 0, 0, 60));
        }
        Notes => {
            tile_ex(cv, r, c(0xFFFFFF, 0x3A3A40), c(0xEFEBDD, 0x131315), lt);
            cv.push_clip(g(0.0, 0.0, 64.0, 19.0));
            cv.fill_squircle(r, 5.0, Paint::VGrad { y0: r.y, y1: r.y + 19.0 * s, c0: c(0xFFDB6B, 0xF5C02A), c1: c(0xFFBE1A, 0xC98F00) });
            cv.fill_rect(g(0.0, 17.8, 64.0, 1.2), Color::rgba(160, 100, 0, 70));
            cv.pop_clip();
            let lc = if dark { Color::rgba(255, 255, 255, 56) } else { Color::rgba(60, 60, 70, 46) };
            for i in 0..4 { cv.fill_rrect(g(11.0, 28.0 + i as f32 * 8.2, 42.0, 2.2), 1.1 * s, lc); }
            cv.fill_rrect(g(11.0, 28.0 + 3.0 * 8.2, 24.0, 2.2), 1.1 * s, lc);
        }
        Photos => {
            tile_ex(cv, r, c(0xFFFFFF, 0x34363F), c(0xE6E9EF, 0x0B0C10), lt);
            let cols = [0xFF6B5E_u32, 0xFFA21F, 0xFFD60A, 0x34D65F, 0x38BDF2, 0x5E6BFF, 0xC261F5, 0xFF3D78];
            for (i, col) in cols.iter().enumerate() {
                let a = i as f32 * PI / 4.0 - PI / 2.0;
                cv.fill_circle(r.cx() + cos(a) * 11.4 * s, r.cy() + sin(a) * 11.4 * s, 10.8 * s, Paint::Radial { c: Pt::new(r.cx() + cos(a) * 14.0 * s, r.cy() + sin(a) * 14.0 * s), r: 11.0 * s, c0: Color::hex(*col).fade(0.92), c1: Color::hex(*col).fade(if dark { 0.70 } else { 0.62 }) });
            }
            cv.fill_circle(r.cx(), r.cy(), 6.0 * s, Color::rgba(255, 255, 255, if dark { 70 } else { 120 }));
        }
        Music => {
            tile_ex(cv, r, c(0xFF8196, 0x55202C), c(0xDE1038, 0x12050A), lt);
            let gr = g(13.0, 12.0, 38.0, 38.0);
            depth(cv, s, Color::rgba(if dark { 0 } else { 90 }, 0, if dark { 0 } else { 20 }, 255), &|cv, off, col| { if let Some(cc) = col { draw_icon(cv, Icon::Music, gr.offset(0.0, off), cc); } });
            draw_icon(cv, Icon::Music, gr, if dark { Color::hex(0xFF6B8A) } else { Color::WHITE });
        }
        Messages => {
            tile_ex(cv, r, c(0x78F58A, 0x1F4A30), c(0x0FAE45, 0x05120A), lt);
            let b = g(10.0, 13.0, 44.0, 31.0);
            cv.shadow_rrect(b.offset(0.0, 2.5 * s), 15.0 * s, 5.0 * s, Color::rgba(0, 70, 20, if dark { 160 } else { 100 }), false);
            cv.fill_poly(&[Pt::new(r.x + 17.0 * s, r.y + 38.0 * s), Pt::new(r.x + 13.0 * s, r.y + 51.0 * s), Pt::new(r.x + 29.0 * s, r.y + 42.0 * s)], c(0xE3F8E8, 0x1DB954));
            cv.fill_rrect(b, 15.5 * s, Paint::VGrad { y0: b.y, y1: b.bottom(), c0: c(0xFFFFFF, 0x6BF590), c1: c(0xE3F8E8, 0x17B84C) });
        }
        ActivityMonitor => {
            tile_ex(cv, r, c(0x565B68, 0x2C3038), c(0x0A0B0E, 0x040506), lt);
            let p = |x: f32, y: f32| Pt::new(r.x + x * s, r.y + y * s);
            for k in 0..4 { cv.fill_rect(g(10.0, 16.0 + k as f32 * 10.5, 44.0, 0.9), Color::rgba(255, 255, 255, 22)); }
            let pts = [p(8.0, 38.0), p(19.0, 38.0), p(24.0, 22.0), p(31.0, 48.0), p(37.0, 28.0), p(41.0, 38.0), p(56.0, 38.0)];
            let gcol = Color::hex(0x5BF29B);
            cv.polyline(&pts, 8.0 * s, gcol.fade(0.16));
            cv.polyline(&pts, 3.6 * s, gcol);
        }
        Calculator => {
            tile_ex(cv, r, c(0x7A808C, 0x3A3E48), c(0x23262D, 0x0C0D10), lt);
            cv.fill_rrect(g(9.0, 9.0, 46.0, 15.0), 4.0 * s, Color::rgba(0, 0, 0, if dark { 150 } else { 120 }));
            cv.fill_rrect(g(36.0, 13.0, 15.0, 2.6), 1.3 * s, Color::rgba(255, 255, 255, 190));
            for j in 0..3 { for i in 0..4 {
                let col = if i == 3 { Color::hex(0xFF9F0A) } else if j == 0 { Color::hex(0xA5A8B1) } else { Color::hex(0x5A5E69) };
                cv.fill_rrect(g(9.0 + i as f32 * 12.0, 28.0 + j as f32 * 9.6, 10.0, 7.6), 3.0 * s, col);
            } }
        }
        About => { kash_badge(cv, r, dark); }
    }
}

pub fn draw_folder_glyph(cv: &mut Canvas, r: Rect, c: Color) {
    cv.fill_rrect(Rect::new(r.x, r.y, r.w * 0.45, r.h * 0.34), r.h * 0.12, c.fade(0.9));
    cv.fill_rrect(Rect::new(r.x, r.y + r.h * 0.16, r.w, r.h * 0.84), r.h * 0.14, c);
}

pub fn trash_icon(cv: &mut Canvas, r: Rect, full: bool) { trash_icon_t(cv, r, full, false); }
pub fn trash_icon_t(cv: &mut Canvas, r: Rect, full: bool, dark: bool) {
    let lt = if dark { 0.55 } else { 1.0 };
    if dark { tile_ex(cv, r, Color::hex(0x4C5260), Color::hex(0x14171D), lt); } else { tile_ex(cv, r, Color::hex(0xEEF1F7), Color::hex(0x98A1B3), lt); }
    let s = r.w / 64.0;
    let lt = if dark { 0.55 } else { 1.0 };
    let gr = Rect::new(r.x + 12.0 * s, r.y + 11.0 * s, 40.0 * s, 40.0 * s);
    if !dark { draw_icon(cv, Icon::Trash, gr.offset(0.0, 1.2 * s), Color::rgba(255, 255, 255, 170)); }
    for (k, a) in [(0.8f32, 28u8), (1.8, 18), (3.0, 10)] { draw_icon(cv, Icon::Trash, gr.offset(0.0, k * s), Color::rgba(0, 0, 0, if dark { a * 3 } else { a })); }
    draw_icon(cv, Icon::Trash, gr, if dark { Color::rgba(222, 228, 240, 245) } else { Color::rgba(52, 60, 78, 240) });
    if full { cv.fill_circle(r.right() - 12.0 * s, r.y + 12.0 * s, 6.0 * s, Color::hex(0xFF453A)); }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind { Folder, Doc, Pdf, Image, Audio, Archive, Code, Text, Iso, Pcap, App, Vault, Exec, Driver }

pub fn file_icon(cv: &mut Canvas, kind: FileKind, r: Rect) {
    let s = r.w.min(r.h) / 64.0;
    let ox = r.cx() - 32.0 * s; let oy = r.cy() - 32.0 * s;
    let g = |dx: f32, dy: f32, ww: f32, hh: f32| Rect::new(ox + dx * s, oy + dy * s, ww * s, hh * s);
    match kind {
        FileKind::Folder | FileKind::Vault => {
            let back = Color::hex(0x2F8BEF); let front_t = Color::hex(0x6CC1FF); let front_b = Color::hex(0x2E8CF2);
            cv.shadow_rrect(g(4.0, 12.0, 56.0, 44.0).offset(0.0, 2.0 * s), 6.0 * s, 4.0 * s, Color::rgba(0, 20, 60, 40), false);
            cv.fill_rrect(g(4.0, 9.0, 24.0, 16.0), 5.0 * s, back);
            cv.fill_rrect(g(4.0, 15.0, 56.0, 40.0), 6.0 * s, back.darken(0.1));
            cv.fill_rrect(g(4.0, 20.0, 56.0, 36.0), 6.0 * s, Paint::VGrad { y0: oy + 20.0 * s, y1: oy + 56.0 * s, c0: front_t, c1: front_b });
            cv.fill_rect(g(6.0, 20.6, 52.0, 1.2), Color::rgba(255, 255, 255, 90));
            if kind == FileKind::Vault { draw_icon(cv, Icon::Lock, g(22.0, 26.0, 20.0, 20.0), Color::rgba(255, 255, 255, 235)); }
        }
        _ => {
            let (lc, glyph): (Color, Option<Icon>) = match kind {
                FileKind::Pdf => (Color::hex(0xEF4444), None),
                FileKind::Doc => (Color::hex(0x2F7BF5), None),
                FileKind::Text => (Color::hex(0x8E8E93), None),
                FileKind::Code => (Color::hex(0xF97316), None),
                FileKind::Archive => (Color::hex(0xA855F7), None),
                FileKind::Iso => (Color::hex(0x14B8A6), None),
                FileKind::Pcap => (Color::hex(0x10B981), None),
                FileKind::App => (Color::hex(0x6366F1), Some(Icon::Ghost)),
                FileKind::Exec => (Color::hex(0x30D158), Some(Icon::Terminal)),
                FileKind::Driver => (Color::hex(0xFF9F0A), Some(Icon::Chip)),
                FileKind::Audio => (Color::hex(0xFF2D55), Some(Icon::Music)),
                FileKind::Image => (Color::hex(0x32ADE6), Some(Icon::Photo)),
                _ => (Color::hex(0x888888), None),
            };
            let page = g(11.0, 4.0, 42.0, 56.0);
            cv.shadow_rrect(page.offset(0.0, 2.0 * s), 6.0 * s, 4.0 * s, Color::rgba(0, 0, 0, 38), false);
            if kind == FileKind::Image {
                cv.fill_rrect(page, 6.0 * s, Paint::Linear { p0: Pt::new(page.x, page.y), p1: Pt::new(page.right(), page.bottom()), c0: Color::hex(0xFFB36B), c1: Color::hex(0x7C5CFF) });
                cv.fill_circle(page.x + page.w * 0.7, page.y + page.h * 0.3, 6.0 * s, Color::rgba(255, 255, 255, 200));
                cv.fill_poly(&[Pt::new(page.x, page.bottom()), Pt::new(page.x + page.w * 0.4, page.y + page.h * 0.55), Pt::new(page.x + page.w * 0.7, page.bottom() - page.h * 0.2), Pt::new(page.right(), page.bottom() - page.h * 0.35), Pt::new(page.right(), page.bottom() - 6.0 * s), Pt::new(page.right() - 6.0 * s, page.bottom())], Color::rgba(20, 20, 60, 110));
                cv.stroke_rrect(page, 6.0 * s, 1.0, Color::rgba(255, 255, 255, 120));
            } else {
                cv.fill_rrect(page, 6.0 * s, Paint::VGrad { y0: page.y, y1: page.bottom(), c0: Color::hex(0xFFFFFF), c1: Color::hex(0xEEF0F4) });
                cv.stroke_rrect(page, 6.0 * s, 1.0, Color::rgba(0, 0, 0, 40));
                cv.fill_poly(&[Pt::new(page.right() - 12.0 * s, page.y), Pt::new(page.right(), page.y + 12.0 * s), Pt::new(page.right() - 12.0 * s, page.y + 12.0 * s)], Color::rgba(0, 0, 0, 28));
                if let Some(ic) = glyph {
                    draw_icon(cv, ic, g(20.0, 20.0, 24.0, 24.0), lc);
                } else {
                    for i in 0..3 { cv.fill_rrect(g(18.0, 16.0 + i as f32 * 6.0, 22.0 - i as f32 * 4.0, 2.2), 1.1 * s, Color::rgba(0, 0, 0, 36)); }
                    cv.fill_rrect(g(11.0, 40.0, 42.0, 14.0), 3.0 * s, lc);
                }
            }
        }
    }
}


// ───────────────────────── icon cache ─────────────────────────
use alloc::collections::BTreeMap;

/// Pre-rendered icon: premultiplied ARGB (a<<24 | r<<16 | g<<8 | b).
pub struct IconBmp { pub n: i32, pub px: alloc::vec::Vec<u32> }

const LEVELS: [i32; 7] = [32, 48, 64, 96, 128, 192, 256];

#[derive(Default)]
pub struct IconCache { map: BTreeMap<(u16, i32), IconBmp> }

impl IconCache {
    pub fn new() -> IconCache { IconCache { map: BTreeMap::new() } }

    fn level_for(px: f32) -> i32 {
        for l in LEVELS.iter() { if (*l as f32) >= px * 0.98 { return *l; } }
        *LEVELS.last().unwrap()
    }

    /// Draw cached icon `key` (rendered lazily by `paint` onto a transparent square) into `dest`.
    pub fn draw(&mut self, cv: &mut Canvas, key: u16, dest: Rect, alpha: f32, paint: &dyn Fn(&mut Canvas, Rect)) {
        if dest.w < 1.0 || dest.h < 1.0 { return; }
        let level = Self::level_for(dest.w.max(dest.h));
        if !self.map.contains_key(&(key, level)) {
            let mut c = Canvas::new(level, level);
            let r = Rect::new(0.0, 0.0, level as f32, level as f32);
            c.clear(Color::BLACK); paint(&mut c, r);
            let on_black: alloc::vec::Vec<u32> = c.px.clone();
            c.clear(Color::WHITE); paint(&mut c, r);
            let mut px = alloc::vec::Vec::with_capacity(on_black.len());
            for (a, b) in on_black.iter().zip(c.px.iter()) {
                // on black: C = c*α ; on white: W = c*α + (1-α)  ⇒ α = 1 - (W - C)
                let (ar, ag, ab) = ((*a >> 16) & 255, (*a >> 8) & 255, *a & 255);
                let (br, bg, bb) = ((*b >> 16) & 255, (*b >> 8) & 255, *b & 255);
                let d = ((br - ar.min(br)) + (bg - ag.min(bg)) + (bb - ab.min(bb))) / 3;
                let al = 255 - d.min(255);
                px.push((al << 24) | (ar.min(al) << 16) | (ag.min(al) << 8) | ab.min(al));
            }
            self.map.insert((key, level), IconBmp { n: level, px });
        }
        let bmp = self.map.get(&(key, level)).unwrap();
        cv.blit_icon(bmp, dest, alpha);
    }
}

impl Canvas {
    /// Bilinear blit of a premultiplied icon into float `dest`.
    pub fn blit_icon(&mut self, bmp: &IconBmp, dest: Rect, alpha: f32) {
        let clip = self.clip();
        let bb = IRect::from_rect_outer(&dest).intersect(&clip);
        if bb.is_empty() { return; }
        let n = bmp.n;
        let sx = n as f32 / dest.w; let sy = n as f32 / dest.h;
        let a256 = (saturate(alpha) * 256.0) as u32;
        let maxq = (n - 1) * 256 - 1;
        for y in bb.y0..bb.y1 {
            let fy = ((((y as f32 + 0.5 - dest.y) * sy - 0.5) * 256.0) as i32).clamp(0, maxq);
            let (y0, ty) = ((fy >> 8) as usize, (fy & 255) as u32);
            let row = (y * self.w) as usize;
            for x in bb.x0..bb.x1 {
                let fx = ((((x as f32 + 0.5 - dest.x) * sx - 0.5) * 256.0) as i32).clamp(0, maxq);
                let (x0, tx) = ((fx >> 8) as usize, (fx & 255) as u32);
                let nn = n as usize;
                let (p00, p10, p01, p11) = (bmp.px[y0 * nn + x0], bmp.px[y0 * nn + x0 + 1], bmp.px[(y0 + 1) * nn + x0], bmp.px[(y0 + 1) * nn + x0 + 1]);
                let ch = |sh: u32| -> u32 {
                    let top = ((p00 >> sh) & 255) * (256 - tx) + ((p10 >> sh) & 255) * tx;
                    let bot = ((p01 >> sh) & 255) * (256 - tx) + ((p11 >> sh) & 255) * tx;
                    (top * (256 - ty) + bot * ty) >> 16
                };
                let (a, r, g, b) = (ch(24), ch(16), ch(8), ch(0));
                if a == 0 { continue; }
                let a = a * a256 >> 8; let ia = 255 - a;
                let r = r * a256 >> 8; let g = g * a256 >> 8; let b = b * a256 >> 8;
                let i = row + x as usize;
                let d = self.px[i];
                let nr = (r + (((d >> 16) & 255) * ia + 127) / 255).min(255);
                let ng = (g + (((d >> 8) & 255) * ia + 127) / 255).min(255);
                let nb = (b + ((d & 255) * ia + 127) / 255).min(255);
                self.px[i] = (nr << 16) | (ng << 8) | nb;
            }
        }
    }
}

pub fn app_key(k: crate::ui::AppKind) -> u16 { k as u16 }
pub fn file_key(k: FileKind) -> u16 { 100 + k as u16 }

/// Launchpad tile: silver glass with a 3×3 grid of tiny coloured app squares.
pub fn launchpad_icon(cv: &mut Canvas, r: Rect, dark: bool) {
    let s = r.w / 64.0;
    if dark { tile_ex(cv, r, Color::hex(0x5A6072), Color::hex(0x161922), 0.55); } else { tile_ex(cv, r, Color::hex(0xF1F4FA), Color::hex(0x98A2B8), 1.0); }
    let cols = [0xFF5F57u32, 0xFFBD2E, 0x30D158, 0x0A84FF, 0xBF5AF2, 0xFF375F, 0x64D2FF, 0xFF9F0A, 0x5E5CE6];
    for (i, c) in cols.iter().enumerate() {
        let (cx_, cy_) = ((i % 3) as f32, (i / 3) as f32);
        let q = Rect::new(r.x + (13.0 + cx_ * 13.2) * s, r.y + (13.0 + cy_ * 13.2) * s, 11.0 * s, 11.0 * s);
        cv.shadow_rrect(q.offset(0.0, 0.8 * s), 3.2 * s, 1.5 * s, Color::rgba(0, 0, 0, if dark { 120 } else { 50 }), false);
        cv.fill_rrect(q, 3.2 * s, Paint::VGrad { y0: q.y, y1: q.bottom(), c0: Color::hex(*c).lighten(0.18), c1: Color::hex(*c) });
    }
}

/// Downloads stack tile: blue glass with a white down-arrow.
pub fn downloads_icon(cv: &mut Canvas, r: Rect, dark: bool) {
    let s = r.w / 64.0;
    if dark { tile_ex(cv, r, Color::hex(0x2C5F9E), Color::hex(0x0A1B36), 0.55); } else { tile_ex(cv, r, Color::hex(0x7FD3FF), Color::hex(0x1670F0), 1.0); }
    let gr = Rect::new(r.x + 13.0 * s, r.y + 11.0 * s, 38.0 * s, 38.0 * s);
    for (k, a) in [(0.8f32, 70u8), (1.8, 45), (3.0, 24)] { draw_icon(cv, Icon::Download, gr.offset(0.0, k * s), Color::rgba(0, 20, 80, a)); }
    draw_icon(cv, Icon::Download, gr, if dark { Color::hex(0x9ED8FF) } else { Color::WHITE });
}
