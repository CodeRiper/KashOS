//! Activity Monitor and Calculator.
use alloc::format;
use alloc::string::String;
use crate::app::*;
use crate::color::*;
use crate::geom::*;
use crate::anim::*;
use crate::text::*;
use crate::ui::*;

fn bar(cx: &mut Ctx, area: Rect, title: &str) {
    let r = Rect::new(0.0, 0.0, area.w, 54.0);
    let mut st = cx.th.glass(crate::theme::GlassKind::Toolbar, 0.0);
    st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0;
    cx.glass_style(r, &st);
    let c = cx.th.label();
    cx.text(18.0, 33.0, title, 13.5, Weight::Semibold, c);
    let sc = cx.th.separator();
    cx.cv.fill_rect(Rect::new(0.0, 53.0, area.w, 1.0), sc);
}

// ───────── Activity Monitor ─────────
pub struct ActivityMonitor { scroll: Scroll }
impl ActivityMonitor { pub fn new() -> ActivityMonitor { ActivityMonitor { scroll: Scroll::default() } } }

impl App for ActivityMonitor {
    fn kind(&self) -> AppKind { AppKind::ActivityMonitor }
    fn default_size(&self) -> (f32, f32) { (760.0, 520.0) }
    fn min_size(&self) -> (f32, f32) { (600.0, 400.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        cx.sys.blink_req = true;
        cx.cv.fill_rect(area, th.content_bg());
        // No telemetry service is connected, so present an explicit empty state instead of sample data.
        let g = Rect::new(20.0, 70.0, area.w - 40.0, 110.0);
        cx.group_box(g);
        let l2 = th.label2(); let lc = th.label();
        let stat = |cx: &mut Ctx, x: f32, v: &str, l: &str| { cx.text(x, 214.0, v, 18.0, Weight::Bold, lc); cx.text(x, 232.0, l, 11.0, Weight::Regular, l2); };
        cx.text_in(g, "Live system metrics are unavailable: no telemetry service is connected.", 13.0, Weight::Regular, l2, Align::Center);
        stat(cx, 24.0, "Unavailable", "CPU metrics");
        stat(cx, 220.0, "Unavailable", "Memory metrics");
        stat(cx, 430.0, "Unavailable", "Network metrics");
        // This is the registered application catalog, not a list of running processes.
        let head = Rect::new(20.0, 250.0, area.w - 40.0, 24.0);
        cx.text(head.x + 8.0, head.y + 16.0, "Registered app", 11.5, Weight::Semibold, l2);
        cx.text(head.x + head.w * 0.46, head.y + 16.0, "Category", 11.5, Weight::Semibold, l2);
        cx.text(head.x + head.w * 0.64, head.y + 16.0, "Runtime", 11.5, Weight::Semibold, l2);
        cx.text(head.x + head.w * 0.80, head.y + 16.0, "Declared class", 11.5, Weight::Semibold, l2);
        cx.separator_h(head.x, head.right(), head.bottom());
        let list = Rect::new(20.0, 276.0, area.w - 40.0, area.h - 290.0);
        let rows = cx.sys.reg.apps.len();
        self.scroll.update(cx.io, cx.hover(list), rows as f32 * 30.0 - list.h);
        cx.cv.push_clip(list);
        for i in 0..rows {
            let y = list.y + i as f32 * 30.0 - self.scroll.y;
            if y > list.bottom() || y + 30.0 < list.y { continue; }
            let ap = &cx.sys.reg.apps[i];
            let (nm, cls, sys_) = (ap.name.clone(), ap.class, ap.system);
            if i % 2 == 0 { cx.cv.fill_rrect(Rect::new(list.x, y, list.w, 30.0), 8.0, th.hover_fill().fade(0.5)); }
            cx.file_icon(cls.file_kind(), Rect::new(list.x + 8.0, y + 4.0, 22.0, 22.0));
            cx.text(list.x + 38.0, y + 20.0, &nm, 12.5, Weight::Regular, lc);
            cx.text(list.x + list.w * 0.46, y + 20.0, cls.singular(), 12.0, Weight::Regular, l2);
            cx.text(list.x + list.w * 0.64, y + 20.0, "Not running", 12.0, Weight::Regular, l2);
            cx.text(list.x + list.w * 0.80, y + 20.0, if sys_ { "System" } else { "User" }, 12.0, Weight::Regular, l2);
        }
        cx.cv.pop_clip();
        bar(cx, area, "Activity Monitor");
    }
}

// ───────── Calculator ─────────
pub struct Calculator { disp: String, acc: f64, op: char, fresh: bool }
impl Calculator { pub fn new() -> Calculator { Calculator { disp: String::from("0"), acc: 0.0, op: ' ', fresh: true } } }
fn parse(s: &str) -> f64 {
    let (neg, body) = if let Some(b) = s.strip_prefix('-') { (true, b) } else { (false, s) };
    let mut it = body.split('.');
    let ip = it.next().unwrap_or("0"); let fp = it.next().unwrap_or("");
    let mut v = 0.0f64; for ch in ip.chars() { if let Some(d) = ch.to_digit(10) { v = v * 10.0 + d as f64; } }
    let mut sc = 0.1f64; for ch in fp.chars() { if let Some(d) = ch.to_digit(10) { v += d as f64 * sc; sc *= 0.1; } }
    if neg { -v } else { v }
}
fn fmt(v: f64) -> String {
    if v != v { return String::from("Error"); }
    let neg = v < 0.0; let a = if neg { -v } else { v };
    let scaled = (a * 1_000_000.0 + 0.5) as u128;
    let (ip, mut fp) = (scaled / 1_000_000, scaled % 1_000_000);
    let mut f = format!("{:06}", fp); while f.ends_with('0') { f.pop(); } fp = 0; let _ = fp;
    let mut s = String::new(); if neg && (ip > 0 || !f.is_empty()) { s.push('-'); }
    s.push_str(&format!("{}", ip)); if !f.is_empty() { s.push('.'); s.push_str(&f); }
    s
}
impl Calculator {
    fn press(&mut self, k: &str) {
        match k {
            "AC" => { self.disp = String::from("0"); self.acc = 0.0; self.op = ' '; self.fresh = true; }
            "±" => { if self.disp != "0" { if let Some(b) = self.disp.strip_prefix('-') { self.disp = String::from(b); } else { self.disp = format!("-{}", self.disp); } } }
            "%" => { let v = parse(&self.disp) / 100.0; self.disp = fmt(v); }
            "+" | "−" | "×" | "÷" => { self.eval(); self.op = k.chars().next().unwrap(); self.fresh = true; }
            "=" => { self.eval(); self.op = ' '; self.fresh = true; }
            "." => { if self.fresh { self.disp = String::from("0."); self.fresh = false; } else if !self.disp.contains('.') { self.disp.push('.'); } }
            d => { if self.fresh || self.disp == "0" { self.disp = String::from(d); } else if self.disp.len() < 14 { self.disp.push_str(d); } self.fresh = false; }
        }
    }
    fn eval(&mut self) {
        let v = parse(&self.disp);
        if self.op == ' ' { self.acc = v; } else {
            self.acc = match self.op { '+' => self.acc + v, '−' => self.acc - v, '×' => self.acc * v, _ => if v == 0.0 { f64::NAN } else { self.acc / v } };
            self.disp = fmt(self.acc);
        }
        if self.op == ' ' { self.acc = v; }
    }
}
impl App for Calculator {
    fn kind(&self) -> AppKind { AppKind::Calculator }
    fn default_size(&self) -> (f32, f32) { (330.0, 470.0) }
    fn min_size(&self) -> (f32, f32) { (330.0, 470.0) }
    fn animating(&self) -> bool { false }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        cx.cv.fill_rect(area, th.pick(Color::hex(0x2B2D33), Color::hex(0x16171B)));
        let l = if self.disp.len() > 9 { 40.0 } else { 54.0 };
        cx.text_in(Rect::new(16.0, 58.0, area.w - 32.0, 96.0), &self.disp.clone(), l, Weight::Medium, Color::WHITE, Align::Right);
        let rows = [["AC", "±", "%", "÷"], ["7", "8", "9", "×"], ["4", "5", "6", "−"], ["1", "2", "3", "+"], ["0", "0", ".", "="]];
        let gap = 10.0; let bw = (area.w - 32.0 - gap * 3.0) / 4.0; let bh = 56.0;
        for (j, row) in rows.iter().enumerate() {
            for (i, k) in row.iter().enumerate() {
                if j == 4 && i == 1 { continue; }
                let wide = j == 4 && i == 0;
                let r = Rect::new(16.0 + i as f32 * (bw + gap), 164.0 + j as f32 * (bh + gap), if wide { bw * 2.0 + gap } else { bw }, bh);
                let op = i == 3; let top = j == 0 && i < 3;
                let base = if op { Color::hex(0xFF9F0A) } else if top { Color::hex(0xA5A8B1) } else { Color::hex(0x54575F) };
                let id = format!("calc{}{}", j, i);
                let h = cx.hit(id_of(&id), r);
                let hv = cx.anim(id2(id_of(&id), 1), if h.hovered { 1.0 } else { 0.0 });
                let pr = cx.anim(id2(id_of(&id), 2), if h.pressed { 1.0 } else { 0.0 });
                cx.cv.fill_rrect(r.inset(-pr * 1.5), bh * 0.5, base.lighten(hv * 0.08).lighten(pr * 0.25));
                let tc = if top { Color::BLACK } else { Color::WHITE };
                if wide { cx.text_in(Rect::new(r.x + 14.0, r.y, r.w - 14.0, r.h), k, 22.0, Weight::Medium, tc, Align::Left); } else { cx.text_in(r, k, 22.0, Weight::Medium, tc, Align::Center); }
                if h.clicked { self.press(k); }
            }
        }
        if cx.io.focused { for k in cx.io.keys.clone() { match k.key { Key::Char => { let s = String::from(k.ch); match k.ch { '0'..='9' | '.' | '%' => self.press(&s), '+' => self.press("+"), '-' => self.press("−"), '*' => self.press("×"), '/' => self.press("÷"), '=' => self.press("="), _ => {} } } Key::Enter => self.press("="), Key::Escape => self.press("AC"), Key::Backspace => self.press("AC"), _ => {} } } }
    }
}
