//! Control Center, Spotlight, toast notifications.
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::icons::*;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;
use crate::apps::settings::PANES;
use crate::shell::menubar::BAR_H;

fn sat(x: f32) -> f32 { x.clamp(0.0, 1.0) }

// ───────────────────────── Control Center ─────────────────────────
pub struct ControlCenter { pub open: bool, t: Spring }
impl ControlCenter {
    pub fn new() -> ControlCenter { ControlCenter { open: false, t: Spring::new(0.0, 0.3, 0.82) } }
    pub fn rect(screen: Rect) -> Rect { Rect::new(screen.right() - 16.0 - 344.0, BAR_H + 8.0, 344.0, 392.0) }
    pub fn t_x(&self) -> f32 { self.t.x }
    pub fn busy(&self) -> bool { self.open || !self.t.settled() || self.t.x.abs() > 0.01 }
    pub fn visible(&self) -> bool { self.open || self.t.x.abs() > 0.01 }
    pub fn contains(&self, screen: Rect, p: Pt) -> bool { self.visible() && Self::rect(screen).contains(p.x, p.y) }

    pub fn update_draw(&mut self, cx: &mut Ctx, screen: Rect) {
        self.t.set(if self.open { 1.0 } else { 0.0 }); self.t.update(cx.io.dt);
        if !self.visible() { return; }
        let th = *cx.th;
        let t = sat(self.t.x);
        let r = Self::rect(screen);
        let s = 0.90 + 0.10 * self.t.x.min(1.04);
        let rr = Rect::new(r.right() - r.w * s, r.y, r.w * s, r.h * s);
        cx.cv.shadow_rrect(rr.offset(0.0, 10.0), 28.0, 26.0, th.shadow(0.30 * t), false);
        let mut st = th.glass(GlassKind::Popover, 28.0);
        st.tint.a = (st.tint.a as f32 * (0.6 + 0.4 * t)) as u8;
        cx.glass_style(rr, &st);
        if self.open && cx.io.pressed && !r.contains(cx.io.mouse.x, cx.io.mouse.y) && cx.io.mouse.y > BAR_H { self.open = false; }
        if t < 0.55 { return; }
        let a = sat((t - 0.55) / 0.45);
        let tile = th.pick(Color::rgba(255, 255, 255, 120), Color::rgba(255, 255, 255, 26)).fade(a);
        let lc = th.label().fade(a); let l2 = th.label2().fade(a);
        let x0 = r.x + 12.0; let w = r.w - 24.0;
        let c1 = Rect::new(x0, r.y + 12.0, w * 0.5 - 4.0, 138.0);
        cx.cv.fill_rrect(c1, 20.0, tile);
        let rows = [("Wi-Fi", Icon::Wifi, 0usize), ("Bluetooth", Icon::Bluetooth, 1), ("AirDrop", Icon::Airdrop, 2)];
        for (i, (n, ic, k)) in rows.iter().enumerate() {
            let rr = Rect::new(c1.x + 10.0, c1.y + 8.0 + i as f32 * 42.0, c1.w - 20.0, 38.0);
            let on = match k { 0 => cx.sys.wifi, 1 => cx.sys.bluetooth, _ => cx.sys.airdrop };
            let h = cx.hit(id_of(n) ^ 0xCC, rr);
            if h.clicked { match k { 0 => cx.sys.wifi = !on, 1 => cx.sys.bluetooth = !on, _ => cx.sys.airdrop = !on } }
            let t_on = cx.anim(id2(id_of(n), 0xCD), if on { 1.0 } else { 0.0 });
            let circ = Color::rgba(120, 120, 128, 70).mix(th.accent(), t_on).fade(a);
            cx.cv.fill_circle(rr.x + 18.0, rr.cy(), 17.0, circ);
            draw_icon(cx.cv, *ic, Rect::new(rr.x + 8.0, rr.cy() - 10.0, 20.0, 20.0), Color::WHITE.mix(th.label(), 1.0 - t_on).fade(a));
            cx.text(rr.x + 44.0, rr.cy() - 1.0, n, 12.5, Weight::Semibold, lc);
            cx.text(rr.x + 44.0, rr.cy() + 12.5, if on { if *k == 0 { "Lezdo-Corp" } else { "On" } } else { "Off" }, 11.0, Weight::Regular, l2);
        }
        let c2 = Rect::new(c1.right() + 8.0, c1.y, w * 0.5 - 4.0, 64.0);
        cx.cv.fill_rrect(c2, 20.0, tile);
        let hf = cx.hit(id_of("ccfocus"), c2);
        if hf.clicked { cx.sys.focus = !cx.sys.focus; }
        let tf = cx.anim(id_of("ccfocus_t"), if cx.sys.focus { 1.0 } else { 0.0 });
        cx.cv.fill_circle(c2.x + 28.0, c2.cy(), 17.0, Color::rgba(120, 120, 128, 70).mix(Color::hex(0x5E5CE6), tf).fade(a));
        draw_icon(cx.cv, Icon::Moon, Rect::new(c2.x + 18.0, c2.cy() - 10.0, 20.0, 20.0), Color::WHITE.mix(th.label(), 1.0 - tf).fade(a));
        cx.text(c2.x + 54.0, c2.cy() + 4.5, "Focus", 12.5, Weight::Semibold, lc);
        let sq = (c2.w - 8.0) * 0.5;
        let c3 = Rect::new(c2.x, c2.bottom() + 10.0, sq, 64.0);
        let c4 = Rect::new(c3.right() + 8.0, c3.y, sq, 64.0);
        let dark_on = th.is_dark();
        for (i, (rc, ic, name)) in [(c3, Icon::Display, "Dark"), (c4, Icon::Eye, "Clear")].iter().enumerate() {
            cx.cv.fill_rrect(*rc, 20.0, tile);
            let h = cx.hit(id_of(name) ^ 0xCE, *rc);
            let on = if i == 0 { dark_on } else { cx.sys.clarity > 0.7 };
            if h.clicked { if i == 0 { cx.sys.appearance = if dark_on { Appearance::Light } else { Appearance::Dark }; } else { cx.sys.clarity = if cx.sys.clarity > 0.7 { 0.15 } else { 0.95 }; } }
            let tn = cx.anim(id2(id_of(name), 0xCF), if on { 1.0 } else { 0.0 });
            cx.cv.fill_circle(rc.cx(), rc.y + 24.0, 15.0, Color::rgba(120, 120, 128, 70).mix(th.accent(), tn).fade(a));
            draw_icon(cx.cv, *ic, Rect::new(rc.cx() - 9.0, rc.y + 15.0, 18.0, 18.0), Color::WHITE.mix(th.label(), 1.0 - tn).fade(a));
            cx.text_in(Rect::new(rc.x, rc.y + 40.0, rc.w, 18.0), name, 11.0, Weight::Medium, l2, Align::Center);
        }
        let mut y = r.y + 12.0 + 138.0 + 12.0;
        for (n, k) in [("Display", 0usize), ("Sound", 1), ("Liquid Glass", 2)] {
            let rr = Rect::new(x0, y, w, 62.0);
            cx.cv.fill_rrect(rr, 20.0, tile);
            cx.text(rr.x + 14.0, rr.y + 20.0, n, 12.0, Weight::Semibold, lc);
            let sr = Rect::new(rr.x + 8.0, rr.y + 26.0, rr.w - 16.0, 30.0);
            match k {
                0 => { let mut v = cx.sys.brightness; cx.slider("cc_bright", sr, &mut v); cx.sys.brightness = v; }
                1 => { let mut v = cx.sys.volume; cx.slider("cc_vol", sr, &mut v); cx.sys.volume = v; }
                _ => { let mut v = 1.0 - cx.sys.clarity; if cx.slider("cc_glass", sr, &mut v) { cx.sys.clarity = 1.0 - v; } cx.text_in(Rect::new(rr.x + 14.0, rr.y + 6.0, rr.w - 28.0, 18.0), "Clear  ↔  Tinted", 10.5, Weight::Regular, l2, Align::Right); }
            }
            y += 70.0;
        }
    }
}

// ───────────────────────── Spotlight ─────────────────────────
#[derive(Clone)]
pub struct Hit { pub name: String, pub sub: String, pub kind: HitKind }
#[derive(Clone)]
pub enum HitKind { App(AppKind), Pane(usize), Path(String), Command(Cmd) }

pub struct Spotlight { pub open: bool, t: Spring, text: String, blink: f32, sel: usize, index: Vec<Hit> }

impl Spotlight {
    pub fn new() -> Spotlight {
        let mut index = Vec::new();
        for k in [AppKind::Files, AppKind::Browser, AppKind::Messages, AppKind::Photos, AppKind::Music, AppKind::Notes, AppKind::Terminal, AppKind::Settings, AppKind::About] {
            index.push(Hit { name: String::from(k.name()), sub: String::from("Application"), kind: HitKind::App(k) });
        }
        for (i, (n, _, _)) in PANES.iter().enumerate() { index.push(Hit { name: String::from(*n), sub: String::from("System Settings"), kind: HitKind::Pane(i) }); }
        for (n, p) in [("Documents", "Documents"), ("Downloads", "Downloads"), ("Pictures", "Pictures"), ("Reports", "Documents/Reports"), ("Source", "Documents/Source"), ("Desktop", "Desktop"), ("phantom-kernel.iso", "Downloads"), ("VAPT-mediaxis.pdf", "Documents/Reports"), ("golden-gate.png", "Pictures")] {
            index.push(Hit { name: String::from(n), sub: alloc::format!("Files · {}", p), kind: HitKind::Path(String::from(p)) });
        }
        index.push(Hit { name: String::from("Shut Down"), sub: String::from("Command"), kind: HitKind::Command(Cmd::Shutdown) });
        Spotlight { open: false, t: Spring::new(0.0, 0.28, 0.82), text: String::new(), blink: 0.0, sel: 0, index }
    }
    pub fn toggle(&mut self) { self.open = !self.open; if self.open { self.text.clear(); self.sel = 0; self.t.snap(0.0); } }
    pub fn visible(&self) -> bool { self.open || self.t.x.abs() > 0.01 }

    fn results(&self) -> Vec<Hit> {
        let q = self.text.to_lowercase();
        let mut v: Vec<(u8, Hit)> = Vec::new();
        for h in self.index.iter() {
            let n = h.name.to_lowercase();
            if q.is_empty() { if matches!(h.kind, HitKind::App(_)) { v.push((1, h.clone())); } continue; }
            if n.starts_with(&q) { v.push((0, h.clone())); } else if n.contains(&q) { v.push((2, h.clone())); }
        }
        v.sort_by_key(|(r, _)| *r);
        v.into_iter().map(|(_, h)| h).take(7).collect()
    }

    pub fn update_draw(&mut self, cx: &mut Ctx, screen: Rect) {
        self.t.set(if self.open { 1.0 } else { 0.0 }); self.t.update(cx.io.dt);
        if !self.visible() { return; }
        let th = *cx.th;
        let t = sat(self.t.x);
        cx.cv.fill_rect(screen, Color::rgba(0, 0, 0, (t * 46.0) as u8));
        let mut entered = false;
        if self.open {
            let before = self.text.len();
            for k in cx.io.keys.clone() {
                match k.key {
                    Key::Down => self.sel += 1,
                    Key::Up => self.sel = self.sel.saturating_sub(1),
                    Key::Escape => self.open = false,
                    Key::Enter => entered = true,
                    Key::Char if !k.ctrl => { self.text.push(k.ch); self.blink = 0.0; }
                    Key::Space => self.text.push(' '),
                    Key::Backspace => { self.text.pop(); }
                    _ => {}
                }
            }
            if self.text.len() != before { self.sel = 0; }
        }
        self.blink += cx.io.dt;
        let results = self.results();
        self.sel = self.sel.min(results.len().saturating_sub(1));
        let w = 660.0; let s = 0.94 + 0.06 * self.t.x.min(1.05);
        let bar = Rect::new(screen.cx() - w * 0.5 * s, screen.h * 0.2 - (1.0 - t) * 14.0, w * s, 62.0 * s);
        cx.cv.shadow_rrect(bar.offset(0.0, 10.0), 31.0, 28.0, th.shadow(0.24 * t), true);
        cx.glass_style(bar, &th.glass(GlassKind::Clear, 31.0 * s));
        draw_icon(cx.cv, Icon::Search, Rect::new(bar.x + 20.0, bar.cy() - 12.0, 24.0, 24.0), th.label2().fade(t));
        let fr = Rect::new(bar.x + 56.0, bar.y + 8.0, bar.w - 76.0, bar.h - 16.0);
        if self.text.is_empty() { cx.text_in(fr, "Spotlight Search", 22.0, Weight::Regular, th.label3().fade(t), Align::Left); }
        else { cx.text_in(fr, &self.text, 22.0, Weight::Regular, th.label().fade(t), Align::Left); }
        if self.open && (self.blink % 1.0) < 0.6 { let tw = cx.measure(&self.text, 22.0, Weight::Regular); cx.cv.fill_rect(Rect::new(fr.x + tw + 1.0, bar.cy() - 12.0, 2.0, 24.0), th.accent()); }
        let rh = 46.0;
        let mut panel_h = 0.0;
        if !results.is_empty() {
            let panel = Rect::new(bar.x, bar.bottom() + 10.0, bar.w, results.len() as f32 * rh + 16.0);
            panel_h = panel.h + 10.0;
            cx.cv.shadow_rrect(panel.offset(0.0, 10.0), 24.0, 26.0, th.shadow(0.22 * t), true);
            cx.glass_style(panel, &th.glass(GlassKind::Clear, 24.0));
            let mut fire: Option<Hit> = None;
            for (i, h) in results.iter().enumerate() {
                let rr = Rect::new(panel.x + 8.0, panel.y + 8.0 + i as f32 * rh, panel.w - 16.0, rh - 2.0);
                let hov = cx.hover(rr);
                if hov && cx.io.pressed { self.sel = i; }
                let st_ = cx.anim(id2(id_of("sp"), i as u32), if self.sel == i { 1.0 } else { 0.0 });
                if st_ > 0.01 { cx.cv.fill_rrect(rr, 14.0, th.accent().fade(st_ * t)); }
                let ir = Rect::new(rr.x + 8.0, rr.y + 5.0, 34.0, 34.0);
                match &h.kind {
                    HitKind::App(k) => cx.app_icon(*k, ir),
                    HitKind::Pane(p) => { let (_, ic, col) = PANES[*p]; cx.cv.fill_rrect(ir.inset(3.0), 8.0, Color::hex(col)); draw_icon(cx.cv, ic, ir.inset(8.0), Color::WHITE); }
                    HitKind::Path(_) => cx.file_icon(FileKind::Folder, ir),
                    HitKind::Command(_) => { cx.cv.fill_rrect(ir.inset(3.0), 8.0, Color::hex(0xFF453A)); draw_icon(cx.cv, Icon::Power, ir.inset(8.0), Color::WHITE); }
                }
                let sel = self.sel == i;
                let (c1, c2) = if sel { (Color::WHITE, Color::rgba(255, 255, 255, 190)) } else { (th.label(), th.label2()) };
                cx.text(rr.x + 54.0, rr.cy() - 2.0, &h.name, 14.5, Weight::Medium, c1);
                cx.text(rr.x + 54.0, rr.cy() + 13.0, &h.sub, 11.5, Weight::Regular, c2);
                if cx.io.released && hov && self.open { fire = Some(h.clone()); }
            }
            if entered { fire = results.get(self.sel).cloned(); }
            if let Some(h) = fire { self.fire(h, cx); }
        }
        if cx.io.pressed && self.open {
            let all = Rect::new(bar.x, bar.y, bar.w, bar.h + panel_h);
            if !all.contains(cx.io.mouse.x, cx.io.mouse.y) { self.open = false; }
        }
    }

    fn fire(&mut self, h: Hit, cx: &mut Ctx) {
        match h.kind {
            HitKind::App(k) => cx.cmds.push(Cmd::Open(k)),
            HitKind::Pane(p) => cx.cmds.push(Cmd::OpenSettingsPane(p)),
            HitKind::Path(p) => cx.cmds.push(Cmd::OpenPath(p)),
            HitKind::Command(c) => cx.cmds.push(c),
        }
        self.open = false;
    }
}

// ───────────────────────── Toasts ─────────────────────────
pub struct Toasts { items: Vec<(String, f32, Spring)> }
impl Toasts {
    pub fn new() -> Toasts { Toasts { items: Vec::new() } }
    pub fn busy(&self) -> bool { !self.items.is_empty() }
    pub fn push(&mut self, s: String) { let mut sp = Spring::new(0.0, 0.4, 0.78); sp.set(1.0); if self.items.len() > 3 { self.items.remove(0); } self.items.push((s, 3.6, sp)); }
    pub fn update_draw(&mut self, cx: &mut Ctx, screen: Rect) {
        let th = *cx.th;
        let dt = cx.io.dt;
        for it in self.items.iter_mut() { it.1 -= dt; it.2.set(if it.1 > 0.0 { 1.0 } else { 0.0 }); it.2.update(dt); }
        self.items.retain(|it| it.1 > 0.0 || it.2.x > 0.02);
        let mut y = BAR_H + 10.0;
        for (s, _, sp) in self.items.iter() {
            let t = sp.x;
            let w = (cx.measure(s, 13.0, Weight::Medium) + 84.0).max(280.0);
            let r = Rect::new(screen.right() - 16.0 - w + (1.0 - t.min(1.0)) * 60.0, y, w, 58.0);
            cx.cv.shadow_rrect(r.offset(0.0, 6.0), 22.0, 16.0, th.shadow(0.24 * sat(t)), false);
            cx.glass_style(r, &th.glass(GlassKind::Popover, 22.0));
            cx.app_icon(AppKind::About, Rect::new(r.x + 12.0, r.y + 11.0, 36.0, 36.0));
            cx.text(r.x + 60.0, r.y + 25.0, "KashOS", 12.0, Weight::Semibold, th.label().fade(sat(t)));
            cx.text(r.x + 60.0, r.y + 42.0, s, 13.0, Weight::Regular, th.label2().fade(sat(t)));
            y += 66.0;
        }
    }
}

// ───────────────────────── Launchpad ─────────────────────────
pub struct Launchpad { pub open: bool, t: Spring, text: String, blink: f32 }
impl Launchpad {
    pub fn new() -> Launchpad { Launchpad { open: false, t: Spring::new(0.0, 0.34, 0.86), text: String::new(), blink: 0.0 } }
    pub fn toggle(&mut self) { self.open = !self.open; if self.open { self.text.clear(); self.t.snap(0.0); } }
    pub fn visible(&self) -> bool { self.open || self.t.x.abs() > 0.01 }

    pub fn update_draw(&mut self, cx: &mut Ctx, screen: Rect) {
        self.t.set(if self.open { 1.0 } else { 0.0 }); self.t.update(cx.io.dt);
        if !self.visible() { return; }
        let th = *cx.th;
        let t = sat(self.t.x);
        // backdrop: blurred desktop + scrim
        let mut st = th.glass(GlassKind::Sidebar, 0.0);
        st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0; st.tint.a = (st.tint.a as f32 * 0.85 * t) as u8;
        cx.glass_style(screen, &st);
        cx.cv.fill_rect(screen, Color::rgba(0, 0, 0, (t * if th.is_dark() { 120.0 } else { 70.0 }) as u8));
        if self.open {
            let before = self.text.len();
            for k in cx.io.keys.clone() {
                match k.key {
                    Key::Escape => self.open = false,
                    Key::Char if !k.ctrl => { self.text.push(k.ch); self.blink = 0.0; }
                    Key::Space => { if !self.text.is_empty() { self.text.push(' '); } }
                    Key::Backspace => { self.text.pop(); }
                    _ => {}
                }
            }
            let _ = before;
        }
        self.blink += cx.io.dt;
        let q = self.text.to_lowercase();
        let mut apps: Vec<(AppKind, String)> = Vec::new();
        for a in cx.sys.reg.apps.iter() { if let Some(k) = a.kind { if q.is_empty() || a.name.to_lowercase().contains(&q) { apps.push((k, a.name.clone())); } } }
        // search pill
        let sw = 300.0;
        let sr = Rect::new(screen.cx() - sw * 0.5, 58.0 - (1.0 - t) * 10.0, sw, 38.0);
        cx.glass_style(sr, &th.glass(GlassKind::Clear, 19.0));
        draw_icon(cx.cv, Icon::Search, Rect::new(sr.x + 14.0, sr.cy() - 8.0, 16.0, 16.0), Color::rgba(255, 255, 255, (200.0 * t) as u8));
        let fr = Rect::new(sr.x + 40.0, sr.y, sr.w - 52.0, sr.h);
        if self.text.is_empty() { cx.text_in(fr, "Search", 15.0, Weight::Regular, Color::rgba(255, 255, 255, (150.0 * t) as u8), Align::Left); }
        else { cx.text_in(fr, &self.text, 15.0, Weight::Regular, Color::rgba(255, 255, 255, (240.0 * t) as u8), Align::Left); }
        if self.open && (self.blink % 1.0) < 0.6 { let tw = cx.measure(&self.text, 15.0, Weight::Regular); cx.cv.fill_rect(Rect::new(fr.x + tw + 1.0, sr.cy() - 9.0, 1.5, 18.0), Color::WHITE); }
        // grid
        let cell_w = 150.0; let cell_h = 142.0;
        let cols = (((screen.w - 160.0) / cell_w) as usize).clamp(1, 7).min(apps.len().max(1));
        let rows = (apps.len() + cols - 1) / cols.max(1);
        let gw = cols as f32 * cell_w; let gh = rows as f32 * cell_h;
        let gx = screen.cx() - gw * 0.5; let gy = (screen.h * 0.5 - gh * 0.5 + 20.0).max(130.0);
        let mut launch: Option<AppKind> = None;
        let mut over_cell = false;
        for (i, (k, name)) in apps.iter().enumerate() {
            let (c, r) = (i % cols, i / cols);
            let cell = Rect::new(gx + c as f32 * cell_w, gy + r as f32 * cell_h, cell_w, cell_h);
            let ti = sat(self.t.x * 1.7 - i as f32 * 0.035);
            let ez = 1.0 - (1.0 - ti) * (1.0 - ti);
            let hv = self.open && t > 0.6 && cx.hover(cell.inset(6.0));
            if hv { over_cell = true; *cx.over_widget = true; }
            let hz = cx.anim(id2(id_of(name), 0x1A9), if hv { 1.0 } else { 0.0 });
            let sz = 88.0 * (0.78 + 0.22 * ez) * (1.0 + 0.07 * hz);
            let ir = Rect::new(cell.cx() - sz * 0.5, cell.y + 14.0 + (88.0 - sz) * 0.5, sz, sz);
            cx.cv.shadow_rrect(ir.offset(0.0, 6.0), sz * 0.225, 14.0, Color::rgba(0, 0, 0, (90.0 * ez) as u8), false);
            cx.app_icon(*k, ir);
            let w = cx.measure(name, 13.0, Weight::Medium);
            cx.text(cell.cx() - w * 0.5, cell.y + 124.0, name, 13.0, Weight::Medium, Color::rgba(255, 255, 255, (235.0 * ez) as u8));
            if cx.io.released && hv { launch = Some(*k); }
        }
        if apps.is_empty() { cx.text_in(Rect::new(0.0, screen.h * 0.45, screen.w, 24.0), "No Results", 18.0, Weight::Medium, Color::rgba(255, 255, 255, (180.0 * t) as u8), Align::Center); }
        let _ = over_cell;
        if cx.io.pressed && self.open && !over_cell && !sr.contains(cx.io.mouse.x, cx.io.mouse.y) { self.open = false; }
        if self.open { for k in cx.io.keys.iter() { if k.key == Key::Enter { if let Some((kk, _)) = apps.first() { launch = Some(*kk); } } } }
        // page dots
        let dy = screen.bottom() - 120.0;
        cx.cv.fill_circle(screen.cx(), dy, 3.5, Color::rgba(255, 255, 255, (210.0 * t) as u8));
        if let Some(k) = launch { cx.cmds.push(Cmd::Open(k)); self.open = false; }
    }
}

// ───────────────────────── Permission prompt ─────────────────────────
pub struct PermPrompt { t: Spring, cur: Option<(usize, crate::registry::Perm)> }
impl PermPrompt {
    pub fn new() -> PermPrompt { PermPrompt { t: Spring::new(0.0, 0.34, 0.8), cur: None } }
    pub fn busy(&self) -> bool { !self.t.settled() }
    pub fn visible(&self) -> bool { self.cur.is_some() || self.t.x.abs() > 0.01 }
    pub fn update_draw(&mut self, cx: &mut Ctx, screen: Rect) {
        let front = cx.sys.reg.pending.first().copied();
        if let Some(f) = front { self.cur = Some(f); }
        self.t.set(if front.is_some() { 1.0 } else { 0.0 }); self.t.update(cx.io.dt);
        if self.t.x < 0.01 && front.is_none() { self.cur = None; return; }
        let (ai, perm) = match self.cur { Some(c) => c, None => return };
        if ai >= cx.sys.reg.apps.len() { cx.sys.reg.pending.clear(); self.cur = None; return; }
        let th = *cx.th;
        let t = sat(self.t.x);
        cx.cv.fill_rect(screen, Color::rgba(0, 0, 0, (t * 64.0) as u8));
        let (name, kind, class) = { let a = &cx.sys.reg.apps[ai]; (a.name.clone(), a.kind, a.class) };
        let s = 0.92 + 0.08 * self.t.x.min(1.04);
        let w = 400.0 * s; let h = 232.0 * s;
        let r = Rect::new(screen.cx() - w * 0.5, screen.cy() - h * 0.5 - 40.0 + (1.0 - t) * 12.0, w, h);
        cx.cv.shadow_rrect(r.offset(0.0, 14.0), 26.0, 34.0, th.shadow(0.34 * t), true);
        let mut st = th.glass(GlassKind::Popover, 26.0);
        st.tint.a = (st.tint.a as f32 * (0.6 + 0.4 * t)) as u8;
        cx.glass_style(r, &st);
        let ir = Rect::new(r.cx() - 28.0, r.y + 22.0, 56.0, 56.0);
        match kind { Some(k) => cx.app_icon(k, ir), None => cx.file_icon(class.file_kind(), ir) }
        // small badge for the permission
        let br = Rect::new(ir.right() - 14.0, ir.bottom() - 14.0, 26.0, 26.0);
        cx.cv.fill_circle(br.cx(), br.cy(), 13.0, Color::hex(perm.color()));
        cx.cv.ring(br.cx(), br.cy(), 13.0, 1.5, Color::rgba(255, 255, 255, 230));
        draw_icon(cx.cv, perm.icon(), br.inset(5.5), Color::WHITE);
        let title = alloc::format!("“{}” would like to {}", name, perm.prompt());
        let lines = cx.fonts.wrap(&title, 15.0, Weight::Semibold, r.w - 56.0);
        let mut y = r.y + 108.0;
        for l in lines.iter().take(2) { cx.text_in(Rect::new(r.x, y - 14.0, r.w, 20.0), l, 15.0, Weight::Semibold, th.label().fade(t), Align::Center); y += 19.0; }
        let d = alloc::format!("{}. You can change this later in Settings → Privacy & Security.", perm.desc());
        let dl = cx.fonts.wrap(&d, 12.0, Weight::Regular, r.w - 56.0);
        y += 2.0;
        for l in dl.iter().take(3) { cx.text_in(Rect::new(r.x, y - 11.0, r.w, 16.0), l, 12.0, Weight::Regular, th.label2().fade(t), Align::Center); y += 15.0; }
        let bw = (r.w - 24.0 * 2.0 - 12.0) * 0.5;
        let b1 = Rect::new(r.x + 24.0, r.bottom() - 52.0, bw, 34.0);
        let b2 = Rect::new(b1.right() + 12.0, b1.y, bw, 34.0);
        let mut decision: Option<crate::registry::PS> = None;
        if cx.button("pp_deny", b1, "Don’t Allow", false) && t > 0.6 { decision = Some(crate::registry::PS::Deny); }
        if cx.button("pp_allow", b2, "Allow", true) && t > 0.6 { decision = Some(crate::registry::PS::Allow); }
        if front.is_some() {
            for k in cx.io.keys.iter() { match k.key { Key::Escape => decision = Some(crate::registry::PS::Deny), Key::Enter => decision = Some(crate::registry::PS::Allow), _ => {} } }
        }
        if let Some(s) = decision {
            let now = cx.sys.unix_secs;
            cx.sys.reg.set(ai, perm, s, now);
            if !cx.sys.reg.pending.is_empty() { cx.sys.reg.pending.remove(0); }
            cx.cmds.push(Cmd::Toast(alloc::format!("{} {} for “{}”", if s == crate::registry::PS::Allow { "Allowed" } else { "Denied" }, perm.name(), name)));
        }
    }
}
