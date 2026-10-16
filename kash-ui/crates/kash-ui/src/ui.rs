//! Immediate-mode UI context: input, drawing helpers, widgets, system settings.
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::glass::*;
use crate::icons::*;
use crate::mathf::*;
use crate::text::*;
use crate::theme::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key { Char, Enter, Backspace, Delete, Left, Right, Up, Down, Home, End, Tab, Escape, Space, PageUp, PageDown }

#[derive(Clone, Copy, Debug)]
pub struct KeyEv { pub key: Key, pub ch: char, pub ctrl: bool, pub shift: bool, pub alt: bool }

#[derive(Clone, Debug, Default)]
pub struct Io {
    pub mouse: Pt,
    pub down: bool,
    pub pressed: bool,
    pub released: bool,
    pub right_pressed: bool,
    pub click_count: u32,
    pub wheel: Pt,
    pub keys: Vec<KeyEv>,
    pub dt: f32,
    pub time: f32,
    /// Is the pointer allowed to hover/click things in this context (not blocked by something above)?
    pub hot: bool,
    pub focused: bool,
}

impl Io {
    pub fn local(&self, origin: Pt) -> Io {
        let mut o = self.clone();
        o.mouse = Pt::new(self.mouse.x - origin.x, self.mouse.y - origin.y);
        o
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppKind { Files, Settings, Terminal, About, Notes, Browser, Photos, Music, Messages, ActivityMonitor, Calculator }

impl AppKind {
    pub fn name(&self) -> &'static str {
        match self { AppKind::Files => "Files", AppKind::Settings => "System Settings", AppKind::Terminal => "Terminal", AppKind::About => "About KashOS",
            AppKind::Notes => "Notes", AppKind::Browser => "Browser", AppKind::Photos => "Photos", AppKind::Music => "Music", AppKind::Messages => "Messages", AppKind::ActivityMonitor => "Activity Monitor", AppKind::Calculator => "Calculator" }
    }
}

#[derive(Clone, Debug)]
pub enum Cmd {
    Open(AppKind),
    OpenSettingsPane(usize),
    OpenPermissions(String),
    Quit(AppKind),
    Launchpad,
    OpenPath(String),
    Toast(String),
    CloseWindow,
    Minimize,
    Zoom,
    Spotlight,
    Lock,
    Shutdown,
    Restart,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Appearance { Light, Dark, Auto }

/// All user-facing system settings (what the Settings app edits and the shell reads).
#[derive(Clone, Debug)]
pub struct SysState {
    /// Set by widgets that draw a blinking caret this frame (lets the compositor schedule 10 Hz redraws).
    pub blink_req: bool,
    pub appearance: Appearance,
    pub accent: usize,
    pub clarity: f32,
    pub reduce_transparency: bool,
    pub dock_size: f32,
    pub dock_magnify: f32,
    pub dock_magnify_on: bool,
    pub dock_autohide: bool,
    pub wallpaper: usize,
    pub wifi: bool,
    pub bluetooth: bool,
    pub airdrop: bool,
    pub focus: bool,
    pub brightness: f32,
    pub volume: f32,
    pub cursor_size: f32,
    pub tracking: f32,
    pub notifications: bool,
    pub night_shift: bool,
    // Phantom kernel services (mirrors kernel/src/phantom.rs Tier3Status)
    pub anon_gateway: bool,
    pub packet_filter: bool,
    pub kill_switch: bool,
    pub telemetry: bool,
    pub key_manager: bool,
    pub duress: bool,
    pub unix_secs: i64,
    pub screen: Rect,
    pub settings_pane_request: Option<usize>,
    pub reg: crate::registry::Registry,
    pub privacy_request: Option<String>,
    pub dock_recents: bool,
    pub dock_downloads: bool,
    pub dock_indicators: bool,
    pub dock_bounce: bool,
    pub stack_view: usize,
    // ── lock screen / credentials (Kash UI) ──
    pub passphrase: String,
    pub duress_pass: String,
    pub duress_active: bool,
    /// 0 never, 1 = 1 min, 2 = 5 min, 3 = 10 min of inactivity.
    pub lock_idle: usize,
    pub lock_buttons: bool,
    pub lock_clock: bool,
    pub lock_user: bool,
    pub lock_gateway: bool,
    pub lock_hint: String,
    pub bios_on_boot: bool,
    // ── notifications ──
    pub notif_preview: usize,
    pub notif_locked: bool,
    pub notif_sleeping: bool,
    pub notif_mirror: bool,
    pub notif_group: usize,
    pub notif_apps: Vec<AppNotif>,
}

/// Per-app notification preferences (Settings → Notifications).
#[derive(Clone, Copy, Debug)]
pub struct AppNotif { pub allow: bool, pub style: usize, pub badges: bool, pub sounds: bool, pub lock_screen: bool, pub center: bool }
impl AppNotif { pub fn new() -> AppNotif { AppNotif { allow: true, style: 1, badges: true, sounds: true, lock_screen: true, center: true } } }

impl SysState {
    pub fn new() -> SysState {
        SysState {
            blink_req: false,
            appearance: Appearance::Light, accent: 0, clarity: 0.55, reduce_transparency: false,
            dock_size: 0.45, dock_magnify: 0.6, dock_magnify_on: true, dock_autohide: false, wallpaper: 0,
            wifi: true, bluetooth: true, airdrop: false, focus: false, brightness: 1.0, volume: 0.55, cursor_size: 0.0, tracking: 0.5,
            notifications: true, night_shift: false,
            anon_gateway: true, packet_filter: true, kill_switch: true, telemetry: false, key_manager: true, duress: false,
            unix_secs: 1_791_786_840, screen: Rect::new(0.0, 0.0, 1440.0, 900.0), settings_pane_request: None,
            passphrase: String::from("kash"), duress_pass: String::new(), duress_active: false, lock_idle: 0, lock_buttons: true, lock_clock: true, lock_user: true, lock_gateway: true, lock_hint: String::new(), bios_on_boot: true,
            notif_preview: 1, notif_locked: true, notif_sleeping: false, notif_mirror: false, notif_group: 0, notif_apps: alloc::vec![AppNotif::new(); 32],
            reg: crate::registry::Registry::new(), privacy_request: None, dock_recents: true, dock_downloads: true, dock_indicators: true, dock_bounce: true, stack_view: 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CursorShape { Arrow, IBeam, Hand, ResizeNS, ResizeEW, ResizeNWSE, ResizeNESW, Move }

pub struct Ctx<'a> {
    pub cv: &'a mut Canvas,
    pub fonts: &'a mut Fonts,
    pub scratch: &'a mut GlassScratch,
    pub th: &'a Theme,
    pub io: &'a Io,
    pub anims: &'a mut Anims,
    pub sys: &'a mut SysState,
    pub cmds: &'a mut Vec<Cmd>,
    pub bounds: Rect,
    pub cursor: &'a mut CursorShape,
    /// Set when the pointer is over any interactive widget (stops titlebar-drag).
    pub over_widget: &'a mut bool,
}

pub struct WidgetResp { pub hovered: bool, pub pressed: bool, pub clicked: bool, pub down: bool }
impl WidgetResp { pub fn none() -> WidgetResp { WidgetResp { hovered: false, pressed: false, clicked: false, down: false } } }

impl<'a> Ctx<'a> {
    pub fn text(&mut self, x: f32, baseline: f32, s: &str, size: f32, wt: Weight, c: Color) -> f32 { self.fonts.draw(self.cv, x, baseline, s, size, wt, c) }
    pub fn text_in(&mut self, r: Rect, s: &str, size: f32, wt: Weight, c: Color, a: Align) { self.fonts.draw_in(self.cv, r, s, size, wt, c, a) }
    pub fn measure(&mut self, s: &str, size: f32, wt: Weight) -> f32 { self.fonts.measure(s, size, wt) }
    pub fn glass(&mut self, rect: Rect, kind: GlassKind, radius: f32) {
        let st = self.th.glass(kind, radius);
        self.cv.glass(rect, &st, self.scratch);
    }
    pub fn glass_style(&mut self, rect: Rect, st: &GlassStyle) { self.cv.glass(rect, st, self.scratch); }
    pub fn icon(&mut self, ic: Icon, r: Rect, c: Color) { draw_icon(self.cv, ic, r, c); }
    /// Cached coloured app tile.
    pub fn app_icon(&mut self, k: AppKind, r: Rect) { let d = self.th.is_dark(); self.fonts.icons.draw(self.cv, app_key(k) + if d { 500 } else { 0 }, r, 1.0, &|cv, rr| app_icon_t(cv, k, rr, d)); }
    pub fn file_icon(&mut self, k: FileKind, r: Rect) { self.fonts.icons.draw(self.cv, file_key(k), r, 1.0, &|cv, rr| file_icon(cv, k, rr)); }
    pub fn trash_icon(&mut self, r: Rect) { let d = self.th.is_dark(); self.fonts.icons.draw(self.cv, if d { 800 } else { 300 }, r, 1.0, &|cv, rr| trash_icon_t(cv, rr, false, d)); }

    pub fn hover(&self, r: Rect) -> bool { self.io.hot && r.contains(self.io.mouse.x, self.io.mouse.y) }
    pub fn anim(&mut self, id: u32, target: f32) -> f32 { self.anims.follow(id, target, Preset::Snappy) }
    pub fn anim_p(&mut self, id: u32, target: f32, p: Preset) -> f32 { self.anims.follow(id, target, p) }

    /// Hit region with press tracking (a press must start *and* end inside to click).
    pub fn hit(&mut self, id: u32, r: Rect) -> WidgetResp {
        let hovered = self.hover(r);
        if hovered { *self.over_widget = true; }
        let cap = id2(id, 0x51);
        let was = self.anims.get(cap).unwrap_or(0.0) > 0.5;
        let mut pressed_now = was;
        if hovered && self.io.pressed { pressed_now = true; }
        let mut clicked = false;
        if self.io.released {
            if was && hovered { clicked = true; }
            pressed_now = false;
        } else if !self.io.down { pressed_now = false; }
        self.anims.follow(cap, if pressed_now { 1.0 } else { 0.0 }, Preset::Snappy);
        self.anims.snap(cap, if pressed_now { 1.0 } else { 0.0 });
        WidgetResp { hovered, pressed: pressed_now, clicked, down: pressed_now }
    }

    pub fn separator_h(&mut self, x0: f32, x1: f32, y: f32) { let c = self.th.separator(); self.cv.fill_rect(Rect::new(x0, y, x1 - x0, 1.0), c); }

    pub fn button(&mut self, id: &str, r: Rect, label: &str, prominent: bool) -> bool {
        let h = id_of(id);
        let resp = self.hit(h, r);
        let hv = self.anim(id2(h, 1), if resp.hovered { 1.0 } else { 0.0 });
        let pr = self.anim(id2(h, 2), if resp.pressed { 1.0 } else { 0.0 });
        let rad = (r.h * 0.5).min(14.0);
        if prominent {
            let c = self.th.accent().lighten(hv * 0.08).darken(pr * 0.12);
            self.cv.fill_rrect(r, rad, c);
            self.text_in(r, label, 13.0, Weight::Medium, Color::WHITE, Align::Center);
        } else {
            let c = self.th.control_fill().mix(self.th.control_fill_hi(), hv * 0.6 + pr * 0.6);
            self.cv.fill_rrect(r, rad, c);
            let lc = self.th.label();
            self.text_in(r, label, 13.0, Weight::Regular, lc, Align::Center);
        }
        resp.clicked
    }

    pub fn glass_icon_button(&mut self, id: &str, r: Rect, ic: Icon, enabled: bool) -> bool {
        let h = id_of(id);
        let resp = if enabled { self.hit(h, r) } else { WidgetResp::none() };
        let hv = self.anim(id2(h, 1), if resp.hovered { 1.0 } else { 0.0 });
        let pr = self.anim(id2(h, 2), if resp.pressed { 1.0 } else { 0.0 });
        let rr = r.inset(-pr * 1.5);
        let mut st = self.th.glass(GlassKind::Control, rr.h * 0.5);
        st.tint.a = (st.tint.a as f32 * (1.0 + hv * 0.25)).min(255.0) as u8;
        self.cv.glass(rr, &st, self.scratch);
        let c = if enabled { self.th.label() } else { self.th.label3() };
        draw_icon(self.cv, ic, Rect::new(rr.cx() - 9.0, rr.cy() - 9.0, 18.0, 18.0), c);
        resp.clicked
    }

    pub fn toggle(&mut self, id: &str, r: Rect, on: &mut bool) -> bool {
        let h = id_of(id);
        let resp = self.hit(h, r);
        if resp.clicked { *on = !*on; }
        let t = self.anim_p(id2(h, 3), if *on { 1.0 } else { 0.0 }, Preset::Bouncy);
        let pr = self.anim(id2(h, 2), if resp.pressed { 1.0 } else { 0.0 });
        let off = self.th.pick(Color::rgba(120, 120, 128, 66), Color::rgba(120, 120, 128, 110));
        let track = off.mix(self.th.accent(), saturate(t));
        self.cv.fill_rrect(r, r.h * 0.5, track);
        let kh = r.h - 4.0;
        let kw = kh * (1.0 + 0.28 * pr);
        let x0 = r.x + 2.0; let x1 = r.right() - 2.0 - kw;
        let kx = lerp(x0, x1, t.clamp(-0.1, 1.1));
        let kr = Rect::new(kx, r.y + 2.0, kw, kh);
        self.cv.shadow_rrect(kr.offset(0.0, 1.0), kh * 0.5, 3.0, Color::rgba(0, 0, 0, 40), false);
        self.cv.fill_rrect(kr, kh * 0.5, Color::WHITE);
        self.cv.stroke_rrect(kr, kh * 0.5, 0.8, Color::rgba(0, 0, 0, 22));
        resp.clicked
    }

    pub fn slider(&mut self, id: &str, r: Rect, v: &mut f32) -> bool {
        let h = id_of(id);
        let resp = self.hit(h, r.inset_xy(-6.0, -8.0));
        let mut changed = false;
        if resp.pressed {
            let nv = saturate((self.io.mouse.x - r.x - 10.0) / (r.w - 20.0));
            if (nv - *v).abs() > 0.0001 { *v = nv; changed = true; }
        }
        let pr = self.anim(id2(h, 2), if resp.pressed { 1.0 } else { 0.0 });
        let ty = r.cy();
        let tc = self.th.pick(Color::rgba(120, 120, 128, 60), Color::rgba(120, 120, 128, 110));
        self.cv.fill_rrect(Rect::new(r.x, ty - 2.0, r.w, 4.0), 2.0, tc);
        let kx = r.x + 10.0 + (r.w - 20.0) * *v;
        let acc = self.th.accent();
        self.cv.fill_rrect(Rect::new(r.x, ty - 2.0, kx - r.x, 4.0), 2.0, acc);
        let kw = 20.0 + pr * 3.0; let kh = 14.0 + pr * 2.0;
        let kr = Rect::new(kx - kw * 0.5, ty - kh * 0.5, kw, kh);
        self.cv.shadow_rrect(kr.offset(0.0, 1.0), kh * 0.5, 3.0, Color::rgba(0, 0, 0, 55), false);
        self.cv.fill_rrect(kr, kh * 0.5, Color::WHITE);
        self.cv.stroke_rrect(kr, kh * 0.5, 0.8, Color::rgba(0, 0, 0, 25));
        changed
    }

    pub fn segmented(&mut self, id: &str, r: Rect, labels: &[&str], sel: &mut usize) -> bool {
        let h = id_of(id);
        let n = labels.len().max(1);
        let sw = r.w / n as f32;
        let mut changed = false;
        let resp = self.hit(h, r);
        if resp.clicked {
            let i = (((self.io.mouse.x - r.x) / sw) as usize).min(n - 1);
            if i != *sel { *sel = i; changed = true; }
        }
        let t = self.anim_p(id2(h, 9), *sel as f32, Preset::Snappy);
        self.cv.fill_rrect(r, r.h * 0.5, self.th.control_fill());
        let th = Rect::new(r.x + 2.0 + t * sw, r.y + 2.0, sw - 4.0, r.h - 4.0);
        self.cv.shadow_rrect(th.offset(0.0, 1.0), th.h * 0.5, 3.0, Color::rgba(0, 0, 0, 30), false);
        self.cv.fill_rrect(th, th.h * 0.5, self.th.pick(Color::WHITE, Color::rgb(98, 98, 104)));
        for (i, l) in labels.iter().enumerate() {
            let cr = Rect::new(r.x + sw * i as f32, r.y, sw, r.h);
            let lc = self.th.label();
            self.text_in(cr, l, 12.5, if i == *sel { Weight::Medium } else { Weight::Regular }, lc, Align::Center);
        }
        changed
    }

    /// Single-line text field. Returns true when Enter pressed.
    pub fn text_field(&mut self, id: &str, r: Rect, st: &mut FieldState, placeholder: &str, icon: Option<Icon>) -> bool {
        let h = id_of(id);
        let resp = self.hit(h, r);
        if resp.hovered && self.io.pressed { st.focused = true; st.caret = st.text.chars().count(); }
        else if self.io.pressed && !resp.hovered { st.focused = false; }
        let foc = self.anim(id2(h, 5), if st.focused { 1.0 } else { 0.0 });
        self.cv.fill_rrect(r, r.h * 0.5, self.th.field_bg());
        if foc > 0.01 { self.cv.stroke_rrect(r, r.h * 0.5, 2.0, self.th.accent().fade(0.55 * foc)); }
        let mut tx = r.x + 10.0;
        if let Some(ic) = icon { draw_icon(self.cv, ic, Rect::new(tx, r.cy() - 7.0, 14.0, 14.0), self.th.label2()); tx += 20.0; }
        let mut entered = false;
        if st.focused && self.io.focused {
            for k in self.io.keys.iter() {
                match k.key {
                    Key::Char | Key::Space => { if !k.ctrl { let ch = if k.key == Key::Space { ' ' } else { k.ch }; let bi = char_byte(&st.text, st.caret); st.text.insert(bi, ch); st.caret += 1; st.blink = caret_reset(self.io.time); } }
                    Key::Backspace => { if st.caret > 0 { let bi = char_byte(&st.text, st.caret - 1); st.text.remove(bi); st.caret -= 1; } }
                    Key::Delete => { if st.caret < st.text.chars().count() { let bi = char_byte(&st.text, st.caret); st.text.remove(bi); } }
                    Key::Left => { if st.caret > 0 { st.caret -= 1; } st.blink = caret_reset(self.io.time); }
                    Key::Right => { if st.caret < st.text.chars().count() { st.caret += 1; } st.blink = caret_reset(self.io.time); }
                    Key::Home => st.caret = 0,
                    Key::End => st.caret = st.text.chars().count(),
                    Key::Enter => entered = true,
                    Key::Escape => st.focused = false,
                    _ => {}
                }
            }
        }
        if st.focused { self.sys.blink_req = true; }
        let tr = Rect::new(tx, r.y, r.right() - tx - 8.0, r.h);
        if st.text.is_empty() {
            let c = self.th.label3();
            self.text_in(tr, placeholder, 13.0, Weight::Regular, c, Align::Left);
            if st.focused && caret_on(self.io.time, st.blink) { let a = self.th.accent(); self.cv.fill_rect(Rect::new(tr.x, r.cy() - 8.0, 1.5, 16.0), a); }
        } else {
            self.cv.push_clip(tr);
            let shown: String = if st.mask { st.text.chars().map(|_| '•').collect() } else { st.text.clone() };
            let pre: String = shown.chars().take(st.caret).collect();
            let pw = self.measure(&pre, 13.0, Weight::Regular);
            let scroll = if pw > tr.w - 6.0 { pw - tr.w + 6.0 } else { 0.0 };
            let lc = self.th.label();
            self.text(tr.x - scroll, r.cy() + 4.7, &shown, 13.0, Weight::Regular, lc);
            self.cv.pop_clip();
            if st.focused && caret_on(self.io.time, st.blink) { let a = self.th.accent(); self.cv.fill_rect(Rect::new(tr.x + pw - scroll, r.cy() - 8.0, 1.5, 16.0), a); }
        }
        if resp.hovered { *self.cursor = CursorShape::IBeam; }
        entered
    }

    pub fn group_box(&mut self, r: Rect) {
        self.cv.fill_rrect(r, 12.0, self.th.group_bg());
        self.cv.stroke_rrect(r, 12.0, 0.8, self.th.separator());
    }
}

fn char_byte(s: &str, ci: usize) -> usize { s.char_indices().nth(ci).map(|(i, _)| i).unwrap_or(s.len()) }

/// Caret blink on a 10 Hz grid so cached frames stay exactly in step with live ones.
pub fn caret_on(time: f32, t0: f32) -> bool { let a = crate::mathf::floor(time * 10.0) as i64; let b = crate::mathf::round(t0 * 10.0) as i64; (a - b).rem_euclid(10) < 6 }
pub fn caret_reset(time: f32) -> f32 { crate::mathf::floor(time * 10.0) / 10.0 }
#[derive(Clone, Debug, Default)]
pub struct FieldState { pub text: String, pub caret: usize, pub focused: bool, pub blink: f32, pub mask: bool }

/// Scroll state with wheel inertia and rubber-banding.
#[derive(Clone, Debug, Default)]
pub struct Scroll { pub y: f32, pub v: f32, pub max: f32 }
impl Scroll {
    pub fn moving(&self) -> bool { self.v.abs() > 0.01 || self.y < -0.01 || self.y > self.max + 0.01 }
    pub fn update(&mut self, io: &Io, hovered: bool, max: f32) {
        self.max = max.max(0.0);
        if hovered { self.v += io.wheel.y * 9.0; }
        let dt = io.dt.min(0.05);
        self.y += self.v * dt * 60.0 * 0.12;
        self.v *= exp(-dt * 7.5);
        if self.y < 0.0 { self.y += (0.0 - self.y) * (1.0 - exp(-dt * 14.0)); if fabs(self.y) < 0.2 { self.y = 0.0; } }
        if self.y > self.max { self.y += (self.max - self.y) * (1.0 - exp(-dt * 14.0)); if fabs(self.y - self.max) < 0.2 { self.y = self.max; } }
        if fabs(self.v) < 0.02 { self.v = 0.0; }
    }
}

/// Simple vertical form layout for Settings-style panes.
pub struct Form { pub x: f32, pub y: f32, pub w: f32 }
pub struct Group { pub x: f32, pub w: f32, pub y: f32, pub row_h: f32, pub idx: usize }

impl<'a> Ctx<'a> {
    pub fn group_begin(&mut self, f: &mut Form, rows: usize, row_h: f32) -> Group {
        let h = rows as f32 * row_h;
        self.group_box(Rect::new(f.x, f.y, f.w, h));
        let g = Group { x: f.x, w: f.w, y: f.y, row_h, idx: 0 };
        f.y += h + 18.0;
        g
    }
    pub fn group_row(&mut self, g: &mut Group) -> Rect {
        let r = Rect::new(g.x, g.y + g.idx as f32 * g.row_h, g.w, g.row_h);
        if g.idx > 0 { let c = self.th.separator(); self.cv.fill_rect(Rect::new(r.x + 14.0, r.y, r.w - 14.0, 1.0), c); }
        g.idx += 1;
        r
    }
    pub fn heading(&mut self, f: &mut Form, s: &str) {
        let c = self.th.label2();
        self.text(f.x + 6.0, f.y + 12.0, s, 12.0, Weight::Semibold, c);
        f.y += 22.0;
    }
    pub fn caption(&mut self, f: &mut Form, s: &str) {
        let lines = self.fonts.wrap(s, 11.5, Weight::Regular, f.w - 12.0);
        f.y -= 8.0;
        let c = self.th.label2();
        for l in lines { self.text(f.x + 6.0, f.y + 12.0, &l, 11.5, Weight::Regular, c); f.y += 15.0; }
        f.y += 12.0;
    }
    pub fn row_toggle(&mut self, g: &mut Group, id: &str, label: &str, sub: &str, on: &mut bool) -> bool {
        let r = self.group_row(g);
        let lc = self.th.label();
        if sub.is_empty() {
            self.text_in(Rect::new(r.x + 14.0, r.y, r.w - 90.0, r.h), label, 13.5, Weight::Regular, lc, Align::Left);
        } else {
            self.text(r.x + 14.0, r.y + r.h * 0.5 - 2.0, label, 13.5, Weight::Regular, lc);
            let c2 = self.th.label2();
            self.text(r.x + 14.0, r.y + r.h * 0.5 + 13.0, sub, 11.5, Weight::Regular, c2);
        }
        self.toggle(id, Rect::new(r.right() - 14.0 - 40.0, r.cy() - 11.0, 40.0, 22.0), on)
    }
    pub fn row_slider(&mut self, g: &mut Group, id: &str, label: &str, v: &mut f32, lo: &str, hi: &str) -> bool {
        let r = self.group_row(g);
        let lc = self.th.label();
        self.text(r.x + 14.0, r.cy() + 4.7, label, 13.5, Weight::Regular, lc);
        let c2 = self.th.label2();
        let sx = r.x + r.w * 0.44; let sw = r.w * 0.38;
        if !lo.is_empty() { self.text_in(Rect::new(sx - 52.0, r.y, 46.0, r.h), lo, 11.5, Weight::Regular, c2, Align::Right); }
        let ch = self.slider(id, Rect::new(sx, r.y, sw, r.h), v);
        if !hi.is_empty() { self.text(sx + sw + 8.0, r.cy() + 4.3, hi, 11.5, Weight::Regular, c2); }
        ch
    }
    pub fn row_value(&mut self, g: &mut Group, label: &str, value: &str) -> Rect {
        let r = self.group_row(g);
        let lc = self.th.label(); let c2 = self.th.label2();
        self.text_in(Rect::new(r.x + 14.0, r.y, r.w * 0.5, r.h), label, 13.5, Weight::Regular, lc, Align::Left);
        self.text_in(Rect::new(r.x + r.w * 0.4, r.y, r.w * 0.6 - 14.0, r.h), value, 13.0, Weight::Regular, c2, Align::Right);
        r
    }
}
