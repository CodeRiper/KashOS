//! Boot sequence (firmware POST → logo) and the lock screen (passphrase, duress passphrase, lockout).
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::color::*;
use crate::geom::*;
use crate::glass::*;
use crate::gfx::*;
use crate::icons::*;
use crate::mathf::*;
use crate::shell::menubar::civil;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase { Bios, Logo, Locked, Run }

/// Events the host OS can poll with `Desktop::take_events()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiEvent {
    /// Regular passphrase accepted.
    Unlocked,
    /// Duress passphrase accepted: the UI unlocks normally; the host should mount the decoy volume / raise the silent alarm.
    DuressUnlock,
    /// Wrong passphrase (running count since last success).
    FailedAttempts(u32),
    Locked,
    SleepRequested,
    RestartRequested,
    ShutdownRequested,
}

pub const BIOS_SECS: f32 = 3.9;
pub const LOGO_SECS: f32 = 2.6;

pub struct Lock {
    pub phase: Phase,
    pub t: f32,
    pub show: Spring,
    pass: String,
    setup_passphrase: Option<String>,
    fail_t: f32,
    pub fails: u32,
    lockout: f32,
    bg: Option<Canvas>,
    bg_key: (usize, i32, i32),
    pub layer: Option<Canvas>,
    pub events: Vec<UiEvent>,
    pub idle: f32,
}

impl Lock {
    pub fn new() -> Lock {
        Lock { phase: Phase::Run, t: 0.0, show: Spring::new(0.0, 0.42, 1.0), pass: String::new(), setup_passphrase: None, fail_t: -1.0, fails: 0, lockout: 0.0, bg: None, bg_key: (usize::MAX, 0, 0), layer: None, events: Vec::new(), idle: 0.0 }
    }
    pub fn start_boot(&mut self, bios: bool) {
        self.phase = if bios { Phase::Bios } else { Phase::Logo };
        self.t = 0.0; self.show.snap(1.0); self.pass.clear(); self.fail_t = -1.0;
    }
    pub fn lock_now(&mut self) {
        if self.phase != Phase::Run { return; }
        self.phase = Phase::Locked; self.t = 0.0; self.pass.clear(); self.fail_t = -1.0;
        self.show.snap(0.0); self.show.set(1.0);
        self.events.push(UiEvent::Locked);
    }
    pub fn is_locked(&self) -> bool { self.phase != Phase::Run }
    /// Fully covering the desktop → the desktop itself need not be drawn.
    pub fn opaque(&self) -> bool { match self.phase { Phase::Bios | Phase::Logo => true, Phase::Locked => self.show.x > 0.995, Phase::Run => false } }
    pub fn visible(&self) -> bool { self.phase != Phase::Run || self.show.x > 0.003 }
    pub fn advance(&mut self, dt: f32) {
        self.t += dt;
        self.show.update(dt);
        if self.lockout > 0.0 { self.lockout = (self.lockout - dt).max(0.0); }
        if self.fail_t >= 0.0 { self.fail_t += dt; if self.fail_t > 0.35 { self.pass.clear(); } if self.fail_t > 1.6 { self.fail_t = -1.0; } }
        match self.phase {
            Phase::Bios => if self.t >= BIOS_SECS { self.phase = Phase::Logo; self.t = 0.0; },
            Phase::Logo => if self.t >= LOGO_SECS { self.phase = Phase::Locked; self.t = 0.0; },
            _ => {}
        }
    }
    pub fn skip_bios(&mut self) { if self.phase == Phase::Bios { self.phase = Phase::Logo; self.t = 0.0; } }
    pub fn skip_logo(&mut self) { if self.phase == Phase::Logo && self.t > 0.4 { self.t = LOGO_SECS - 0.5; } }

    /// Pre-blurred wallpaper used as the lock backdrop (rebuilt when the wallpaper or screen size changes).
    pub fn ensure_bg(&mut self, wp: &Canvas, scratch: &mut GlassScratch, key: usize) {
        if self.bg.is_some() && self.bg_key == (key, wp.w, wp.h) { return; }
        let (w, h) = (wp.w, wp.h);
        let mut c = Canvas::new(w, h);
        c.px.copy_from_slice(&wp.px);
        let mut st = GlassStyle::new(0.0);
        st.blur = 30.0; st.bezel = 0.0; st.refraction = 0.0; st.spec = 0.0; st.saturation = 1.2; st.tint = Color::rgba(6, 8, 22, 84); st.dark = true;
        c.glass(Rect::new(0.0, 0.0, w as f32, h as f32), &st, scratch);
        self.bg = Some(c); self.bg_key = (key, w, h);
    }
    pub fn take_bg(&mut self) -> Option<Canvas> { self.bg.take() }
    pub fn put_bg(&mut self, c: Option<Canvas>) { self.bg = c; }

    fn submit(&mut self, sys: &mut SysState) {
        if self.lockout > 0.0 || self.fail_t >= 0.0 { return; }
        if sys.passphrase.is_empty() {
            if let Some(first) = self.setup_passphrase.take() {
                if first != self.pass {
                    self.fails += 1;
                    self.fail_t = 0.0;
                    self.events.push(UiEvent::FailedAttempts(self.fails));
                    if self.fails >= 5 { self.lockout = 10.0 * (1u32 << (self.fails - 5).min(4)) as f32; }
                    return;
                }
                sys.passphrase = first;
            } else {
                if self.pass.chars().count() < 12 {
                    self.fails += 1;
                    self.fail_t = 0.0;
                    self.events.push(UiEvent::FailedAttempts(self.fails));
                    if self.fails >= 5 { self.lockout = 10.0 * (1u32 << (self.fails - 5).min(4)) as f32; }
                    return;
                }
                self.setup_passphrase = Some(core::mem::take(&mut self.pass));
                return;
            }
        }
        let duress = !sys.duress_pass.is_empty() && self.pass == sys.duress_pass;
        if self.pass == sys.passphrase || duress {
            sys.duress_active = duress && self.pass != sys.passphrase;
            self.events.push(if sys.duress_active { UiEvent::DuressUnlock } else { UiEvent::Unlocked });
            self.fails = 0; self.pass.clear(); self.phase = Phase::Run; self.show.set(0.0);
        } else {
            self.fails += 1; self.fail_t = 0.0;
            self.events.push(UiEvent::FailedAttempts(self.fails));
            if self.fails >= 5 { self.lockout = 10.0 * (1u32 << (self.fails - 5).min(4)) as f32; }
        }
    }

    /// Draw (and, when `live`, drive) the lock screen into `cx.cv` (a full-screen layer).
    pub fn update_draw(&mut self, cx: &mut Ctx, bg: &Canvas, live: bool) {
        let area = cx.bounds;
        let (w, h) = (area.w, area.h);
        if cx.cv.px.len() == bg.px.len() { cx.cv.px.copy_from_slice(&bg.px); } else { cx.cv.blit_scaled(bg, area, 0.0, 1.0); }
        let ent = ease_out_cubic(saturate(self.t / 0.7));
        let white = Color::WHITE;
        let dim = Color::rgba(255, 255, 255, 170);

        // ── status icons (top-right) ──
        let wifi = cx.sys.wifi;
        if wifi { draw_icon(cx.cv, Icon::Wifi, Rect::new(w - 76.0, 17.0, 18.0, 18.0), Color::rgba(255, 255, 255, 215)); }
        draw_icon(cx.cv, Icon::Battery, Rect::new(w - 44.0, 17.0, 20.0, 18.0), Color::rgba(255, 255, 255, 215));

        // ── date & clock ──
        if cx.sys.lock_clock {
            const WD: [&str; 7] = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
            const MO: [&str; 12] = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
            let (_, m, d, wd, hh, mi) = civil(cx.sys.unix_secs, 330);
            let date = format!("{}, {} {}", WD[wd as usize], d, MO[(m - 1) as usize]);
            let time = format!("{}:{:02}", if hh % 12 == 0 { 12 } else { hh % 12 }, mi);
            let off = (1.0 - ent) * -18.0;
            cx.text_in(Rect::new(0.0, h * 0.11 + off, w, 30.0), &date, 22.0, Weight::Semibold, Color::rgba(255, 255, 255, (200.0 * ent) as u8), Align::Center);
            cx.text_in(Rect::new(0.0, h * 0.11 + 34.0 + off, w, 130.0), &time, 118.0, Weight::Bold, Color::rgba(255, 255, 255, (235.0 * ent) as u8), Align::Center);
        }

        // ── avatar, name, field ──
        let cxm = w * 0.5;
        let ay = h * 0.50 + (1.0 - ent) * 24.0;
        let show_user = cx.sys.lock_user;
        if show_user {
            cx.cv.shadow_rrect(Rect::new(cxm - 38.0, ay - 38.0, 76.0, 76.0).offset(0.0, 6.0), 38.0, 14.0, Color::rgba(0, 0, 0, 90), false);
            cx.cv.fill_circle(cxm, ay, 38.0, Paint::Linear { p0: Pt::new(cxm - 38.0, ay - 38.0), p1: Pt::new(cxm + 38.0, ay + 38.0), c0: Color::hex(0x62CBFF), c1: Color::hex(0x5A2BD2) });
            draw_kash_mark(cx.cv, Rect::new(cxm - 26.0, ay - 26.0, 52.0, 52.0), Color::WHITE, Some(Color::hex(0xB6F3FF)));
            cx.text_in(Rect::new(cxm - 150.0, ay + 48.0, 300.0, 24.0), "Akash J", 17.0, Weight::Semibold, white, Align::Center);
        }
        let fy = ay + if show_user { 86.0 } else { 0.0 };
        let (fw, fh) = (256.0, 40.0);
        let shake = if self.fail_t >= 0.0 { sin(self.fail_t * 46.0) * exp(-self.fail_t * 7.0) * 16.0 } else { 0.0 };
        let fr = Rect::new(cxm - fw * 0.5 + shake, fy, fw, fh);
        // field
        cx.glass(fr, GlassKind::Control, fh * 0.5);
        let failing = self.fail_t >= 0.0;
        if failing { let a = (0.6 * (1.0 - saturate(self.fail_t / 1.4)) * 255.0) as u8; cx.cv.stroke_rrect(fr, fh * 0.5, 1.6, Color::rgba(255, 90, 80, a)); }
        let n = self.pass.chars().count();
        let sub_btn = Rect::new(fr.right() - 34.0, fr.cy() - 14.0, 28.0, 28.0);
        if n == 0 {
            let msg = if cx.sys.passphrase.is_empty() { if self.setup_passphrase.is_some() { "Confirm new passphrase" } else { "Create passphrase (12+ characters)" } } else { "Enter Passphrase" };
            cx.text_in(fr, msg, 14.0, Weight::Regular, Color::rgba(255, 255, 255, 140), Align::Center);
        } else {
            let sp = 12.0; let tot = (n as f32 - 1.0) * sp;
            for i in 0..n { cx.cv.fill_circle(fr.cx() - tot * 0.5 + i as f32 * sp, fr.cy(), 3.4, white); }
        }
        if n > 0 && live {
            let hv = cx.hit(id_of("lock_go"), sub_btn);
            let t = cx.anim(id2(id_of("lock_go"), 1), if hv.hovered { 1.0 } else { 0.0 });
            cx.cv.fill_circle(sub_btn.cx(), sub_btn.cy(), 12.5, Color::rgba(255, 255, 255, (60.0 + 60.0 * t) as u8));
            draw_icon(cx.cv, Icon::ChevR, Rect::new(sub_btn.cx() - 7.0, sub_btn.cy() - 7.0, 14.0, 14.0), white);
            if hv.clicked { self.submit(cx.sys); }
        } else if n > 0 {
            cx.cv.fill_circle(sub_btn.cx(), sub_btn.cy(), 12.5, Color::rgba(255, 255, 255, 60));
            draw_icon(cx.cv, Icon::ChevR, Rect::new(sub_btn.cx() - 7.0, sub_btn.cy() - 7.0, 14.0, 14.0), white);
        }
        // status line under the field
        let (msg, col) = if self.lockout > 0.0 { (format!("Too many attempts — try again in {} s", ceil(self.lockout) as i32), Color::rgb(255, 140, 130)) }
            else if failing { (String::from("Incorrect passphrase"), Color::rgb(255, 140, 130)) }
            else if self.fails > 0 && !cx.sys.lock_hint.is_empty() { (format!("Hint: {}", cx.sys.lock_hint), dim) }
            else { (String::from(if cx.sys.passphrase.is_empty() { if self.setup_passphrase.is_some() { "Re-enter the new passphrase to confirm" } else { "Set a passphrase before unlocking" } } else { "Enter your passphrase to unlock" }), Color::rgba(255, 255, 255, 120)) };
        cx.text_in(Rect::new(cxm - 220.0, fr.bottom() + 8.0, 440.0, 20.0), &msg, 12.5, Weight::Regular, col, Align::Center);

        // ── gateway chip ──
        if cx.sys.lock_gateway {
            let gw = "Anonymity Gateway unavailable";
            let tw = cx.measure(gw, 11.5, Weight::Medium) + 34.0;
            let r = Rect::new(cxm - tw * 0.5, h - 138.0, tw, 26.0);
            cx.cv.fill_rrect(r, 13.0, Color::rgba(255, 255, 255, 34));
            draw_icon(cx.cv, Icon::Shield, Rect::new(r.x + 8.0, r.cy() - 6.5, 13.0, 13.0), Color::rgba(255, 255, 255, 220));
            cx.text(r.x + 26.0, r.cy() + 4.2, gw, 11.5, Weight::Medium, Color::rgba(255, 255, 255, 215));
        }
        // ── power buttons ──
        if cx.sys.lock_buttons {
            let items = [("Sleep", Icon::Moon), ("Restart", Icon::Bolt), ("Shut Down", Icon::Power)];
            for (i, (lb, ic)) in items.iter().enumerate() {
                let c = Pt::new(cxm + (i as f32 - 1.0) * 100.0, h - 76.0);
                let r = Rect::new(c.x - 23.0, c.y - 23.0, 46.0, 46.0);
                let hv = if live { cx.hit(id_of(lb) ^ 0x10C4, r) } else { WidgetResp::none() };
                let t = cx.anim(id2(id_of(lb), 0x10C5), if hv.hovered { 1.0 } else { 0.0 });
                cx.cv.fill_circle(c.x, c.y, 23.0 + t * 1.5, Color::rgba(255, 255, 255, (36.0 + 40.0 * t) as u8));
                draw_icon(cx.cv, *ic, Rect::new(c.x - 10.0, c.y - 10.0, 20.0, 20.0), white);
                cx.text_in(Rect::new(c.x - 48.0, c.y + 28.0, 96.0, 16.0), lb, 11.5, Weight::Regular, Color::rgba(255, 255, 255, 190), Align::Center);
                if hv.clicked { match i { 0 => self.events.push(UiEvent::SleepRequested), 1 => { self.events.push(UiEvent::RestartRequested); cx.cmds.push(Cmd::Restart); } _ => { self.events.push(UiEvent::ShutdownRequested); cx.cmds.push(Cmd::Shutdown); } } }
            }
        }

        // ── keyboard ──
        if live && cx.io.focused {
            let keys: Vec<KeyEv> = cx.io.keys.clone();
            for k in keys {
                match k.key {
                    Key::Char | Key::Space if !k.ctrl && self.fail_t < 0.0 && self.lockout <= 0.0 && self.pass.chars().count() < 64 => { self.pass.push(if k.key == Key::Space { ' ' } else { k.ch }); }
                    Key::Backspace => { if self.fail_t < 0.0 { self.pass.pop(); } }
                    Key::Escape => { if self.fail_t < 0.0 { self.pass.clear(); } }
                    Key::Enter => self.submit(cx.sys),
                    _ => {}
                }
            }
        }
    }

    pub fn animating(&self) -> bool { self.visible() }
}

// ───────────────────────── boot screens ─────────────────────────

const POST: [(f32, &str, &str); 11] = [
    (0.35, "CPU    x86-64 · features reported by kernel", "OK"),
    (0.55, "Memory", "MEM"),
    (1.55, "Measured boot (TPM 2.0)", "unavailable"),
    (1.75, "IOMMU / DMA protection (VT-d)", "not verified"),
    (1.95, "KashOS Microkernel 0.2.0", "loaded"),
    (2.15, "Capability core self-test", "passed"),
    (2.35, "Vault encrypted storage", "locked · unlock required"),
    (2.55, "Anonymity Gateway", "planned (Part C)"),
    (2.75, "Remote networking", "unavailable · egress blocked"),
    (2.8, "Device drivers", "support varies"),
    (3.0, "Starting kash-ui compositor", "OK"),
];

/// Firmware POST screen.
pub fn draw_bios(cv: &mut Canvas, fonts: &mut Fonts, t: f32) {
    let (w, h) = (cv.w as f32, cv.h as f32);
    cv.clear(Color::rgb(3, 4, 8));
    let mono = Weight::Mono;
    let x0 = (w * 0.06).max(40.0);
    let dest = Rect::new(x0, 42.0, 40.0, 40.0);
    fonts.icons.draw(cv, 900, dest, 1.0, &|c, rr| draw_kash_mark(c, rr, Color::WHITE, Some(Color::hex(0x7BE3FF))));
    fonts.draw(cv, x0 + 54.0, 60.0, "KashOS Firmware 1.0", 20.0, Weight::Semibold, Color::rgb(235, 240, 250));
    fonts.draw(cv, x0 + 54.0, 80.0, "KashOS Boot ROM · Kash Labs", 12.5, Weight::Regular, Color::rgb(120, 130, 150));
    let size = 13.5;
    let cw = fonts.measure("M", size, mono);
    let cols = ((w - x0 * 2.0) / cw).min(74.0) as usize;
    let lh = 24.0;
    let mut y = 126.0;
    for (ts, label, status) in POST.iter() {
        if t < *ts { break; }
        let el = t - ts;
        let nch = label.chars().count();
        let shown = ((el * 110.0) as usize).min(nch);
        let lab: String = label.chars().take(shown).collect();
        fonts.draw(cv, x0, y, &lab, size, mono, Color::rgb(200, 208, 222));
        if shown >= nch {
            let st = if *status == "MEM" { let mib = ((el / 0.95).min(1.0) * 512.0) as u32; if el / 0.95 >= 1.0 { String::from("512 MiB OK") } else { format!("{} MiB", mib) } } else { String::from(*status) };
            let done = *status != "MEM" || el >= 0.95;
            let dots = cols.saturating_sub(nch + st.chars().count() + 2);
            let mut ds = String::new(); for _ in 0..dots { ds.push('.'); }
            let ex = x0 + nch as f32 * cw;
            fonts.draw(cv, ex + cw, y, &ds, size, mono, Color::rgb(70, 78, 96));
            fonts.draw(cv, x0 + (cols - st.chars().count()) as f32 * cw, y, &st, size, mono, if done { Color::rgb(110, 240, 170) } else { Color::rgb(240, 200, 110) });
        }
        y += lh;
    }
    if t > 3.3 { fonts.draw(cv, x0, y + 8.0, "Handing over to KashOS …", size, mono, Color::rgb(255, 255, 255)); }
    // blinking block cursor
    if ((t * 2.2) as i32) % 2 == 0 && t < BIOS_SECS - 0.2 { cv.fill_rect(Rect::new(x0, y + 8.0 - 12.0 + if t > 3.3 { 24.0 } else { 0.0 }, cw * 0.8, 15.0), Color::rgba(200, 208, 222, 200)); }
    fonts.draw(cv, x0, h - 34.0, "Esc — skip     F2 — firmware setup", 12.0, mono, Color::rgb(90, 98, 118));
    // closing fade
    if t > BIOS_SECS - 0.25 { let a = saturate((t - (BIOS_SECS - 0.25)) / 0.25); cv.fill_rect(Rect::new(0.0, 0.0, w, h), Color::rgba(0, 0, 0, (a * 255.0) as u8)); }
}

/// Logo screen drawn over whatever is already in `cv` (black until t>2.1, then it fades to reveal the lock screen).
pub fn draw_logo(cv: &mut Canvas, fonts: &mut Fonts, t: f32, over_lock: bool) {
    let (w, h) = (cv.w as f32, cv.h as f32);
    let fade_out = saturate((t - (LOGO_SECS - 0.5)) / 0.5);
    let a = 1.0 - ease_in_out(fade_out);
    if !over_lock { cv.clear(Color::rgb(0, 0, 0)); } else { cv.fill_rect(Rect::new(0.0, 0.0, w, h), Color::rgba(0, 0, 0, (a * 255.0) as u8)); }
    if a <= 0.001 { return; }
    let c = Pt::new(w * 0.5, h * 0.5);
    let pop = ease_out_cubic(saturate(t / 0.75));
    let sz = 92.0 * (0.78 + 0.22 * pop);
    let dest = Rect::new(c.x - sz * 0.5, c.y - sz * 0.5 - 22.0, sz, sz);
    fonts.icons.draw(cv, 900, dest, pop * a, &|cv2, rr| draw_kash_mark(cv2, rr, Color::WHITE, Some(Color::hex(0x7BE3FF))));
    let wm = saturate((t - 0.5) / 0.5);
    fonts.draw_in(cv, Rect::new(c.x - 150.0, c.y + 40.0, 300.0, 30.0), "KashOS", 24.0, Weight::Semibold, Color::rgba(255, 255, 255, (230.0 * wm * a) as u8), Align::Center);
    let bw = 170.0; let prog = ease_in_out(saturate((t - 0.3) / 1.7));
    cv.fill_rrect(Rect::new(c.x - bw * 0.5, c.y + 88.0, bw, 4.0), 2.0, Color::rgba(255, 255, 255, (46.0 * a) as u8));
    cv.fill_rrect(Rect::new(c.x - bw * 0.5, c.y + 88.0, bw * prog, 4.0), 2.0, Color::rgba(255, 255, 255, (225.0 * a) as u8));
    fonts.draw_in(cv, Rect::new(c.x - 150.0, h - 44.0, 300.0, 16.0), "Kash UI 1.0", 11.5, Weight::Regular, Color::rgba(255, 255, 255, (90.0 * wm * a) as u8), Align::Center);
}
