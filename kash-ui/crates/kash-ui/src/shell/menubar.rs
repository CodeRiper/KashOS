//! Menu bar: adaptive text, glass dropdown menus, status items.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::app::*;
use crate::color::*;
use crate::geom::*;
use crate::icons::*;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;

pub const BAR_H: f32 = 30.0;

pub fn civil(unix: i64, tz_min: i64) -> (i32, u32, u32, u32, u32, u32) {
    let t = unix + tz_min * 60;
    let days = t.div_euclid(86400); let secs = t.rem_euclid(86400);
    let z = days + 719468; let era = z.div_euclid(146097); let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400; let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    let wd = ((days + 4).rem_euclid(7)) as u32;
    (y as i32, m, d, wd, (secs / 3600) as u32, ((secs % 3600) / 60) as u32)
}
pub fn clock_string(unix: i64) -> String {
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (_, m, d, wd, h, mi) = civil(unix, 330);
    let (h12, ap) = if h == 0 { (12, "AM") } else if h < 12 { (h, "AM") } else if h == 12 { (12, "PM") } else { (h - 12, "PM") };
    format!("{} {} {}   {}:{:02} {}", WD[wd as usize], MO[(m - 1) as usize], d, h12, mi, ap)
}

pub struct MenuBar {
    pub open: Option<usize>,
    popup_t: Spring,
    luma: Spring,
    xs: Vec<(f32, f32)>,
    last_open: usize,
    pub status_cc: Rect,
    pub status_search: Rect,
    pub popup_rect: Rect,
}

pub enum BarEvent { None, Action(Action), ControlCenter, Spotlight }

impl MenuBar {
    pub fn new() -> MenuBar {
        MenuBar { open: None, popup_t: Spring::new(0.0, 0.2, 0.95), luma: Spring::new(0.0, 0.3, 1.0), xs: Vec::new(), last_open: 0, status_cc: Rect::ZERO, status_search: Rect::ZERO, popup_rect: Rect::ZERO }
    }
    pub fn busy(&self) -> bool { self.open.is_some() || !self.popup_t.settled() || !self.luma.settled() }
    pub fn close(&mut self) { self.open = None; }
    pub fn is_open(&self) -> bool { self.open.is_some() }

    pub fn update_draw(&mut self, cx: &mut Ctx, screen: Rect, menus: &[(String, Vec<MenuItem>)], hot_bar: bool) -> BarEvent {
        let th = *cx.th;
        let mut ev = BarEvent::None;
        let bar = Rect::new(0.0, 0.0, screen.w, BAR_H);
        let mut st = th.glass(GlassKind::MenuBar, 0.0);
        st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0;
        cx.glass_style(bar, &st);
        // adaptive ink from what's behind the bar
        let (mut s, mut n) = (0.0f32, 0.0f32);
        for y in (2..(BAR_H as i32 - 2)).step_by(4) { for x in (0..cx.cv.w).step_by(24) { s += Color::from_pix(cx.cv.px[(y * cx.cv.w + x) as usize]).luma(); n += 1.0; } }
        let l = if n > 0.0 { s / n } else { 0.5 };
        self.luma.set(if l > 0.58 { 1.0 } else { 0.0 }); self.luma.update(cx.io.dt);
        let ink = Color::rgb(245, 246, 250).mix(Color::rgb(18, 18, 22), self.luma.x.clamp(0.0, 1.0));
        // title positions: index 0 = logo menu, then app menus
        self.xs.clear();
        let mut x = 14.0;
        self.xs.push((x - 8.0, 32.0));
        x += 30.0;
        for (i, (t, _)) in menus.iter().enumerate() {
            let w = cx.measure(t, 13.5, if i == 0 { Weight::Bold } else { Weight::Medium });
            self.xs.push((x - 8.0, w + 16.0));
            x += w + 18.0;
        }
        let m = cx.io.mouse;
        self.popup_rect = Rect::ZERO;
        // dropdown geometry up-front so clicks on it don't close the menu
        let mut popup: Option<(usize, Vec<MenuItem>, Rect)> = None;
        if let Some(oi) = self.open {
            if oi < self.xs.len() {
                let (tx, _) = self.xs[oi];
                let items: Vec<MenuItem> = if oi == 0 { kash_menu() } else { menus[oi - 1].1.clone() };
                let mut mw = 170.0f32;
                for it in items.iter() { if it.is_sep() { continue; } let w = cx.measure(&it.label, 13.5, Weight::Regular) + if it.shortcut.is_empty() { 0.0 } else { cx.measure(it.shortcut, 12.5, Weight::Regular) + 34.0 }; mw = mw.max(w + 36.0); }
                let mut mh = 12.0; for it in items.iter() { mh += if it.is_sep() { 11.0 } else { 26.0 }; }
                let pr = Rect::new((tx - 2.0).min(screen.w - mw - 8.0).max(8.0), BAR_H + 2.0, mw, mh);
                self.popup_rect = pr;
                popup = Some((oi, items, pr));
            } else { self.open = None; }
        }
        let popup_hot = hot_bar && popup.as_ref().map(|p| p.2.contains(m.x, m.y)).unwrap_or(false);
        let over_bar = hot_bar && bar.contains(m.x, m.y);
        let mut hover_title = None;
        if over_bar { for (i, (tx, tw)) in self.xs.iter().enumerate() { if m.x >= *tx && m.x < tx + tw { hover_title = Some(i); } } }
        if let Some(h) = hover_title {
            if cx.io.pressed { self.open = if self.open == Some(h) { None } else { Some(h) }; }
            else if self.open.is_some() && self.open != Some(h) { self.open = Some(h); }
        } else if cx.io.pressed && self.open.is_some() && !popup_hot { self.open = None; }
        if over_bar { *cx.over_widget = true; }
        for (i, (tx, tw)) in self.xs.iter().enumerate() {
            let hl = Rect::new(*tx, 3.0, *tw, BAR_H - 6.0);
            let t = cx.anim(id2(id_of("mbt"), i as u32), if self.open == Some(i) { 1.0 } else if hover_title == Some(i) && self.open.is_none() { 0.5 } else { 0.0 });
            if t > 0.01 { cx.cv.fill_rrect(hl, 8.0, ink.fade(0.18 * t)); }
            if i == 0 { draw_kash_mark(cx.cv, Rect::new(hl.cx() - 9.0, hl.cy() - 9.0, 18.0, 18.0), ink, None); }
            else { cx.text_in(hl, &menus[i - 1].0, 13.5, if i == 1 { Weight::Bold } else { Weight::Medium }, ink, Align::Center); }
        }
        // status items (right)
        let clock = clock_string(cx.sys.unix_secs);
        let cw = cx.measure(&clock, 13.0, Weight::Medium);
        let mut rx = screen.w - 14.0 - cw;
        cx.text(rx, BAR_H * 0.5 + 4.7, &clock, 13.0, Weight::Medium, ink);
        rx -= 14.0;
        let items: [(Icon, f32); 4] = [(Icon::Sliders, 17.0), (Icon::Search, 15.0), (Icon::Battery, 22.0), (Icon::Wifi, 17.0)];
        let mut rects = [Rect::ZERO; 4];
        for (i, (ic, w)) in items.iter().enumerate() {
            rx -= *w;
            let r = Rect::new(rx - 5.0, 3.0, *w + 10.0, BAR_H - 6.0);
            rects[i] = r;
            let hv = hot_bar && r.contains(m.x, m.y);
            let t = cx.anim(id2(id_of("mbs"), i as u32), if hv { 1.0 } else { 0.0 });
            if t > 0.01 { cx.cv.fill_rrect(r, 8.0, ink.fade(0.16 * t)); }
            let c = if *ic == Icon::Wifi && !cx.sys.wifi { ink.fade(0.4) } else { ink };
            draw_icon(cx.cv, *ic, Rect::new(rx, BAR_H * 0.5 - w * 0.5, *w, *w), c);
            if hv && cx.io.pressed { ev = match i { 0 => BarEvent::ControlCenter, 1 => BarEvent::Spotlight, _ => BarEvent::None }; self.open = None; }
            rx -= 12.0;
        }
        self.status_cc = rects[0]; self.status_search = rects[1];
        // dropdown
        if let Some((oi, items, rect)) = popup {
            if self.open.is_none() { return ev; }
            if oi != self.last_open { self.popup_t.snap(0.0); }
            self.last_open = oi;
            let mh = rect.h;
            self.popup_t.set(1.0); self.popup_t.update(cx.io.dt);
            let t = (self.popup_t.x * 1.15).clamp(0.0, 1.0);
            let reveal = Rect::new(rect.x - 30.0, rect.y - 4.0, rect.w + 60.0, (mh + 40.0) * t + 4.0);
            cx.cv.push_clip(reveal);
            cx.cv.shadow_rrect(rect.offset(0.0, 8.0), 14.0, 22.0, th.shadow(0.30 * t), false);
            cx.glass_style(rect, &th.glass(GlassKind::Popover, 14.0));
            let mut y = rect.y + 6.0;
            for (i, it) in items.iter().enumerate() {
                if it.is_sep() { cx.cv.fill_rect(Rect::new(rect.x + 14.0, y + 5.0, rect.w - 28.0, 1.0), th.separator()); y += 11.0; continue; }
                let ir = Rect::new(rect.x + 6.0, y, rect.w - 12.0, 26.0);
                let hov = popup_hot && it.enabled && ir.contains(m.x, m.y);
                let ht = cx.anim(id2(id_of("mbi"), i as u32 + (oi as u32) * 64), if hov { 1.0 } else { 0.0 });
                if ht > 0.01 { cx.cv.fill_rrect(ir, 9.0, th.accent().fade(ht)); }
                let c = if !it.enabled { th.label3() } else { th.label().mix(Color::WHITE, ht) };
                cx.text_in(Rect::new(ir.x + 10.0, ir.y, ir.w - 20.0, ir.h), &it.label, 13.5, Weight::Regular, c, Align::Left);
                if !it.shortcut.is_empty() { cx.text_in(Rect::new(ir.x + 10.0, ir.y, ir.w - 20.0, ir.h), it.shortcut, 12.5, Weight::Regular, if hov { Color::rgba(255, 255, 255, 190) } else { th.label2() }, Align::Right); }
                if hov && cx.io.released { ev = BarEvent::Action(it.action.clone()); self.open = None; }
                y += 26.0;
            }
            cx.cv.pop_clip();
            if popup_hot { *cx.over_widget = true; }
        } else { self.popup_t.snap(0.0); }
        ev
    }
}

pub fn kash_menu() -> Vec<MenuItem> {
    alloc::vec![
        MenuItem::new("About KashOS", "", Action::Cmd(Cmd::Open(AppKind::About))), MenuItem::sep(),
        MenuItem::new("System Settings…", "", Action::Cmd(Cmd::Open(AppKind::Settings))), MenuItem::new("Privacy & Security…", "", Action::Cmd(Cmd::OpenSettingsPane(14))), MenuItem::sep(),
        MenuItem::new("Lock Screen", "Ctrl Shift L", Action::Cmd(Cmd::Lock)), MenuItem::new("Toggle Dark Mode", "", Action::ToggleDark), MenuItem::new("Spotlight Search", "Ctrl Space", Action::Cmd(Cmd::Spotlight)), MenuItem::sep(),
        MenuItem::new("Shut Down…", "", Action::Cmd(Cmd::Shutdown)),
    ]
}
