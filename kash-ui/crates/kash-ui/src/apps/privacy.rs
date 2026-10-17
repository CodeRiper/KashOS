//! Privacy & Security — per-app permission manager for GUI apps, CLI tools and drivers.
//! Navigation: Home → (permission | app class | security | log) → app detail, with slide transitions.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::icons::*;
use crate::registry::*;
use crate::text::*;
use crate::ui::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page { Home, Perm(Perm), Class(AppClass), App(usize), Security, Log }

pub struct Privacy { pub nav: Vec<Page>, pub t: Spring, pub dir: f32, pub nav_changed: bool, confirm_reset: bool }

fn tile(cx: &mut Ctx, r: Rect, ic: Icon, col: u32) {
    let c = Color::hex(col);
    cx.cv.fill_rrect(r, r.h * 0.26, Paint::VGrad { y0: r.y, y1: r.bottom(), c0: c.lighten(0.16), c1: c });
    draw_icon(cx.cv, ic, r.inset(r.h * 0.2), Color::WHITE);
}
fn entry_icon(cx: &mut Ctx, i: usize, r: Rect) {
    let (k, c) = { let a = &cx.sys.reg.apps[i]; (a.kind, a.class) };
    match k { Some(k) => cx.app_icon(k, r), None => cx.file_icon(c.file_kind(), r) }
}
fn fit(cx: &mut Ctx, s: &str, size: f32, w: f32) -> String { cx.fonts.fit(s, size, Weight::Regular, w) }

/// Row that navigates somewhere: tile + title + value + chevron.
fn nav_row(cx: &mut Ctx, g: &mut Group, id: &str, ic: Icon, col: u32, title: &str, value: &str) -> bool {
    let r = cx.group_row(g);
    let h = cx.hit(id_of(id) ^ 0x7A1, r);
    let hv = cx.anim(id2(id_of(id), 0x7A2), if h.hovered { 1.0 } else { 0.0 });
    if hv > 0.01 { let hf = cx.th.hover_fill().fade(hv); cx.cv.fill_rrect(r.inset(1.0), 10.0, hf); }
    tile(cx, Rect::new(r.x + 12.0, r.cy() - 13.0, 26.0, 26.0), ic, col);
    let lc = cx.th.label(); let l2 = cx.th.label2(); let l3 = cx.th.label3();
    cx.text(r.x + 50.0, r.cy() + 4.7, title, 13.5, Weight::Regular, lc);
    cx.text_in(Rect::new(r.x + r.w * 0.5, r.y, r.w * 0.5 - 38.0, r.h), value, 12.5, Weight::Regular, l2, Align::Right);
    draw_icon(cx.cv, Icon::ChevR, Rect::new(r.right() - 26.0, r.cy() - 6.0, 12.0, 12.0), l3);
    h.clicked
}

fn ps_idx(p: PS) -> usize { match p { PS::Allow => 0, PS::Ask => 1, _ => 2 } }
const PS_COL: [u32; 3] = [0x30D158, 0xFF9F0A, 0xFF453A];

/// Three-way Allow / Ask / Deny control with a sliding coloured thumb.
pub(crate) fn ps_control(cx: &mut Ctx, id: &str, r: Rect, cur: PS, enabled: bool) -> Option<PS> {
    let h = id_of(id);
    let resp = if enabled { cx.hit(h ^ 0x9C1, r) } else { WidgetResp::none() };
    let mut out = None;
    let sw = r.w / 3.0;
    if resp.clicked { let i = (((cx.io.mouse.x - r.x) / sw) as usize).min(2); let ns = match i { 0 => PS::Allow, 1 => PS::Ask, _ => PS::Deny }; if ns != cur { out = Some(ns); } }
    let shown = ps_idx(out.unwrap_or(cur));
    let t = cx.anim_p(id2(h, 0x9C2), shown as f32, Preset::Snappy);
    let dim = if enabled { 1.0 } else { 0.45 };
    let cf = cx.th.control_fill();
    cx.cv.fill_rrect(r, r.h * 0.5, cf.fade(dim));
    let c0 = Color::hex(PS_COL[0]); let c1 = Color::hex(PS_COL[1]); let c2 = Color::hex(PS_COL[2]);
    let col = c0.mix(c1, t.clamp(0.0, 1.0)).mix(c2, (t - 1.0).clamp(0.0, 1.0));
    let th_r = Rect::new(r.x + 2.0 + t * sw, r.y + 2.0, sw - 4.0, r.h - 4.0);
    cx.cv.shadow_rrect(th_r.offset(0.0, 1.0), th_r.h * 0.5, 3.0, Color::rgba(0, 0, 0, 34), false);
    cx.cv.fill_rrect(th_r, th_r.h * 0.5, col.fade(dim));
    let labs = ["Allow", "Ask", "Deny"];
    for i in 0..3 {
        let cr = Rect::new(r.x + sw * i as f32, r.y, sw, r.h);
        let on = (t - i as f32).abs() < 0.5;
        let lc = if on { Color::WHITE } else { cx.th.label2() };
        cx.text_in(cr, labs[i], 12.0, if on { Weight::Semibold } else { Weight::Regular }, lc.fade(dim), Align::Center);
    }
    out
}

fn bulk_row(cx: &mut Ctx, g: &mut Group, id: &str, label: &str) -> Option<PS> {
    let r = cx.group_row(g);
    let lc = cx.th.label();
    cx.text(r.x + 14.0, r.cy() + 4.7, label, 13.5, Weight::Regular, lc);
    let bw = 70.0; let gap = 8.0;
    let x0 = r.right() - 14.0 - 3.0 * bw - 2.0 * gap;
    let mut out = None;
    for (i, (l, p)) in [("Allow all", PS::Allow), ("Ask all", PS::Ask), ("Deny all", PS::Deny)].iter().enumerate() {
        if cx.button(&format!("{}{}", id, i), Rect::new(x0 + i as f32 * (bw + gap), r.cy() - 13.0, bw, 26.0), l, false) { out = Some(*p); }
    }
    out
}

fn ago(now: i64, t: i64) -> String {
    let d = (now - t).max(0);
    if d < 60 { String::from("just now") } else if d < 3600 { format!("{} min ago", d / 60) } else { format!("{} h ago", d / 3600) }
}

impl Privacy {
    pub fn new() -> Privacy { let mut t = Spring::new(1.0, 0.3, 1.0); t.snap(1.0); Privacy { nav: alloc::vec![Page::Home], t, dir: 1.0, nav_changed: false, confirm_reset: false } }
    pub fn cur(&self) -> Page { *self.nav.last().unwrap_or(&Page::Home) }
    pub fn animating(&self) -> bool { !self.t.settled() }
    fn kick(&mut self, dir: f32) { self.dir = dir; self.t.snap(0.0); self.t.set(1.0); self.nav_changed = true; self.confirm_reset = false; }
    pub fn push(&mut self, p: Page) { self.nav.push(p); self.kick(1.0); }
    pub fn back(&mut self) { if self.nav.len() > 1 { self.nav.pop(); self.kick(-1.0); } }
    pub fn reset(&mut self) { self.nav.clear(); self.nav.push(Page::Home); self.t.snap(1.0); self.nav_changed = true; }
    pub fn goto_app(&mut self, reg: &Registry, name: &str) {
        if let Some(i) = reg.find_name(name) { self.nav.clear(); self.nav.push(Page::Home); self.nav.push(Page::Class(reg.apps[i].class)); self.nav.push(Page::App(i)); self.kick(1.0); }
    }
    pub fn title(&self, reg: &Registry) -> String {
        match self.cur() {
            Page::Home => String::from("Privacy & Security"),
            Page::Perm(p) => String::from(p.name()),
            Page::Class(c) => String::from(c.plural()),
            Page::App(i) => reg.apps.get(i).map(|a| a.name.clone()).unwrap_or_default(),
            Page::Security => String::from("Security"),
            Page::Log => String::from("Activity Log"),
        }
    }
    pub fn parent_title(&self, reg: &Registry) -> String {
        if self.nav.len() < 2 { return String::new(); }
        let mut p = Privacy::new(); p.nav = self.nav[..self.nav.len() - 1].to_vec(); p.title(reg)
    }

    pub fn draw(&mut self, cx: &mut Ctx, f: &mut Form) {
        self.t.update(cx.io.dt);
        let tt = self.t.x.clamp(0.0, 1.0);
        f.x += (1.0 - tt) * 36.0 * self.dir;
        match self.cur() {
            Page::Home => self.home(cx, f),
            Page::Perm(p) => self.perm_page(cx, f, p),
            Page::Class(c) => self.class_page(cx, f, c),
            Page::App(i) => self.app_page(cx, f, i),
            Page::Security => self.security(cx, f),
            Page::Log => self.log(cx, f),
        }
        f.x -= (1.0 - tt) * 36.0 * self.dir;
    }

    // ───────── Home ─────────
    fn home(&mut self, cx: &mut Ctx, f: &mut Form) {
        let (a, k, d) = cx.sys.reg.totals();
        let (na, nc, nd) = (cx.sys.reg.of_class(AppClass::Gui).len(), cx.sys.reg.of_class(AppClass::Cli).len(), cx.sys.reg.of_class(AppClass::Driver).len());
        let lock = cx.sys.reg.lockdown;
        let r = Rect::new(f.x, f.y, f.w, 124.0);
        cx.group_box(r);
        let sr = Rect::new(r.x + 18.0, r.y + 18.0, 56.0, 56.0);
        cx.cv.fill_rrect(sr, 15.0, Paint::VGrad { y0: sr.y, y1: sr.bottom(), c0: Color::hex(0x5AC8FA), c1: Color::hex(0x0A6CFF) });
        draw_icon(cx.cv, Icon::Shield, sr.inset(13.0), Color::WHITE);
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text(r.x + 90.0, r.y + 40.0, if lock { "Lockdown Mode is on" } else { "Your privacy is protected" }, 16.0, Weight::Bold, lc);
        cx.text(r.x + 90.0, r.y + 60.0, &format!("{} apps · {} command-line tools · {} drivers", na, nc, nd), 12.0, Weight::Regular, l2);
        let cols = [("Allowed", a, PS_COL[0]), ("Asking", k, PS_COL[1]), ("Denied", d, PS_COL[2])];
        for (i, (l, n, c)) in cols.iter().enumerate() {
            let x = r.x + 18.0 + i as f32 * (r.w - 36.0) / 3.0;
            cx.cv.fill_circle(x + 5.0, r.y + 96.0, 4.0, Color::hex(*c));
            cx.text(x + 16.0, r.y + 100.0, &format!("{}", n), 14.0, Weight::Bold, lc);
            let nw = cx.measure(&format!("{}", n), 14.0, Weight::Bold);
            cx.text(x + 20.0 + nw, r.y + 100.0, l, 12.0, Weight::Regular, l2);
        }
        f.y += 124.0 + 18.0;

        cx.heading(f, "Applications & Drivers");
        let mut g = cx.group_begin(f, 3, 52.0);
        for c in AppClass::ALL {
            let n = cx.sys.reg.of_class(c).len();
            let (_, ask, deny) = cx.sys.reg.class_counts(c);
            let v = format!("{} · {} asking · {} denied", if n == 1 { String::from("1 item") } else { format!("{} items", n) }, ask, deny);
            if nav_row(cx, &mut g, c.plural(), c.icon(), c.color(), c.plural(), &v) { self.push(Page::Class(c)); }
        }
        cx.caption(f, "Graphical apps live in /Applications, command-line tools in /CLI Applications and kernel drivers in /Drivers — the same folders you see in Files.");

        for (sec, lo, hi) in SECTIONS.iter() {
            cx.heading(f, sec);
            let mut g = cx.group_begin(f, hi - lo, 48.0);
            for p in ALL_PERMS[*lo..*hi].iter() {
                let (aa, kk, dd) = cx.sys.reg.perm_counts(*p);
                let tot = aa + kk + dd;
                let v = if tot == 0 { String::from("No requests") } else { format!("{} app{}", tot, if tot == 1 { "" } else { "s" }) };
                if nav_row(cx, &mut g, p.name(), p.icon(), p.color(), p.name(), &v) { self.push(Page::Perm(*p)); }
            }
        }

        cx.heading(f, "Security");
        let mut g = cx.group_begin(f, 2, 52.0);
        let lv = if lock { "Lockdown on" } else { "Standard" };
        if nav_row(cx, &mut g, "sec_page", Icon::Lock, 0x5E5CE6, "Security & Lockdown", lv) { self.push(Page::Security); }
        let ne = cx.sys.reg.log.len();
        if nav_row(cx, &mut g, "log_page", Icon::Clock, 0x8E8E93, "Activity Log", &format!("{} event{}", ne, if ne == 1 { "" } else { "s" })) { self.push(Page::Log); }

        cx.heading(f, "Service status");
        let mut g = cx.group_begin(f, 6, 44.0);
        for name in ["Anonymity Gateway", "Packet Filter", "Network kill-switch", "Telemetry service", "Hardware key manager", "Kernel duress handler"] {
            cx.row_value(&mut g, name, "Not connected to this UI build");
        }
        cx.caption(f, "These services are not controlled by the desktop preferences. The current kernel boot status is printed to the serial console.");
        cx.heading(f, "Capabilities");
        let mut g = cx.group_begin(f, 3, 44.0);
        cx.row_value(&mut g, "Capability core", "Boot self-tests; no live UI feed");
        cx.row_value(&mut g, "Physical memory", "No live UI feed");
        cx.row_value(&mut g, "Encrypted vault", "Library present; not mounted by this UI");
    }

    // ───────── by permission ─────────
    fn perm_page(&mut self, cx: &mut Ctx, f: &mut Form, p: Perm) {
        let now = cx.sys.unix_secs;
        cx.caption(f, &format!("{}. Choose which apps, tools and drivers may use this. “Ask” prompts the first time it is needed.", p.desc()));
        f.y += 4.0;
        if cx.sys.reg.lockdown { cx.caption(f, "Lockdown Mode is on: anything set to Ask is denied automatically."); }
        let users = cx.sys.reg.for_perm(p);
        if users.is_empty() { cx.heading(f, "No requests"); cx.caption(f, "No installed item has asked for this capability."); return; }
        let mut g = cx.group_begin(f, 1, 48.0);
        if let Some(s) = bulk_row(cx, &mut g, "pbulk", "Set everything to") { cx.sys.reg.set_perm_all(p, s, now); }
        for c in AppClass::ALL {
            let list: Vec<usize> = users.iter().copied().filter(|i| cx.sys.reg.apps[*i].class == c).collect();
            if list.is_empty() { continue; }
            cx.heading(f, c.plural());
            let mut g = cx.group_begin(f, list.len(), 56.0);
            for i in list {
                let r = cx.group_row(&mut g);
                let (name, sub, st, blocked) = { let a = &cx.sys.reg.apps[i]; (a.name.clone(), a.path(), a.perms[p.idx()], cx.sys.reg.blocked(i)) };
                let nr = Rect::new(r.x, r.y, r.w - 196.0, r.h);
                let h = cx.hit(id_of(&format!("pn{}_{}", p.idx(), i)), nr);
                if h.hovered { let hf = cx.th.hover_fill(); cx.cv.fill_rrect(nr.inset(1.0), 10.0, hf); }
                entry_icon(cx, i, Rect::new(r.x + 12.0, r.cy() - 16.0, 32.0, 32.0));
                let lc = cx.th.label(); let l2 = cx.th.label2();
                let nm = fit(cx, &name, 13.5, nr.w - 64.0);
                cx.text(r.x + 54.0, r.cy() - 2.0, &nm, 13.5, Weight::Regular, lc);
                let sb = fit(cx, &sub, 11.5, nr.w - 64.0);
                cx.text(r.x + 54.0, r.cy() + 13.0, &sb, 11.5, Weight::Regular, l2);
                if h.clicked { self.nav.push(Page::App(i)); self.kick(1.0); }
                if let Some(ns) = ps_control(cx, &format!("pc{}_{}", p.idx(), i), Rect::new(r.right() - 14.0 - 168.0, r.cy() - 13.0, 168.0, 26.0), st, !blocked) { cx.sys.reg.set(i, p, ns, now); }
            }
        }
    }

    // ───────── class (Applications / CLI / Drivers) ─────────
    fn class_page(&mut self, cx: &mut Ctx, f: &mut Form, c: AppClass) {
        let now = cx.sys.unix_secs;
        let (a, k, d) = cx.sys.reg.class_counts(c);
        let n = cx.sys.reg.of_class(c).len();
        let hr = Rect::new(f.x, f.y, f.w, 96.0);
        cx.group_box(hr);
        tile(cx, Rect::new(hr.x + 18.0, hr.y + 20.0, 56.0, 56.0), c.icon(), c.color());
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text(hr.x + 90.0, hr.y + 40.0, c.plural(), 17.0, Weight::Bold, lc);
        cx.text(hr.x + 90.0, hr.y + 60.0, &format!("{} items · {} allowed · {} asking · {} denied", n, a, k, d), 12.0, Weight::Regular, l2);
        cx.text(hr.x + 90.0, hr.y + 77.0, &format!("/{}", c.folder()), 11.5, Weight::Regular, l2);
        f.y += 96.0 + 18.0;
        let mut g = cx.group_begin(f, 2, 50.0);
        let r = cx.group_row(&mut g);
        let h = cx.hit(id_of("showfolder") ^ 0x3, r);
        if h.hovered { let hf = cx.th.hover_fill(); cx.cv.fill_rrect(r.inset(1.0), 10.0, hf); }
        cx.file_icon(FileKind::Folder, Rect::new(r.x + 12.0, r.cy() - 14.0, 28.0, 28.0));
        cx.text(r.x + 50.0, r.cy() + 4.7, "Show in Files", 13.5, Weight::Regular, lc);
        draw_icon(cx.cv, Icon::ChevR, Rect::new(r.right() - 26.0, r.cy() - 6.0, 12.0, 12.0), cx.th.label3());
        if h.clicked { cx.cmds.push(Cmd::OpenPath(String::from(c.folder()))); }
        if let Some(s) = bulk_row(cx, &mut g, "cbulk", "Set every permission to") { cx.sys.reg.set_class_all(c, s, now); }
        cx.heading(f, c.plural());
        let list = cx.sys.reg.of_class(c);
        let mut g = cx.group_begin(f, list.len(), 56.0);
        for i in list {
            let r = cx.group_row(&mut g);
            let (name, ok_sig, publ, ver) = { let a = &cx.sys.reg.apps[i]; (a.name.clone(), a.signed, a.publisher, a.version) };
            let (aa, kk, dd) = cx.sys.reg.apps[i].counts();
            let h = cx.hit(id_of(&format!("cl{}", i)) ^ 0x4, r);
            let hv = cx.anim(id2(id_of(&format!("cl{}", i)), 0x5), if h.hovered { 1.0 } else { 0.0 });
            if hv > 0.01 { let hf = cx.th.hover_fill().fade(hv); cx.cv.fill_rrect(r.inset(1.0), 10.0, hf); }
            entry_icon(cx, i, Rect::new(r.x + 12.0, r.cy() - 16.0, 32.0, 32.0));
            cx.text(r.x + 54.0, r.cy() - 2.0, &name, 13.5, Weight::Regular, lc);
            let sub = format!("{} · v{}", publ, ver);
            cx.text(r.x + 54.0, r.cy() + 13.0, &sub, 11.5, Weight::Regular, l2);
            if !ok_sig { let w = cx.measure("Unsigned", 11.0, Weight::Semibold) + 14.0; let br = Rect::new(r.x + r.w * 0.55 - w, r.cy() - 9.0, w, 18.0); cx.cv.fill_rrect(br, 9.0, Color::hex(0xFF9F0A).fade(0.2)); cx.text_in(br, "Unsigned", 11.0, Weight::Semibold, Color::hex(0xFF9F0A), Align::Center); }
            let mut x = r.right() - 34.0;
            for (n, col) in [(dd, PS_COL[2]), (kk, PS_COL[1]), (aa, PS_COL[0])].iter() {
                if *n == 0 { continue; }
                let w = 30.0; x -= w + 6.0;
                let br = Rect::new(x, r.cy() - 10.0, w, 20.0);
                cx.cv.fill_rrect(br, 10.0, Color::hex(*col).fade(0.18));
                cx.text_in(br, &format!("{}", n), 12.0, Weight::Semibold, Color::hex(*col), Align::Center);
            }
            draw_icon(cx.cv, Icon::ChevR, Rect::new(r.right() - 26.0, r.cy() - 6.0, 12.0, 12.0), cx.th.label3());
            if h.clicked { self.push(Page::App(i)); }
        }
    }

    // ───────── one app ─────────
    fn app_page(&mut self, cx: &mut Ctx, f: &mut Form, i: usize) {
        if i >= cx.sys.reg.apps.len() { return; }
        let now = cx.sys.unix_secs;
        let (name, class, ver, publ, signed, system, date, blurb, size) = { let a = &cx.sys.reg.apps[i]; (a.name.clone(), a.class, a.version, a.publisher, a.signed, a.system, a.date, a.blurb, a.size) };
        let path = cx.sys.reg.apps[i].path();
        let blocked = cx.sys.reg.blocked(i);
        let lc = cx.th.label(); let l2 = cx.th.label2();
        let hr = Rect::new(f.x, f.y, f.w, 132.0);
        cx.group_box(hr);
        let ir = Rect::new(hr.x + 18.0, hr.y + 20.0, 72.0, 72.0);
        cx.cv.shadow_rrect(ir.offset(0.0, 4.0), 16.0, 9.0, cx.th.shadow(0.18), false);
        entry_icon(cx, i, ir);
        cx.text(hr.x + 108.0, hr.y + 40.0, &name, 19.0, Weight::Bold, lc);
        cx.text(hr.x + 108.0, hr.y + 60.0, &format!("{} · Version {} · {}", class.singular(), ver, publ), 12.0, Weight::Regular, l2);
        cx.text(hr.x + 108.0, hr.y + 78.0, &path, 11.5, Weight::Regular, l2);
        let (lab, col) = if signed { (if system { "Signed · KashOS system" } else { "Signed developer" }, 0x30D158u32) } else { ("Unsigned", 0xFF9F0A) };
        let cw = cx.measure(lab, 11.0, Weight::Semibold) + 24.0;
        let chip = Rect::new(hr.x + 108.0, hr.y + 90.0, cw, 20.0);
        cx.cv.fill_rrect(chip, 10.0, Color::hex(col).fade(0.18));
        draw_icon(cx.cv, if signed { Icon::Check } else { Icon::Info }, Rect::new(chip.x + 6.0, chip.cy() - 6.0, 12.0, 12.0), Color::hex(col));
        cx.text(chip.x + 21.0, chip.cy() + 4.0, lab, 11.0, Weight::Semibold, Color::hex(col));
        cx.text_in(Rect::new(hr.right() - 200.0, hr.y + 16.0, 184.0, 18.0), &format!("{} · {}", fmt_sz(size), date), 11.5, Weight::Regular, l2, Align::Right);
        f.y += 132.0 + 14.0;
        cx.caption(f, blurb);
        if blocked {
            let msg = if class == AppClass::Driver { "Blocked: this driver is unsigned and your driver policy only loads signed drivers. All access is denied." } else { "Blocked: this item is unsigned and your policy only runs signed software. All access is denied." };
            let lines = cx.fonts.wrap(msg, 12.0, Weight::Regular, f.w - 60.0);
            let h = 24.0 + lines.len() as f32 * 16.0;
            let br = Rect::new(f.x, f.y, f.w, h);
            cx.cv.fill_rrect(br, 12.0, Color::hex(0xFF453A).fade(0.14));
            draw_icon(cx.cv, Icon::Info, Rect::new(br.x + 12.0, br.y + 12.0, 16.0, 16.0), Color::hex(0xFF453A));
            for (k, l) in lines.iter().enumerate() { cx.text(br.x + 38.0, br.y + 24.0 + k as f32 * 16.0, l, 12.0, Weight::Regular, lc); }
            f.y += h + 10.0;
            let mut g = cx.group_begin(f, 1, 50.0);
            let r = nav_row(cx, &mut g, "to_security", Icon::Lock, 0x5E5CE6, "Change policy in Security", "");
            if r { self.nav.clear(); self.nav.push(Page::Home); self.nav.push(Page::Security); self.kick(1.0); }
        }
        let mut g = cx.group_begin(f, 2, 50.0);
        let r = cx.group_row(&mut g);
        let h = cx.hit(id_of("appfolder") ^ 0x3, r);
        if h.hovered { let hf = cx.th.hover_fill(); cx.cv.fill_rrect(r.inset(1.0), 10.0, hf); }
        cx.file_icon(FileKind::Folder, Rect::new(r.x + 12.0, r.cy() - 14.0, 28.0, 28.0));
        cx.text(r.x + 50.0, r.cy() + 4.7, &format!("Show in Files — /{}", class.folder()), 13.5, Weight::Regular, lc);
        draw_icon(cx.cv, Icon::ChevR, Rect::new(r.right() - 26.0, r.cy() - 6.0, 12.0, 12.0), cx.th.label3());
        if h.clicked { cx.cmds.push(Cmd::OpenPath(String::from(class.folder()))); }
        if let Some(s) = bulk_row(cx, &mut g, "abulk", "Set every permission to") { cx.sys.reg.set_app_all(i, s, now); }

        let declared = cx.sys.reg.apps[i].declared();
        if declared == 0 { cx.heading(f, "Access"); cx.caption(f, "This item doesn’t request any special access."); return; }
        for (sec, lo, hi) in SECTIONS.iter() {
            let ps: Vec<Perm> = ALL_PERMS[*lo..*hi].iter().copied().filter(|p| cx.sys.reg.apps[i].perms[p.idx()] != PS::NA).collect();
            if ps.is_empty() { continue; }
            cx.heading(f, sec);
            let mut g = cx.group_begin(f, ps.len(), 58.0);
            for p in ps {
                let r = cx.group_row(&mut g);
                let st = cx.sys.reg.apps[i].perms[p.idx()];
                tile(cx, Rect::new(r.x + 12.0, r.cy() - 14.0, 28.0, 28.0), p.icon(), p.color());
                cx.text(r.x + 52.0, r.cy() - 2.0, p.name(), 13.5, Weight::Regular, lc);
                let d = fit(cx, p.desc(), 11.5, r.w - 52.0 - 196.0);
                cx.text(r.x + 52.0, r.cy() + 13.0, &d, 11.5, Weight::Regular, l2);
                if let Some(ns) = ps_control(cx, &format!("ac{}_{}", i, p.idx()), Rect::new(r.right() - 14.0 - 168.0, r.cy() - 13.0, 168.0, 26.0), st, !blocked) { cx.sys.reg.set(i, p, ns, now); }
            }
        }
        if cx.sys.reg.lockdown { cx.caption(f, "Lockdown Mode is on: permissions set to Ask are treated as Denied."); }
    }

    // ───────── security ─────────
    fn security(&mut self, cx: &mut Ctx, f: &mut Form) {
        let now = cx.sys.unix_secs;
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.heading(f, "Allow applications from");
        let mut g = cx.group_begin(f, 1, 56.0);
        let r = cx.group_row(&mut g);
        cx.text(r.x + 14.0, r.cy() + 4.7, "Applications & tools", 13.5, Weight::Regular, lc);
        let mut sel = cx.sys.reg.app_policy;
        if cx.segmented("pol_app", Rect::new(r.right() - 14.0 - 290.0, r.cy() - 14.0, 290.0, 28.0), &["KashOS only", "Identified", "Anywhere"], &mut sel) { cx.sys.reg.app_policy = sel; cx.sys.reg.rev += 1; cx.cmds.push(Cmd::Toast(String::from("Application policy updated"))); }
        cx.caption(f, match cx.sys.reg.app_policy { 0 => "Only software signed by KashOS can run.", 1 => "Software signed by an identified developer can run. Unsigned software is blocked.", _ => "Any software can run, including unsigned code. Not recommended." });
        cx.heading(f, "Allow drivers from");
        let mut g = cx.group_begin(f, 1, 56.0);
        let r = cx.group_row(&mut g);
        cx.text(r.x + 14.0, r.cy() + 4.7, "Kernel drivers", 13.5, Weight::Regular, lc);
        let mut sel = cx.sys.reg.driver_policy;
        if cx.segmented("pol_drv", Rect::new(r.right() - 14.0 - 290.0, r.cy() - 14.0, 290.0, 28.0), &["KashOS only", "Identified", "Anywhere"], &mut sel) { cx.sys.reg.driver_policy = sel; cx.sys.reg.rev += 1; cx.cmds.push(Cmd::Toast(String::from("Driver policy updated"))); }
        cx.caption(f, "Drivers run with kernel-adjacent privileges. Each one only holds the capabilities listed in Privacy & Security → Drivers.");
        cx.heading(f, "Accessories");
        let mut g = cx.group_begin(f, 1, 56.0);
        let r = cx.group_row(&mut g);
        cx.text(r.x + 14.0, r.cy() + 4.7, "Allow accessories to connect", 13.5, Weight::Regular, lc);
        let mut sel = cx.sys.reg.accessories;
        if cx.segmented("pol_acc", Rect::new(r.right() - 14.0 - 290.0, r.cy() - 14.0, 290.0, 28.0), &["Ask each time", "When unlocked", "Always"], &mut sel) { cx.sys.reg.accessories = sel; cx.sys.reg.rev += 1; }
        cx.heading(f, "Lockdown Mode");
        let mut g = cx.group_begin(f, 1, 60.0);
        let mut on = cx.sys.reg.lockdown;
        if cx.row_toggle(&mut g, "lockdown", "Lockdown Mode", "Deny every prompt automatically · block unsigned code", &mut on) { cx.sys.reg.lockdown = on; cx.sys.reg.rev += 1; cx.cmds.push(Cmd::Toast(String::from(if on { "Lockdown Mode on" } else { "Lockdown Mode off" }))); }
        cx.caption(f, "This policy affects the UI app catalog only. It is not enforced by kernel capabilities or a process sandbox.");

        cx.heading(f, "Security mechanisms");
        let mut g = cx.group_begin(f, 4, 44.0);
        for name in ["TRESOR key staging", "Memory scrub on shutdown", "USB data-line gating", "Authenticated vault mount"] {
            cx.row_value(&mut g, name, "Not controlled by this UI build");
        }
        cx.caption(f, "KashOS is a prototype kernel. These rows are informational; this page cannot enable hardware security features.");

        cx.heading(f, "Installation");
        let mut g = cx.group_begin(f, 1, 60.0);
        let r = cx.group_row(&mut g);
        cx.text(r.x + 14.0, r.cy() - 2.0, "Disk installation", 13.5, Weight::Regular, lc);
        cx.text(r.x + 14.0, r.cy() + 13.0, "Installer is not implemented", 11.5, Weight::Regular, l2);
        cx.text_in(Rect::new(r.right() - 150.0, r.y, 136.0, r.h), "Unavailable", 12.5, Weight::Medium, l2, Align::Right);
        cx.caption(f, "This build boots from a test image. It does not partition or install to a physical disk.");

        cx.heading(f, "Reset");
        let mut g = cx.group_begin(f, 1, 56.0);
        let r = cx.group_row(&mut g);
        cx.text(r.x + 14.0, r.cy() - 2.0, "Reset all permissions", 13.5, Weight::Regular, lc);
        cx.text(r.x + 14.0, r.cy() + 13.0, "Restore factory permissions for every app, tool and driver", 11.5, Weight::Regular, l2);
        if !self.confirm_reset {
            if cx.button("reset_ask", Rect::new(r.right() - 14.0 - 90.0, r.cy() - 13.0, 90.0, 26.0), "Reset…", false) { self.confirm_reset = true; }
        } else {
            if cx.button("reset_no", Rect::new(r.right() - 14.0 - 170.0, r.cy() - 13.0, 80.0, 26.0), "Cancel", false) { self.confirm_reset = false; }
            if cx.button("reset_yes", Rect::new(r.right() - 14.0 - 80.0, r.cy() - 13.0, 80.0, 26.0), "Reset", true) { cx.sys.reg.reset(now); self.confirm_reset = false; cx.cmds.push(Cmd::Toast(String::from("All permissions were reset"))); }
        }
    }

    // ───────── log ─────────
    fn log(&mut self, cx: &mut Ctx, f: &mut Form) {
        let now = cx.sys.unix_secs;
        let lc = cx.th.label(); let l2 = cx.th.label2();
        let entries: Vec<(String, PS, i64)> = cx.sys.reg.log.iter().map(|e| (e.text.clone(), e.state, e.t)).collect();
        if entries.is_empty() { cx.caption(f, "No permission changes yet. Changes you make here and answers to prompts appear in this list."); return; }
        let mut g = cx.group_begin(f, entries.len(), 44.0);
        for (t, st, at) in entries {
            let r = cx.group_row(&mut g);
            let col = PS_COL[ps_idx(st)];
            cx.cv.fill_circle(r.x + 22.0, r.cy(), 5.0, Color::hex(col));
            let tx = fit(cx, &t, 13.0, r.w - 150.0);
            cx.text(r.x + 40.0, r.cy() + 4.5, &tx, 13.0, Weight::Regular, lc);
            cx.text_in(Rect::new(r.right() - 120.0, r.y, 106.0, r.h), &ago(now, at), 11.5, Weight::Regular, l2, Align::Right);
        }
    }
}

fn fmt_sz(b: u64) -> String { if b < 1_000_000 { format!("{} KB", b / 1000) } else { format!("{:.1} MB", b as f32 / 1e6) } }
