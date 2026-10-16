//! The Dock: floating glass pill — pinned apps, a recent-apps section, Downloads stack, Trash, right-click menus,
//! spring-driven magnification, bounce and tooltips.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::color::*;
use crate::geom::*;
use crate::icons::*;
use crate::mathf::*;
use crate::registry::*;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;

pub const DEFAULT_PINNED: [AppKind; 8] = [AppKind::Files, AppKind::Browser, AppKind::Messages, AppKind::Photos, AppKind::Music, AppKind::Notes, AppKind::Terminal, AppKind::Settings];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Item { Launchpad, App(AppKind), Downloads, Trash }
impl Item {
    fn id(self) -> u32 { match self { Item::Launchpad => 100, Item::App(k) => k as u32, Item::Downloads => 101, Item::Trash => 102 } }
    fn name(self) -> &'static str { match self { Item::Launchpad => "Launchpad", Item::App(k) => k.name(), Item::Downloads => "Downloads", Item::Trash => "Trash" } }
}

struct Slot { id: u32, scale: Spring, bounce: Spring, press: Spring, grow: Spring }

#[derive(Clone, PartialEq)]
enum Act { Keep(AppKind), Unkeep(AppKind), Open(AppKind), Quit(AppKind), Show(&'static str), Perms(String), Launchpad, DlOpen, DlView(usize), DlClear, TrashOpen, TrashEmpty }
struct Row { label: String, act: Option<Act>, check: bool, sep: bool, danger: bool }
impl Row {
    fn head(s: &str) -> Row { Row { label: String::from(s), act: None, check: false, sep: false, danger: false } }
    fn act(s: &str, a: Act) -> Row { Row { label: String::from(s), act: Some(a), check: false, sep: false, danger: false } }
    fn chk(s: &str, a: Act, on: bool) -> Row { Row { label: String::from(s), act: Some(a), check: on, sep: false, danger: false } }
    fn bad(s: &str, a: Act) -> Row { Row { label: String::from(s), act: Some(a), check: false, sep: false, danger: true } }
    fn sep() -> Row { Row { label: String::new(), act: None, check: false, sep: true, danger: false } }
    fn h(&self) -> f32 { if self.sep { 11.0 } else if self.act.is_none() { 30.0 } else { 30.0 } }
}
struct Menu { id: u32, rows: Vec<Row>, t: Spring, open: bool, ax: f32, press: Option<usize>, rect: Rect }

struct Entry { name: String, kind: FileKind, size: u64, date: String, prog: Option<f32> }

pub struct Dock {
    slots: Vec<Slot>,
    inited: bool,
    hide: Spring,
    pub rect: Rect,
    icons: Vec<(u32, Rect)>,
    tip_t: Spring,
    tip_id: u32,
    tip_x: f32,
    pressed: Option<u32>,
    pub active: bool,
    pub pinned: Vec<AppKind>,
    menu: Option<Menu>,
    stack: Spring,
    stack_open: bool,
    stack_hover: Option<usize>,
    popup: Rect,
}

fn fmt_size(b: u64) -> String {
    if b == 0 { return String::from("--"); }
    if b < 1_000_000 { format!("{:.0} KB", b as f32 / 1000.0) } else if b < 1_000_000_000 { format!("{:.1} MB", b as f32 / 1e6) } else { format!("{:.2} GB", b as f32 / 1e9) }
}

impl Dock {
    pub fn new() -> Dock {
        Dock { slots: Vec::new(), inited: false, hide: Spring::new(0.0, 0.4, 0.9), rect: Rect::ZERO, icons: Vec::new(), tip_t: Spring::new(0.0, 0.16, 1.0), tip_id: 0, tip_x: 0.0,
            pressed: None, active: false, pinned: DEFAULT_PINNED.to_vec(), menu: None, stack: Spring::new(0.0, 0.34, 0.8), stack_open: false, stack_hover: None, popup: Rect::ZERO }
    }

    pub fn busy(&self) -> bool {
        self.hide.x.abs() > 0.0005 && !self.hide.settled() || !self.tip_t.settled() || !self.stack.settled()
            || self.menu.as_ref().map(|m| !m.t.settled()).unwrap_or(false)
            || self.slots.iter().any(|s| !s.scale.settled() || s.bounce.x.abs() > 0.35 || s.bounce.v.abs() > 8.0 || !s.press.settled() || !s.grow.settled())
    }
    pub fn dbg(&self) -> alloc::string::String {
        use alloc::format;
        let mut o = alloc::string::String::new();
        if !self.tip_t.settled() { o.push_str("tip "); } if !self.stack.settled() { o.push_str("stack "); }
        if self.hide.x.abs() > 0.0005 && !self.hide.settled() { o.push_str("hide "); }
        for (i, s) in self.slots.iter().enumerate() { for (n, sp) in [("scale", &s.scale), ("press", &s.press), ("grow", &s.grow)] { if !sp.settled() { o.push_str(&format!("s{}.{}={:.3}/{:.3} ", i, n, sp.x, sp.target)); } } }
        o
    }
    pub fn popup_open(&self) -> bool { self.menu.is_some() || self.stack_open || self.stack.x > 0.01 }
    pub fn popup_contains(&self, p: Pt) -> bool { self.popup_open() && self.popup.inset(-6.0).contains(p.x, p.y) }
    pub fn zone(&self, screen: Rect) -> Rect {
        let base = Rect::new(self.rect.x - 80.0, self.rect.y - 110.0, self.rect.w + 160.0, screen.bottom() - self.rect.y + 110.0);
        if self.popup_open() && self.popup.w > 0.0 { base.union(&self.popup.inset(-12.0)) } else { base }
    }
    fn slot_idx(&mut self, id: u32) -> usize {
        if let Some(i) = self.slots.iter().position(|s| s.id == id) { return i; }
        let g0 = if self.inited { 0.0 } else { 1.0 };
        self.slots.push(Slot { id, scale: Spring::new(1.0, 0.17, 0.95), bounce: Spring::new(0.0, 0.55, 0.30), press: Spring::new(1.0, 0.15, 0.9), grow: Spring::new(g0, 0.36, 0.78) });
        self.slots.len() - 1
    }
    pub fn bounce_kind(&mut self, k: AppKind) { let i = self.slot_idx(k as u32); self.slots[i].bounce.snap(0.0); self.slots[i].bounce.kick(430.0); }
    /// Screen-space centre of an icon (genie target).
    pub fn icon_center(&self, kind: AppKind, screen: Rect) -> Pt {
        if let Some((_, r)) = self.icons.iter().find(|(id, _)| *id == kind as u32) { return Pt::new(r.cx(), r.cy()); }
        Pt::new(screen.cx(), screen.bottom() - 40.0)
    }
    pub fn center_of(&self, id: u32, screen: Rect) -> Pt { if let Some((_, r)) = self.icons.iter().find(|(i, _)| *i == id) { Pt::new(r.cx(), r.cy()) } else { Pt::new(screen.cx(), screen.bottom() - 40.0) } }
    pub fn is_pinned(&self, k: AppKind) -> bool { self.pinned.iter().any(|p| *p == k) }

    fn build_menu(&self, cx: &Ctx, item: Item, running: &[AppKind]) -> Vec<Row> {
        let mut v = Vec::new();
        v.push(Row::head(item.name()));
        match item {
            Item::App(k) => {
                let run = running.contains(&k);
                v.push(if self.is_pinned(k) { Row::act("Remove from Dock", Act::Unkeep(k)) } else { Row::act("Keep in Dock", Act::Keep(k)) });
                v.push(Row::act("Show in Files", Act::Show("Applications")));
                if cx.sys.reg.find_name(k.name()).is_some() { v.push(Row::act("Permissions…", Act::Perms(String::from(k.name())))); }
                v.push(Row::sep());
                v.push(if run { Row::bad("Quit", Act::Quit(k)) } else { Row::act("Open", Act::Open(k)) });
            }
            Item::Launchpad => { v.push(Row::act("Open Launchpad", Act::Launchpad)); }
            Item::Downloads => {
                v.push(Row::act("Open in Files", Act::DlOpen)); v.push(Row::sep());
                let sv = cx.sys.stack_view;
                v.push(Row::chk("View as Fan", Act::DlView(0), sv == 0)); v.push(Row::chk("View as Grid", Act::DlView(1), sv == 1)); v.push(Row::chk("View as List", Act::DlView(2), sv == 2));
                v.push(Row::sep()); v.push(Row::bad("Clear Downloads", Act::DlClear));
            }
            Item::Trash => { v.push(Row::act("Open Trash", Act::TrashOpen)); v.push(Row::sep()); v.push(Row::bad("Empty Trash", Act::TrashEmpty)); }
        }
        v
    }

    fn run(&mut self, a: Act, cx: &mut Ctx) {
        match a {
            Act::Keep(k) => { if !self.is_pinned(k) { self.pinned.push(k); } }
            Act::Unkeep(k) => { self.pinned.retain(|p| *p != k); }
            Act::Open(k) => cx.cmds.push(Cmd::Open(k)),
            Act::Quit(k) => cx.cmds.push(Cmd::Quit(k)),
            Act::Show(p) => cx.cmds.push(Cmd::OpenPath(String::from(p))),
            Act::Perms(n) => cx.cmds.push(Cmd::OpenPermissions(n)),
            Act::Launchpad => cx.cmds.push(Cmd::Launchpad),
            Act::DlOpen => cx.cmds.push(Cmd::OpenPath(String::from("Downloads"))),
            Act::DlView(v) => { cx.sys.stack_view = v; }
            Act::DlClear => { cx.sys.reg.clear_downloads(); cx.cmds.push(Cmd::Toast(String::from("Downloads cleared"))); }
            Act::TrashOpen => cx.cmds.push(Cmd::Toast(String::from("Trash is empty"))),
            Act::TrashEmpty => cx.cmds.push(Cmd::Toast(String::from("Trash is already empty"))),
        }
    }

    pub fn update_draw(&mut self, cx: &mut Ctx, running: &[AppKind], recents: &[AppKind], screen: Rect, hot: bool) {
        let th = *cx.th;
        let dt = cx.io.dt;
        let dark = th.is_dark();
        // ── model ──
        let mut items: Vec<Item> = Vec::new();
        let mut divs: Vec<usize> = Vec::new();
        items.push(Item::Launchpad);
        for k in self.pinned.iter() { items.push(Item::App(*k)); }
        if cx.sys.dock_recents && !recents.is_empty() { divs.push(items.len()); for k in recents.iter() { items.push(Item::App(*k)); } }
        divs.push(items.len());
        if cx.sys.dock_downloads { items.push(Item::Downloads); }
        items.push(Item::Trash);
        let n = items.len();
        let mut sidx: Vec<usize> = Vec::with_capacity(n);
        for it in items.iter() { let i = self.slot_idx(it.id()); sidx.push(i); }
        for s in self.slots.iter_mut() { let live = items.iter().any(|it| it.id() == s.id); s.grow.set(if live { 1.0 } else { 0.0 }); }
        self.inited = true;

        let base = 38.0 + cx.sys.dock_size * 46.0;
        let pad = 10.0; let gap = 8.0; let sep = 22.0;
        let maxs = if cx.sys.dock_magnify_on { 1.0 + 0.25 + 0.85 * cx.sys.dock_magnify } else { 1.0 };
        let ndiv = divs.len() as f32;
        let total0 = n as f32 * base + (n as f32 - 1.0) * gap + sep * ndiv;
        let start0 = screen.cx() - total0 * 0.5;
        let base_cx = |i: usize| -> f32 { let nd = divs.iter().filter(|d| **d <= i).count() as f32; start0 + i as f32 * (base + gap) + base * 0.5 + nd * sep };
        let pill_h = base + pad * 2.0;
        let pill_y0 = screen.bottom() - 10.0 - pill_h;
        let near = cx.io.mouse.y > screen.bottom() - 8.0 || (self.rect.h > 0.0 && cx.io.mouse.y > self.rect.y - 6.0 && cx.io.mouse.x > self.rect.x - 30.0 && cx.io.mouse.x < self.rect.right() + 30.0);
        let hide_t = if cx.sys.dock_autohide && !near && !self.popup_open() { 1.0 } else { 0.0 };
        self.hide.set(hide_t); self.hide.update(dt);
        let hide_off = self.hide.x * (pill_h + 24.0);
        let mx = cx.io.mouse.x; let my = cx.io.mouse.y;
        let zone = Rect::new(start0 - 60.0, pill_y0 - base * 0.9 + hide_off, total0 + 120.0, pill_h + base * 0.9 + 14.0);
        self.active = hot && zone.contains(mx, my) && self.hide.x < 0.5 && self.menu.is_none();
        for i in 0..n {
            let s = &mut self.slots[sidx[i]];
            let t = if self.active && cx.sys.dock_magnify_on { let d = (mx - base_cx(i)) / base; 1.0 + (maxs - 1.0) * exp(-d * d * 0.62) } else { 1.0 };
            s.scale.set(t); s.scale.update(dt);
            s.bounce.update(dt); if s.bounce.x.abs() <= 0.35 && s.bounce.v.abs() <= 8.0 { s.bounce.snap(0.0); } s.grow.update(dt);
            let pt = if self.pressed == Some(items[i].id()) { 0.9 } else { 1.0 };
            s.press.set(pt); s.press.update(dt);
        }
        let mut widths = Vec::new(); let mut adv = Vec::new();
        let mut total = sep * ndiv;
        for i in 0..n {
            let s = &self.slots[sidx[i]];
            let g = s.grow.x.clamp(0.0, 1.0);
            let w = base * s.scale.x * g;
            widths.push(w);
            let a = w + if i + 1 < n { gap * g } else { 0.0 };
            adv.push(a); total += a;
        }
        let start = screen.cx() - total * 0.5;
        let pill = Rect::new(start - pad, pill_y0 + hide_off, total + pad * 2.0, pill_h);
        self.rect = pill;
        cx.cv.shadow_rrect(pill.offset(0.0, 8.0), 30.0, 22.0, th.shadow(0.20), true);
        cx.cv.shadow_rrect(pill.offset(0.0, 2.0), 30.0, 5.0, th.shadow(0.07), true);
        let rad = (pill_h * 0.40).min(32.0);
        cx.glass(pill, GlassKind::Clear, rad);

        // ── layout ──
        let mut x = start;
        let mut rects: Vec<Rect> = Vec::new();
        for i in 0..n {
            if divs.contains(&i) {
                let sx = x + (sep - gap - 1.2) * 0.5;
                let dh = pill.h - pad * 2.0 - 10.0;
                cx.cv.fill_rrect(Rect::new(sx, pill.cy() - dh * 0.5, 1.2, dh), 0.6, th.pick(Color::rgba(0, 0, 0, 46), Color::rgba(255, 255, 255, 64)));
                x += sep;
            }
            let s = &self.slots[sidx[i]];
            let w = widths[i];
            let sz = w * s.press.x;
            let by = pill.bottom() - pad - sz - s.bounce.x.max(0.0);
            rects.push(Rect::new(x + (w - sz) * 0.5, by, sz, sz));
            x += adv[i];
        }
        // ── input ──
        let mut new_hover: Option<usize> = None;
        if hot && self.hide.x < 0.5 {
            for (i, r) in rects.iter().enumerate() { if r.w > 8.0 && Rect::new(r.x - 2.0, pill.y, r.w + 4.0, pill.h).contains(mx, my) { new_hover = Some(i); } }
        }
        let in_menu = self.menu.as_ref().map(|m| m.rect.contains(mx, my)).unwrap_or(false);
        let in_stack = self.stack_open && self.popup.inset(-4.0).contains(mx, my);
        if cx.io.pressed && hot {
            // outside click closes popups
            if self.menu.is_some() && !in_menu { if let Some(m) = self.menu.as_mut() { m.open = false; } }
            if self.stack_open && !in_stack && new_hover.map(|i| items[i] != Item::Downloads).unwrap_or(true) { self.stack_open = false; }
            if !in_menu { self.pressed = new_hover.map(|i| items[i].id()); if new_hover.is_some() { *cx.over_widget = true; } }
        }
        if cx.io.right_pressed && hot {
            if let Some(i) = new_hover {
                let rows = self.build_menu(cx, items[i], running);
                self.stack_open = false;
                self.menu = Some(Menu { id: items[i].id(), rows, t: Spring::new(0.0, 0.26, 0.82), open: true, ax: rects[i].cx(), press: None, rect: Rect::ZERO });
                self.pressed = None;
            } else if let Some(m) = self.menu.as_mut() { m.open = false; }
        }
        let mut left_click: Option<Item> = None;
        if cx.io.released {
            if let (Some(p), Some(h)) = (self.pressed, new_hover) { if items[h].id() == p && !in_menu { left_click = Some(items[h]); } }
            self.pressed = None;
        }
        if hot && self.hide.x < 0.5 && pill.contains(mx, my) { *cx.over_widget = true; }
        if let Some(it) = left_click {
            match it {
                Item::App(k) => cx.cmds.push(Cmd::Open(k)),
                Item::Launchpad => cx.cmds.push(Cmd::Launchpad),
                Item::Downloads => { self.stack_open = !self.stack_open; self.menu = None; }
                Item::Trash => cx.cmds.push(Cmd::Toast(String::from("Trash is empty"))),
            }
        }

        // ── icons ──
        for (i, r) in rects.iter().enumerate() {
            if r.w < 2.0 { continue; }
            cx.cv.shadow_rrect(r.offset(0.0, r.h * 0.05), r.w * 0.225, r.w * 0.08 + 2.0, Color::rgba(0, 0, 0, 55), false);
            match items[i] {
                Item::App(k) => {
                    cx.app_icon(k, *r);
                    if cx.sys.dock_indicators && running.contains(&k) {
                        let c = th.pick(Color::rgba(0, 0, 0, 150), Color::rgba(255, 255, 255, 215));
                        cx.cv.fill_circle(r.cx(), pill.bottom() - 4.4, 3.4, c.fade(0.14));
                        cx.cv.fill_circle(r.cx(), pill.bottom() - 4.4, 1.9, c);
                    }
                }
                Item::Launchpad => { cx.fonts.icons.draw(cx.cv, if dark { 701 } else { 700 }, *r, 1.0, &|cv, rr| launchpad_icon(cv, rr, dark)); }
                Item::Downloads => {
                    cx.fonts.icons.draw(cx.cv, if dark { 703 } else { 702 }, *r, 1.0, &|cv, rr| downloads_icon(cv, rr, dark));
                    if let Some((_, _, _, p)) = cx.sys.reg.dl_active.as_ref() {
                        let b = Rect::new(r.x + r.w * 0.14, r.bottom() - r.h * 0.16, r.w * 0.72, 5.0);
                        cx.cv.fill_rrect(b, 2.5, Color::rgba(0, 0, 0, 90));
                        cx.cv.fill_rrect(Rect::new(b.x, b.y, b.w * p.clamp(0.0, 1.0), b.h), 2.5, Color::WHITE);
                    }
                }
                Item::Trash => cx.trash_icon(*r),
            }
        }
        self.icons.clear();
        for (i, r) in rects.iter().enumerate() { self.icons.push((items[i].id(), *r)); }

        // ── tooltip ──
        let showing_popup = self.popup_open();
        if let Some(h) = new_hover { self.tip_id = items[h].id(); self.tip_x = rects[h].cx(); }
        self.tip_t.set(if new_hover.is_some() && !showing_popup { 1.0 } else { 0.0 }); self.tip_t.update(dt);
        if self.tip_t.x > 0.02 {
            if let Some(it) = items.iter().find(|it| it.id() == self.tip_id) {
                let ir = self.icons.iter().find(|(id, _)| *id == self.tip_id).map(|(_, r)| *r).unwrap_or(pill);
                let name = it.name();
                let tw = cx.measure(name, 13.0, Weight::Medium) + 26.0;
                let t = saturate(self.tip_t.x);
                let tr = Rect::new(ir.cx() - tw * 0.5, ir.y.min(pill.y) - 38.0 + (1.0 - t) * 6.0, tw, 28.0);
                cx.cv.shadow_rrect(tr.offset(0.0, 4.0), 12.0, 10.0, th.shadow(0.20 * t), false);
                let mut st = th.glass(GlassKind::Tooltip, 14.0);
                st.tint.a = (st.tint.a as f32 * t) as u8;
                cx.glass_style(tr, &st);
                cx.text_in(tr, name, 13.0, Weight::Medium, th.label().fade(t), Align::Center);
            }
        }

        self.popup = Rect::ZERO;
        self.draw_stack(cx, &items, &rects, pill, screen, hot);
        self.draw_menu(cx, pill, screen, hot);
    }

    fn entries(cx: &Ctx, cap: usize) -> Vec<Entry> {
        let mut v = Vec::new();
        if let Some((n, k, s, p)) = cx.sys.reg.dl_active.as_ref() { v.push(Entry { name: n.clone(), kind: *k, size: *s, date: String::from("Downloading…"), prog: Some(*p) }); }
        for d in cx.sys.reg.downloads.iter() { if v.len() >= cap { break; } v.push(Entry { name: d.name.clone(), kind: d.kind, size: d.size, date: d.date.clone(), prog: None }); }
        v
    }

    fn draw_stack(&mut self, cx: &mut Ctx, items: &[Item], rects: &[Rect], pill: Rect, screen: Rect, hot: bool) {
        self.stack.set(if self.stack_open { 1.0 } else { 0.0 }); self.stack.update(cx.io.dt);
        if self.stack.x < 0.01 && !self.stack_open { self.stack_hover = None; return; }
        let th = *cx.th;
        let di = match items.iter().position(|i| *i == Item::Downloads) { Some(i) => i, None => { self.stack_open = false; return; } };
        let ir = rects[di];
        let t = self.stack.x.clamp(0.0, 1.2);
        let ts = saturate(t);
        let view = cx.sys.stack_view;
        let (mx, my) = (cx.io.mouse.x, cx.io.mouse.y);
        let mut clicked = false;
        let mut hov: Option<usize> = None;
        let anchor_y = pill.y - 14.0;
        let ents = Dock::entries(cx, if view == 0 { 7 } else if view == 1 { 9 } else { 8 });
        if view == 0 {
            // ── fan: icons rise from the Downloads tile along a gentle arc, names to their left ──
            let mut bbox = Rect::new(ir.x, ir.y, ir.w, ir.h);
            let mut n = ents.len();
            let total = n + 1; // + "Open in Files"
            let mut all: Vec<(String, FileKind, Option<f32>)> = ents.iter().map(|e| (e.name.clone(), e.kind, e.prog)).collect();
            all.push((String::from("Open in Files"), FileKind::Folder, None));
            n = all.len();
            let _ = total;
            for (j, (name, kind, prog)) in all.iter().enumerate() {
                let tj = saturate(t * 1.5 - j as f32 * 0.07);
                let ez = 1.0 - (1.0 - tj) * (1.0 - tj) * (1.0 - tj);
                let sz = 46.0;
                let fj = j as f32;
                let ty = anchor_y - 28.0 - fj * 52.0;
                let tx = ir.cx() - (fj * fj) * 2.6 - fj * 2.0;
                let (px, py) = (lerp(ir.cx(), tx, ez), lerp(ir.cy(), ty, ez));
                let r = Rect::new(px - sz * 0.5, py - sz * 0.5, sz, sz);
                bbox = bbox.union(&r);
                let lw = cx.measure(name, 13.0, Weight::Medium) + 22.0;
                let lr = Rect::new(r.x - 12.0 - lw, r.cy() - 13.0, lw, 26.0);
                bbox = bbox.union(&lr);
                let hit = Rect::new(lr.x, r.y - 2.0, r.right() - lr.x, r.h + 4.0);
                let hv = hot && ts > 0.6 && hit.contains(mx, my);
                if hv { hov = Some(j); }
                let sc = if hv { 1.12 } else { 1.0 };
                let rr = Rect::new(r.cx() - sz * sc * 0.5, r.cy() - sz * sc * 0.5, sz * sc, sz * sc);
                cx.cv.shadow_rrect(rr.offset(0.0, 3.0), 10.0, 8.0, Color::rgba(0, 0, 0, (70.0 * ez) as u8), false);
                cx.file_icon(*kind, rr);
                if let Some(p) = prog { let b = Rect::new(rr.x + 4.0, rr.bottom() - 7.0, rr.w - 8.0, 4.0); cx.cv.fill_rrect(b, 2.0, Color::rgba(0, 0, 0, 90)); cx.cv.fill_rrect(Rect::new(b.x, b.y, b.w * p, 4.0), 2.0, th.accent()); }
                let mut st = th.glass(GlassKind::Tooltip, 13.0);
                st.tint.a = (st.tint.a as f32 * ez) as u8;
                cx.cv.shadow_rrect(lr.offset(0.0, 3.0), 13.0, 8.0, th.shadow(0.18 * ez), false);
                cx.glass_style(lr, &st);
                cx.text_in(lr, name, 13.0, Weight::Medium, th.label().fade(ez), Align::Center);
                let _ = n;
            }
            self.popup = bbox;
            if hot && bbox.contains(mx, my) { *cx.over_widget = true; }
            if cx.io.released && hot { if let Some(j) = hov { clicked = true; let _ = j; } }
        } else {
            // ── grid / list: a glass popover anchored above the tile ──
            let (w, h);
            let cols = 3usize; let cw = 88.0; let ch = 94.0; let rh = 40.0;
            let rows = if view == 1 { (ents.len().max(1) + cols - 1) / cols } else { ents.len().max(1) };
            if view == 1 { w = cols as f32 * cw + 24.0; h = rows as f32 * ch + 24.0 + 44.0; } else { w = 300.0; h = rows as f32 * rh + 16.0 + 44.0; }
            let x = (ir.cx() - w * 0.5).clamp(10.0, screen.w - w - 10.0);
            let y = anchor_y - h + (1.0 - ts) * 16.0;
            let pr = Rect::new(x, y, w, h);
            self.popup = pr;
            if hot && pr.contains(mx, my) { *cx.over_widget = true; }
            cx.cv.shadow_rrect(pr.offset(0.0, 10.0), 26.0, 26.0, th.shadow(0.24 * ts), true);
            let mut st = th.glass(GlassKind::Popover, 26.0);
            st.tint.a = (st.tint.a as f32 * ts) as u8;
            cx.glass_style(pr, &st);
            cx.cv.push_clip(pr);
            if ents.is_empty() { cx.text_in(Rect::new(pr.x, pr.y, pr.w, pr.h - 44.0), "No recent downloads", 13.0, Weight::Medium, th.label3().fade(ts), Align::Center); }
            for (j, e) in ents.iter().enumerate() {
                if view == 1 {
                    let (c, r_) = (j % cols, j / cols);
                    let cell = Rect::new(pr.x + 12.0 + c as f32 * cw, pr.y + 12.0 + r_ as f32 * ch, cw, ch);
                    let hv = hot && ts > 0.6 && cell.contains(mx, my);
                    if hv { hov = Some(j); cx.cv.fill_rrect(cell.inset(3.0), 14.0, th.hover_fill()); }
                    cx.file_icon(e.kind, Rect::new(cell.cx() - 26.0, cell.y + 8.0, 52.0, 52.0));
                    let nm = cx.fonts.fit(&e.name, 11.5, Weight::Regular, cw - 10.0);
                    cx.text_in(Rect::new(cell.x, cell.y + 64.0, cell.w, 16.0), &nm, 11.5, Weight::Regular, th.label().fade(ts), Align::Center);
                    if let Some(p) = e.prog { let b = Rect::new(cell.x + 14.0, cell.y + 84.0, cell.w - 28.0, 4.0); cx.cv.fill_rrect(b, 2.0, th.control_fill()); cx.cv.fill_rrect(Rect::new(b.x, b.y, b.w * p, 4.0), 2.0, th.accent()); }
                } else {
                    let row = Rect::new(pr.x + 8.0, pr.y + 8.0 + j as f32 * rh, pr.w - 16.0, rh);
                    let hv = hot && ts > 0.6 && row.contains(mx, my);
                    if hv { hov = Some(j); cx.cv.fill_rrect(row, 10.0, th.hover_fill()); }
                    cx.file_icon(e.kind, Rect::new(row.x + 6.0, row.y + 5.0, 30.0, 30.0));
                    let nm = cx.fonts.fit(&e.name, 13.0, Weight::Medium, row.w - 130.0);
                    cx.text(row.x + 46.0, row.cy() - 2.0, &nm, 13.0, Weight::Medium, th.label().fade(ts));
                    let sub = if let Some(p) = e.prog { format!("{}%", (p * 100.0) as i32) } else { format!("{}", e.date) };
                    cx.text(row.x + 46.0, row.cy() + 12.0, &sub, 11.0, Weight::Regular, th.label2().fade(ts));
                    cx.text_in(Rect::new(row.right() - 84.0, row.y, 76.0, row.h), &fmt_size(e.size), 11.5, Weight::Regular, th.label2().fade(ts), Align::Right);
                }
            }
            // footer
            let fr = Rect::new(pr.x + 10.0, pr.bottom() - 40.0, pr.w - 20.0, 32.0);
            cx.separator_h(pr.x + 14.0, pr.right() - 14.0, fr.y - 4.0);
            let fh = hot && ts > 0.6 && fr.contains(mx, my);
            if fh { hov = Some(usize::MAX); cx.cv.fill_rrect(fr, 10.0, th.hover_fill()); }
            cx.file_icon(FileKind::Folder, Rect::new(fr.x + 6.0, fr.y + 4.0, 24.0, 24.0));
            cx.text(fr.x + 38.0, fr.cy() + 4.5, "Open in Files", 13.0, Weight::Medium, th.label().fade(ts));
            cx.cv.pop_clip();
            if cx.io.released && hot && hov.is_some() { clicked = true; }
        }
        self.stack_hover = hov;
        if clicked && self.stack_open { cx.cmds.push(Cmd::OpenPath(String::from("Downloads"))); self.stack_open = false; }
    }

    fn draw_menu(&mut self, cx: &mut Ctx, pill: Rect, screen: Rect, hot: bool) {
        let th = *cx.th;
        let mut fire: Option<Act> = None;
        let mut drop_it = false;
        if let Some(m) = self.menu.as_mut() {
            m.t.set(if m.open { 1.0 } else { 0.0 }); m.t.update(cx.io.dt);
            if !m.open && m.t.x < 0.02 { drop_it = true; } else {
                let t = saturate(m.t.x);
                let w = 218.0;
                let h: f32 = m.rows.iter().map(|r| r.h()).sum::<f32>() + 16.0;
                let x = (m.ax - w * 0.5).clamp(10.0, screen.w - w - 10.0);
                let y = pill.y - 12.0 - h + (1.0 - t) * 14.0;
                let mr = Rect::new(x, y, w, h);
                m.rect = mr;
                self.popup = self.popup.union(&mr);
                if hot && mr.contains(cx.io.mouse.x, cx.io.mouse.y) { *cx.over_widget = true; }
                cx.cv.shadow_rrect(mr.offset(0.0, 10.0), 18.0, 26.0, th.shadow(0.26 * t), true);
                let mut st = th.glass(GlassKind::Popover, 18.0);
                st.tint.a = (st.tint.a as f32 * t) as u8;
                cx.glass_style(mr, &st);
                let mut yy = mr.y + 8.0;
                for (i, r) in m.rows.iter().enumerate() {
                    let rh = r.h();
                    let rr = Rect::new(mr.x + 8.0, yy, mr.w - 16.0, rh);
                    yy += rh;
                    if r.sep { cx.separator_h(rr.x + 4.0, rr.right() - 4.0, rr.cy()); continue; }
                    if r.act.is_none() { cx.text(rr.x + 8.0, rr.cy() + 4.5, &r.label, 12.5, Weight::Semibold, th.label2().fade(t)); continue; }
                    let hv = hot && t > 0.5 && rr.contains(cx.io.mouse.x, cx.io.mouse.y);
                    if hv { *cx.over_widget = true; }
                    if hv && cx.io.pressed { m.press = Some(i); }
                    if hv { cx.cv.fill_rrect(rr, 9.0, if r.danger { Color::hex(0xFF453A) } else { th.accent() }); }
                    let tc = if hv { Color::WHITE } else if r.danger { Color::hex(0xFF453A) } else { th.label() };
                    if r.check { draw_icon(cx.cv, Icon::Check, Rect::new(rr.x + 6.0, rr.cy() - 7.0, 14.0, 14.0), tc.fade(t)); }
                    cx.text(rr.x + if r.check { 26.0 } else { 10.0 }, rr.cy() + 4.7, &r.label, 13.0, Weight::Regular, tc.fade(t));
                    if cx.io.released && hv && m.press == Some(i) { fire = r.act.clone(); }
                }
                if cx.io.released { m.press = None; }
            }
        }
        if drop_it { self.menu = None; }
        if let Some(a) = fire { if let Some(m) = self.menu.as_mut() { m.open = false; } self.run(a, cx); }
    }
}
