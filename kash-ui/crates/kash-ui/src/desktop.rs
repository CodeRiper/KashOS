//! The desktop: window manager + shell. Feed it `Input` each frame, read `screen` back.
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::app::*;
use crate::apps::{about::About, files::Files, misc::*, settings::Settings, terminal::Terminal};
use crate::color::*;
use crate::cursor::draw_cursor;
use crate::geom::*;
use crate::glass::GlassScratch;
use crate::gfx::*;
use crate::icons::*;
use crate::mathf::*;
use crate::shell::{dock::*, lock::*, menubar::*, overlays::*};
use crate::text::*;
use crate::theme::*;
use crate::ui::*;
use crate::wallpaper;

pub struct Input {
    pub mouse: Pt,
    pub left: bool,
    pub wheel: Pt,
    pub keys: Vec<KeyEv>,
    pub dt: f32,
    pub right: bool,
}

#[inline] #[allow(dead_code)] fn is_focus_changed(w: &Window) -> bool { !w.focus.settled() }

fn make_app(k: AppKind) -> Box<dyn App> {
    match k {
        AppKind::Files => Box::new(Files::new()), AppKind::Settings => Box::new(Settings::new()), AppKind::Terminal => Box::new(Terminal::new()),
        AppKind::About => Box::new(About::new()), AppKind::Notes => Box::new(Notes::new()), AppKind::Browser => Box::new(Browser::new()),
        AppKind::Photos => Box::new(Photos::new()), AppKind::Music => Box::new(Music::new()), AppKind::Messages => Box::new(Messages::new()),
        AppKind::ActivityMonitor => Box::new(crate::apps::tools::ActivityMonitor::new()), AppKind::Calculator => Box::new(crate::apps::tools::Calculator::new()),
    }
}

/// Width of one caption button (– □ ✕); apps keep `CAPTION_RESERVE` free at the top-right.
pub const CAPTION_BTN_W: f32 = 38.0;
const WIN_R: f32 = 24.0;
const DRAG_H: f32 = 46.0;

struct Window {
    id: u32,
    kind: AppKind,
    app: Box<dyn App>,
    restore: Rect,
    zoomed: bool,
    zoom: Spring,
    open: Spring,
    closing: bool,
    min: Spring,
    minimized: bool,
    layer: Canvas,
    anims: Anims,
    focus: Spring,
    light_down: Option<usize>,
    light_hover: Spring,
    #[allow(dead_code)]
    last_click_t: f32,
    // ── retained-composite cache ──
    was_hot: bool,
    in_chain: u64,
    out_chain: u64,
    snap: Vec<u32>,
    snap_box: (i32, i32, i32, i32),
    snap_ok: bool,
    cache_rect: (i32, i32, i32, i32),
    cache_blink: u64,
    cache_spot: bool,
    blinks: bool,
    layer_ok: bool,
    layer_dims: (i32, i32),
    layer_draws: u32,
}

impl Window {
    fn rect(&self, max: Rect) -> Rect {
        if self.zoom.x.abs() < 0.0005 { self.restore } else { self.restore.lerp(&max, self.zoom.x) }
    }
}

enum Drag { None, Move { id: u32, off: Pt }, Resize { id: u32, edge: u8, start: Rect, m0: Pt } }

pub struct Desktop {
    pub screen: Canvas,
    pub sys: SysState,
    pub exit_requested: bool,
    th: Theme,
    dark: Spring,
    fonts: Fonts,
    scratch: GlassScratch,
    wp: Canvas,
    wp_prev: Option<Canvas>,
    wp_fade: Spring,
    wp_idx: usize,
    windows: Vec<Window>,
    next_id: u32,
    dock: Dock,
    bar: MenuBar,
    cc: ControlCenter,
    spot: Spotlight,
    toasts: Toasts,
    drag: Drag,
    cmds: Vec<Cmd>,
    prev_left: bool,
    prev_right: bool,
    lp: Launchpad,
    pp: PermPrompt,
    pub lock: Lock,
    pub restart_requested: bool,
    lock_snap: Option<Canvas>,
    time: f32,
    clock_acc: f32,
    last_click: (f32, Pt),
    prev_mouse: Pt,
    shake: f32,
    shake_dir: f32,
    cur_scale: Spring,
    cursor_shape: CursorShape,
    boot: f32,
    power: Spring,
    anims: Anims,
    scene: Canvas,
    scene_valid: bool,
    last_clock_min: i64,
    base_chain: u64,
    last_clock_min_dirty: bool,
    chain_ctr: u64,
    th_sig: u64,
    pub stats_win_cached: u64,
    owed_frames: u32,
    pub dbg_reasons: [u64; 17],
    /// Optional monotonic clock in ms (set by hosts that have one) → fills `prof`.
    pub clock: Option<fn() -> f32>,
    /// Optional host heap diagnostic for constrained-target bring-up.
    pub prof: [f32; 8],
    pub windows_force_dirty: bool,
    pub stats_win_drawn: u64,
    /// Number of full scene renders vs. cursor-only presents (diagnostics).
    pub stats_full: u64,
    pub stats_fast: u64,
}

impl Desktop {
    pub fn new(w: i32, h: i32, boot: bool) -> Desktop {
        let mut d = Desktop {
            screen: Canvas::new(w, h), sys: SysState::new(), exit_requested: false, th: Theme::new(), dark: Spring::new(0.0, 0.5, 1.0), fonts: Fonts::new(),
            scratch: GlassScratch::default(), wp: Canvas::new(w, h), wp_prev: None, wp_fade: Spring::new(1.0, 0.5, 1.0), wp_idx: usize::MAX, windows: Vec::new(), next_id: 1,
            dock: Dock::new(), bar: MenuBar::new(), cc: ControlCenter::new(), spot: Spotlight::new(), toasts: Toasts::new(), drag: Drag::None, cmds: Vec::new(),
            prev_left: false, prev_right: false, lp: Launchpad::new(), pp: PermPrompt::new(), lock: Lock::new(), restart_requested: false, lock_snap: None, time: 0.0, clock_acc: 0.0, last_click: (-10.0, Pt::new(-99.0, -99.0)), prev_mouse: Pt::new(w as f32 * 0.5, h as f32 * 0.5),
            shake: 0.0, shake_dir: 0.0, cur_scale: Spring::new(1.0, 0.25, 0.7), cursor_shape: CursorShape::Arrow, boot: if boot { 0.0 } else { 9.0 },
            power: Spring::new(0.0, 0.6, 1.0), anims: Anims::new(),
            scene: Canvas::new(w, h), scene_valid: false, last_clock_min: 0, base_chain: 1, last_clock_min_dirty: false, chain_ctr: 1, th_sig: 0, stats_win_cached: 0, owed_frames: 0, dbg_reasons: [0; 17], clock: None, prof: [0.0; 8], windows_force_dirty: false, stats_win_drawn: 0, stats_full: 0, stats_fast: 0,
        };
        d.sys.screen = Rect::new(0.0, 0.0, w as f32, h as f32);
        d.sync_theme(0.0, true);
        d.ensure_wallpaper();
        // Caches populate on-demand as widgets render
        d
    }

    /// Fill the glyph + dock-icon caches for the primary active theme so the first frame doesn't hitch.
    pub fn prewarm(&mut self) {
        self.fonts.prewarm();
        let mut tmp = Canvas::new(160, 160);
        let dark = true;
        for k in [AppKind::Files, AppKind::Browser, AppKind::Terminal, AppKind::Settings, AppKind::ActivityMonitor].iter() {
            let (k2, r) = (*k, Rect::new(0.0, 0.0, 60.0, 60.0));
            self.fonts.icons.draw(&mut tmp, app_key(k2) + if dark { 500 } else { 0 }, r, 1.0, &|cv, rr| app_icon_t(cv, k2, rr, dark));
        }
        let r = Rect::new(0.0, 0.0, 60.0, 60.0);
        self.fonts.icons.draw(&mut tmp, if dark { 701 } else { 700 }, r, 1.0, &|cv, rr| launchpad_icon(cv, rr, dark));
        self.fonts.icons.draw(&mut tmp, if dark { 800 } else { 300 }, r, 1.0, &|cv, rr| trash_icon_t(cv, rr, false, dark));
    }

    /// Reduce retained icon bitmap memory for the host's constrained compositor mode.
    pub fn set_low_memory_mode(&mut self) { self.fonts.icons.set_max_level(64); self.fonts.set_low_memory_mode(); }

    pub fn resize(&mut self, w: i32, h: i32) {
        if w == self.screen.w && h == self.screen.h { return; }
        self.screen.resize(w, h); self.scene.resize(w, h); self.scene_valid = false; self.chain_ctr += 1; self.base_chain = self.chain_ctr; self.wp.resize(w, h); self.wp_prev = None; self.wp_idx = usize::MAX;
        self.sys.screen = Rect::new(0.0, 0.0, w as f32, h as f32);
        self.ensure_wallpaper();
    }

    /// True while anything on screen is still moving (springs, inertia, overlays, boot…).
    #[inline] fn now(&self) -> f32 { match self.clock { Some(f) => f(), None => 0.0 } }
    pub fn dbg_busy(&self) -> alloc::string::String {
        use alloc::format;
        let mut o = alloc::string::String::new();
        let c = [("lock", self.lock.visible()), ("boot", self.boot < 1.9), ("power", !self.power.settled() || self.power.x > 0.003), ("wp", !self.wp_fade.settled() || self.wp_prev.is_some()), ("dark", !self.dark.settled()), ("cur", !self.cur_scale.settled()), ("anims", self.anims.animating()),
            ("dock", self.dock.busy()), ("bar", self.bar.busy()), ("toast", self.toasts.busy()), ("cc", self.cc.busy()), ("spot", self.spot.visible()), ("lp", self.lp.visible()), ("pp", self.pp.visible()), ("dl", self.sys.reg.dl_active.is_some()), ("popup", self.dock.popup_open()), ("drag", !matches!(self.drag, Drag::None)), ("cmds", !self.cmds.is_empty())];
        for (n, b) in c { if b { o.push_str(n); o.push(' '); } }
        o.push_str(&self.dock.dbg());
        let fid = self.focused_idx();
        for (wi, w) in self.windows.iter().enumerate() {
            if Some(wi) == fid && w.blinks && w.cache_blink != (self.time * 10.0) as u64 { o.push_str(&format!("blink{} ", wi)); }
            if !w.open.settled() { o.push_str(&format!("open{} ", wi)); } if !w.min.settled() { o.push_str(&format!("min{} ", wi)); } if !w.zoom.settled() { o.push_str("zoom "); }
            if !w.focus.settled() { o.push_str(&format!("focus{} ", wi)); } if !w.light_hover.settled() { o.push_str("lh "); } if w.anims.animating() { o.push_str(&format!("wanims{} ", wi)); } if w.app.animating() { o.push_str(&format!("app{} ", wi)); }
        }
        o
    }
    fn scene_busy(&self) -> bool {
        if self.lock.visible() || self.boot < 1.9 || !self.power.settled() || self.power.x > 0.003 || !self.wp_fade.settled() || self.wp_prev.is_some() { return true; }
        if !self.dark.settled() || !self.cur_scale.settled() || self.anims.animating() { return true; }
        if self.dock.busy() || self.bar.busy() || self.toasts.busy() || self.cc.busy() || self.spot.visible() || self.lp.visible() || self.pp.busy() || !self.sys.reg.pending.is_empty() && !self.pp.visible() || self.sys.reg.dl_active.is_some() || self.dock.popup_open() { return true; }
        if !matches!(self.drag, Drag::None) || !self.cmds.is_empty() { return true; }
        let bp = (self.time * 10.0) as u64;
        let fid = self.focused_idx();
        for (wi, w) in self.windows.iter().enumerate() {
            if Some(wi) == fid && w.blinks && w.cache_blink != bp { return true; }
            if w.closing || w.minimized && !w.min.settled() { return true; }
            if !w.open.settled() || !w.min.settled() || !w.zoom.settled() || !w.focus.settled() || !w.light_hover.settled() || w.anims.animating() || w.app.animating() { return true; }
        }
        false
    }

    /// Can a pointer at `p` change anything visible besides the cursor sprite itself?
    fn pointer_touches_scene(&self, p: Pt, screen_r: Rect) -> bool {
        if p.y <= BAR_H + 2.0 || self.pp.visible() { return true; }
        if self.dock.zone(screen_r).contains(p.x, p.y) { return true; }
        let m = self.max_rect();
        // Only trigger full scene composite if pointer touches interactive controls (traffic lights) or resize borders
        self.windows.iter().any(|w| {
            if w.minimized { return false; }
            let r = w.rect(m);
            let in_traffic_lights = p.x >= r.x && p.x <= r.x + 72.0 && p.y >= r.y && p.y <= r.y + 32.0;
            let near_border = r.inset(-4.0).contains(p.x, p.y) && !r.inset(6.0).contains(p.x, p.y);
            in_traffic_lights || near_border
        })
    }

    pub fn dbg_unsettled(&self) -> alloc::vec::Vec<(AppKind, alloc::vec::Vec<(u32, f32, f32, f32)>)> { self.windows.iter().map(|w| (w.kind, w.anims.unsettled())).collect() }
    pub fn dbg_cc(&self) -> (bool, f32) { (self.cc.open, self.cc.t_x()) }
    pub fn dock_icon_center(&self, k: AppKind) -> Pt { self.dock.icon_center(k, Rect::new(0.0, 0.0, self.screen.w as f32, self.screen.h as f32)) }
    pub fn window_rect(&self, k: AppKind) -> Option<Rect> { let m = self.max_rect(); self.windows.iter().rev().find(|w| w.kind == k && !w.closing).map(|w| w.rect(m)) }
    pub fn dock_item_center(&self, id: u32) -> Pt { self.dock.center_of(id, Rect::new(0.0, 0.0, self.screen.w as f32, self.screen.h as f32)) }
    pub fn dock_rect(&self) -> Rect { self.dock.rect }
    pub fn open_app(&mut self, k: AppKind) { self.cmds.push(Cmd::Open(k)); }
    pub fn window_count(&self) -> usize { self.windows.len() }
    pub fn toggle_spotlight(&mut self) { self.spot.toggle(); }
    pub fn open_control_center(&mut self, on: bool) { self.cc.open = on; }

    fn ensure_wallpaper(&mut self) {
        if self.wp_idx == self.sys.wallpaper { return; }
        let (w, h) = (self.screen.w, self.screen.h);
        if self.wp_idx != usize::MAX {
            let mut old = Canvas::new(w, h);
            old.px.copy_from_slice(&self.wp.px);
            self.wp_prev = Some(old);
            self.wp_fade.snap(0.0); self.wp_fade.set(1.0);
        }
        wallpaper::paint(&mut self.wp, self.sys.wallpaper);
        self.wp_idx = self.sys.wallpaper;
    }

    fn sync_theme(&mut self, dt: f32, snap: bool) {
        let want_dark = match self.sys.appearance {
            Appearance::Dark => true, Appearance::Light => false,
            Appearance::Auto => { let (_, _, _, _, h, _) = civil(self.sys.unix_secs, 330); h >= 19 || h < 6 }
        };
        self.dark.set(if want_dark { 1.0 } else { 0.0 });
        if snap { self.dark.snap(if want_dark { 1.0 } else { 0.0 }); } else { self.dark.update(dt); }
        self.th.dark_t = self.dark.x.clamp(0.0, 1.0);
        let (_, l, d) = (ACCENTS[self.sys.accent].0, ACCENTS[self.sys.accent].1, ACCENTS[self.sys.accent].2);
        self.th.accent_light = l; self.th.accent_dark = d;
        self.th.clarity = self.sys.clarity; self.th.reduce_transparency = self.sys.reduce_transparency;
    }

    fn max_rect(&self) -> Rect {
        let (w, h) = (self.screen.w as f32, self.screen.h as f32);
        let reserve = if self.sys.dock_autohide { 22.0 } else { 40.0 + self.sys.dock_size * 46.0 + 38.0 };
        Rect::new(10.0, BAR_H + 8.0, w - 20.0, h - BAR_H - 8.0 - reserve)
    }

    fn focused_idx(&self) -> Option<usize> { self.windows.iter().rposition(|w| !w.minimized && !w.closing) }

    fn spawn(&mut self, k: AppKind, app: Option<Box<dyn App>>) {
        let app = app.unwrap_or_else(|| make_app(k));
        let (mut w, mut h) = app.default_size();
        let sw = self.screen.w as f32; let sh = self.screen.h as f32;
        w = w.min(sw - 60.0); h = h.min(sh - 160.0);
        let n = self.windows.len() as f32;
        let x = ((sw - w) * 0.5 + (n % 6.0) * 30.0 - 60.0).clamp(10.0, (sw - w - 10.0).max(10.0));
        let y = (BAR_H + 40.0 + (n % 6.0) * 26.0).clamp(BAR_H + 6.0, (sh - h - 110.0).max(BAR_H + 6.0));
        let r = Rect::new(x, y, round(w), round(h));
        let mut open = Spring::new(0.0, 0.36, 0.7); open.set(1.0);
        self.windows.push(Window {
            id: self.next_id, kind: k, app, restore: r, zoomed: false, zoom: Spring::new(0.0, 0.34, 0.9), open, closing: false, min: Spring::new(0.0, 0.42, 0.85), minimized: false,
            layer: Canvas::new(r.w as i32, r.h as i32), anims: Anims::new(), focus: Spring::new(1.0, 0.25, 1.0), light_down: None, light_hover: Spring::new(0.0, 0.2, 1.0), last_click_t: -10.0,
            was_hot: false, in_chain: 0, out_chain: 0, snap: Vec::new(), snap_box: (0, 0, 0, 0), snap_ok: false, cache_rect: (0, 0, 0, 0), cache_blink: u64::MAX, cache_spot: false, blinks: false, layer_ok: false, layer_dims: (0, 0), layer_draws: 0,
        });
        self.next_id += 1;
        if self.sys.dock_bounce { self.dock.bounce_kind(k); }
        let now = self.sys.unix_secs;
        self.sys.reg.touch(k, now);
        if !matches!(k, AppKind::Files | AppKind::Settings | AppKind::About | AppKind::Calculator | AppKind::Terminal | AppKind::Notes | AppKind::Browser | AppKind::ActivityMonitor | AppKind::Photos | AppKind::Music | AppKind::Messages) { self.sys.reg.queue_launch_prompt(k); }
    }

    fn raise(&mut self, id: u32) {
        if let Some(i) = self.windows.iter().position(|w| w.id == id) { let w = self.windows.remove(i); self.windows.push(w); }
    }

    fn set_zoom(&mut self, id: u32) {
        let max = self.max_rect();
        if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
            if w.zoomed { w.zoomed = false; w.zoom.set(0.0); }
            else { w.restore = w.rect(max); w.zoomed = true; w.zoom.set(1.0); }
        }
    }

    fn process_cmds(&mut self) {
        let cmds: Vec<Cmd> = core::mem::take(&mut self.cmds);
        for c in cmds {
            match c {
                Cmd::Open(k) => {
                    if let Some(i) = self.windows.iter().position(|w| w.kind == k && !w.closing) {
                        let id = self.windows[i].id;
                        self.windows[i].minimized = false; self.windows[i].min.set(0.0);
                        self.raise(id);
                        if self.sys.dock_bounce { self.dock.bounce_kind(k); }
                        let now = self.sys.unix_secs; self.sys.reg.touch(k, now);
                    } else { self.spawn(k, None); }
                }
                Cmd::OpenSettingsPane(p) => { self.sys.settings_pane_request = Some(p); self.cmds.push(Cmd::Open(AppKind::Settings)); }
                Cmd::OpenPermissions(n) => { self.sys.privacy_request = Some(n); self.sys.settings_pane_request = Some(14); self.cmds.push(Cmd::Open(AppKind::Settings)); }
                Cmd::Quit(k) => { let ids: Vec<usize> = (0..self.windows.len()).filter(|i| self.windows[*i].kind == k).collect(); for i in ids { self.close_idx(i); } }
                Cmd::Launchpad => self.lp.toggle(),
                Cmd::OpenPath(p) => self.spawn(AppKind::Files, Some(Box::new(Files::with_path(&p)))),
                Cmd::Toast(s) => self.toasts.push(s),
                Cmd::CloseWindow => { if let Some(i) = self.focused_idx() { self.close_idx(i); } }
                Cmd::Minimize => { if let Some(i) = self.focused_idx() { self.windows[i].minimized = true; self.windows[i].min.set(1.0); } }
                Cmd::Zoom => { if let Some(i) = self.focused_idx() { let id = self.windows[i].id; self.set_zoom(id); } }
                Cmd::Spotlight => self.spot.toggle(),
                Cmd::Shutdown => { self.power.set(1.0); self.lock.events.push(UiEvent::ShutdownRequested); }
                Cmd::Restart => { self.restart_requested = true; self.power.set(1.0); }
                Cmd::Lock => self.lock_now(),
            }
        }
    }

    fn close_idx(&mut self, i: usize) {
        let w = &mut self.windows[i];
        if w.closing { return; }
        w.closing = true;
        w.open = Spring::new(w.open.x, 0.24, 1.0); w.open.set(0.0);
    }

    fn menus(&self) -> Vec<(String, Vec<MenuItem>)> {
        let mut v: Vec<(String, Vec<MenuItem>)> = Vec::new();
        let (name, extras) = match self.focused_idx() { Some(i) => (String::from(self.windows[i].kind.name()), self.windows[i].app.extra_menus()), None => (String::from("Desktop"), Vec::new()) };
        v.push((name.clone(), alloc::vec![
            MenuItem::new(&format!("About {}", name), "", Action::Cmd(Cmd::Open(AppKind::About))), MenuItem::sep(),
            MenuItem::new("Settings…", "Ctrl ,", Action::Cmd(Cmd::Open(AppKind::Settings))), MenuItem::sep(),
            MenuItem::new(&format!("Quit {}", name), "Ctrl Q", Action::Cmd(Cmd::CloseWindow)),
        ]));
        v.push((String::from("File"), alloc::vec![
            MenuItem::new("New Window", "Ctrl N", Action::AppCmd("__new")), MenuItem::sep(),
            MenuItem::new("Close Window", "Ctrl W", Action::Cmd(Cmd::CloseWindow)),
        ]));
        v.push((String::from("Edit"), alloc::vec![
            MenuItem::off("Undo", "Ctrl Z"), MenuItem::off("Redo", "Ctrl Shift Z"), MenuItem::sep(),
            MenuItem::off("Cut", "Ctrl X"), MenuItem::off("Copy", "Ctrl C"), MenuItem::off("Paste", "Ctrl V"),
        ]));
        for e in extras { v.push(e); }
        v.push((String::from("Window"), alloc::vec![
            MenuItem::new("Minimize", "Ctrl M", Action::Cmd(Cmd::Minimize)), MenuItem::new("Zoom", "", Action::Cmd(Cmd::Zoom)),
        ]));
        v
    }

    /// Start the boot sequence: optional firmware POST screen → logo → lock screen.
    pub fn start_boot(&mut self, bios: bool) { self.boot = 9.0; self.lock.start_boot(bios); self.scene_valid = false; }
    /// Lock the session now (what Ctrl+Shift+L and the Apple menu do).
    pub fn lock_now(&mut self) {
        if self.lock.is_locked() { return; }
        let mut snap = Canvas::new(self.screen.w, self.screen.h);
        snap.px.copy_from_slice(&self.screen.px);
        self.lock_snap = Some(snap);
        self.cc.open = false; self.bar.close(); self.spot.open = false;
        self.lock.lock_now(); self.scene_valid = false;
    }
    /// Drain events for the host OS (unlock, duress unlock, failed attempts, power requests).
    pub fn take_events(&mut self) -> Vec<UiEvent> { core::mem::take(&mut self.lock.events) }

    /// Render the lock UI into its layer. Returns the layer (put back by the caller).
    fn draw_lock_layer(&mut self, inp: &Input, dt: f32, pressed: bool, released: bool, live: bool) -> Canvas {
        let (w, h) = (self.screen.w, self.screen.h);
        let screen_r = Rect::new(0.0, 0.0, w as f32, h as f32);
        self.lock.ensure_bg(&self.wp, &mut self.scratch, self.wp_idx);
        let bg = self.lock.take_bg().unwrap();
        let mut layer = self.lock.layer.take().unwrap_or_else(|| Canvas::new(w, h));
        if layer.w != w || layer.h != h { layer = Canvas::new(w, h); }
        let mut th = self.th; th.dark_t = 1.0;
        let io = Io { mouse: inp.mouse, down: inp.left, pressed, released, right_pressed: false, click_count: 1, wheel: inp.wheel, keys: if live { inp.keys.clone() } else { Vec::new() }, dt, time: self.time, hot: live, focused: live };
        let mut cursor = CursorShape::Arrow; let mut over = false;
        {
            let this = &mut *self;
            let mut cx = Ctx { cv: &mut layer, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &io, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds, bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
            this.lock.update_draw(&mut cx, &bg, live);
        }
        self.lock.put_bg(Some(bg));
        if over { self.cursor_shape = CursorShape::Hand; } else { self.cursor_shape = CursorShape::Arrow; }
        layer
    }

    /// Opaque stages: firmware POST, logo, lock screen.
    fn lock_frame(&mut self, inp: &Input, dt: f32) {
        let pressed = inp.left && !self.prev_left;
        let released = !inp.left && self.prev_left;
        self.prev_left = inp.left; self.prev_right = inp.right; self.prev_mouse = inp.mouse;
        self.anims.step(dt);
        self.cur_scale.set(1.0 + self.sys.cursor_size * 1.1); self.cur_scale.update(dt);
        let (w, h) = (self.screen.w, self.screen.h);
        let any_key = inp.keys.iter().any(|k| k.key == Key::Escape || k.key == Key::Enter || k.key == Key::Space);
        match self.lock.phase {
            Phase::Bios => { if any_key { self.lock.skip_bios(); } draw_bios(&mut self.screen, &mut self.fonts, self.lock.t); }
            Phase::Logo => {
                if any_key || pressed { self.lock.skip_logo(); }
                let t = self.lock.t;
                let late = t > LOGO_SECS - 0.5;
                if late {
                    let layer = self.draw_lock_layer(inp, dt, false, false, false);
                    self.screen.px.copy_from_slice(&layer.px); self.lock.layer = Some(layer);
                }
                draw_logo(&mut self.screen, &mut self.fonts, t, late);
            }
            _ => {
                let layer = self.draw_lock_layer(inp, dt, pressed, released, true);
                let s = self.lock.show.x;
                if s >= 0.995 || self.lock_snap.is_none() { self.screen.px.copy_from_slice(&layer.px); }
                else {
                    if let Some(sn) = self.lock_snap.as_ref() { self.screen.px.copy_from_slice(&sn.px); }
                    let k = 1.0 + (1.0 - s) * 0.05;
                    let dest = Rect::new(w as f32 * 0.5 * (1.0 - k), h as f32 * 0.5 * (1.0 - k), w as f32 * k, h as f32 * k);
                    self.screen.blit_scaled(&layer, dest, 0.0, s.clamp(0.0, 1.0));
                }
                self.lock.layer = Some(layer);
            }
        }
        self.scene_valid = false; self.stats_full += 1;
        let show_cursor = match self.lock.phase { Phase::Bios => false, Phase::Logo => self.lock.t > LOGO_SECS - 0.5, _ => true };
        if show_cursor { draw_cursor(&mut self.screen, inp.mouse.x, inp.mouse.y, self.cursor_shape, self.cur_scale.x); }
    }

    /// Unlock transition: the live desktop with the lock layer zooming/fading away on top.
    fn draw_lock_overlay(&mut self, inp: &Input, dt: f32) {
        let s = self.lock.show.x.clamp(0.0, 1.0);
        if s <= 0.003 { return; }
        let (w, h) = (self.screen.w as f32, self.screen.h as f32);
        let layer = self.draw_lock_layer(inp, dt, false, false, false);
        let k = 1.0 + (1.0 - s) * 0.06;
        let dest = Rect::new(w * 0.5 * (1.0 - k), h * 0.5 * (1.0 - k), w * k, h * k);
        self.screen.blit_scaled(&layer, dest, 0.0, s);
        self.lock.layer = Some(layer);
    }

    /// Run one frame. `inp.dt` in seconds.
    pub fn frame(&mut self, inp: &Input) {
        let dt = inp.dt.clamp(0.0005, 0.05);
        self.time += dt;
        self.boot += dt;
        self.clock_acc += dt;
        while self.clock_acc >= 1.0 { self.clock_acc -= 1.0; self.sys.unix_secs += 1; }
        self.sync_theme(dt, false);
        self.ensure_wallpaper();
        self.wp_fade.update(dt);
        self.power.update(dt);
        if self.power.x > 0.995 { self.exit_requested = true; }
        // ─── auto-lock on inactivity ───
        if inp.mouse.x != self.prev_mouse.x || inp.mouse.y != self.prev_mouse.y || inp.left || inp.right || !inp.keys.is_empty() { self.lock.idle = 0.0; } else { self.lock.idle += dt; }
        if self.sys.lock_idle > 0 && self.lock.idle > [0.0, 60.0, 300.0, 600.0][self.sys.lock_idle.min(3)] && !self.lock.is_locked() { self.lock_now(); }
        self.lock.advance(dt);
        if self.lock.opaque() { self.lock_frame(inp, dt); return; }

        let screen_r = Rect::new(0.0, 0.0, self.screen.w as f32, self.screen.h as f32);
        // ─── retained-scene fast path: nothing but the cursor changed ───
        {
            let minute = self.sys.unix_secs / 60;
            let clock_changed = minute != self.last_clock_min;
            let moved = inp.mouse.x != self.prev_mouse.x || inp.mouse.y != self.prev_mouse.y;
            let touches = moved && (self.pointer_touches_scene(inp.mouse, screen_r) || self.pointer_touches_scene(self.prev_mouse, screen_r));
            let input = inp.left || self.prev_left || inp.right || self.prev_right || (inp.wheel.x != 0.0 || inp.wheel.y != 0.0) || !inp.keys.is_empty() || touches;
            // immediate-mode UI: a click/key changes state *during* the frame it lands in and shows up in the next one,
            // so every interactive frame owes two more full frames before we may go idle.
            if input || clock_changed { self.owed_frames = 2; }
            if self.scene_valid && !self.windows_force_dirty && !clock_changed && !input && self.owed_frames == 0 && !self.scene_busy() {
                let dxm = inp.mouse.x - self.prev_mouse.x;
                if fabs(dxm) > 14.0 { let sg = if dxm > 0.0 { 1.0 } else { -1.0 }; if sg != self.shake_dir { self.shake += 1.0; self.shake_dir = sg; } }
                self.shake = (self.shake - dt * 3.2).max(0.0);
                self.prev_mouse = inp.mouse;
                let size_base = 1.0 + self.sys.cursor_size * 1.1;
                self.cur_scale.set(size_base * if self.shake > 4.0 { 2.4 } else { 1.0 });
                self.cur_scale.update(dt);
                self.screen.px.copy_from_slice(&self.scene.px);
                if moved { self.cursor_shape = CursorShape::Arrow; } // off all windows/shell: plain arrow; otherwise keep the shape from the last full frame
                draw_cursor(&mut self.screen, inp.mouse.x, inp.mouse.y, self.cursor_shape, self.cur_scale.x);
                self.stats_fast += 1;
                return;
            }
            if self.owed_frames > 0 && !input && !clock_changed { self.owed_frames -= 1; }
            if clock_changed { self.last_clock_min_dirty = true; }
            self.last_clock_min = minute;
        }
        self.anims.step(dt);
        if let Some(n) = self.sys.reg.tick_download(dt) { self.toasts.push(format!("Download complete: {}", n)); }
        let mouse = inp.mouse;
        let pressed = inp.left && !self.prev_left;
        let released = !inp.left && self.prev_left;
        self.prev_left = inp.left;
        let rpressed = inp.right && !self.prev_right;
        self.prev_right = inp.right;
        let mut click_count = 1;
        if pressed {
            let dist = { let (a, b) = (mouse.x - self.last_click.1.x, mouse.y - self.last_click.1.y); sqrt(a * a + b * b) };
            if self.time - self.last_click.0 < 0.38 && dist < 6.0 { click_count = 2; self.last_click = (-10.0, mouse); } else { self.last_click = (self.time, mouse); }
        }
        // pointer "shake to locate"
        let dx = mouse.x - self.prev_mouse.x;
        if fabs(dx) > 14.0 { let s = if dx > 0.0 { 1.0 } else { -1.0 }; if s != self.shake_dir { self.shake += 1.0; self.shake_dir = s; } }
        self.shake = (self.shake - dt * 3.2).max(0.0);
        let ptr_moved = mouse.x != self.prev_mouse.x || mouse.y != self.prev_mouse.y;
        self.prev_mouse = mouse;
        let size_base = 1.0 + self.sys.cursor_size * 1.1;
        self.cur_scale.set(size_base * if self.shake > 4.0 { 2.4 } else { 1.0 });
        self.cur_scale.update(dt);

        // ─── keyboard shortcuts ───
        let mut keys: Vec<KeyEv> = Vec::new();
        for k in inp.keys.iter() {
            if k.ctrl && k.key == Key::Space { self.spot.toggle(); continue; }
            if k.ctrl && k.shift && k.key == Key::Char && (k.ch == 'l' || k.ch == 'L') { self.cmds.push(Cmd::Lock); continue; }
            if k.key == Key::Escape && (self.cc.open || self.bar.is_open()) { self.cc.open = false; self.bar.close(); continue; }
            if k.ctrl && k.key == Key::Char {
                match k.ch {
                    'w' => { self.cmds.push(Cmd::CloseWindow); continue; }
                    'm' => { self.cmds.push(Cmd::Minimize); continue; }
                    'q' => { self.cmds.push(Cmd::CloseWindow); continue; }
                    'n' => { if let Some(i) = self.focused_idx() { let kd = self.windows[i].kind; if kd == AppKind::Files { self.spawn(AppKind::Files, None); continue; } } }
                    ',' | 's' => { self.cmds.push(Cmd::Open(AppKind::Settings)); continue; }
                    't' => { self.cmds.push(Cmd::Open(AppKind::Terminal)); continue; }
                    'f' => { self.cmds.push(Cmd::Open(AppKind::Files)); continue; }
                    'b' => { self.cmds.push(Cmd::Open(AppKind::Browser)); continue; }
                    'l' => { self.cmds.push(Cmd::Launchpad); continue; }
                    'a' => { self.cmds.push(Cmd::Open(AppKind::ActivityMonitor)); continue; }
                    _ => {}
                }
            }
            keys.push(*k);
        }

        // ─── pointer ownership ───
        let spot_vis = self.spot.visible() || self.lp.visible() || self.pp.visible();
        let menu_blocks = self.bar.is_open() && (mouse.y <= BAR_H || self.bar.popup_rect.contains(mouse.x, mouse.y));
        let in_bar = mouse.y <= BAR_H;
        let in_cc = self.cc.contains(screen_r, mouse);
        let in_dock = self.dock.rect.contains(mouse.x, mouse.y) || self.dock.popup_contains(mouse);
        let overlay_open = self.bar.is_open() || self.cc.open;
        let shell_blocked = spot_vis || menu_blocks || in_bar || in_cc || in_dock;
        let max_r = self.max_rect();
        let interacting = !matches!(self.drag, Drag::None);

        // top-most window under pointer
        let mut top_hit: Option<u32> = None;
        let mut edge: u8 = 0;
        if !shell_blocked && !interacting {
            for w in self.windows.iter().rev() {
                if w.minimized || w.closing || w.min.x > 0.05 { continue; }
                let r = w.rect(max_r);
                let slop = if w.zoomed || w.zoom.x > 0.01 { 0.0 } else { 5.0 };
                if r.inset(-slop).contains(mouse.x, mouse.y) {
                    top_hit = Some(w.id);
                    if slop > 0.0 {
                        let lx = mouse.x - r.x; let ly = mouse.y - r.y;
                        let c = 14.0;
                        let l = lx < 4.0; let rr = lx > r.w - 4.0; let t = ly < 4.0; let b = ly > r.h - 4.0;
                        let lc = lx < c; let rc = lx > r.w - c; let tc = ly < c; let bc = ly > r.h - c;
                        if (l && (tc || bc)) || (t && (lc || rc)) || (rr && (tc || bc)) || (b && (lc || rc)) || (lc && tc && (l || t)) {
                            // corner
                        }
                        if l || (lx < 0.0) { edge |= 1; } if rr || lx > r.w { edge |= 2; } if t || ly < 0.0 { edge |= 4; } if b || ly > r.h { edge |= 8; }
                        // corner grab zones
                        if (l || lx < 0.0) && (bc || ly > r.h) { edge |= 8; } if (rr || lx > r.w) && (bc || ly > r.h) { edge |= 8; }
                        if (l || lx < 0.0) && (tc) { edge |= 4; } if (rr || lx > r.w) && tc { edge |= 4; }
                        if (b || ly > r.h) && lc { edge |= 1; } if (b || ly > r.h) && rc { edge |= 2; }
                        if (t || ly < 0.0) && lc { edge |= 1; } if (t || ly < 0.0) && rc { edge |= 2; }
                    }
                    break;
                }
            }
        }
        // raise/focus on press
        if pressed && !shell_blocked && !overlay_open && !interacting { if let Some(id) = top_hit { self.raise(id); } }
        if pressed && overlay_open && !menu_blocks && !in_cc { /* swallowed: overlay closes itself */ }
        let swallow = pressed && overlay_open;
        let focused_id = self.focused_idx().map(|i| self.windows[i].id);

        // resize start
        let mut next_cursor = CursorShape::Arrow;
        if edge != 0 && !swallow {
            next_cursor = match edge { 1 | 2 => CursorShape::ResizeEW, 4 | 8 => CursorShape::ResizeNS, 5 | 10 => CursorShape::ResizeNWSE, _ => CursorShape::ResizeNESW };
            if pressed { if let Some(id) = top_hit { if let Some(w) = self.windows.iter().find(|w| w.id == id) { self.drag = Drag::Resize { id, edge, start: w.rect(max_r), m0: mouse }; } } }
        }
        // drag updates
        let mut drag_clear = false;
        match self.drag {
            Drag::Move { id, off } => {
                if !inp.left { drag_clear = true; }
                if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
                    w.restore.x = mouse.x - off.x; w.restore.y = (mouse.y - off.y).max(BAR_H + 2.0);
                    w.restore.y = w.restore.y.min(screen_r.h - 60.0);
                }
                next_cursor = CursorShape::Arrow;
            }
            Drag::Resize { id, edge: e, start, m0 } => {
                if !inp.left { drag_clear = true; }
                if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
                    let (mw, mh) = w.app.min_size();
                    let (ddx, ddy) = (mouse.x - m0.x, mouse.y - m0.y);
                    let mut r = start;
                    if e & 2 != 0 { r.w = (start.w + ddx).max(mw); }
                    if e & 8 != 0 { r.h = (start.h + ddy).max(mh); }
                    if e & 1 != 0 { let nw = (start.w - ddx).max(mw); r.x = start.x + start.w - nw; r.w = nw; }
                    if e & 4 != 0 { let nh = (start.h - ddy).max(mh); r.y = (start.y + start.h - nh).max(BAR_H + 2.0); r.h = start.y + start.h - r.y; r.h = r.h.max(mh); }
                    r.w = round(r.w); r.h = round(r.h);
                    w.restore = r;
                }
                next_cursor = match e { 1 | 2 => CursorShape::ResizeEW, 4 | 8 => CursorShape::ResizeNS, 5 | 10 => CursorShape::ResizeNWSE, _ => CursorShape::ResizeNESW };
            }
            Drag::None => {}
        }
        if drag_clear { self.drag = Drag::None; }

        let t_a = self.now();
        // ─── draw: wallpaper ───
        {
            let scr = &mut self.screen;
            scr.px.copy_from_slice(&self.wp.px);
            if let Some(prev) = &self.wp_prev {
                let f = self.wp_fade.x.clamp(0.0, 1.0);
                if f < 0.999 {
                    let a = ((1.0 - f) * 256.0) as u32;
                    for (d, s) in scr.px.iter_mut().zip(prev.px.iter()) { *d = mix_pix(*d, *s, a); }
                }
            }
            if self.wp_fade.x > 0.999 { self.wp_prev = None; }
        }

        let t_b = self.now();
        // ─── draw: windows ───
        let th = self.th;
        let mut io_base = Io { dt, time: self.time, ..Io::default() };
        io_base.down = inp.left; io_base.right_pressed = rpressed; io_base.click_count = click_count;
        let n = self.windows.len();
        // invalidate the per-window composite caches when anything *under* all windows changed
        {
            let sig = (self.th.dark_t * 255.0) as u64 | ((self.th.clarity * 255.0) as u64) << 8 | (self.sys.accent as u64) << 16 | (self.th.reduce_transparency as u64) << 24
                | (self.sys.wallpaper as u64) << 28 | (self.sys.dock_autohide as u64) << 36 | ((self.sys.dock_size * 100.0) as u64) << 40;
            let under_busy = !self.wp_fade.settled() || self.wp_prev.is_some() || !self.dark.settled() || self.cc.busy() || self.last_clock_min_dirty;
            if sig != self.th_sig || under_busy { self.th_sig = sig; self.chain_ctr += 1; self.base_chain = self.chain_ctr; }
            self.last_clock_min_dirty = false;
        }
        let mut chain = self.base_chain;
        let hot_active = ptr_moved || inp.left || inp.right || released || inp.wheel.x != 0.0 || inp.wheel.y != 0.0 || !keys.is_empty() || self.owed_frames > 0;
        let blink_phase = (self.time * 10.0) as u64;
        let mut want_cursor: Option<CursorShape> = None;
        let mut start_drag: Option<(u32, Pt)> = None;
        let mut zoom_req: Option<u32> = None;
        let mut close_req: Option<usize> = None;
        let mut min_req: Option<usize> = None;
        for i in 0..n {
            let this = &mut *self;
            let w = &mut this.windows[i];
            w.open.update(dt); w.min.update(dt); w.zoom.update(dt);
            let is_focus = Some(w.id) == focused_id;
            w.focus.set(if is_focus { 1.0 } else { 0.0 }); w.focus.update(dt);
            let rect = w.rect(max_r);
            let (lw, lh) = (round(rect.w) as i32, round(rect.h) as i32);
            if w.minimized && w.min.x > 0.995 { continue; }
            if w.closing && w.open.x < 0.01 { continue; }
            w.layer.resize(lw.max(1), lh.max(1));
            let (rx, ry) = (round(rect.x) as i32, round(rect.y) as i32);
            let hot = top_hit == Some(w.id) && !swallow && !matches!(this.drag, Drag::Resize { .. });
            // ── cache: reuse last frame's finished composite if nothing it depends on changed ──
            {
                let dirty = !w.snap_ok || w.in_chain != chain || w.cache_rect != (rx, ry, lw, lh) || (hot && hot_active) || w.was_hot != hot || w.light_down.is_some()
                    || (is_focus && (!keys.is_empty() || (w.blinks && w.cache_blink != blink_phase))) || w.cache_spot != spot_vis
                    || !w.open.settled() || !w.min.settled() || !w.zoom.settled() || !w.focus.settled() || !w.light_hover.settled() || w.closing || w.minimized
                    || w.anims.animating() || w.app.animating() || this.windows_force_dirty;
                if dirty {
                    let r = [!w.snap_ok, w.in_chain != chain, w.cache_rect != (rx, ry, lw, lh), hot, w.was_hot != hot, w.light_down.is_some(), is_focus && !keys.is_empty(), is_focus && w.cache_blink != blink_phase, w.cache_spot != spot_vis,
                        !w.open.settled(), !w.min.settled(), !w.zoom.settled(), !w.focus.settled(), !w.light_hover.settled(), w.closing || w.minimized, w.anims.animating(), w.app.animating()];
                    for (k, v) in r.iter().enumerate() { if *v { this.dbg_reasons[k] += 1; } }
                }
                if !dirty {
                    let (bx, by, bw, bh) = w.snap_box;
                    for y in 0..bh {
                        let d = ((by + y) * this.screen.w + bx) as usize;
                        let sidx = (y * bw) as usize;
                        this.screen.px[d..d + bw as usize].copy_from_slice(&w.snap[sidx..sidx + bw as usize]);
                    }
                    chain = w.out_chain;
                    this.stats_win_cached += 1;
                    continue;
                }
            }
            this.stats_win_drawn += 1;
            let anims_busy = w.anims.animating();
            w.anims.step(dt);
            this.sys.blink_req = false;
            let (p_in, p_hot, p_rect, p_blink, p_spot) = (w.in_chain, w.was_hot, w.cache_rect, w.cache_blink, w.cache_spot);
            w.was_hot = hot;
            // while the window is animating in/out (or only its inactive veil is fading) its content is static: reuse the last drawn layer
            let animating_fx = ((w.open.x - 1.0).abs() > 0.002 || w.min.x > 0.002) && w.zoom.settled();
            let content_clean = w.layer_ok && w.layer_dims == (lw, lh) && w.layer_draws >= 3 && p_rect == (rx, ry, lw, lh) && !hot && !p_hot && w.light_down.is_none()
                && !(is_focus && (!keys.is_empty() || (w.blinks && p_blink != blink_phase))) && p_spot == spot_vis && !anims_busy && !w.app.animating();
            let reuse = content_clean && (animating_fx || (p_in == chain && !w.focus.settled()));
            if !reuse { w.in_chain = chain; w.cache_blink = blink_phase; w.cache_spot = spot_vis; w.cache_rect = (rx, ry, lw, lh); }
            w.snap_ok = false;
            if !reuse {
            // backdrop copy: what is behind the window right now
            for y in 0..lh {
                let sy = ry + y;
                let row = (y * lw) as usize;
                if sy < 0 || sy >= this.screen.h { for p in w.layer.px[row..row + lw as usize].iter_mut() { *p = 0; } continue; }
                let x0 = rx.max(0); let x1 = (rx + lw).min(this.screen.w);
                if x1 <= x0 { continue; }
                let srow = (sy * this.screen.w) as usize;
                w.layer.px[row + (x0 - rx) as usize..row + (x1 - rx) as usize].copy_from_slice(&this.screen.px[srow + x0 as usize..srow + x1 as usize]);
            }
            let mut io = io_base.clone();
            io.mouse = Pt::new(mouse.x - rx as f32, mouse.y - ry as f32);
            io.hot = hot; io.pressed = pressed && hot; io.right_pressed = rpressed && hot; io.released = released; io.focused = is_focus && !spot_vis;
            if hot { io.wheel = inp.wheel; }
            if is_focus && !spot_vis { io.keys = keys.clone(); }
            let mut cursor = CursorShape::Arrow;
            let mut over_widget = false;
            {
                let mut cx = Ctx { cv: &mut w.layer, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &io, anims: &mut w.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: Rect::new(0.0, 0.0, lw as f32, lh as f32), cursor: &mut cursor, over_widget: &mut over_widget };
                let area = Rect::new(0.0, 0.0, lw as f32, lh as f32);
                w.app.draw(&mut cx, area);
                w.blinks = cx.sys.blink_req;
                // ── window controls: classic caption glyphs (– □ ✕) blended into the titlebar, soft Aero-style glow on hover ──
                let (bw, bh) = (CAPTION_BTN_W, 30.0f32);
                let gx = lw as f32 - 8.0 - bw * 3.0;
                let group = Rect::new(gx, 2.0, bw * 3.0, bh);
                let over_group = hot && group.contains(io.mouse.x, io.mouse.y);
                if over_group { *cx.over_widget = true; }
                let dark = th.is_dark();
                let ink = th.label().fade(0.80); // static: the cached layer must not depend on the focus fade
                // idx: 1 = minimise, 2 = maximise, 0 = close (matches the request handlers below)
                // glows are drawn first (all three) so a neighbour's halo never paints over another glyph
                let mut hv_all = [0.0f32; 3];
                for (slot, idx) in [(0usize, 1usize), (1, 2), (2, 0)] {
                    let br = Rect::new(gx + slot as f32 * bw, group.y, bw, bh);
                    let hit = hot && br.contains(io.mouse.x, io.mouse.y);
                    if hit && io.pressed { w.light_down = Some(idx); }
                    let down = w.light_down == Some(idx) && io.down;
                    let hv = cx.anim(id2(id_of("wc"), idx as u32), if hit { 1.0 } else { 0.0 });
                    hv_all[idx] = hv;
                    if hv > 0.01 {
                        let k = hv * if down { 1.0 } else { 0.78 };
                        let (gcx, gcy) = (br.cx(), br.cy());
                        if idx == 0 {
                            let gc = Color::rgb(255, 64, 44);
                            cx.cv.fill_circle(gcx, gcy, 30.0, Paint::Radial { c: Pt::new(gcx, gcy), r: 30.0, c0: gc.fade(0.62 * k), c1: gc.fade(0.0) });
                            cx.cv.fill_circle(gcx, gcy, 14.0, Paint::Radial { c: Pt::new(gcx, gcy), r: 14.0, c0: Color::rgb(255, 150, 120).fade(0.75 * k), c1: gc.fade(0.0) });
                        } else {
                            let gc = if dark { Color::rgb(190, 220, 255) } else { Color::rgb(70, 160, 255) };
                            cx.cv.fill_circle(gcx, gcy, 26.0, Paint::Radial { c: Pt::new(gcx, gcy), r: 26.0, c0: gc.fade((if dark { 0.34 } else { 0.50 }) * k), c1: gc.fade(0.0) });
                            cx.cv.fill_circle(gcx, gcy, 12.0, Paint::Radial { c: Pt::new(gcx, gcy), r: 12.0, c0: Color::WHITE.fade(0.40 * k), c1: gc.fade(0.0) });
                        }
                    }
                }
                for (slot, idx) in [(0usize, 1usize), (1, 2), (2, 0)] {
                    let br = Rect::new(gx + slot as f32 * bw, group.y, bw, bh);
                    let hit = hot && br.contains(io.mouse.x, io.mouse.y);
                    let hv = hv_all[idx];
                    let is_close = idx == 0;
                    let ic = if is_close { ink.mix(Color::WHITE, hv) } else { ink.mix(if dark { Color::WHITE } else { Color::BLACK }, hv * 0.5) };
                    let (cxm, cym) = (br.cx(), br.cy());
                    let lw_ = 1.6;
                    // faint halo behind each glyph at rest keeps it legible over any titlebar
                    let halo = if dark { Color::rgba(0, 0, 0, 60) } else { Color::rgba(255, 255, 255, 120) };
                    for pass in 0..2 {
                        let (col, o, wd) = if pass == 0 { (halo.fade(1.0 - hv), 0.8f32, lw_ + 1.6) } else { (ic, 0.0, lw_) };
                        match idx {
                            1 => { cx.cv.line(Pt::new(cxm - 4.6, cym + 3.4 + o), Pt::new(cxm + 4.6, cym + 3.4 + o), wd + 0.2, col); }
                            2 => {
                                if w.zoomed { cx.cv.stroke_rrect(Rect::new(cxm - 3.0, cym - 4.6 + o, 7.4, 7.4), 1.0, wd * 0.8, col); cx.cv.stroke_rrect(Rect::new(cxm - 4.8, cym - 2.6 + o, 7.4, 7.4), 1.0, wd * 0.8, col); }
                                else { cx.cv.stroke_rrect(Rect::new(cxm - 4.6, cym - 4.4 + o, 9.2, 8.8), 1.2, wd * 0.8, col); cx.cv.fill_rect(Rect::new(cxm - 4.4, cym - 4.2 + o, 8.8, 1.8), col); }
                            }
                            _ => { cx.cv.line(Pt::new(cxm - 4.4, cym - 4.4 + o), Pt::new(cxm + 4.4, cym + 4.4 + o), wd + 0.1, col); cx.cv.line(Pt::new(cxm + 4.4, cym - 4.4 + o), Pt::new(cxm - 4.4, cym + 4.4 + o), wd + 0.1, col); }
                        }
                    }
                    if io.released && w.light_down == Some(idx) && hit { match idx { 0 => close_req = Some(i), 1 => min_req = Some(i), _ => zoom_req = Some(w.id) } }
                }
                if io.released { w.light_down = None; }
            }
            if hot { want_cursor = Some(cursor); }
            // titlebar drag / double-click zoom
            if hot && pressed && !over_widget && io.mouse.y >= 0.0 && io.mouse.y < DRAG_H && w.light_down.is_none() {
                if click_count >= 2 { zoom_req = Some(w.id); } else { start_drag = Some((w.id, Pt::new(io.mouse.x, io.mouse.y))); }
            }
            w.layer_ok = true; w.layer_dims = (lw, lh); w.layer_draws += 1;
            }
            // inactive veil (Golden Gate: active window is more distinct) is applied while compositing, not baked into the layer
            // ─ composite onto the screen ─
            let veil_dim = ((1.0 - w.focus.x.clamp(0.0, 1.0)) * if th.is_dark() { 34.0 } else { 14.0 }) as u32;
            let o = w.open.x;
            let fa = (o * 1.7).clamp(0.0, 1.0);
            let focus_t = w.focus.x.clamp(0.0, 1.0);
            let scr = &mut this.screen;
            // PDF Section 6.3: Unforgeable 2-pixel colored security border based on kernel capability badge
            let (_badge, border_color) = match w.kind {
                // Badge 0x01: Cyan Border: Core System Settings & File Manager (0x00E5FF)
                AppKind::Settings | AppKind::Files | AppKind::ActivityMonitor | AppKind::About => (0x01u8, Color::rgb(0, 229, 255)),
                // Badge 0x02: Emerald Border: Sovereign Personal Workspaces (0x00E676)
                AppKind::Messages | AppKind::Notes => (0x02u8, Color::rgb(0, 230, 118)),
                // Badge 0x03: Blue Border: Enterprise Work Compartments (0x2979FF)
                AppKind::Terminal | AppKind::Calculator => (0x03u8, Color::rgb(41, 121, 255)),
                // Badge 0x04: Tangerine Border: Ephemeral RAM-Only Sandboxes (0xFF9100)
                AppKind::Browser => (0x04u8, Color::rgb(255, 145, 0)),
                // Badge 0x05: Red Border: Untrusted External Media / FUSE Drivers (0xFF1744)
                AppKind::Photos | AppKind::Music => (0x05u8, Color::rgb(255, 23, 68)),
            };
            if w.min.x > 0.002 {
                let tgt = this.dock.icon_center(w.kind, screen_r);
                scr.blit_genie(&w.layer, Rect::new(rx as f32, ry as f32, lw as f32, lh as f32), tgt, w.min.x.clamp(0.0, 1.0), 1.0 - 0.3 * w.min.x.clamp(0.0, 1.0));
            } else if (o - 1.0).abs() > 0.002 {
                let s = 0.86 + 0.14 * o;
                let dr = Rect::new(rect.cx() - rect.w * s * 0.5, rect.cy() - rect.h * s * 0.5 + (1.0 - o.min(1.0)) * 10.0, rect.w * s, rect.h * s);
                scr.shadow_rrect(dr.offset(0.0, 14.0), WIN_R, 34.0, th.shadow(0.30 * fa), true);
                scr.blit_scaled(&w.layer, dr, WIN_R * s, fa);
                scr.stroke_rrect(dr, WIN_R * s, 1.0, th.pick(Color::rgba(0, 0, 0, 50), Color::rgba(255, 255, 255, 36)).fade(fa));
                scr.stroke_rrect(dr, WIN_R * s, 2.0, border_color.fade(0.8 * fa));
            } else {
                let full = Rect::new(rx as f32, ry as f32, lw as f32, lh as f32);
                scr.shadow_rrect(full.offset(0.0, 8.0 + 8.0 * focus_t), WIN_R, 20.0 + 18.0 * focus_t, th.shadow(0.12 + 0.20 * focus_t), true);
                scr.shadow_rrect(full.offset(0.0, 1.5), WIN_R, 3.0, th.shadow(0.12), true);
                scr.blit_rounded_dim(&w.layer, rx, ry, WIN_R, 255, veil_dim);
                scr.stroke_rrect(full, WIN_R, 1.0, th.pick(Color::rgba(0, 0, 0, 56), Color::rgba(0, 0, 0, 120)));
                let border_alpha = if is_focus { 230 } else { 120 };
                // 2-pixel unforgeable capability border
                scr.stroke_rrect(full, WIN_R, 2.0, border_color.fade(border_alpha as f32 / 255.0));
                // snapshot the finished composite (window + shadow over everything below) for reuse
                if w.open.settled() && w.min.settled() && w.focus.settled() && !w.closing {
                    let m = 64;
                    let bx = (rx - m).max(0); let by = (ry - m).max(0);
                    let bx2 = (rx + lw + m).min(scr.w); let by2 = (ry + lh + m).min(scr.h);
                    if bx2 > bx && by2 > by {
                        let (bw, bh) = (bx2 - bx, by2 - by);
                        w.snap.clear(); w.snap.reserve((bw * bh) as usize);
                        for y in 0..bh { let o = ((by + y) * scr.w + bx) as usize; w.snap.extend_from_slice(&scr.px[o..o + bw as usize]); }
                        w.snap_box = (bx, by, bw, bh); w.snap_ok = true;
                    }
                }
            }
            chain = { this.chain_ctr += 1; this.chain_ctr }; w.out_chain = chain;
        }
        if let Some((id, off)) = start_drag {
            if let Some(w) = self.windows.iter_mut().find(|w| w.id == id) {
                if w.zoomed {
                    let ratio = off.x / w.rect(max_r).w.max(1.0);
                    let r0 = w.restore;
                    w.zoomed = false; w.zoom.snap(0.0);
                    w.restore = Rect::new(mouse.x - ratio * r0.w, mouse.y - off.y, r0.w, r0.h);
                    self.drag = Drag::Move { id, off: Pt::new(ratio * r0.w, off.y) };
                } else { self.drag = Drag::Move { id, off }; }
            }
        }
        if let Some(id) = zoom_req { self.set_zoom(id); }
        if let Some(i) = close_req { self.close_idx(i); }
        if let Some(i) = min_req { self.windows[i].minimized = true; self.windows[i].min.set(1.0); }
        self.windows.retain(|w| !(w.closing && w.open.x < 0.01));
        if matches!(self.drag, Drag::Move { .. }) { next_cursor = CursorShape::Arrow; }
        if let Some(c) = want_cursor { if edge == 0 && matches!(self.drag, Drag::None) { next_cursor = c; } }

        let t_c = self.now();
        // ─── shell layers ───
        let menus = self.menus();
        let mut running: Vec<AppKind> = Vec::new();
        for w in self.windows.iter() { if !w.closing && !running.contains(&w.kind) { running.push(w.kind); } }
        let mut recents: Vec<AppKind> = Vec::new();
        if self.sys.dock_recents {
            for k in running.iter() { if !self.dock.is_pinned(*k) && *k != AppKind::About { recents.push(*k); } }
            let mut cand: Vec<(i64, AppKind)> = Vec::new();
            for a in self.sys.reg.apps.iter() { if let Some(k) = a.kind { if a.last_used > 0 && !self.dock.is_pinned(k) && !recents.contains(&k) && k != AppKind::About { cand.push((a.last_used, k)); } } }
            cand.sort_by(|a, b| b.0.cmp(&a.0));
            for (_, k) in cand { if recents.len() >= 3 { break; } recents.push(k); }
            recents.truncate(4);
        }
        let mut io = io_base.clone();
        io.mouse = mouse; io.pressed = pressed; io.released = released; io.hot = true; io.wheel = inp.wheel; io.focused = false;
        let mut cursor = CursorShape::Arrow;
        let mut over = false;
        let bar_event;
        {
            let this = &mut *self;
            // Dock (under the menubar so popups can overlap)
            let dock_hot = !spot_vis && !menu_blocks && !in_cc && !(this.bar.is_open() && !in_dock);
            {
                let mut cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &io, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                this.dock.update_draw(&mut cx, &running, &recents, screen_r, dock_hot && !interacting);
            }
            {
                let mut cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &io, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                bar_event = this.bar.update_draw(&mut cx, screen_r, &menus, !spot_vis && !interacting);
            }
            {
                let mut cio = io.clone(); cio.hot = !spot_vis;
                let mut cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &cio, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                this.cc.update_draw(&mut cx, screen_r);
            }
            {
                let cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &io, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                let mut sio = io.clone(); sio.keys = keys.clone();
                let mut cx2 = Ctx { cv: cx.cv, fonts: cx.fonts, scratch: cx.scratch, th: cx.th, io: &sio, anims: cx.anims, sys: cx.sys, cmds: cx.cmds, bounds: screen_r, cursor: cx.cursor, over_widget: cx.over_widget };
                this.spot.update_draw(&mut cx2, screen_r);
            }
            {
                let mut lio = io.clone(); lio.keys = keys.clone();
                let mut cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &lio, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                this.lp.update_draw(&mut cx, screen_r);
            }
            {
                let mut pio = io.clone(); pio.keys = keys.clone();
                let mut cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &pio, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                this.pp.update_draw(&mut cx, screen_r);
            }
            {
                let mut cx = Ctx { cv: &mut this.screen, fonts: &mut this.fonts, scratch: &mut this.scratch, th: &th, io: &io, anims: &mut this.anims, sys: &mut this.sys, cmds: &mut this.cmds,
                    bounds: screen_r, cursor: &mut cursor, over_widget: &mut over };
                this.toasts.update_draw(&mut cx, screen_r);
            }
        }
        match bar_event {
            BarEvent::Action(a) => match a {
                Action::Cmd(c) => self.cmds.push(c),
                Action::ToggleDark => { self.sys.appearance = if self.th.is_dark() { Appearance::Light } else { Appearance::Dark }; }
                Action::AppCmd(name) => {
                    if name == "__new" { if let Some(i) = self.focused_idx() { let k = self.windows[i].kind; if k == AppKind::Files { self.spawn(k, None); } } }
                    else if let Some(i) = self.focused_idx() { self.windows[i].app.command(name); }
                }
                Action::None => {}
            },
            BarEvent::ControlCenter => { self.cc.open = !self.cc.open; }
            BarEvent::Spotlight => self.spot.toggle(),
            BarEvent::None => {}
        }
        self.process_cmds();
        if self.lock.visible() { self.draw_lock_overlay(inp, dt); }
        let t_d = self.now();

        // ─── post: brightness / night shift ───
        let bright = self.sys.brightness.clamp(0.2, 1.0);
        if bright < 0.995 || self.sys.night_shift {
            let dimq = (bright * 256.0) as u32;
            let night = self.sys.night_shift;
            for p in self.screen.px.iter_mut() {
                let (mut r, mut g, mut b) = ((*p >> 16) & 255, (*p >> 8) & 255, *p & 255);
                if night { g = g * 245 / 256; b = b * 205 / 256; }
                r = r * dimq >> 8; g = g * dimq >> 8; b = b * dimq >> 8;
                *p = (r << 16) | (g << 8) | b;
            }
        }
        // ─── boot / power overlays ───
        let boot_alpha = if self.boot < 1.1 { 1.0 } else { (1.0 - (self.boot - 1.1) / 0.7).clamp(0.0, 1.0) };
        if boot_alpha > 0.002 {
            let a = (boot_alpha * 255.0) as u8;
            self.screen.fill_rect(screen_r, Color::rgba(0, 0, 0, a));
            let c = screen_r.center();
            let pop = ease_out_cubic((self.boot / 0.6).min(1.0));
            let sz = 84.0 * (0.8 + 0.2 * pop);
            { let dest = Rect::new(c.x - sz * 0.5, c.y - sz * 0.5 - 18.0, sz, sz); self.fonts.icons.draw(&mut self.screen, 900, dest, boot_alpha * pop, &|cv, rr| draw_kash_mark(cv, rr, Color::WHITE, Some(Color::hex(0x7BE3FF)))); }
            let bw = 180.0; let prog = (self.boot / 1.0).min(1.0);
            self.screen.fill_rrect(Rect::new(c.x - bw * 0.5, c.y + 52.0, bw, 4.0), 2.0, Color::rgba(255, 255, 255, (50.0 * boot_alpha) as u8));
            self.screen.fill_rrect(Rect::new(c.x - bw * 0.5, c.y + 52.0, bw * prog, 4.0), 2.0, Color::rgba(255, 255, 255, (230.0 * boot_alpha) as u8));
        }
        if self.power.x > 0.003 {
            let a = (self.power.x.clamp(0.0, 1.0) * 255.0) as u8;
            self.screen.fill_rect(screen_r, Color::rgba(0, 0, 0, a));
            let c = screen_r.center();
            let s = self.power.x.clamp(0.0, 1.0);
            { let dest = Rect::new(c.x - 36.0, c.y - 36.0, 72.0, 72.0); self.fonts.icons.draw(&mut self.screen, 900, dest, s, &|cv, rr| draw_kash_mark(cv, rr, Color::WHITE, Some(Color::hex(0x7BE3FF)))); }
            self.fonts.draw_in(&mut self.screen, Rect::new(c.x - 200.0, c.y + 50.0, 400.0, 24.0), "Shutting down…", 14.0, Weight::Medium, Color::rgba(255, 255, 255, (200.0 * s) as u8), Align::Center);
        }
        let t_e = self.now();
        self.prof = [t_b - t_a, t_c - t_b, t_d - t_c, t_e - t_d, 0.0, 0.0, 0.0, 0.0];
        // ─── retain the finished scene (everything except the cursor sprite) ───
        if boot_alpha <= 0.0 && self.power.x <= 0.003 && !self.lock.visible() {
            if self.scene.w != self.screen.w || self.scene.h != self.screen.h { self.scene.resize(self.screen.w, self.screen.h); }
            self.scene.px.copy_from_slice(&self.screen.px);
            self.scene_valid = true;
        } else { self.scene_valid = false; }
        self.stats_full += 1;
        // ─── cursor (always last, exact position) ───
        self.cursor_shape = next_cursor;
        if boot_alpha < 0.98 {
            draw_cursor(&mut self.screen, mouse.x, mouse.y, self.cursor_shape, self.cur_scale.x);
        }
        let _ = (&mut self.time, over, cursor);
    }
}
