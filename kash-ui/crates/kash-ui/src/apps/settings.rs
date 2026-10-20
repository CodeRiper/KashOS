//! System Settings — edge-to-edge glass sidebar and grouped prototype panes.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::app::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::icons::*;
use crate::mathf::saturate;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;
use crate::wallpaper;

pub const PANES: [(&str, Icon, u32); 23] = [
    ("Wi-Fi", Icon::Wifi, 0x0A84FF), ("Bluetooth", Icon::Bluetooth, 0x0A84FF), ("Network", Icon::Globe, 0x0A84FF), ("Battery", Icon::Battery, 0x30D158),
    ("General", Icon::Gear, 0x8E8E93), ("Appearance", Icon::Palette, 0x1C1C1E), ("Accessibility", Icon::Accessibility, 0x0A84FF), ("Control Center", Icon::Sliders, 0x8E8E93),
    ("Desktop & Dock", Icon::Dock, 0x1C1C1E), ("Displays", Icon::Sun, 0x0A84FF), ("Wallpaper", Icon::Wallpaper, 0x32ADE6),
    ("Notifications", Icon::Bell, 0xFF453A), ("Sound", Icon::Sound, 0xFF375F), ("Focus", Icon::Moon, 0x5E5CE6),
    ("Privacy & Security", Icon::Shield, 0x0A84FF), ("Keyboard", Icon::Keyboard, 0x8E8E93), ("Mouse", Icon::Mouse, 0x8E8E93), ("Users & Groups", Icon::User, 0x0A84FF),
    ("Lock Screen", Icon::Lock, 0x1C1C1E), ("Software Update", Icon::Gear, 0x8E8E93), ("Storage", Icon::Disk, 0x8E8E93), ("Date & Time", Icon::Clock, 0x0A84FF), ("About", Icon::Info, 0x8E8E93),
];
const BREAKS: [usize; 4] = [4, 11, 14, 18];

pub struct Settings {
    pub sel: usize,
    search: FieldState,
    scroll: Scroll,
    sb_scroll: Scroll,
    sb_total: f32,
    pane_t: Spring,
    thumbs: Vec<Option<Canvas>>,
    pub(crate) kb: [f32; 2],
    privacy: crate::apps::privacy::Privacy,
    pub(crate) pw_f: [FieldState; 4],
    pub(crate) dz_f: [FieldState; 3],
    pub(crate) pw_msg: (String, bool),
    pub(crate) dz_msg: (String, bool),
    pub(crate) notif_open: Option<usize>,
}

impl Settings {
    pub fn new() -> Settings {
        let mut s = Settings { sel: 5, search: FieldState::default(), scroll: Scroll::default(), sb_scroll: Scroll::default(), sb_total: 0.0, pane_t: Spring::new(1.0, 0.3, 1.0), thumbs: Vec::new(), kb: [0.6, 0.4], privacy: crate::apps::privacy::Privacy::new(), pw_f: [FieldState { mask: true, ..FieldState::default() }, FieldState { mask: true, ..FieldState::default() }, FieldState { mask: true, ..FieldState::default() }, FieldState::default()], dz_f: [FieldState { mask: true, ..FieldState::default() }, FieldState { mask: true, ..FieldState::default() }, FieldState { mask: true, ..FieldState::default() }], pw_msg: (String::new(), true), dz_msg: (String::new(), true), notif_open: None };
        s.pane_t.snap(1.0);
        for _ in 0..5 { s.thumbs.push(None); }
        s
    }
    pub fn open_pane(&mut self, i: usize) { if i < PANES.len() && i != self.sel { self.sel = i; self.scroll = Scroll::default(); self.pane_t.snap(0.0); self.pane_t.set(1.0); } }
}

const SB_W: f32 = 246.0;

impl App for Settings {
    fn kind(&self) -> AppKind { AppKind::Settings }
    fn title(&self) -> String { String::from(PANES[self.sel].0) }
    fn default_size(&self) -> (f32, f32) { (880.0, 640.0) }
    fn min_size(&self) -> (f32, f32) { (700.0, 420.0) }

    fn animating(&self) -> bool { !self.pane_t.settled() || self.privacy.animating() || self.scroll.moving() || self.sb_scroll.moving() }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        if let Some(p) = cx.sys.settings_pane_request.take() { self.open_pane(p); }
        if let Some(n) = cx.sys.privacy_request.take() { self.open_pane(14); self.privacy.goto_app(&cx.sys.reg, &n); self.scroll = Scroll::default(); }
        if self.privacy.nav_changed { self.privacy.nav_changed = false; self.scroll = Scroll::default(); }
        self.pane_t.update(cx.io.dt);
        let content = Rect::new(SB_W, 0.0, area.w - SB_W, area.h);
        let sb = Rect::new(0.0, 0.0, SB_W, area.h);
        let mut st = th.glass(GlassKind::Sidebar, 0.0);
        st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0;
        cx.glass_style(sb, &st);
        cx.cv.fill_rect(content, th.window_bg());

        cx.cv.push_clip(content);
        let pw = (content.w - 56.0).min(580.0);
        let px = content.x + (content.w - pw) * 0.5;
        let tt = saturate(self.pane_t.x);
        let mut form = Form { x: px, y: 72.0 - self.scroll.y + (1.0 - tt) * 14.0, w: pw };
        let y0 = form.y;
        let sel = self.sel;
        match sel {
            0 => self.pane_wifi(cx, &mut form),
            1 => self.pane_bluetooth(cx, &mut form),
            2 => self.pane_network(cx, &mut form),
            3 => self.pane_battery(cx, &mut form),
            4 => self.pane_general(cx, &mut form),
            5 => self.pane_appearance(cx, &mut form),
            6 => self.pane_accessibility(cx, &mut form),
            7 => self.pane_control_center(cx, &mut form),
            8 => self.pane_dock(cx, &mut form),
            9 => self.pane_displays(cx, &mut form),
            10 => self.pane_wallpaper(cx, &mut form),
            11 => self.pane_notifications(cx, &mut form),
            12 => self.pane_sound(cx, &mut form),
            13 => self.pane_focus(cx, &mut form),
            14 => self.privacy.draw(cx, &mut form),
            15 => self.pane_keyboard(cx, &mut form),
            18 => self.pane_lock(cx, &mut form),
            19 => self.pane_update(cx, &mut form),
            20 => self.pane_storage(cx, &mut form),
            21 => self.pane_datetime(cx, &mut form),
            22 => self.pane_about(cx, &mut form),
            16 => self.pane_mouse(cx, &mut form),
            17 => self.pane_users(cx, &mut form),
            _ => self.pane_generic(cx, &mut form),
        }
        let total = form.y - y0 + 90.0;
        let hov = cx.hover(content);
        self.scroll.update(cx.io, hov, total - area.h);
        let wb = th.window_bg();
        cx.cv.fill_rect(Rect::new(content.x, 0.0, content.w, 54.0), wb.fade(0.985));
        cx.cv.fill_rect(Rect::new(content.x, 54.0, content.w, 26.0), Paint::VGrad { y0: 54.0, y1: 80.0, c0: wb.fade(0.985), c1: wb.fade(0.0) });
        if sel == 14 && self.privacy.nav.len() > 1 {
            let pt = self.privacy.parent_title(&cx.sys.reg);
            let bw = cx.measure(&pt, 13.0, Weight::Medium) + 36.0;
            let br = Rect::new(content.x + 14.0, 16.0, bw, 28.0);
            let h = cx.hit(id_of("privback"), br);
            let hv = cx.anim(id2(id_of("privback"), 1), if h.hovered { 1.0 } else { 0.0 });
            cx.cv.fill_rrect(br, 14.0, th.hover_fill().fade(hv));
            draw_icon(cx.cv, Icon::ChevL, Rect::new(br.x + 8.0, br.cy() - 7.0, 14.0, 14.0), th.accent());
            cx.text(br.x + 26.0, br.cy() + 4.6, &pt, 13.0, Weight::Medium, th.accent());
            if h.clicked { self.privacy.back(); self.scroll = Scroll::default(); }
            let title = self.privacy.title(&cx.sys.reg);
            cx.text_in(Rect::new(content.x, 12.0, content.w, 36.0), &title, 15.0, Weight::Semibold, th.label(), Align::Center);
        } else { cx.text(content.x + 28.0, 38.0, PANES[sel].0, 20.0, Weight::Bold, th.label()); }
        cx.cv.pop_clip();

        // sidebar
        cx.cv.fill_rect(Rect::new(SB_W - 1.0, 0.0, 1.0, area.h), th.separator());
        cx.text_field("ssearch", Rect::new(14.0, 50.0, SB_W - 28.0, 30.0), &mut self.search, "Search", Some(Icon::Search));
        let q = self.search.text.to_lowercase();
        let hov_sb = cx.hover(sb);
        self.sb_scroll.update(cx.io, hov_sb, self.sb_total + 16.0 - area.h);
        cx.cv.push_clip(Rect::new(0.0, 88.0, SB_W - 1.0, area.h - 88.0));
        let mut y = 92.0 - self.sb_scroll.y;
        if q.is_empty() {
            let pr = Rect::new(10.0, y, SB_W - 20.0, 58.0);
            let h = cx.hit(id_of("sprof"), pr);
            if h.hovered { cx.cv.fill_rrect(pr, 12.0, th.hover_fill()); }
            cx.cv.fill_circle(pr.x + 30.0, pr.cy(), 20.0, Paint::Linear { p0: Pt::new(pr.x + 10.0, pr.y), p1: Pt::new(pr.x + 50.0, pr.bottom()), c0: Color::hex(0x62CBFF), c1: Color::hex(0x5A2BD2) });
            draw_kash_mark(cx.cv, Rect::new(pr.x + 17.0, pr.cy() - 13.0, 26.0, 26.0), Color::WHITE, Some(Color::hex(0xB6F3FF)));
            cx.text(pr.x + 60.0, pr.cy() - 3.0, "Local session", 14.0, Weight::Semibold, th.label());
            cx.text(pr.x + 60.0, pr.cy() + 13.0, "Account service unavailable", 11.5, Weight::Regular, th.label2());
            if h.clicked { self.open_pane(17); }
            y += 70.0;
        }
        for (i, (name, ic, col)) in PANES.iter().enumerate() {
            if !q.is_empty() && !name.to_lowercase().contains(&q) { continue; }
            if q.is_empty() && BREAKS.contains(&i) { y += 10.0; }
            let r = Rect::new(10.0, y, SB_W - 20.0, 32.0);
            let h = cx.hit(id_of(name) ^ 0x5E, r);
            let cur = i == self.sel;
            let t = cx.anim(id2(id_of(name), 0x5F), if cur { 1.0 } else { 0.0 });
            if t > 0.01 { cx.cv.fill_rrect(r, 11.0, th.accent().fade(t)); }
            else if h.hovered { cx.cv.fill_rrect(r, 11.0, th.hover_fill()); }
            let tile = Rect::new(r.x + 8.0, r.y + 5.0, 22.0, 22.0);
            let tcol = if *col == 0x1C1C1E && th.is_dark() { Color::hex(0x636366) } else { Color::hex(*col) };
            cx.cv.fill_rrect(tile, 6.0, Paint::VGrad { y0: tile.y, y1: tile.bottom(), c0: tcol.lighten(0.18), c1: tcol });
            draw_icon(cx.cv, *ic, tile.inset(3.5), Color::WHITE);
            let tc = th.label().mix(Color::WHITE, t);
            cx.text_in(Rect::new(r.x + 40.0, r.y, r.w - 44.0, r.h), name, 13.0, Weight::Regular, tc, Align::Left);
            if h.clicked { self.open_pane(i); }
            y += 33.0;
        }
        self.sb_total = y + self.sb_scroll.y;
        cx.cv.pop_clip();
    }
}

impl Settings {
    fn pane_wifi(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mut g = cx.group_begin(f, 2, 48.0);
        cx.row_value(&mut g, "Wi-Fi adapter", "No Wi-Fi driver connected");
        cx.row_value(&mut g, "Known networks", "Unavailable");
        cx.caption(f, "This build has no Wi-Fi connection manager. The control center does not connect to a network.");
    }

    fn pane_bluetooth(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mut g = cx.group_begin(f, 2, 48.0);
        cx.row_value(&mut g, "Bluetooth controller", "No controller service connected");
        cx.row_value(&mut g, "Paired devices", "Unavailable");
        cx.caption(f, "Pairing controls will appear when a Bluetooth driver and service are connected.");
    }

    fn pane_network(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mut g = cx.group_begin(f, 4, 44.0);
        cx.row_value(&mut g, "Network interface", "Unavailable (no active NIC service)");
        cx.row_value(&mut g, "Anonymity gateway", "Unavailable (not implemented)");
        cx.row_value(&mut g, "Remote networking", "Unavailable (no verified protocol path)");
        cx.row_value(&mut g, "Packet filter", "Policy helper only (not NIC-integrated)");
        cx.caption(f, "This build has no verified NIC-to-TCP, DNS, or HTTPS path. Network and Tor access are unavailable; the policy helper is not connected to hardware egress.");
    }

    fn pane_battery(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mut g = cx.group_begin(f, 2, 48.0);
        cx.row_value(&mut g, "Battery", "No battery telemetry available");
        cx.row_value(&mut g, "Power controls", "Unavailable");
        cx.caption(f, "Battery percentage, estimated runtime, and charging controls require a battery driver.");
    }

    fn pane_general(&mut self, cx: &mut Ctx, f: &mut Form) {
        let r = Rect::new(f.x, f.y, f.w, 170.0);
        cx.group_box(r);
        cx.app_icon(AppKind::About, Rect::new(r.cx() - 44.0, r.y + 18.0, 88.0, 88.0));
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text_in(Rect::new(r.x, r.y + 112.0, r.w, 22.0), "KashOS", 18.0, Weight::Bold, lc, Align::Center);
        cx.text_in(Rect::new(r.x, r.y + 136.0, r.w, 18.0), &format!("KashOS development build · {}", env!("CARGO_PKG_VERSION")), 12.0, Weight::Regular, l2, Align::Center);
        f.y += 188.0;
        cx.heading(f, "About");
        let mut g = cx.group_begin(f, 6, 40.0);
        cx.row_value(&mut g, "Kernel", &format!("KashOS kernel {}", env!("CARGO_PKG_VERSION")));
        #[cfg(target_arch = "x86_64")]
        cx.row_value(&mut g, "Build target", "x86-64");
        #[cfg(target_arch = "aarch64")]
        cx.row_value(&mut g, "Build target", "AArch64");
        cx.row_value(&mut g, "Memory", "Runtime total unavailable");
        cx.row_value(&mut g, "Capability self-tests", "Boot log only · not reported to UI");
        cx.row_value(&mut g, "Encrypted vault", "Status unavailable · no UI service feed");
        cx.row_value(&mut g, "Display server", "kash-ui · software renderer");
    }

    fn pane_appearance(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Appearance");
        let cw = (f.w - 24.0) / 3.0;
        let names = ["Light", "Dark", "Auto"];
        for i in 0..3 {
            let r = Rect::new(f.x + i as f32 * (cw + 12.0), f.y, cw, 104.0);
            let sel = match (cx.sys.appearance, i) { (Appearance::Light, 0) | (Appearance::Dark, 1) | (Appearance::Auto, 2) => true, _ => false };
            let h = cx.hit(id_of(names[i]) ^ 0x41, r);
            if h.clicked { cx.sys.appearance = match i { 0 => Appearance::Light, 1 => Appearance::Dark, _ => Appearance::Auto }; }
            let t = cx.anim(id2(id_of(names[i]), 0x42), if sel { 1.0 } else { 0.0 });
            let box_r = Rect::new(r.x, r.y, r.w, 78.0);
            let acc = cx.th.accent();
            cx.cv.fill_rrect(box_r.inset(-3.0 * t), 12.0 + 3.0 * t, acc.fade(t));
            cx.cv.fill_rrect(box_r.inset(1.5), 10.0, Paint::Linear { p0: Pt::new(box_r.x, box_r.y), p1: Pt::new(box_r.right(), box_r.bottom()), c0: Color::hex(0x6BA7FF), c1: Color::hex(0xB48CFF) });
            let halves = if i == 2 { 2 } else { 1 };
            for half in 0..halves {
                let dark = if i == 2 { half == 1 } else { i == 1 };
                let wr = if i == 2 { Rect::new(box_r.x + 12.0 + half as f32 * (box_r.w / 2.0 - 10.0), box_r.y + 14.0, box_r.w / 2.0 - 14.0, 52.0) } else { Rect::new(box_r.x + 18.0, box_r.y + 14.0, box_r.w - 36.0, 52.0) };
                cx.cv.fill_rrect(wr, 6.0, if dark { Color::hex(0x2B2B30) } else { Color::hex(0xF7F7FA) });
                cx.cv.fill_rrect(Rect::new(wr.x, wr.y, wr.w * 0.28, wr.h), 6.0, if dark { Color::hex(0x3A3A42) } else { Color::hex(0xE4E6EE) });
                cx.cv.fill_rrect(Rect::new(wr.x + wr.w * 0.36, wr.y + 10.0, wr.w * 0.4, 5.0), 2.5, if dark { Color::hex(0x777782) } else { Color::hex(0xB8BBC8) });
                cx.cv.fill_rrect(Rect::new(wr.x + wr.w * 0.36, wr.y + 22.0, wr.w * 0.5, 5.0), 2.5, acc);
            }
            let lc = cx.th.label();
            cx.text_in(Rect::new(r.x, r.y + 80.0, r.w, 22.0), names[i], 12.5, if sel { Weight::Semibold } else { Weight::Regular }, lc, Align::Center);
        }
        f.y += 122.0;
        cx.heading(f, "Accent colour");
        let g = Rect::new(f.x, f.y, f.w, 60.0);
        cx.group_box(g);
        for (i, (name, l, d)) in ACCENTS.iter().enumerate() {
            let c = cx.th.pick(*l, *d);
            let cxp = g.x + 26.0 + i as f32 * ((g.w - 40.0) / 9.0);
            let r = Rect::new(cxp - 14.0, g.cy() - 14.0, 28.0, 28.0);
            let h = cx.hit(id_of(name) ^ 0x43, r.inset(-3.0));
            if h.clicked { cx.sys.accent = i; }
            let t = cx.anim(id2(id_of(name), 0x44), if cx.sys.accent == i { 1.0 } else { 0.0 });
            let hv = cx.anim(id2(id_of(name), 0x45), if h.hovered { 1.0 } else { 0.0 });
            cx.cv.fill_circle(r.cx(), r.cy(), 12.0 + hv * 1.5, c);
            if t > 0.01 { cx.cv.ring(r.cx(), r.cy(), 16.5, 2.0, c.fade(t)); draw_icon(cx.cv, Icon::Check, r.inset(7.0), Color::WHITE.fade(t)); }
        }
        f.y += 78.0;
        cx.heading(f, "Liquid Glass");
        let pr = Rect::new(f.x, f.y, f.w, 132.0);
        cx.cv.push_clip(pr);
        cx.cv.fill_rrect(pr, 14.0, Paint::Linear { p0: Pt::new(pr.x, pr.y), p1: Pt::new(pr.right(), pr.bottom()), c0: Color::hex(0xFF8A5C), c1: Color::hex(0x5C6BFF) });
        for (i, c) in [0xFFD60Au32, 0x30D158, 0xFF2D55, 0x64D2FF, 0xBF5AF2].iter().enumerate() {
            cx.cv.fill_circle(pr.x + 60.0 + i as f32 * 100.0, pr.cy() + if i % 2 == 0 { -22.0 } else { 20.0 }, 30.0, Color::hex(*c));
        }
        cx.cv.pop_clip();
        cx.cv.stroke_rrect(pr, 14.0, 0.8, cx.th.separator());
        let gp = Rect::new(pr.x + 60.0, pr.cy() - 30.0, pr.w - 120.0, 60.0);
        let sh = cx.th.shadow(0.25);
        cx.cv.shadow_rrect(gp.offset(0.0, 6.0), 30.0, 14.0, sh, false);
        cx.glass(gp, GlassKind::Dock, 30.0);
        let lc = cx.th.label();
        cx.text_in(gp, "KashOS · Liquid Glass", 15.0, Weight::Semibold, lc, Align::Center);
        f.y += 150.0;
        let mut g = cx.group_begin(f, 2, 52.0);
        let mut tint = 1.0 - cx.sys.clarity;
        if cx.row_slider(&mut g, "glass_slider", "Look", &mut tint, "Clear", "Tinted") { cx.sys.clarity = 1.0 - tint; }
        let mut rt = cx.sys.reduce_transparency;
        cx.row_toggle(&mut g, "reduce_tr", "Reduce transparency", "Replaces glass with a frosted solid", &mut rt);
        cx.sys.reduce_transparency = rt;
    }

    fn pane_dock(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Dock");
        let mut g = cx.group_begin(f, 4, 52.0);
        let mut s = cx.sys.dock_size;
        cx.row_slider(&mut g, "dock_size", "Size", &mut s, "Small", "Large"); cx.sys.dock_size = s;
        let mut m = cx.sys.dock_magnify_on;
        cx.row_toggle(&mut g, "dock_mag_on", "Magnification", "", &mut m); cx.sys.dock_magnify_on = m;
        let mut mv = cx.sys.dock_magnify;
        cx.row_slider(&mut g, "dock_mag", "Magnification amount", &mut mv, "Min", "Max"); cx.sys.dock_magnify = mv;
        let mut ah = cx.sys.dock_autohide;
        cx.row_toggle(&mut g, "dock_ah", "Automatically hide and show the Dock", "", &mut ah); cx.sys.dock_autohide = ah;
        cx.caption(f, "Changes apply instantly — hover the Dock to feel the spring-driven magnification.");
        self.pane_dock_extra(cx, f);
    }

    fn pane_displays(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Resolution & scaling");
        let mut g = cx.group_begin(f, 2, 52.0);
        let mut fit = cx.sys.display_scale == 0;
        if cx.row_toggle(&mut g, "display_fit", "Automatic fit", "Detects the framebuffer and chooses a low-memory size that fills it", &mut fit) && fit {
            cx.sys.display_scale = 0;
        }
        let mut compact = cx.sys.display_scale == 1;
        if cx.row_toggle(&mut g, "display_640", "640 × 480", "Low-memory desktop rendering", &mut compact) && compact {
            cx.sys.display_scale = 1;
        }
        let mut detail = cx.sys.display_scale == 2;
        if cx.row_toggle(&mut g, "display_800", "800 × 600", "Sharper rendering; requires additional free memory", &mut detail) && detail {
            cx.sys.display_scale = 2;
        }
        let mut output_size = cx.sys.display_scale == 3;
        if cx.row_toggle(&mut g, "display_native", "Output-sized", "Uses detected output dimensions, capped for memory safety", &mut output_size) && output_size {
            cx.sys.display_scale = 3;
        }
        let mode = match cx.sys.display_scale {
            0 => "Automatic fit",
            1 => "640 × 480 renderer",
            2 => "800 × 600 renderer",
            _ => "Output-sized renderer",
        };
        let output = format!("{} × {} output; {} × {} render; {}", cx.sys.display_output.w as i32, cx.sys.display_output.h as i32, cx.sys.screen.w as i32, cx.sys.screen.h as i32, mode);
        let mut g = cx.group_begin(f, 2, 44.0);
        cx.row_value(&mut g, "Active display mode", &output);
        cx.caption(f, "The framebuffer size is detected at boot. These options change the compositor resolution and scale it to fit; changing the physical monitor mode requires a video driver for the device.");

        let mut g = cx.group_begin(f, 3, 52.0);
        let mut b = cx.sys.brightness;
        cx.row_slider(&mut g, "brightness", "Brightness", &mut b, "", ""); cx.sys.brightness = b;
        let mut ns = cx.sys.night_shift;
        cx.row_toggle(&mut g, "night", "Night Shift", "Warmer colours after sunset", &mut ns); cx.sys.night_shift = ns;
        cx.heading(f, "Display capabilities");
        let mut g = cx.group_begin(f, 2, 44.0);
        cx.row_value(&mut g, "Framebuffer mode", "Reported by boot handoff");
        cx.row_value(&mut g, "Color temperature", "Not supported by framebuffer backend");
    }

    fn pane_wallpaper(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Wallpaper");
        let cols = 3usize;
        let gap = 12.0;
        let tw = (f.w - gap * (cols as f32 - 1.0)) / cols as f32;
        let th_ = tw * 0.625;
        for i in 0..wallpaper::WALLPAPERS.len() {
            let (c, r) = (i % cols, i / cols);
            let rect = Rect::new(f.x + c as f32 * (tw + gap), f.y + r as f32 * (th_ + 34.0), tw, th_);
            if self.thumbs[i].is_none() { let mut cv = Canvas::new(180, 112); wallpaper::paint(&mut cv, i); self.thumbs[i] = Some(cv); }
            let sel = cx.sys.wallpaper == i;
            let h = cx.hit(id_of(wallpaper::WALLPAPERS[i]) ^ 0x46, rect);
            if h.clicked { cx.sys.wallpaper = i; }
            let t = cx.anim(id2(id_of(wallpaper::WALLPAPERS[i]), 0x47), if sel { 1.0 } else { 0.0 });
            let hv = cx.anim(id2(id_of(wallpaper::WALLPAPERS[i]), 0x48), if h.hovered { 1.0 } else { 0.0 });
            let acc = cx.th.accent();
            if t > 0.01 { cx.cv.fill_rrect(rect.inset(-3.0), 13.0, acc.fade(t)); }
            let dr = rect.inset(-hv * 1.5);
            cx.cv.blit_scaled(self.thumbs[i].as_ref().unwrap(), dr, 10.0, 1.0);
            let lc = cx.th.label();
            cx.text_in(Rect::new(rect.x, rect.bottom() + 4.0, rect.w, 20.0), wallpaper::WALLPAPERS[i], 12.0, if sel { Weight::Semibold } else { Weight::Regular }, lc, Align::Center);
        }
        f.y += 2.0 * (th_ + 34.0);
    }

    fn pane_sound(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mut g = cx.group_begin(f, 2, 48.0);
        cx.row_value(&mut g, "Audio device", "No audio driver connected");
        cx.row_value(&mut g, "Volume control", "Unavailable");
        cx.caption(f, "Volume and output selection are not connected to an audio backend.");
    }

    fn pane_mouse(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Pointer & Tracking");
        let mut g = cx.group_begin(f, 2, 52.0);
        let mut speed = ((cx.sys.pointer_speed.clamp(0.5, 2.0) - 0.5) / 1.5).clamp(0.0, 1.0);
        cx.row_slider(&mut g, "pointer_speed", "Tracking speed", &mut speed, "Slow", "Fast");
        cx.sys.pointer_speed = 0.5 + speed * 1.5;
        let mut c = cx.sys.cursor_size;
        cx.row_slider(&mut g, "cursor_size", "Pointer size", &mut c, "Normal", "Large");
        cx.sys.cursor_size = c;
        cx.caption(f, "Tracking speed applies immediately to pointer movement. Device-specific acceleration remains fixed by the input driver.");

        cx.heading(f, "Mouse & Trackpad Scrolling");
        let mut g2 = cx.group_begin(f, 3, 52.0);
        let mut s_speed = ((cx.sys.scroll_speed.clamp(0.2, 3.0) - 0.2) / 2.8).clamp(0.0, 1.0);
        cx.row_slider(&mut g2, "scroll_speed", "Scrolling speed", &mut s_speed, "Slow", "Fast");
        cx.sys.scroll_speed = 0.2 + s_speed * 2.8;

        let mut nat = cx.sys.natural_scroll;
        cx.row_toggle(&mut g2, "natural_scroll", "Natural scrolling", "Content tracks finger or wheel movement", &mut nat);
        cx.sys.natural_scroll = nat;

        let mut tap = cx.sys.trackpad_tap;
        cx.row_toggle(&mut g2, "trackpad_tap", "Tap to click", "Single finger tap acts as primary click", &mut tap);
        cx.sys.trackpad_tap = tap;
        cx.caption(f, "Scrolling options support standard PS/2 IntelliMouse hardware, trackpad scroll areas, and USB wheel mice.");

        cx.heading(f, "Hardware Controller");
        let mut g3 = cx.group_begin(f, 2, 46.0);
        cx.row_value(&mut g3, "Controller", "8042 PS/2 Keyboard & Auxiliary Mouse");
        cx.row_value(&mut g3, "Packet Format", "IntelliMouse 4-byte streaming (Z-axis wheel active)");
    }

    fn pane_generic(&mut self, cx: &mut Ctx, f: &mut Form) {
        let name = PANES[self.sel].0;
        let mut g = cx.group_begin(f, 1, 48.0);
        cx.row_value(&mut g, name, "Unavailable · no service connected");
        cx.caption(f, "This settings pane has no connected service in this build.");
    }
}
