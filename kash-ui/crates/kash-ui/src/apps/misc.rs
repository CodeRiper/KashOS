//! Notes, Browser, Photos, Music, Messages — lightweight apps that showcase glass chrome.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::app::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::*;
use crate::icons::*;
use crate::mathf::*;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;
use crate::wallpaper;

fn title_bar(cx: &mut Ctx, area: Rect, title: &str) {
    let r = Rect::new(0.0, 0.0, area.w, 54.0);
    let mut st = cx.th.glass(GlassKind::Toolbar, 0.0);
    st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0;
    cx.glass_style(r, &st);
    let c = cx.th.label();
    cx.text_in(r, title, 13.5, Weight::Semibold, c, Align::Center);
    let sc = cx.th.separator();
    cx.cv.fill_rect(Rect::new(0.0, 53.0, area.w, 1.0), sc);
}

// ───────── Notes ─────────
pub struct Notes { text: String, blink: f32, scroll: Scroll }
impl Notes { pub fn new() -> Notes { Notes { text: String::from("KashOS — notes\n\n• Golden Gate glass: clarity slider lives in Settings → Appearance\n• Dock magnification is spring-driven\n• Everything here is drawn by the Rust software renderer\n\nType here…"), blink: 0.0, scroll: Scroll::default() } } }
impl App for Notes {
    fn animating(&self) -> bool { self.scroll.moving() }
    fn kind(&self) -> AppKind { AppKind::Notes }
    fn default_size(&self) -> (f32, f32) { (640.0, 480.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        cx.cv.fill_rect(area, th.content_bg());
        if cx.io.focused { cx.sys.blink_req = true; }
        if cx.io.focused {
            for k in cx.io.keys.clone() { match k.key { Key::Char if !k.ctrl => { self.text.push(k.ch); self.blink = caret_reset(cx.io.time); } Key::Space => self.text.push(' '), Key::Enter => self.text.push('\n'), Key::Backspace => { self.text.pop(); } _ => {} } }
        }
        let lines = cx.fonts.wrap(&self.text, 15.0, Weight::Regular, area.w - 64.0);
        let total = 80.0 + lines.len() as f32 * 23.0;
        self.scroll.update(cx.io, cx.hover(area), total - area.h);
        cx.cv.push_clip(area);
        let mut y = 84.0 - self.scroll.y;
        let n = lines.len();
        for (i, l) in lines.iter().enumerate() {
            let w = cx.measure(l, 15.0, Weight::Regular);
            let is_title = i == 0;
            cx.text(32.0, y, l, if is_title { 20.0 } else { 15.0 }, if is_title { Weight::Bold } else { Weight::Regular }, th.label());
            if i + 1 == n && (!cx.io.focused || caret_on(cx.io.time, self.blink)) { cx.cv.fill_rect(Rect::new(32.0 + w + 1.0, y - 15.0, 1.5, 19.0), th.accent()); }
            y += 23.0;
        }
        cx.cv.pop_clip();
        title_bar(cx, area, "Notes");
    }
}

// ───────── Firefox Browser ─────────
pub struct Browser {
    url: FieldState,
    scroll: Scroll,
}

impl Browser {
    pub fn new() -> Browser {
        Browser {
            url: FieldState { text: String::from("https://start.duckduckgo.com"), ..FieldState::default() },
            scroll: Scroll::default(),
        }
    }
}

impl App for Browser {
    fn animating(&self) -> bool { self.scroll.moving() }
    fn kind(&self) -> AppKind { AppKind::Browser }
    fn default_size(&self) -> (f32, f32) { (880.0, 580.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        cx.cv.fill_rect(area, th.content_bg());

        let content_r = Rect::new(0.0, 54.0, area.w, area.h - 54.0);
        let total_h = 760.0;
        self.scroll.update(cx.io, cx.hover(content_r), (total_h - content_r.h).max(0.0));

        cx.cv.push_clip(content_r);
        let base_y = 54.0 - self.scroll.y;

        cx.cv.fill_rect(Rect::new(0.0, base_y, area.w, total_h), Paint::VGrad {
            y0: base_y,
            y1: base_y + total_h,
            c0: th.pick(Color::hex(0xEAF2FF), Color::hex(0x161B2E)),
            c1: th.content_bg(),
        });

        cx.text_in(Rect::new(0.0, base_y + 40.0, area.w, 36.0), "Browser (demo)", 28.0, Weight::Bold, th.label(), Align::Center);
        cx.text_in(Rect::new(0.0, base_y + 75.0, area.w, 20.0), "KashOS Native Lightweight Web Browser · Software Rendered · Strict Isolation", 12.0, Weight::Medium, th.pick(Color::hex(0x0A84FF), Color::hex(0x5E5CE6)), Align::Center);

        // Security Lockdown Status Card
        let sec_card = Rect::new(area.cx() - 320.0, base_y + 105.0, 640.0, 36.0);
        cx.cv.fill_rrect(sec_card, 10.0, th.pick(Color::rgba(255, 69, 58, 24), Color::rgba(255, 69, 58, 36)));
        cx.cv.stroke_rrect(sec_card, 10.0, 1.0, Color::rgba(255, 69, 58, 90));
        cx.text_in(sec_card, "Browser demo · Remote networking and process-isolated permissions are unavailable", 11.5, Weight::Regular, th.pick(Color::hex(0xC92A2A), Color::hex(0xFF6B6B)), Align::Center);

        let favs = [("DuckDuckGo", 0xDE5833), ("Mozilla", 0x000000), ("Wikipedia", 0x3366CC), ("EFF", 0xED1C24), ("Tor Project", 0x7D4698), ("Vault", 0x30D158)];
        let tw = 84.0; let gap = 20.0; let total = favs.len() as f32 * tw + (favs.len() as f32 - 1.0) * gap;
        for (i, (n, c)) in favs.iter().enumerate() {
            let r = Rect::new(area.cx() - total * 0.5 + i as f32 * (tw + gap), base_y + 165.0, tw, tw);
            let h = cx.hit(id_of(n) ^ 0xB0, r);
            let hv = cx.anim(id2(id_of(n), 0xB1), if h.hovered { 1.0 } else { 0.0 });
            let rr = r.inset(-hv * 3.0);
            cx.cv.shadow_rrect(rr.offset(0.0, 4.0), 20.0, 8.0, th.shadow(0.12), false);
            cx.cv.fill_rrect(rr, 20.0, Paint::VGrad { y0: rr.y, y1: rr.bottom(), c0: Color::hex(*c).lighten(0.2), c1: Color::hex(*c) });
            cx.text_in(rr, &n[..1], 30.0, Weight::Bold, Color::WHITE, Align::Center);
            cx.text_in(Rect::new(r.x - 10.0, r.bottom() + 6.0, r.w + 20.0, 18.0), n, 11.0, Weight::Regular, th.label2(), Align::Center);
        }

        // Search & Stories Section (revealed when scrolling down)
        let section_y = base_y + 290.0;
        cx.text(area.cx() - 320.0, section_y, "Recommended by Pocket", 16.0, Weight::Bold, th.label());

        let stories = [
            ("seL4 Microkernel Principles in Modern Operating Systems", "Formal verification and capability-based security architectures.", "systems.org · 5 min read"),
            ("Rust in the Kernel: Safe Memory Management without Garbage Collection", "Zero-cost abstractions and memory safety for bare-metal kernels.", "rust-lang.org · 8 min read"),
            ("Hardware Memory Budgets: Running Modern Workloads on 100 MB RAM", "Optimizing data structures, paging, and software renderers for constrained hardware.", "embedded.org · 12 min read"),
        ];

        for (i, (title, desc, meta)) in stories.iter().enumerate() {
            let card_r = Rect::new(area.cx() - 320.0, section_y + 16.0 + i as f32 * 105.0, 640.0, 92.0);
            let h = cx.hit(id2(0xB2, i as u32), card_r);
            let hv = cx.anim(id2(0xB3, i as u32), if h.hovered { 1.0 } else { 0.0 });
            let r_draw = card_r.inset(-hv * 1.5);
            cx.cv.fill_rrect(r_draw, 12.0, th.pick(Color::rgba(255, 255, 255, 180), Color::rgba(30, 36, 52, 180)));
            cx.cv.stroke_rrect(r_draw, 12.0, 1.0, th.separator());
            cx.text(card_r.x + 18.0, card_r.y + 26.0, title, 14.0, Weight::Semibold, th.label());
            cx.text(card_r.x + 18.0, card_r.y + 50.0, desc, 12.0, Weight::Regular, th.label2());
            cx.text(card_r.x + 18.0, card_r.y + 74.0, meta, 11.0, Weight::Regular, th.pick(Color::hex(0x0A84FF), Color::hex(0x5E5CE6)));
        }

        // Draw scrollbar if scrollable
        if total_h > content_r.h {
            let track_h = content_r.h - 16.0;
            let thumb_h = (content_r.h / total_h * track_h).max(24.0);
            let thumb_y = content_r.y + 8.0 + (self.scroll.y / (total_h - content_r.h)) * (track_h - thumb_h);
            let thumb_r = Rect::new(area.w - 10.0, thumb_y, 4.0, thumb_h);
            cx.cv.fill_rrect(thumb_r, 2.0, th.separator().fade(0.8));
        }

        cx.cv.pop_clip();

        title_bar(cx, area, "");
        cx.glass_icon_button("bback", Rect::new(84.0, 10.0, 34.0, 34.0), Icon::ChevL, true);
        cx.glass_icon_button("bfwd", Rect::new(124.0, 10.0, 34.0, 34.0), Icon::ChevR, false);
        let ur = Rect::new(172.0, 10.0, (area.w - 172.0 - 70.0 - CAPTION_RESERVE).max(120.0), 34.0);
        cx.glass(ur, GlassKind::Toolbar, 17.0);
        cx.text_field("burl", ur.inset_xy(3.0, 4.0), &mut self.url, "Search with DuckDuckGo or enter address", Some(Icon::Lock));
        cx.glass_icon_button("bshare", Rect::new(ur.right() + 12.0, 10.0, 34.0, 34.0), Icon::Share, true);
    }
}

// ───────── Photos ─────────
pub struct Photos { thumbs: Vec<Option<Canvas>>, open: Option<usize>, op: Spring, scroll: Scroll }
impl Photos { pub fn new() -> Photos { let mut t = Vec::new(); for _ in 0..10 { t.push(None); } Photos { thumbs: t, open: None, op: Spring::new(0.0, 0.34, 0.85), scroll: Scroll::default() } } }
impl App for Photos {
    fn animating(&self) -> bool { !self.op.settled() || self.scroll.moving() || self.thumbs.iter().any(|t| t.is_none()) }
    fn kind(&self) -> AppKind { AppKind::Photos }
    fn default_size(&self) -> (f32, f32) { (860.0, 580.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        cx.cv.fill_rect(area, th.content_bg());
        let cols = ((area.w - 24.0) / 190.0).max(2.0) as usize;
        let cw = (area.w - 8.0) / cols as f32;
        let rows = (10 + cols - 1) / cols;
        self.scroll.update(cx.io, cx.hover(area) && self.open.is_none(), 64.0 + rows as f32 * cw * 0.75 - area.h);
        cx.cv.push_clip(area);
        let mut clicked: Option<usize> = None;
        for i in 0..10 {
            if self.thumbs[i].is_none() {
                let mut cv = Canvas::new(240, 180); wallpaper::paint(&mut cv, i % 5);
                if i >= 5 { for p in cv.px.iter_mut() { let c = Color::from_pix(*p); *p = Color::rgb(c.b, c.r, c.g).pix(); } }
                self.thumbs[i] = Some(cv);
            }
            let (c, r) = (i % cols, i / cols);
            let rect = Rect::new(4.0 + c as f32 * cw, 62.0 + r as f32 * cw * 0.75 - self.scroll.y, cw - 4.0, cw * 0.75 - 4.0);
            let h = cx.hit(id_of(&format!("ph{}", i)), rect);
            let hv = cx.anim(id2(i as u32, 0xC1), if h.hovered { 1.0 } else { 0.0 });
            cx.cv.blit_scaled(self.thumbs[i].as_ref().unwrap(), rect.inset(-hv * 2.0), 6.0, 1.0);
            if h.clicked && self.open.is_none() { clicked = Some(i); }
        }
        cx.cv.pop_clip();
        if let Some(i) = clicked { self.open = Some(i); self.op.snap(0.0); self.op.set(1.0); }
        self.op.update(cx.io.dt);
        if let Some(i) = self.open {
            let t = saturate(self.op.x);
            cx.cv.fill_rect(area, Color::rgba(0, 0, 0, (t * 215.0) as u8));
            let w = (area.w - 80.0) * (0.7 + 0.3 * self.op.x); let h = w * 0.75;
            let r = Rect::new(area.cx() - w * 0.5, area.cy() - h * 0.5 + 10.0, w, h);
            cx.cv.blit_scaled(self.thumbs[i].as_ref().unwrap(), r, 16.0, t);
            if cx.glass_icon_button("pclose", Rect::new(area.w - 54.0, 66.0, 36.0, 36.0), Icon::Close, true) || (cx.io.pressed && !r.contains(cx.io.mouse.x, cx.io.mouse.y) && cx.io.mouse.y > 54.0) { self.open = None; }
        }
        title_bar(cx, area, "Photos — Library");
    }
}

// ───────── Music ─────────
pub struct Music { playing: bool, pos: f32, vol: f32, track: usize, bars: [Spring; 16] }
impl Music { pub fn new() -> Music { Music { playing: true, pos: 0.32, vol: 0.6, track: 0, bars: [Spring::new(0.0, 0.18, 0.5); 16] } } }
impl App for Music {
    fn kind(&self) -> AppKind { AppKind::Music }
    fn default_size(&self) -> (f32, f32) { (760.0, 500.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        let tracks = [("Midnight City", "M83"), ("Resonance", "HOME"), ("Nightcall", "Kavinsky"), ("Genesis", "Justice")];
        cx.cv.fill_rect(area, Paint::Linear { p0: Pt::new(0.0, 0.0), p1: Pt::new(area.w, area.h), c0: Color::hex(0xFF3B6B), c1: Color::hex(0x3B2DA8) });
        for i in 0..5 { cx.cv.fill_circle(area.w * (0.15 + 0.2 * i as f32), area.h * (0.3 + 0.4 * ((i * 37 % 10) as f32 / 10.0)), 120.0, Color::hex([0xFFB347u32, 0x00D4FF, 0xFF2D95, 0x7A3CFF, 0x30D158][i]).fade(0.45)); }
        if self.playing { self.pos = fract(self.pos + cx.io.dt / 214.0); }
        for (i, b) in self.bars.iter_mut().enumerate() { b.set(if self.playing { 0.25 + 0.75 * (0.5 + 0.5 * sin(cx.io.time * (3.0 + i as f32 * 0.37) + i as f32)) } else { 0.1 }); b.update(cx.io.dt); }
        let card = Rect::new(area.cx() - 250.0, 70.0, 500.0, area.h - 140.0);
        cx.cv.shadow_rrect(card.offset(0.0, 10.0), 34.0, 22.0, Color::rgba(0, 0, 0, 70), false);
        let mut st = th.glass(GlassKind::Popover, 34.0); st.tint.a = (st.tint.a as f32 * 0.55) as u8;
        cx.glass_style(card, &st);
        let ar = Rect::new(card.x + 28.0, card.y + 28.0, 150.0, 150.0);
        cx.cv.fill_rrect(ar, 22.0, Paint::Linear { p0: Pt::new(ar.x, ar.y), p1: Pt::new(ar.right(), ar.bottom()), c0: Color::hex(0xFFD60A), c1: Color::hex(0xFF2D55) });
        draw_icon(cx.cv, Icon::Music, ar.inset(42.0), Color::WHITE);
        let (t, a) = tracks[self.track];
        cx.text(ar.right() + 24.0, card.y + 80.0, t, 22.0, Weight::Bold, th.label());
        cx.text(ar.right() + 24.0, card.y + 106.0, a, 14.0, Weight::Regular, th.label2());
        for i in 0..16 { let h = 4.0 + 34.0 * self.bars[i].x; cx.cv.fill_rrect(Rect::new(ar.right() + 24.0 + i as f32 * 10.0, card.y + 168.0 - h, 6.0, h), 3.0, th.accent()); }
        let pr = Rect::new(card.x + 28.0, card.y + 206.0, card.w - 56.0, 24.0);
        let mut p = self.pos; if cx.slider("mpos", pr, &mut p) { self.pos = p; }
        let secs = (self.pos * 214.0) as i32;
        cx.text(pr.x, pr.bottom() + 16.0, &format!("{}:{:02}", secs / 60, secs % 60), 11.5, Weight::Regular, th.label2());
        cx.text_in(Rect::new(pr.x, pr.bottom() + 4.0, pr.w, 16.0), "3:34", 11.5, Weight::Regular, th.label2(), Align::Right);
        let cy = card.bottom() - 54.0;
        if cx.glass_icon_button("mprev", Rect::new(card.cx() - 92.0, cy - 22.0, 44.0, 44.0), Icon::ChevL, true) { self.track = (self.track + 3) % 4; self.pos = 0.0; }
        let pr2 = Rect::new(card.cx() - 30.0, cy - 30.0, 60.0, 60.0);
        let h = cx.hit(id_of("mplay"), pr2);
        if h.clicked { self.playing = !self.playing; }
        let sc = cx.anim(id_of("mplay_s"), if h.pressed { 0.92 } else { 1.0 });
        let rr = Rect::new(pr2.cx() - 30.0 * sc, pr2.cy() - 30.0 * sc, 60.0 * sc, 60.0 * sc);
        cx.glass(rr, GlassKind::Control, 30.0 * sc);
        if self.playing { cx.cv.fill_rrect(Rect::new(rr.cx() - 9.0, rr.cy() - 10.0, 6.0, 20.0), 2.0, th.label()); cx.cv.fill_rrect(Rect::new(rr.cx() + 3.0, rr.cy() - 10.0, 6.0, 20.0), 2.0, th.label()); }
        else { cx.cv.fill_poly(&[Pt::new(rr.cx() - 7.0, rr.cy() - 11.0), Pt::new(rr.cx() + 11.0, rr.cy()), Pt::new(rr.cx() - 7.0, rr.cy() + 11.0)], th.label()); }
        if cx.glass_icon_button("mnext", Rect::new(card.cx() + 48.0, cy - 22.0, 44.0, 44.0), Icon::ChevR, true) { self.track = (self.track + 1) % 4; self.pos = 0.0; }
        let mut v = self.vol; cx.slider("mvol", Rect::new(card.x + 28.0, card.bottom() - 34.0, 130.0, 24.0), &mut v); self.vol = v;
        let mut st = th.glass(GlassKind::Toolbar, 0.0); st.bezel = 0.0; st.spec = 0.0; st.tint.a = 20;
        cx.glass_style(Rect::new(0.0, 0.0, area.w, 44.0), &st);
    }
}

// ───────── Messages ─────────
pub struct Messages { sel: usize, input: FieldState, log: Vec<(bool, String, f32)>, scroll: Scroll }
impl Messages {
    pub fn new() -> Messages {
        let mut m = Messages { sel: 0, input: FieldState::default(), log: Vec::new(), scroll: Scroll::default() };
        m.log.push((false, String::from("Liquid Glass looks great on the new build"), 1.0));
        m.log.push((true, String::from("Thanks! Everything is Rust + a software renderer."), 1.0));
        m.log.push((false, String::from("No GPU at all? How is the blur so smooth?"), 1.0));
        m.log.push((true, String::from("Low-res box-blur pyramid + springs. 60 fps target."), 1.0));
        m
    }
}
impl App for Messages {
    fn kind(&self) -> AppKind { AppKind::Messages }
    fn default_size(&self) -> (f32, f32) { (780.0, 560.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        let sbw = 230.0;
        let content = Rect::new(sbw, 0.0, area.w - sbw, area.h);
        cx.cv.fill_rect(content, th.content_bg());
        let mut y = 74.0 - self.scroll.y;
        let maxw = content.w * 0.6;
        cx.cv.push_clip(content);
        let n = self.log.len();
        for i in 0..n {
            let (me, text) = (self.log[i].0, self.log[i].1.clone());
            let a = &mut self.log[i].2; *a += (1.0 - *a) * (1.0 - exp(-cx.io.dt * 10.0));
            let t = *a;
            let lines = cx.fonts.wrap(&text, 14.0, Weight::Regular, maxw - 28.0);
            let mut w = 0.0f32; for l in &lines { w = w.max(cx.measure(l, 14.0, Weight::Regular)); }
            let (bw, bh) = (w + 28.0, lines.len() as f32 * 19.0 + 18.0);
            let bx = if me { content.right() - 20.0 - bw } else { content.x + 20.0 };
            let by = y + (1.0 - t) * 18.0;
            let col = if me { th.accent() } else { th.pick(Color::rgb(233, 233, 238), Color::rgb(58, 58, 64)) };
            cx.cv.fill_rrect(Rect::new(bx, by, bw * (0.85 + 0.15 * t), bh), 18.0, col.fade(t));
            for (li, l) in lines.iter().enumerate() { cx.text(bx + 14.0, by + 22.0 + li as f32 * 19.0, l, 14.0, Weight::Regular, (if me { Color::WHITE } else { th.label() }).fade(t)); }
            y += bh + 8.0;
        }
        cx.cv.pop_clip();
        let total = y + self.scroll.y + 70.0;
        self.scroll.update(cx.io, cx.hover(content), total - area.h);
        let comp = Rect::new(content.x + 16.0, area.h - 56.0, content.w - 32.0, 40.0);
        cx.glass(comp, GlassKind::Toolbar, 20.0);
        if cx.text_field("msg", comp.inset_xy(4.0, 5.0), &mut self.input, "iMessage", None) {
            if !self.input.text.trim().is_empty() { let t = core::mem::take(&mut self.input.text); self.input.caret = 0; self.log.push((true, t, 0.0)); self.scroll.y = 1.0e6; }
        }
        let mut hs = th.glass(GlassKind::Toolbar, 0.0); hs.bezel = 0.0; hs.spec = 0.0; hs.refraction = 0.0;
        cx.glass_style(Rect::new(content.x, 0.0, content.w, 54.0), &hs);
        cx.text_in(Rect::new(content.x, 0.0, content.w, 54.0), ["Aarav", "Team Kash", "Mom"][self.sel], 13.5, Weight::Semibold, th.label(), Align::Center);
        let mut st = th.glass(GlassKind::Sidebar, 0.0); st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0;
        cx.glass_style(Rect::new(0.0, 0.0, sbw, area.h), &st);
        cx.cv.fill_rect(Rect::new(sbw - 1.0, 0.0, 1.0, area.h), th.separator());
        let convs = [("Aarav", "Liquid Glass looks great", 0x0A84FF), ("Team Kash", "Build is green", 0xBF5AF2), ("Mom", "Call me when free", 0x30D158)];
        for (i, (n, p, c)) in convs.iter().enumerate() {
            let r = Rect::new(10.0, 60.0 + i as f32 * 62.0, sbw - 20.0, 56.0);
            let h = cx.hit(id_of(n) ^ 0xD0, r);
            if h.clicked { self.sel = i; }
            let t = cx.anim(id2(id_of(n), 0xD1), if self.sel == i { 1.0 } else { 0.0 });
            if t > 0.01 { cx.cv.fill_rrect(r, 14.0, th.accent().fade(t)); } else if h.hovered { cx.cv.fill_rrect(r, 14.0, th.hover_fill()); }
            cx.cv.fill_circle(r.x + 28.0, r.cy(), 19.0, Paint::VGrad { y0: r.y, y1: r.bottom(), c0: Color::hex(*c).lighten(0.25), c1: Color::hex(*c) });
            cx.text_in(Rect::new(r.x + 28.0 - 19.0, r.cy() - 19.0, 38.0, 38.0), &n[..1], 16.0, Weight::Semibold, Color::WHITE, Align::Center);
            let (c1, c2) = if self.sel == i { (Color::WHITE, Color::rgba(255, 255, 255, 200)) } else { (th.label(), th.label2()) };
            cx.text(r.x + 56.0, r.cy() - 3.0, n, 13.5, Weight::Semibold, c1);
            let pv = cx.fonts.fit(p, 12.0, Weight::Regular, r.w - 66.0);
            cx.text(r.x + 56.0, r.cy() + 14.0, &pv, 12.0, Weight::Regular, c2);
        }
    }
}
