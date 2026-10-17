//! Terminal — KashOS microkernel console and capability shell.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::app::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::Paint;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;

#[derive(Clone, Copy, PartialEq)]
enum Style { Normal, Dim, Ok, Warn, Accent, Prompt }

pub struct Terminal {
    lines: Vec<(String, Style)>,
    input: String,
    hist: Vec<String>,
    hist_i: usize,
    pending: Vec<(String, Style)>,
    timer: f32,
    scroll: Scroll,
    blink: f32,
    stick: bool,
}

impl Terminal {
    pub fn new() -> Terminal {
        let mut t = Terminal { lines: Vec::new(), input: String::new(), hist: Vec::new(), hist_i: 0, pending: Vec::new(), timer: 0.0, scroll: Scroll::default(), blink: 0.0, stick: true };
        for l in ["KashOS 0.2.0 — UI demo terminal (not connected to the kernel shell)", "`open`, `clear`, `date`, and `shutdown` are local UI actions; system output is unavailable", ""] { t.lines.push((String::from(l), Style::Dim)); }
        t
    }
    /// Run a command as if typed (used by demos).
    pub fn type_and_run(&mut self, cmd: &str, cx: &mut Ctx) { self.run(cmd, cx); }
    pub fn flush(&mut self) { let p = core::mem::take(&mut self.pending); self.lines.extend(p); }
    fn say(&mut self, s: &str, st: Style) { self.pending.push((String::from(s), st)); }
    fn run(&mut self, cmd: &str, cx: &mut Ctx) {
        self.lines.push((format!("kash@kernel ~ % {}", cmd), Style::Prompt));
        let mut it = cmd.split_whitespace();
        let c = it.next().unwrap_or("");
        let rest: Vec<&str> = it.collect();
        match c {
            "" => {}
            "help" => for l in ["help         this list", "clear        clear screen", "date         UI clock value", "open <app>   open a UI app", "shutdown     request power off",
                "uname, whoami, ls, caps, services, selftest, memmap, net, vault", "              unavailable: no kernel-shell connection"] { self.say(l, Style::Normal); },
            "clear" => { self.lines.clear(); self.pending.clear(); }
            "whoami" => self.say("unavailable: no process identity is connected to this UI", Style::Warn),
            "uname" => self.say("KashOS prototype 0.2.0 (kernel identity unavailable in UI)", Style::Normal),
            "date" => { let s = cx.sys.unix_secs; self.say(&format!("unix {}", s), Style::Normal); }
            "echo" => { let s = rest.join(" "); self.say(&s, Style::Normal); }
            "ls" | "caps" | "services" | "selftest" | "memmap" | "net" | "vault" | "neofetch" => self.say("unavailable: this demo terminal is not connected to the kernel service", Style::Warn),
            "open" => { match rest.first().copied().unwrap_or("") { "files" => cx.cmds.push(Cmd::Open(AppKind::Files)), "settings" => cx.cmds.push(Cmd::Open(AppKind::Settings)), "notes" => cx.cmds.push(Cmd::Open(AppKind::Notes)), _ => self.say("usage: open files|settings|notes", Style::Warn) } }
            "shutdown" => cx.cmds.push(Cmd::Shutdown),
            other => self.say(&format!("kash: command not found: {}", other), Style::Warn),
        }
        self.stick = true;
    }
}

impl App for Terminal {
    fn kind(&self) -> AppKind { AppKind::Terminal }
    fn title(&self) -> String { String::from("Terminal — kash@kernel") }
    fn default_size(&self) -> (f32, f32) { (720.0, 440.0) }
    fn min_size(&self) -> (f32, f32) { (420.0, 240.0) }
    fn animating(&self) -> bool { !self.pending.is_empty() || self.stick || self.scroll.moving() }
    fn command(&mut self, name: &str) { if name == "clear" { self.lines.clear(); } }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        cx.cv.fill_rect(area, Paint::VGrad { y0: 0.0, y1: area.h, c0: Color::rgb(24, 25, 32), c1: Color::rgb(12, 13, 17) });
        self.timer += cx.io.dt;
        while self.timer > 0.035 && !self.pending.is_empty() { self.timer -= 0.035; let l = self.pending.remove(0); self.lines.push(l); self.stick = true; }
        if self.pending.is_empty() { self.timer = 0.0; }
        if cx.io.focused { cx.sys.blink_req = true; }
        if cx.io.focused {
            let keys = cx.io.keys.clone();
            for k in keys {
                match k.key {
                    Key::Char if k.ctrl && k.ch == 'l' => { self.lines.clear(); }
                    Key::Char if !k.ctrl => { self.input.push(k.ch); self.stick = true; self.blink = caret_reset(cx.io.time); }
                    Key::Space => { self.input.push(' '); self.stick = true; }
                    Key::Backspace => { self.input.pop(); }
                    Key::Enter => { let c = core::mem::take(&mut self.input); if !c.trim().is_empty() { self.hist.push(c.clone()); } self.hist_i = self.hist.len(); self.run(c.trim(), cx); }
                    Key::Up => { if self.hist_i > 0 { self.hist_i -= 1; self.input = self.hist[self.hist_i].clone(); } }
                    Key::Down => { if self.hist_i + 1 < self.hist.len() { self.hist_i += 1; self.input = self.hist[self.hist_i].clone(); } else { self.hist_i = self.hist.len(); self.input.clear(); } }
                    _ => {}
                }
            }
        }
        let lh = 17.5; let top = 46.0; let pad = 18.0;
        let total = (self.lines.len() + 1) as f32 * lh + top + 16.0;
        let maxs = (total - area.h).max(0.0);
        self.scroll.update(cx.io, cx.hover(area), maxs);
        if self.stick { self.scroll.y += (maxs - self.scroll.y) * 0.35; if (maxs - self.scroll.y).abs() < 0.5 { self.scroll.y = maxs; self.stick = false; } }
        cx.cv.push_clip(Rect::new(0.0, 0.0, area.w, area.h));
        let mut y = top - self.scroll.y;
        for (l, st) in self.lines.iter() {
            if y > -lh && y < area.h + lh {
                let col = match st { Style::Normal => Color::rgb(220, 224, 232), Style::Dim => Color::rgb(125, 132, 150), Style::Ok => Color::rgb(95, 242, 155), Style::Warn => Color::rgb(255, 170, 90), Style::Accent => Color::rgb(130, 180, 255), Style::Prompt => Color::rgb(235, 238, 245) };
                if *st == Style::Prompt {
                    let n = "kash@kernel ~ %".len();
                    let (a, b) = l.split_at(n);
                    let w = cx.text(pad, y + 12.0, a, 12.5, Weight::Mono, Color::rgb(130, 255, 190));
                    cx.text(pad + w, y + 12.0, b, 12.5, Weight::Mono, col);
                } else { cx.text(pad, y + 12.0, l, 12.5, Weight::Mono, col); }
            }
            y += lh;
        }
        let pr = "kash@kernel ~ % ";
        let w = cx.text(pad, y + 12.0, pr, 12.5, Weight::Mono, Color::rgb(130, 255, 190));
        let iw = cx.text(pad + w, y + 12.0, &self.input, 12.5, Weight::Mono, Color::rgb(235, 238, 245));
        if !cx.io.focused || caret_on(cx.io.time, self.blink) { cx.cv.fill_rect(Rect::new(pad + w + iw + 1.0, y + 1.0, 8.0, 15.0), Color::rgba(130, 255, 190, 200)); }
        cx.cv.pop_clip();
        let mut st = th.glass(GlassKind::Toolbar, 0.0);
        st.dark = true; st.bezel = 0.0; st.spec = 0.0; st.tint = Color::rgba(18, 19, 25, 150); st.blur = 14.0;
        cx.glass_style(Rect::new(0.0, 0.0, area.w, 40.0), &st);
        let t = self.title();
        cx.text_in(Rect::new(0.0, 0.0, area.w, 40.0), &t, 13.0, Weight::Medium, Color::rgba(235, 238, 245, 190), Align::Center);
    }
}
