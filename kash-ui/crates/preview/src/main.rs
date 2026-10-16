//! Preview harness for Kash UI (host-only, NOT part of the kernel).
//!   preview video <out.mp4> [w h]     scripted demo → h264 video + key PNG frames
//!   preview shots <dir> [w h]         a few static screenshots
//!   preview window                    interactive window (feature "window")
mod bench2;
use kash_ui::app::*;
use kash_ui::desktop::*;
use kash_ui::geom::*;
use kash_ui::gfx::Canvas;
use kash_ui::ui::*;
use std::io::Write;

fn save_png(path: &str, cv: &Canvas) {
    let f = std::fs::File::create(path).unwrap();
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), cv.w as u32, cv.h as u32);
    enc.set_color(png::ColorType::Rgb); enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header().unwrap();
    let mut data = Vec::with_capacity((cv.w * cv.h * 3) as usize);
    for p in &cv.px { data.push((p >> 16) as u8); data.push((p >> 8) as u8); data.push(*p as u8); }
    w.write_image_data(&data).unwrap();
}

#[derive(Clone)]
enum Step {
    Wait(f32),
    MoveTo(f32, f32, f32),
    MoveDock(AppKind, f32),
    MoveWin(AppKind, f32, f32, f32),
    MoveWinR(AppKind, f32, f32, f32),
    Click, DClick, Down, Up, RClick,
    MoveDockId(u32, f32),
    Type(&'static str),
    Press(Key, bool),
    Scroll(f32),
    Shot(&'static str),
    Sweep(f32, f32, f32),
    Pane(usize),
    SetDuress(&'static str),
    LockNow,
}

struct Runner { steps: Vec<Step>, i: usize, t: f32, from: Pt, to: Pt, pos: Pt, left: bool, right: bool, pending: Vec<KeyEv>, type_idx: usize, type_t: f32, click_phase: u8, wheel: f32, shots: Vec<&'static str>, ctrl_arc: f32, acts: Vec<Step> }

impl Runner {
    fn new(steps: Vec<Step>, start: Pt) -> Runner { Runner { steps, i: 0, t: 0.0, from: start, to: start, pos: start, left: false, right: false, pending: vec![], type_idx: 0, type_t: 0.0, click_phase: 0, wheel: 0.0, shots: vec![], ctrl_arc: 0.0, acts: vec![] } }
    fn done(&self) -> bool { self.i >= self.steps.len() }
    fn begin(&mut self, d: &Desktop) {
        self.t = 0.0; self.type_idx = 0; self.type_t = 0.0; self.click_phase = 0; self.from = self.pos;
        match self.steps[self.i].clone() {
            Step::MoveTo(x, y, _) => self.to = Pt::new(x, y),
            Step::MoveDockId(id, _) => { let c = d.dock_item_center(id); self.to = Pt::new(c.x, c.y); }
            Step::MoveDock(k, _) => { let c = d.dock_icon_center(k); self.to = Pt::new(c.x, c.y); }
            Step::MoveWin(k, dx, dy, _) => { if let Some(r) = d.window_rect(k) { self.to = Pt::new(r.x + dx, r.y + dy); } }
            Step::MoveWinR(k, dx, dy, _) => { if let Some(r) = d.window_rect(k) { self.to = Pt::new(r.right() - dx, r.y + dy); } }
            Step::Sweep(a, b, _) => { self.from = Pt::new(a, self.pos.y); self.to = Pt::new(b, self.pos.y); self.pos = self.from; }
            _ => {}
        }
    }
    fn tick(&mut self, d: &Desktop, dt: f32) -> Input {
        let mut keys = vec![]; let mut wheel = Pt::new(0.0, 0.0);
        if !self.done() {
            if self.t == 0.0 && self.type_idx == 0 && self.click_phase == 0 { self.begin(d); }
            self.t += dt;
            let step = self.steps[self.i].clone();
            let mut finished = false;
            match step {
                Step::Wait(s) => { if self.t >= s { finished = true; } }
                Step::MoveTo(_, _, dur) | Step::MoveDockId(_, dur) | Step::MoveDock(_, dur) | Step::MoveWin(_, _, _, dur) | Step::MoveWinR(_, _, _, dur) | Step::Sweep(_, _, dur) => {
                    let u = (self.t / dur).min(1.0);
                    let e = u * u * u * (u * (u * 6.0 - 15.0) + 10.0); // smootherstep
                    // slight arc for human feel
                    let arc = (std::f32::consts::PI * u).sin() * 14.0 * if matches!(step, Step::Sweep(..)) { 0.0 } else { 1.0 };
                    self.pos = Pt::new(self.from.x + (self.to.x - self.from.x) * e, self.from.y + (self.to.y - self.from.y) * e - arc);
                    if u >= 1.0 { self.pos = self.to; finished = true; }
                }
                Step::Click => { match self.click_phase { 0 => { self.left = true; self.click_phase = 1; self.t = 0.0; } 1 => { if self.t > 0.09 { self.left = false; finished = true; } } _ => {} } }
                Step::DClick => { match self.click_phase { 0 => { self.left = true; self.click_phase = 1; self.t = 0.0; } 1 => { if self.t > 0.06 { self.left = false; self.click_phase = 2; self.t = 0.0; } } 2 => { if self.t > 0.08 { self.left = true; self.click_phase = 3; self.t = 0.0; } } _ => { if self.t > 0.07 { self.left = false; finished = true; } } } }
                Step::RClick => { match self.click_phase { 0 => { self.right = true; self.click_phase = 1; self.t = 0.0; } 1 => { if self.t > 0.09 { self.right = false; finished = true; } } _ => {} } }
                Step::Down => { self.left = true; finished = true; }
                Step::Up => { self.left = false; finished = true; }
                Step::Type(s) => {
                    self.type_t += dt;
                    let chars: Vec<char> = s.chars().collect();
                    while self.type_t > 0.075 && self.type_idx < chars.len() { self.type_t -= 0.075; let c = chars[self.type_idx]; self.type_idx += 1;
                        keys.push(if c == ' ' { KeyEv { key: Key::Space, ch: ' ', ctrl: false, shift: false, alt: false } } else { KeyEv { key: Key::Char, ch: c, ctrl: false, shift: false, alt: false } }); }
                    if self.type_idx >= chars.len() && self.type_t > 0.2 { finished = true; }
                }
                Step::Press(k, ctrl) => { keys.push(KeyEv { key: k, ch: if k == Key::Space { ' ' } else { '\0' }, ctrl, shift: false, alt: false }); finished = true; }
                Step::Scroll(dy) => { wheel = Pt::new(0.0, dy * (1.0 - (self.t / 0.5).min(1.0))); if self.t > 0.5 { finished = true; } }
                Step::Shot(n) => { self.shots.push(n); finished = true; }
                Step::Pane(_) | Step::SetDuress(_) | Step::LockNow => { self.acts.push(step.clone()); finished = true; }
            }
            if finished { self.i += 1; self.t = 0.0; self.type_idx = 0; self.type_t = 0.0; self.click_phase = 0; }
        }
        Input { mouse: self.pos, left: self.left, wheel, keys, dt, right: self.right }
    }
}

fn feature_steps() -> Vec<Step> {
    use Step::*;
    vec![
        Wait(2.0), Shot("f00-desktop"),
        // Launchpad + dock right-click + downloads stack
        MoveDockId(100, 0.8), Wait(0.3), Click, Wait(1.2), Shot("f01-launchpad"), Press(Key::Escape, false), Wait(0.8),
        MoveDock(AppKind::Browser, 0.8), Wait(0.3), RClick, Wait(0.7), Shot("f02-dock-menu"), MoveTo(640.0, 300.0, 0.4), Click, Wait(0.6),
        MoveDockId(101, 0.8), Wait(0.3), Click, Wait(1.1), Shot("f03-downloads-fan"), MoveTo(640.0, 300.0, 0.4), Click, Wait(0.7),
        // Settings → Privacy via Spotlight
        Press(Key::Space, true), Wait(0.5), Type("privacy"), Wait(0.5), Press(Key::Enter, false), Wait(1.6), Shot("f04-privacy-home"),
        MoveTo(700.0, 312.0, 0.6), Click, Wait(1.0), Shot("f05-apps-class"),
        MoveTo(700.0, 572.0, 0.5), Click, Wait(1.0), Shot("f06-app-detail"), MoveTo(950.0, 456.0, 0.5), Click, Wait(0.6), Shot("f06a-camera-denied"), MoveTo(700.0, 500.0, 0.3), Scroll(7.0), Wait(1.2), Shot("f06b-app-detail-2"),
        MoveDock(AppKind::Browser, 0.8), Wait(0.3), RClick, Wait(0.7), MoveTo(380.0, 605.0, 0.4), Click, Wait(1.4), Shot("f07-files-applications"),
        MoveDockId(100, 0.8), Wait(0.3), Click, Wait(1.0), MoveTo(340.0, 336.0, 0.6), Click, Wait(1.6), Shot("f08-activity-monitor"),
        MoveDockId(100, 0.8), Wait(0.3), Click, Wait(1.0), MoveTo(490.0, 478.0, 0.6), Click, Wait(1.4), Shot("f09-calculator"),
        Wait(0.5),
    ]
}

fn boot_steps() -> Vec<Step> {
    use Step::*;
    vec![
        Wait(1.7), Shot("b00-bios-mid"), Wait(1.7), Shot("b01-bios-done"), Wait(1.6), Shot("b02-logo"), Wait(1.4),
        Wait(1.0), Shot("b03-lock"),
        Type("wrong"), Press(Key::Enter, false), Wait(0.16), Shot("b04-lock-wrong"), Wait(1.8),
        Type("kash"), Shot("b04b-lock-typed"), Press(Key::Enter, false), Wait(0.25), Shot("b05-unlocking"), Wait(1.2), Shot("b06-desktop"),
        Pane(22), Wait(1.4), Shot("b07-about"),
        Pane(11), Wait(1.4), Shot("b08-notifications"),
        MoveTo(1000.0, 440.0, 0.4), Scroll(12.0), Wait(1.5), Shot("b08b-notif-scrolled"), MoveTo(1000.0, 400.0, 0.4), Click, Wait(1.2), Shot("b09-notifications-open"),
        Pane(18), Wait(1.4), Shot("b10-lock-settings"), MoveTo(700.0, 500.0, 0.3), Scroll(14.0), Wait(1.6), Shot("b11-credentials"),
        SetDuress("panic"), Press(Key::Char, true), Wait(0.1), LockNow, Wait(1.4), Type("panic"), Shot("b12-duress-typed"), Press(Key::Enter, false), Wait(1.6), Shot("b13-after-duress"),
        Wait(0.5),
    ]
}

fn demo_steps() -> Vec<Step> {
    use Step::*;
    vec![
        Wait(2.1), Shot("00-desktop"),
        // dock magnification sweep
        MoveTo(300.0, 700.0, 0.7), Sweep(300.0, 980.0, 1.8), Sweep(980.0, 520.0, 1.2), Shot("01-dock-magnify"),
        MoveDock(AppKind::Files, 0.6), Wait(0.35), MoveDock(AppKind::Files, 0.15), Wait(0.1), Click, Wait(1.1), Shot("02-files"),
        // browse
        MoveWin(AppKind::Files, 100.0, 186.0, 0.7), Click, Wait(0.7),
        MoveWin(AppKind::Files, 100.0, 155.0, 0.4), Click, Wait(0.6),
        MoveWin(AppKind::Files, 700.0, 28.0, 0.6), Click, Wait(0.8), Shot("03-files-list"),
        MoveWin(AppKind::Files, 664.0, 28.0, 0.4), Click, Wait(0.6),
        MoveWin(AppKind::Files, 360.0, 150.0, 0.6), DClick, Wait(0.9), Shot("04-files-folder"),
        // drag window
        MoveWin(AppKind::Files, 520.0, 20.0, 0.5), Down, Wait(0.05), MoveTo(590.0, 110.0, 0.7), Up, Wait(0.5),
        // open Settings
        MoveDock(AppKind::Settings, 0.8), Wait(0.35), MoveDock(AppKind::Settings, 0.15), Wait(0.1), Click, Wait(1.2), Shot("05-settings-appearance"),
        MoveWin(AppKind::Settings, 560.0, 170.0, 0.8), Click, Wait(1.4), Shot("06-settings-dark"),
        MoveWin(AppKind::Settings, 560.0, 258.0, 0.4), Click, Wait(0.2),
        MoveWin(AppKind::Settings, 505.0, 515.0, 0.6), Down, Wait(0.05), MoveTo(0.0, 0.0, 0.01), Up,
        Wait(0.3),
        // control centre
        MoveTo(1105.0, 15.0, 0.9), Click, Wait(0.9), Shot("07-control-center"),
        MoveTo(600.0, 400.0, 0.6), Click, Wait(0.8),
        // spotlight
        Press(Key::Space, true), Wait(0.5), Type("termi"), Wait(0.5), Shot("08-spotlight"), Press(Key::Enter, false), Wait(1.1),
        Type("selftest"), Press(Key::Enter, false), Wait(1.6), Type("neofetch"), Press(Key::Enter, false), Wait(1.4), Shot("09-terminal"),
        // minimise with genie
        MoveWinR(AppKind::Terminal, 75.0, 20.0, 0.7), Wait(0.5), Shot("09b-controls-hover"), MoveWinR(AppKind::Terminal, 35.0, 20.0, 0.3), Wait(0.5), Shot("09c-close-glow"), MoveWinR(AppKind::Terminal, 109.0, 20.0, 0.3), Wait(0.2), Click, Wait(0.075), Shot("10-genie"), Wait(1.2),
        MoveDock(AppKind::Terminal, 0.7), Wait(0.35), MoveDock(AppKind::Terminal, 0.15), Wait(0.1), Click, Wait(1.0),
        // music + messages
        MoveDock(AppKind::Music, 0.7), Wait(0.35), MoveDock(AppKind::Music, 0.15), Wait(0.1), Click, Wait(1.4), Shot("11-music"),
        MoveDock(AppKind::Messages, 0.6), Wait(0.35), MoveDock(AppKind::Messages, 0.15), Wait(0.1), Click, Wait(1.2), Shot("12-messages"),
        Wait(0.6),
    ]
}

fn run_video(out: &str, w: i32, h: i32) { run_video_steps(out, w, h, demo_steps(), false) }
fn run_video_steps(out: &str, w: i32, h: i32, steps: Vec<Step>, flow: bool) {
    let mut d = Desktop::new(w, h, !flow);
    if flow { d.start_boot(true); }
    let start = Pt::new(w as f32 * 0.5, h as f32 * 0.5);
    let mut r = Runner::new(steps, start);
    let dir = std::path::Path::new(out).parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let mut ff = std::process::Command::new("ffmpeg")
        .args(["-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", &format!("{}x{}", w, h), "-r", "60", "-i", "-", "-c:v", "libx264", "-preset", "veryfast", "-crf", "17", "-pix_fmt", "yuv420p", "-movflags", "+faststart", out])
        .stdin(std::process::Stdio::piped()).spawn().expect("ffmpeg");
    let mut sin = ff.stdin.take().unwrap();
    let dt = 1.0 / 60.0;
    let mut times: Vec<f32> = vec![];
    let mut buf = vec![0u8; (w * h * 3) as usize];
    let mut frames = 0;
    while (!r.done() || frames < 30) && frames < 60 * 90 {
        let inp = r.tick(&d, dt);
        let t0 = std::time::Instant::now();
        for a in r.acts.drain(..) { match a { Step::Pane(p) => { d.sys.settings_pane_request = Some(p); d.open_app(AppKind::Settings); } Step::SetDuress(p) => { d.sys.duress_pass = p.to_string(); } Step::LockNow => d.lock_now(), _ => {} } }
        d.frame(&inp);
        for e in d.take_events() { println!("  [{:.2}s] event {:?}", frames as f32 / 60.0, e); }
        times.push(t0.elapsed().as_secs_f32() * 1000.0);
        for (i, p) in d.screen.px.iter().enumerate() { buf[i * 3] = (p >> 16) as u8; buf[i * 3 + 1] = (p >> 8) as u8; buf[i * 3 + 2] = *p as u8; }
        sin.write_all(&buf).unwrap();
        for n in r.shots.drain(..) { save_png(dir.join(format!("{}.png", n)).to_str().unwrap(), &d.screen); }
        frames += 1;
    }
    drop(sin); ff.wait().unwrap();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let avg: f32 = times.iter().sum::<f32>() / times.len() as f32;
    println!("frames {}  render ms: avg {:.1}  p50 {:.1}  p95 {:.1}  p99 {:.1}  max {:.1}", frames, avg, times[times.len() / 2], times[times.len() * 95 / 100], times[times.len() * 99 / 100], times[times.len() - 1]);
}

fn run_verify(w: i32, h: i32) {
    // Same input stream into a cached desktop (a) and a cache-disabled reference (b); screens must match exactly.
    let mut a = Desktop::new(w, h, true);
    let mut b = Desktop::new(w, h, true);
    b.windows_force_dirty = true;
    let mut r = Runner::new(demo_steps(), Pt::new(w as f32 * 0.5, h as f32 * 0.5));
    let dt = 1.0 / 60.0;
    let (mut frames, mut bad, mut first) = (0, 0, None); let (mut worst, mut big) = (0i32, 0);
    let (mut ta, mut tb) = (0.0f32, 0.0f32);
    while (!r.done() || frames < 30) && frames < 60 * 90 {
        let inp = r.tick(&a, dt);
        let t0 = std::time::Instant::now(); a.frame(&inp); ta += t0.elapsed().as_secs_f32();
        let t0 = std::time::Instant::now(); b.frame(&inp); tb += t0.elapsed().as_secs_f32();
        r.shots.clear();
        if (1596..1612).contains(&frames) { println!("f{} A {:?} B {:?} mouse ({:.0},{:.0}) left {} fast {}", frames, a.dbg_cc(), b.dbg_cc(), inp.mouse.x, inp.mouse.y, inp.left, a.stats_fast); }
        let diff = a.screen.px.iter().zip(b.screen.px.iter()).filter(|(x, y)| x != y).count();
        if diff > 0 {
            let mut mx = 0i32; let (mut x0, mut y0, mut x1, mut y1) = (i32::MAX, i32::MAX, 0, 0);
            for (i, (x, y)) in a.screen.px.iter().zip(b.screen.px.iter()).enumerate() { if x != y {
                let d = (((x >> 16) & 255) as i32 - ((y >> 16) & 255) as i32).abs().max((((x >> 8) & 255) as i32 - ((y >> 8) & 255) as i32).abs()).max(((x & 255) as i32 - (y & 255) as i32).abs());
                if d > 3 { let (px, py) = (i as i32 % w, i as i32 / w); x0 = x0.min(px); y0 = y0.min(py); x1 = x1.max(px); y1 = y1.max(py); }
                mx = mx.max(d); } }
            if mx > worst { worst = mx; }
            if mx > 3 && big == 0 { save_png("/tmp/claude-0/-home-claude/37cb4eea-d179-5ff1-9452-efb366c8a8fe/scratchpad/big_a.png", &a.screen); save_png("/tmp/claude-0/-home-claude/37cb4eea-d179-5ff1-9452-efb366c8a8fe/scratchpad/big_b.png", &b.screen); }
            if mx > 3 { big += 1; if big <= 6 { println!("BIG frame {} maxdelta {} bbox ({},{})-({},{})", frames, mx, x0, y0, x1, y1); } }
        }
        if diff > 0 { bad += 1; if first.is_none() { first = Some((frames, diff)); save_png("/tmp/claude-0/-home-claude/37cb4eea-d179-5ff1-9452-efb366c8a8fe/scratchpad/verify_a.png", &a.screen); save_png("/tmp/claude-0/-home-claude/37cb4eea-d179-5ff1-9452-efb366c8a8fe/scratchpad/verify_b.png", &b.screen); } }
        if frames % 240 == 239 { println!("f{} {:?}", frames, a.dbg_unsettled()); }
        frames += 1;
    }
    println!("frames {}  mismatching frames {}  first {:?}  worst delta {}  frames with delta>3: {}", frames, bad, first, worst, big);
    println!("total render: cached {:.2}s ({:.2} ms/frame)  reference {:.2}s ({:.2} ms/frame)", ta, ta * 1000.0 / frames as f32, tb, tb * 1000.0 / frames as f32);
    println!("dirty reasons [nosnap,chain,rect,hot,wasHot,lightDown,keys,blink,spot,open,min,zoom,focus,lightHov,closing,anims,app]: {:?}", a.dbg_reasons);
    println!("fast frames {} / full {}   windows cached {} / drawn {}", a.stats_fast, a.stats_full, a.stats_win_cached, a.stats_win_drawn);
}

fn run_dockshot(w: i32, h: i32) {
    let dt = 1.0 / 60.0;
    let mut d = Desktop::new(w, h, false);
    let far = Pt::new(w as f32 * 0.5, 120.0);
    let step = |d: &mut Desktop, m: Pt, n: usize| { for _ in 0..n { d.frame(&Input { mouse: m, left: false, wheel: Pt::new(0.0, 0.0), keys: vec![], dt, right: false }); } };
    let crop = |d: &Desktop, name: &str| {
        let r = d.dock_rect();
        let (x0, y0) = (((r.x - 60.0) as i32).max(0), ((r.y - 90.0) as i32).max(0));
        let (cw, ch) = (((r.w + 120.0) as i32).min(w - x0), (h - y0).min(200));
        let mut c = Canvas::new(cw * 2, ch * 2);
        for y in 0..ch * 2 { for x in 0..cw * 2 { c.px[(y * cw * 2 + x) as usize] = d.screen.px[((y0 + y / 2) * w + x0 + x / 2) as usize]; } }
        save_png(name, &c);
    };
    step(&mut d, far, 90);
    crop(&d, "out/dock-rest.png");
    d.open_app(AppKind::Files); d.open_app(AppKind::Terminal); step(&mut d, far, 90);
    crop(&d, "out/dock-running.png");
    let c = d.dock_icon_center(AppKind::Notes);
    step(&mut d, c, 60);
    crop(&d, "out/dock-hover.png");
}

fn ms_now() -> f32 { use std::sync::OnceLock; static T0: OnceLock<std::time::Instant> = OnceLock::new(); T0.get_or_init(std::time::Instant::now).elapsed().as_secs_f32() * 1000.0 }

fn run_logo() {
    use kash_ui::icons::*; use kash_ui::text::*; use kash_ui::gfx::*; use kash_ui::color::Color; use kash_ui::geom::Rect;
    let mut f = Fonts::new();
    // 1) hero badges
    for (name, dark) in [("kashos-logo-light.png", false), ("kashos-logo-dark.png", true)] {
        let mut c = Canvas::new(1024, 1024);
        c.fill_rect(Rect::new(0.0, 0.0, 1024.0, 1024.0), Paint::VGrad { y0: 0.0, y1: 1024.0, c0: if dark { Color::hex(0x0B0C10) } else { Color::hex(0xF2F4F8) }, c1: if dark { Color::hex(0x15171E) } else { Color::hex(0xDDE2EA) } });
        let r = Rect::new(112.0, 112.0, 800.0, 800.0);
        c.shadow_rrect(r.offset(0.0, 28.0), 180.0, 60.0, Color::rgba(0, 0, 0, if dark { 150 } else { 70 }), true);
        kash_badge(&mut c, r, dark);
        save_png(&format!("out/{}", name), &c);
    }
    // 2) brand sheet: badge + wordmark + small sizes + mark-only on both backgrounds
    let mut c = Canvas::new(1600, 900);
    c.fill_rect(Rect::new(0.0, 0.0, 1600.0, 900.0), Paint::VGrad { y0: 0.0, y1: 900.0, c0: Color::hex(0x10121A), c1: Color::hex(0x07080C) });
    c.fill_rect(Rect::new(0.0, 0.0, 1600.0, 900.0), Paint::Radial { c: Pt::new(420.0, 380.0), r: 700.0, c0: Color::rgba(90, 60, 220, 70), c1: Color::rgba(90, 60, 220, 0) });
    let big = Rect::new(120.0, 150.0, 360.0, 360.0);
    c.shadow_rrect(big.offset(0.0, 18.0), 80.0, 36.0, Color::rgba(0, 0, 0, 160), true);
    kash_badge(&mut c, big, true);
    f.draw(&mut c, 540.0, 360.0, "KashOS", 110.0, Weight::Bold, Color::WHITE);
    f.draw(&mut c, 546.0, 420.0, "Rust-native · capability-secured · Liquid Glass", 28.0, Weight::Regular, Color::rgba(255, 255, 255, 160));
    // size ladder (light + dark badges)
    let mut x = 120.0;
    for (i, sz) in [128.0f32, 96.0, 64.0, 48.0, 32.0, 24.0, 16.0].iter().enumerate() { let r = Rect::new(x, 600.0, *sz, *sz); kash_badge(&mut c, r, i % 2 == 1); x += sz + 28.0; }
    // mark-only on tinted chips
    for (k, (bg, fg)) in [(0xFFFFFFu32, 0x111318u32), (0x111318, 0xFFFFFF), (0x5A2BD2, 0xFFFFFF)].iter().enumerate() {
        let r = Rect::new(820.0 + k as f32 * 200.0, 590.0, 170.0, 170.0);
        c.fill_rrect(r, 38.0, Color::hex(*bg)); c.stroke_rrect(r, 38.0, 1.0, Color::rgba(255, 255, 255, 40));
        draw_kash_mark(&mut c, r.inset(26.0), Color::hex(*fg), Some(if *bg == 0xFFFFFF { Color::hex(0x5A2BD2) } else { Color::hex(0x62CBFF) }));
    }
    f.draw(&mut c, 120.0, 840.0, "Mark: a K built from stem, arm and leg — the ring is the capability handle every KashOS app holds.", 22.0, Weight::Regular, Color::rgba(255, 255, 255, 120));
    save_png("out/kashos-brand-sheet.png", &c);
}

fn run_bench(w: i32, h: i32) {
    let dt = 1.0 / 60.0;
    let mut d = Desktop::new(w, h, false);
    d.clock = Some(ms_now);
    let mut measure = |d: &mut Desktop, label: &str, mouse: Pt, n: usize| {
        let mut ts = vec![]; let (f0, u0) = (d.stats_fast, d.stats_full);
        for _ in 0..n { let t0 = std::time::Instant::now(); d.frame(&Input { mouse, left: false, wheel: Pt::new(0.0, 0.0), keys: vec![], dt, right: false }); ts.push(t0.elapsed().as_secs_f32() * 1000.0); }
        ts.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("{:<34} median {:>6.2} ms   p90 {:>6.2} ms   fast {} full {}  split: wp {:.1} win {:.1} shell {:.1}", label, ts[ts.len() / 2], ts[ts.len() * 9 / 10], d.stats_fast - f0, d.stats_full - u0, d.prof[0], d.prof[1], d.prof[2]); println!("    busy: {}", d.dbg_busy());
    };
    let far = Pt::new(w as f32 * 0.5, 120.0);
    for _ in 0..90 { d.frame(&Input { mouse: far, left: false, wheel: Pt::new(0.0, 0.0), keys: vec![], dt, right: false }); }
    measure(&mut d, "empty desktop (dock+menubar)", far, 60);
    d.open_app(AppKind::Files); measure(&mut d, "settle", far, 60);
    measure(&mut d, "+ Files", far, 60);
    d.open_app(AppKind::Settings); measure(&mut d, "settle", far, 60);
    measure(&mut d, "+ Settings", far, 60);
    d.open_app(AppKind::Terminal);
    for k in 0..30 { let t0 = ms_now(); d.frame(&Input { mouse: far, left: false, wheel: Pt::new(0.0, 0.0), keys: vec![], dt, right: false }); println!("open frame {:>2}: total {:>5.1}  wall {:>4.1} windows {:>5.1} shell {:>5.1} post {:>4.1}", k, ms_now() - t0, d.prof[0], d.prof[1], d.prof[2], d.prof[3]); }
    measure(&mut d, "settle", far, 30);
    measure(&mut d, "+ Terminal", far, 60);
    let dockc = d.dock_icon_center(AppKind::Music);
    measure(&mut d, "mouse over dock (magnify)", dockc, 60);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mode = a.get(1).map(|s| s.as_str()).unwrap_or("video");
    let (w, h) = (a.get(3).and_then(|s| s.parse().ok()).unwrap_or(1280), a.get(4).and_then(|s| s.parse().ok()).unwrap_or(800));
    match mode {
        "bench" => run_bench(w, h),
        "micro" => bench2::run(),
        "dockshot" => run_dockshot(w, h),
        "logo" => run_logo(),
        "verify" => run_verify(w, h),
        "features" => run_video_steps(a.get(2).map(|s| s.as_str()).unwrap_or("features.mp4"), w, h, feature_steps(), false),
        "boot" => run_video_steps(a.get(2).map(|s| s.as_str()).unwrap_or("boot.mp4"), w, h, boot_steps(), true),
        "video" => run_video(a.get(2).map(|s| s.as_str()).unwrap_or("demo.mp4"), w, h),
        _ => eprintln!("usage: preview video <out.mp4> [w h]"),
    }
}
