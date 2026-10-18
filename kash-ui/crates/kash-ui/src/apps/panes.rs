//! The remaining System Settings panes — each one fully populated.
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
use crate::apps::settings::Settings;

impl Settings {
    pub(crate) fn opt(&mut self, cx: &mut Ctx, g: &mut Group, _key: usize, label: &str, _sub: &str) {
        cx.row_value(g, label, "Not implemented");
    }
    pub(crate) fn seg_row(&mut self, cx: &mut Ctx, g: &mut Group, slot: usize, label: &str, labels: &[&str], w: f32) {
        let r = cx.group_row(g);
        let lc = cx.th.label();
        cx.text(r.x + 14.0, r.cy() + 4.7, label, 13.5, Weight::Regular, lc);
        let mut s = self.segs[slot];
        cx.segmented(&format!("seg{}", slot), Rect::new(r.right() - 14.0 - w, r.cy() - 14.0, w, 28.0), labels, &mut s);
        self.segs[slot] = s;
    }
    pub(crate) fn card(&mut self, cx: &mut Ctx, f: &mut Form, h: f32, ic: Icon, col: u32, title: &str, sub: &str) -> Rect {
        let r = Rect::new(f.x, f.y, f.w, h);
        cx.group_box(r);
        let t = Rect::new(r.x + 18.0, r.y + 18.0, 52.0, 52.0);
        let c = Color::hex(col);
        cx.cv.fill_rrect(t, 14.0, Paint::VGrad { y0: t.y, y1: t.bottom(), c0: c.lighten(0.16), c1: c });
        draw_icon(cx.cv, ic, t.inset(12.0), Color::WHITE);
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text(r.x + 86.0, r.y + 40.0, title, 16.0, Weight::Bold, lc);
        cx.text(r.x + 86.0, r.y + 59.0, sub, 12.0, Weight::Regular, l2);
        f.y += h + 18.0;
        r
    }

    pub(crate) fn pane_accessibility(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Vision");
        let mut g = cx.group_begin(f, 4, 54.0);
        let mut rt = cx.sys.reduce_transparency;
        cx.row_toggle(&mut g, "ax_rt", "Reduce transparency", "Swap Liquid Glass for a frosted solid", &mut rt); cx.sys.reduce_transparency = rt;
        self.opt(cx, &mut g, 0, "Increase contrast", "Stronger outlines and separators");
        self.opt(cx, &mut g, 1, "Reduce motion", "Replace springs and zooms with fades");
        self.opt(cx, &mut g, 2, "Bold text", "Heavier weight across the system");
        cx.heading(f, "Pointer");
        let mut g = cx.group_begin(f, 2, 54.0);
        let mut c = cx.sys.cursor_size;
        cx.row_slider(&mut g, "ax_cursor", "Pointer size", &mut c, "Normal", "Large"); cx.sys.cursor_size = c;
        self.opt(cx, &mut g, 3, "Shake mouse pointer to locate", "Briefly enlarge the pointer");
        cx.heading(f, "Hearing");
        let mut g = cx.group_begin(f, 2, 54.0);
        self.opt(cx, &mut g, 4, "Flash the screen for alerts", "");
        self.opt(cx, &mut g, 5, "Play stereo as mono", "");
        cx.heading(f, "Motor");
        let mut g = cx.group_begin(f, 3, 54.0);
        self.opt(cx, &mut g, 6, "Sticky Keys", "Press modifier keys one at a time");
        self.opt(cx, &mut g, 7, "Slow Keys", "Adjust how long a key must be held");
        self.opt(cx, &mut g, 8, "Voice Control", "Operate KashOS with spoken commands");
    }

    pub(crate) fn pane_control_center(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Control Center Modules");
        let mut g = cx.group_begin(f, 5, 48.0);
        cx.row_value(&mut g, "Wi-Fi", "No connection service");
        cx.row_value(&mut g, "Bluetooth", "No controller service");
        cx.row_value(&mut g, "Kash Share", "Not implemented");
        let mut fo = cx.sys.focus; cx.row_toggle(&mut g, "cc_focus", "Focus", "Do Not Disturb", &mut fo); cx.sys.focus = fo;
        let mut ns = cx.sys.night_shift; cx.row_toggle(&mut g, "cc_night", "Night Shift", "", &mut ns); cx.sys.night_shift = ns;
        cx.heading(f, "Menu Bar Only");
        let mut g = cx.group_begin(f, 4, 48.0);
        self.opt(cx, &mut g, 10, "Show battery percentage", "");
        self.opt(cx, &mut g, 11, "Show Sound in menu bar", "");
        self.opt(cx, &mut g, 12, "Show date next to the clock", "");
        self.opt(cx, &mut g, 13, "Show KashOS gateway status", "Anonymity Gateway hop count");
        cx.caption(f, "Only the local UI preferences above can be changed here; network modules are unavailable.");
    }

    pub(crate) fn pane_focus(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mut g = cx.group_begin(f, 1, 56.0);
        let mut fo = cx.sys.focus;
        cx.row_toggle(&mut g, "focus_dnd", "Do Not Disturb", "Silence notifications and calls", &mut fo); cx.sys.focus = fo;
        cx.heading(f, "Focus modes");
        let mut g = cx.group_begin(f, 3, 48.0);
        let modes = [("Work", Icon::Terminal, 0x0A84FF, "9:00 – 18:00 · weekdays"), ("Sleep", Icon::Moon, 0x5E5CE6, "23:00 – 07:00 · every day"), ("Personal", Icon::User, 0x30D158, "Off")];
        for (name, _, _, schedule) in modes.iter() {
            cx.row_value(&mut g, name, schedule);
        }
        cx.heading(f, "Options");
        let mut g = cx.group_begin(f, 2, 54.0);
        self.opt(cx, &mut g, 23, "Share Focus status", "Let apps know you’re silenced");
        self.opt(cx, &mut g, 24, "Allow repeated calls", "A second call within 3 minutes breaks through");
        cx.caption(f, "Do Not Disturb is a local UI preference. Scheduling and per-app notification rules are not implemented.");
    }

    pub(crate) fn pane_keyboard(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Keyboard");
        let mut g = cx.group_begin(f, 2, 52.0);
        cx.row_slider(&mut g, "kb_repeat", "Key repeat rate", &mut self.kb[0], "Slow", "Fast");
        cx.row_slider(&mut g, "kb_delay", "Delay until repeat", &mut self.kb[1], "Long", "Short");
        let mut g = cx.group_begin(f, 3, 54.0);
        self.opt(cx, &mut g, 30, "Use F1, F2 as standard function keys", "");
        self.opt(cx, &mut g, 31, "Adjust keyboard brightness in low light", "");
        self.opt(cx, &mut g, 32, "Backlight turns off after inactivity", "");
        cx.heading(f, "Text input");
        let mut g = cx.group_begin(f, 4, 50.0);
        self.opt(cx, &mut g, 33, "Correct spelling automatically", "");
        self.opt(cx, &mut g, 34, "Capitalise words automatically", "");
        self.opt(cx, &mut g, 35, "Add full stop with double-space", "");
        self.opt(cx, &mut g, 36, "Use smart quotes and dashes", "");
        cx.heading(f, "Shortcuts");
        let mut g = cx.group_begin(f, 6, 40.0);
        for (a, b) in [("Spotlight", "Ctrl  Space"), ("System Settings", "Ctrl  ,"), ("Close window", "Ctrl  W"), ("Minimise window", "Ctrl  M"), ("New Files window", "Ctrl  N"), ("Find in Files", "Ctrl  F")] { cx.row_value(&mut g, a, b); }
        cx.heading(f, "Input source");
        let mut g = cx.group_begin(f, 1, 44.0);
        cx.row_value(&mut g, "Layout", "ABC — English (India)");
    }

    pub(crate) fn pane_dock_extra(&mut self, cx: &mut Ctx, f: &mut Form) {
        cx.heading(f, "Recents & stacks");
        let mut g = cx.group_begin(f, 4, 54.0);
        let mut v = cx.sys.dock_recents; cx.row_toggle(&mut g, "dk_rec", "Show recent applications in Dock", "Recently used apps appear after the divider", &mut v); cx.sys.dock_recents = v;
        let mut v = cx.sys.dock_downloads; cx.row_toggle(&mut g, "dk_dl", "Show Downloads stack", "Fan, grid or list of your latest downloads", &mut v); cx.sys.dock_downloads = v;
        let mut v = cx.sys.dock_indicators; cx.row_toggle(&mut g, "dk_ind", "Show indicators for open applications", "", &mut v); cx.sys.dock_indicators = v;
        let mut v = cx.sys.dock_bounce; cx.row_toggle(&mut g, "dk_bnc", "Animate opening applications", "", &mut v); cx.sys.dock_bounce = v;
        let mut g = cx.group_begin(f, 1, 56.0);
        let r = cx.group_row(&mut g);
        let lc = cx.th.label();
        cx.text(r.x + 14.0, r.cy() + 4.7, "Downloads stack view", 13.5, Weight::Regular, lc);
        let mut s = cx.sys.stack_view;
        if cx.segmented("dk_view", Rect::new(r.right() - 14.0 - 210.0, r.cy() - 14.0, 210.0, 28.0), &["Fan", "Grid", "List"], &mut s) { cx.sys.stack_view = s; }
        cx.caption(f, "Right-click any Dock icon for Keep in Dock, Show in Files, Permissions and Quit.");
    }

    pub(crate) fn pane_update(&mut self, cx: &mut Ctx, f: &mut Form) {
        let r = self.card(cx, f, 96.0, Icon::Gear, 0x0A84FF, "KashOS prototype · 0.2.0", "Update service unavailable");
        let bw = 120.0;
        if cx.button("upd_check", Rect::new(r.right() - 18.0 - bw, r.cy() - 14.0, bw, 28.0), "Check Now", false) { cx.cmds.push(Cmd::Toast(String::from("No update service is configured"))); }
        cx.caption(f, "This build has no update repository, signature-update workflow, or installer. No update check has been performed.");
        cx.heading(f, "Installed");
        let mut g = cx.group_begin(f, 4, 42.0);
        cx.row_value(&mut g, "KashOS", "Prototype UI");
        cx.row_value(&mut g, "KashOS Microkernel", "0.2.0");
        cx.row_value(&mut g, "kash-ui", "Software renderer 1.0");
        cx.row_value(&mut g, "Driver set", "No live driver inventory");
    }

    pub(crate) fn pane_storage(&mut self, cx: &mut Ctx, f: &mut Form) {
        let mb = |c: AppClass, reg: &Registry| -> u64 { reg.apps.iter().filter(|a| a.class == c).map(|a| a.size).sum() };
        let (apps, cli, drv) = (mb(AppClass::Gui, &cx.sys.reg), mb(AppClass::Cli, &cx.sys.reg), mb(AppClass::Driver, &cx.sys.reg));
        let docs = 12_400_000u64; let media = 78_000_000u64; let sys = 536_870_912u64 + 2_400_000; let dls: u64 = cx.sys.reg.downloads.iter().map(|d| d.size).sum();
        let cats: [(&str, u64, u32, &str); 6] = [("Applications", apps, 0x0A84FF, "Applications"), ("CLI Applications", cli, 0x30D158, "CLI Applications"), ("Drivers", drv, 0xFF9F0A, "Drivers"),
            ("Documents", docs, 0x5E5CE6, "Documents"), ("Downloads", dls, 0xFF375F, "Downloads"), ("System", sys + media, 0x8E8E93, "System")];
        // The breakdown below is sample UI data; no mounted filesystem reports capacity yet.
        let total: u64 = 256_000_000_000; let used: u64 = cats.iter().map(|c| c.1).sum::<u64>() + 98_000_000_000;
        let r = Rect::new(f.x, f.y, f.w, 124.0);
        cx.group_box(r);
        let lc = cx.th.label(); let l2 = cx.th.label2();
        cx.text(r.x + 20.0, r.y + 36.0, "Kash HD", 16.0, Weight::Bold, lc);
        cx.text(r.x + 20.0, r.y + 55.0, &format!("{:.0} GB of {:.0} GB used", used as f32 / 1e9, total as f32 / 1e9), 12.0, Weight::Regular, l2);
        let bar = Rect::new(r.x + 20.0, r.y + 74.0, r.w - 40.0, 16.0);
        cx.cv.fill_rrect(bar, 8.0, cx.th.control_fill());
        cx.cv.push_clip(bar);
        let mut x = bar.x;
        let scale_boost = 1.0 / (used as f32 / total as f32).max(0.05);
        let _ = scale_boost;
        let seg_total = (used as f32).max(1.0);
        let filled = (used as f32 / total as f32) * bar.w;
        let other = used - cats.iter().map(|c| c.1).sum::<u64>();
        let mut parts: Vec<(f32, u32)> = cats.iter().map(|c| (c.1 as f32, c.2)).collect();
        parts.push((other as f32, 0x64748B));
        for (v, col) in parts.iter() { let w = v / seg_total * filled; cx.cv.fill_rect(Rect::new(x, bar.y, w.max(0.0), bar.h), Color::hex(*col)); x += w; }
        cx.cv.pop_clip();
        cx.cv.stroke_rrect(bar, 8.0, 0.8, cx.th.separator());
        for (i, (n, _, col, _)) in cats.iter().enumerate() {
            let lx = r.x + 20.0 + (i % 6) as f32 * ((r.w - 40.0) / 6.0);
            cx.cv.fill_circle(lx + 4.0, r.y + 106.0, 3.5, Color::hex(*col));
            cx.text(lx + 12.0, r.y + 110.0, n.split(' ').next().unwrap_or(n), 10.5, Weight::Regular, l2);
        }
        f.y += 124.0 + 18.0;
        cx.heading(f, "By category");
        let mut g = cx.group_begin(f, cats.len(), 46.0);
        for (n, sz, col, folder) in cats.iter() {
            let rr = cx.group_row(&mut g);
            let h = cx.hit(id_of(n) ^ 0x57, rr);
            if h.hovered { let hf = cx.th.hover_fill(); cx.cv.fill_rrect(rr.inset(1.0), 10.0, hf); }
            cx.cv.fill_circle(rr.x + 22.0, rr.cy(), 6.0, Color::hex(*col));
            cx.text(rr.x + 40.0, rr.cy() + 4.7, n, 13.5, Weight::Regular, lc);
            let s = if *sz < 1_000_000 { format!("{} KB", sz / 1000) } else if *sz < 1_000_000_000 { format!("{:.1} MB", *sz as f32 / 1e6) } else { format!("{:.2} GB", *sz as f32 / 1e9) };
            cx.text_in(Rect::new(rr.x + rr.w * 0.5, rr.y, rr.w * 0.5 - 38.0, rr.h), &s, 12.5, Weight::Regular, l2, Align::Right);
            draw_icon(cx.cv, Icon::ChevR, Rect::new(rr.right() - 26.0, rr.cy() - 6.0, 12.0, 12.0), cx.th.label3());
            if h.clicked { cx.cmds.push(Cmd::OpenPath(String::from(*folder))); }
        }
        cx.heading(f, "Recommendations");
        cx.caption(f, "Sample data only. This chart is not read from a disk or mounted filesystem.");
        let mut g = cx.group_begin(f, 2, 54.0);
        self.opt(cx, &mut g, 60, "Empty Trash automatically", "Remove items after 30 days");
        self.opt(cx, &mut g, 61, "Optimise storage", "Keep only recent downloads on this disk");
    }

    pub(crate) fn pane_datetime(&mut self, cx: &mut Ctx, f: &mut Form) {
        let secs = cx.sys.unix_secs + 19_800;
        let (h, m) = (((secs / 3600) % 24) as i32, ((secs / 60) % 60) as i32);
        let days = secs.div_euclid(86_400);
        let (y, mo, d) = civil(days);
        let r = self.card(cx, f, 96.0, Icon::Clock, 0xFF9F0A, &format!("{:02}:{:02}", h, m), &format!("{:04}-{:02}-{:02} · India Standard Time", y, mo, d));
        let _ = r;
        let mut g = cx.group_begin(f, 3, 54.0);
        self.opt(cx, &mut g, 70, "Set time and date automatically", "Using the Anonymity Gateway’s time source");
        self.opt(cx, &mut g, 71, "24-hour time", "");
        self.opt(cx, &mut g, 72, "Set time zone automatically", "");
        cx.heading(f, "Details");
        let mut g = cx.group_begin(f, 3, 42.0);
        cx.row_value(&mut g, "Time zone", "Asia/Kolkata (UTC+05:30)");
        cx.row_value(&mut g, "Time server", "No network time service");
        cx.row_value(&mut g, "Calendar", "Gregorian");
    }
}

/// Days since 1970-01-01 → (year, month, day).
fn civil(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
