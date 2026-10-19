//! Files — Golden Gate style: edge-to-edge glass sidebar, floating glass toolbar, icon + list views.
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::anim::*;
use crate::app::*;
use crate::color::*;
use crate::geom::*;
use crate::gfx::Paint;
use crate::icons::*;
use crate::mathf::*;
use crate::text::*;
use crate::theme::*;
use crate::ui::*;
use crate::registry::*;

#[derive(Clone)]
pub struct Node { pub name: String, pub kind: FileKind, pub size: u64, pub date: &'static str, pub children: Vec<Node> }

fn d(name: &str, date: &'static str, ch: Vec<Node>) -> Node { Node { name: String::from(name), kind: FileKind::Folder, size: 0, date, children: ch } }
fn f(name: &str, kind: FileKind, size: u64, date: &'static str) -> Node { Node { name: String::from(name), kind, size, date, children: Vec::new() } }

fn reg_folder(c: AppClass) -> Node {
    let r = Registry::new();
    let ch: Vec<Node> = r.apps.iter().filter(|a| a.class == c).map(|a| f(&a.name, c.file_kind(), a.size, a.date)).collect();
    d(c.folder(), "Oct 9", ch)
}

pub fn build_fs() -> Node {
    d("Kash Root VFS", "Today", alloc::vec![
        reg_folder(AppClass::Gui),
        reg_folder(AppClass::Cli),
        reg_folder(AppClass::Driver),
        d("Desktop", "Today", alloc::vec![
            f("Terminal", FileKind::App, 48_100, "Today"),
            f("OS Installer", FileKind::App, 32_400, "Today"),
            f("Hardware Report", FileKind::App, 12_000, "Today"),
            f("Capability Explorer", FileKind::App, 18_200, "Today"),
        ]),
        d("System", "Today", alloc::vec![
            f("kash-kernel", FileKind::App, 2_400_000, "Today"),
            f("kcore.cap", FileKind::Doc, 80_000, "Today"),
            f("epoch.state", FileKind::Text, 256, "Today"),
            f("audit.log", FileKind::Text, 4_096, "Today"),
        ]),
        d("Drivers", "Today", alloc::vec![
            f("e1000.drv", FileKind::Driver, 16_384, "Today"),
            f("ps2.drv", FileKind::Driver, 8_192, "Today"),
            f("vtd.drv", FileKind::Driver, 12_288, "Today"),
            f("tpm2.drv", FileKind::Driver, 14_336, "Today"),
        ]),
        d("Etc", "Today", alloc::vec![
            f("version", FileKind::Text, 6, "Today"),
            f("hardware.tier", FileKind::Text, 32, "Today"),
            f("security.policy", FileKind::Text, 512, "Today"),
        ]),
        d("Dev", "Today", alloc::vec![
            f("console", FileKind::Code, 0, "Today"),
            f("fb0", FileKind::Image, 0, "Today"),
            f("random", FileKind::Code, 0, "Today"),
        ]),
        { let mut v = d("Vault", "Today", alloc::vec![
            f("kvault.enc", FileKind::Archive, 536_870_912, "Today"),
        ]); v.kind = FileKind::Vault; v },
    ])
}

fn child<'a>(root: &'a Node, path: &[String]) -> &'a Node {
    let mut n = root;
    for p in path { if let Some(c) = n.children.iter().find(|c| &c.name == p) { n = c; } else { break; } }
    n
}

fn fmt_size(b: u64) -> String {
    if b == 0 { return String::from("--"); }
    if b < 1000 { format!("{} bytes", b) }
    else if b < 1_000_000 { format!("{:.0} KB", b as f32 / 1000.0) }
    else if b < 1_000_000_000 { format!("{:.1} MB", b as f32 / 1e6) }
    else { format!("{:.2} GB", b as f32 / 1e9) }
}
fn kind_name(k: FileKind) -> &'static str {
    match k { FileKind::Folder => "Folder", FileKind::Vault => "Encrypted Vault", FileKind::Doc => "Document", FileKind::Pdf => "PDF Document", FileKind::Image => "Image",
        FileKind::Audio => "Audio", FileKind::Archive => "Archive", FileKind::Code => "Rust Source", FileKind::Text => "Plain Text", FileKind::Iso => "Disk Image",
        FileKind::Pcap => "Packet Capture", FileKind::App => "Application", FileKind::Exec => "Command-Line Tool", FileKind::Driver => "Kernel Driver" }
}

#[derive(Clone, Copy, PartialEq)]
enum Sort { Name, Date, Size, Kind }

pub struct Files {
    root: Node,
    path: Vec<String>,
    back: Vec<Vec<String>>,
    fwd: Vec<Vec<String>>,
    sel: Option<String>,
    pub list_view: usize,
    search: FieldState,
    scroll: Scroll,
    sort: Sort,
    asc: bool,
    trans: Spring,
    trans_dir: f32,
    ctx: Option<(Pt, String, FileKind)>,
    ctx_t: Spring,
}

impl Files {
    pub fn new() -> Files {
        let mut s = Files {
            root: build_fs(), path: alloc::vec![String::from("Documents")], back: Vec::new(), fwd: Vec::new(), sel: None, list_view: 0,
            search: FieldState::default(), scroll: Scroll::default(), sort: Sort::Name, asc: true, trans: Spring::new(1.0, 0.32, 0.9), trans_dir: 1.0, ctx: None, ctx_t: Spring::new(0.0, 0.2, 0.9),
        };
        s.trans.snap(1.0);
        s
    }
    pub fn with_path(path: &str) -> Files {
        let mut s = Files::new();
        s.path = path.split('/').filter(|p| !p.is_empty()).map(String::from).collect();
        s
    }
    fn goto(&mut self, p: Vec<String>, push: bool) {
        if p == self.path { return; }
        if push { self.back.push(self.path.clone()); self.fwd.clear(); }
        self.trans_dir = if p.len() >= self.path.len() { 1.0 } else { -1.0 };
        self.path = p; self.sel = None; self.scroll = Scroll::default();
        self.trans.snap(0.0); self.trans.set(1.0);
        self.search.text.clear(); self.search.caret = 0;
    }
    fn items(&self) -> Vec<Node> {
        let n = child(&self.root, &self.path);
        let q: String = self.search.text.to_lowercase();
        let mut v: Vec<Node> = n.children.iter().filter(|c| q.is_empty() || c.name.to_lowercase().contains(&q)).cloned().collect();
        let asc = self.asc;
        v.sort_by(|a, b| {
            let fa = matches!(a.kind, FileKind::Folder | FileKind::Vault); let fb = matches!(b.kind, FileKind::Folder | FileKind::Vault);
            if fa != fb { return fb.cmp(&fa); }
            let o = match self.sort {
                Sort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                Sort::Size => a.size.cmp(&b.size),
                Sort::Kind => kind_name(a.kind).cmp(kind_name(b.kind)),
                Sort::Date => a.date.cmp(b.date),
            };
            if asc { o } else { o.reverse() }
        });
        v
    }
    fn open_item(&mut self, it: &Node, cx: &mut Ctx) {
        match it.kind {
            FileKind::Folder => { let mut p = self.path.clone(); p.push(it.name.clone()); self.goto(p, true); }
            FileKind::Vault => cx.cmds.push(Cmd::Toast(String::from("Vault is sealed — unlock with your passphrase (kvault)"))),
            FileKind::App => {
                let k = match it.name.as_str() { "Terminal" => Some(AppKind::Terminal), "System Settings" => Some(AppKind::Settings), "Notes" => Some(AppKind::Notes), "Firefox" | "Browser" | "Browser (demo)" => Some(AppKind::Browser),
                    "Photos" => Some(AppKind::Photos), "Music" => Some(AppKind::Music), "Messages" => Some(AppKind::Messages), "Files" => Some(AppKind::Files),
                    "Activity Monitor" => Some(AppKind::ActivityMonitor), "Calculator" => Some(AppKind::Calculator), _ => None };
                if let Some(k) = k { cx.cmds.push(Cmd::Open(k)); }
            }
            FileKind::Exec => { cx.cmds.push(Cmd::Toast(format!("“{}” is a command-line tool — run it from Terminal", it.name))); cx.cmds.push(Cmd::Open(AppKind::Terminal)); }
            FileKind::Driver => cx.cmds.push(Cmd::Toast(format!("“{}” is loaded by the kernel — manage it in Privacy & Security", it.name))),
            FileKind::Image => cx.cmds.push(Cmd::Open(AppKind::Photos)),
            FileKind::Audio => cx.cmds.push(Cmd::Open(AppKind::Music)),
            FileKind::Text | FileKind::Code | FileKind::Doc => cx.cmds.push(Cmd::Open(AppKind::Notes)),
            _ => cx.cmds.push(Cmd::Toast(format!("No preview available for “{}”", it.name))),
        }
    }
}

const SB_W: f32 = 212.0;
const TB_H: f32 = 56.0;

impl App for Files {
    fn kind(&self) -> AppKind { AppKind::Files }
    fn title(&self) -> String { self.path.last().cloned().unwrap_or_else(|| String::from("Kash HD")) }
    fn default_size(&self) -> (f32, f32) { (920.0, 620.0) }
    fn min_size(&self) -> (f32, f32) { (700.0, 540.0) }
    fn extra_menus(&self) -> Vec<(String, Vec<MenuItem>)> {
        alloc::vec![(String::from("View"), alloc::vec![
            MenuItem::new("as Icons", "Ctrl 1", Action::AppCmd("view_icons")), MenuItem::new("as List", "Ctrl 2", Action::AppCmd("view_list")),
            MenuItem::sep(), MenuItem::new("Show Enclosing Folder", "Ctrl ↑", Action::AppCmd("up")),
        ]), (String::from("Go"), alloc::vec![
            MenuItem::new("Back", "Ctrl [", Action::AppCmd("back")), MenuItem::new("Forward", "Ctrl ]", Action::AppCmd("forward")), MenuItem::sep(),
            MenuItem::new("Documents", "", Action::AppCmd("go_documents")), MenuItem::new("Downloads", "", Action::AppCmd("go_downloads")), MenuItem::new("Applications", "", Action::AppCmd("go_applications")), MenuItem::new("CLI Applications", "", Action::AppCmd("go_cli")), MenuItem::new("Drivers", "", Action::AppCmd("go_drivers")),
        ])]
    }
    fn animating(&self) -> bool { !self.trans.settled() || self.scroll.moving() || self.ctx.is_some() || !self.ctx_t.settled() }
    fn command(&mut self, name: &str) {
        match name {
            "view_icons" => self.list_view = 0, "view_list" => self.list_view = 1,
            "up" => { if !self.path.is_empty() { let mut p = self.path.clone(); p.pop(); self.goto(p, true); } }
            "back" => { if let Some(p) = self.back.pop() { self.fwd.push(self.path.clone()); self.goto(p, false); } }
            "forward" => { if let Some(p) = self.fwd.pop() { self.back.push(self.path.clone()); self.goto(p, false); } }
            "go_documents" => self.goto(alloc::vec![String::from("Documents")], true),
            "go_downloads" => self.goto(alloc::vec![String::from("Downloads")], true),
            "go_applications" => self.goto(alloc::vec![String::from("Applications")], true),
            "go_cli" => self.goto(alloc::vec![String::from("CLI Applications")], true),
            "go_drivers" => self.goto(alloc::vec![String::from("Drivers")], true),
            _ => {}
        }
    }

    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        let th = *cx.th;
        let items = self.items();
        let content = Rect::new(SB_W, 0.0, area.w - SB_W, area.h);
        cx.cv.fill_rect(content, th.content_bg());

        let tt = saturate(self.trans.x);
        self.trans.update(cx.io.dt);
        let slide = (1.0 - tt) * 26.0 * self.trans_dir;
        let rise = (1.0 - tt) * 10.0;
        let top_pad = TB_H + 12.0;
        let bottom_bar = 30.0;
        let view = Rect::new(content.x, 0.0, content.w, area.h - bottom_bar);
        cx.cv.push_clip(Rect::new(content.x, 0.0, content.w, area.h));
        let hover_content = cx.hover(content);
        if cx.io.focused {
            let keys: Vec<KeyEv> = cx.io.keys.clone();
            for k in keys {
                if self.search.focused { continue; }
                let idx = items.iter().position(|i| Some(&i.name) == self.sel.as_ref());
                let cols = if self.list_view == 0 { (((content.w - 40.0) / 112.0) as usize).max(1) } else { 1 };
                match k.key {
                    Key::Right => { let n = idx.map(|i| (i + 1).min(items.len().saturating_sub(1))).unwrap_or(0); if let Some(it) = items.get(n) { self.sel = Some(it.name.clone()); } }
                    Key::Left => { let n = idx.map(|i| i.saturating_sub(1)).unwrap_or(0); if let Some(it) = items.get(n) { self.sel = Some(it.name.clone()); } }
                    Key::Down => { let n = idx.map(|i| (i + cols).min(items.len().saturating_sub(1))).unwrap_or(0); if let Some(it) = items.get(n) { self.sel = Some(it.name.clone()); } }
                    Key::Up => { let n = idx.map(|i| i.saturating_sub(cols)).unwrap_or(0); if let Some(it) = items.get(n) { self.sel = Some(it.name.clone()); } }
                    Key::Enter => { if let Some(i) = idx { let it = items[i].clone(); self.open_item(&it, cx); } }
                    Key::Backspace => self.command("up"),
                    Key::Char if k.ctrl && k.ch == '1' => self.list_view = 0,
                    Key::Char if k.ctrl && k.ch == '2' => self.list_view = 1,
                    Key::Char if k.ctrl && k.ch == 'f' => self.search.focused = true,
                    _ => {}
                }
            }
        }

        let mut open_target: Option<Node> = None;
        let total_h;
        if self.list_view == 0 {
            let cw = 112.0; let ch = 112.0;
            let cols = (((content.w - 32.0) / cw) as usize).max(1);
            let rows = (items.len() + cols - 1) / cols;
            total_h = top_pad + rows as f32 * ch + 24.0;
            let gx = content.x + (content.w - cols as f32 * cw) * 0.5;
            let base_y = top_pad - self.scroll.y + rise;
            for (i, it) in items.iter().enumerate() {
                let (c, r) = (i % cols, i / cols);
                let cell = Rect::new(gx + c as f32 * cw + slide, base_y + r as f32 * ch, cw, ch);
                if cell.bottom() < 0.0 || cell.y > area.h { continue; }
                let hit = cx.hit(id_of(&it.name) ^ 0x77, cell.inset_xy(4.0, 2.0));
                let selected = self.sel.as_ref() == Some(&it.name);
                if hit.hovered && cx.io.pressed { self.sel = Some(it.name.clone()); self.search.focused = false;
                    if cx.io.click_count >= 2 { open_target = Some(it.clone()); } }
                if hit.hovered && cx.io.right_pressed { self.sel = Some(it.name.clone()); self.search.focused = false; self.ctx = Some((cx.io.mouse, it.name.clone(), it.kind)); self.ctx_t.snap(0.0); }
                let sel_t = cx.anim(id2(id_of(&it.name), 0x31), if selected { 1.0 } else { 0.0 });
                let icon_r = Rect::new(cell.cx() - 32.0, cell.y + 8.0, 64.0, 64.0);
                if sel_t > 0.01 { cx.cv.fill_rrect(Rect::new(cell.cx() - 42.0, cell.y + 2.0, 84.0, 76.0), 14.0, th.control_fill().fade(0.9 * sel_t)); }
                else if hit.hovered { cx.cv.fill_rrect(Rect::new(cell.cx() - 42.0, cell.y + 2.0, 84.0, 76.0), 14.0, th.hover_fill()); }
                cx.file_icon(it.kind, icon_r);
                let lines = cx.fonts.wrap(&it.name, 12.0, Weight::Regular, cw - 14.0);
                for (li, l) in lines.iter().take(2).enumerate() {
                    let l = if li == 1 && lines.len() > 2 { cx.fonts.fit(&format!("{}…", l), 12.0, Weight::Regular, cw - 14.0) } else { cx.fonts.fit(l, 12.0, Weight::Regular, cw - 10.0) };
                    let w = cx.measure(&l, 12.0, Weight::Regular);
                    let ty = cell.y + 90.0 + li as f32 * 14.0;
                    if selected && li == 0 { let pill = Rect::new(cell.cx() - w * 0.5 - 6.0, ty - 12.0, w + 12.0, 17.0); cx.cv.fill_rrect(pill, 8.5, th.accent()); }
                    let col = if selected && li == 0 { Color::WHITE } else { th.label() };
                    cx.text(cell.cx() - w * 0.5, ty, &l, 12.0, Weight::Regular, col);
                }
            }
            if items.is_empty() { cx.text_in(Rect::new(content.x, area.h * 0.45, content.w, 20.0), "No items", 14.0, Weight::Medium, th.label3(), Align::Center); }
        } else {
            let rh = 30.0;
            total_h = top_pad + 30.0 + items.len() as f32 * rh + 24.0;
            let hy = top_pad - self.scroll.y;
            let cols_x = [content.x + 16.0, content.x + content.w * 0.52, content.x + content.w * 0.68, content.x + content.w * 0.82];
            let heads = ["Name", "Date Modified", "Size", "Kind"];
            let sorts = [Sort::Name, Sort::Date, Sort::Size, Sort::Kind];
            for i in 0..4 {
                let wdt = if i < 3 { cols_x[i + 1] - cols_x[i] } else { content.right() - cols_x[3] };
                let hr = Rect::new(cols_x[i] - 4.0, hy, wdt, 26.0);
                let h = cx.hit(id_of(heads[i]) ^ 0x99, hr);
                if h.clicked { if self.sort == sorts[i] { self.asc = !self.asc; } else { self.sort = sorts[i]; self.asc = true; } }
                let c = if self.sort == sorts[i] { th.label() } else { th.label2() };
                cx.text(cols_x[i], hy + 18.0, heads[i], 12.0, Weight::Semibold, c);
                if self.sort == sorts[i] {
                    let hw = cx.measure(heads[i], 12.0, Weight::Semibold);
                    draw_icon(cx.cv, if self.asc { Icon::ChevU } else { Icon::ChevD }, Rect::new(cols_x[i] + hw + 4.0, hy + 7.0, 11.0, 11.0), th.label2());
                }
            }
            cx.separator_h(content.x, content.right(), hy + 28.0);
            for (i, it) in items.iter().enumerate() {
                let row = Rect::new(content.x + 8.0 + slide, hy + 30.0 + i as f32 * rh + rise, content.w - 16.0, rh);
                if row.bottom() < 0.0 || row.y > area.h { continue; }
                let hit = cx.hit(id_of(&it.name) ^ 0x78, row);
                let selected = self.sel.as_ref() == Some(&it.name);
                if hit.hovered && cx.io.pressed { self.sel = Some(it.name.clone()); self.search.focused = false;
                    if cx.io.click_count >= 2 { open_target = Some(it.clone()); } }
                if hit.hovered && cx.io.right_pressed { self.sel = Some(it.name.clone()); self.search.focused = false; self.ctx = Some((cx.io.mouse, it.name.clone(), it.kind)); self.ctx_t.snap(0.0); }
                let sel_t = cx.anim(id2(id_of(&it.name), 0x32), if selected { 1.0 } else { 0.0 });
                if i % 2 == 1 { cx.cv.fill_rrect(row, 8.0, th.pick(Color::rgba(0, 0, 0, 7), Color::rgba(255, 255, 255, 9))); }
                if sel_t > 0.01 { cx.cv.fill_rrect(row, 8.0, th.accent().fade(sel_t)); }
                else if hit.hovered { cx.cv.fill_rrect(row, 8.0, th.hover_fill()); }
                let tc = if selected { Color::WHITE } else { th.label() };
                let tc2 = if selected { Color::rgba(255, 255, 255, 200) } else { th.label2() };
                cx.file_icon(it.kind, Rect::new(cols_x[0] + 2.0, row.y + 3.0, 24.0, 24.0));
                cx.text_in(Rect::new(cols_x[0] + 34.0, row.y, cols_x[1] - cols_x[0] - 40.0, rh), &it.name, 13.0, Weight::Regular, tc, Align::Left);
                cx.text_in(Rect::new(cols_x[1], row.y, cols_x[2] - cols_x[1], rh), it.date, 12.5, Weight::Regular, tc2, Align::Left);
                cx.text_in(Rect::new(cols_x[2], row.y, cols_x[3] - cols_x[2], rh), &fmt_size(it.size), 12.5, Weight::Regular, tc2, Align::Left);
                cx.text_in(Rect::new(cols_x[3], row.y, content.right() - cols_x[3], rh), kind_name(it.kind), 12.5, Weight::Regular, tc2, Align::Left);
            }
        }
        if let Some(it) = open_target { self.open_item(&it, cx); }
        cx.cv.pop_clip();
        self.scroll.update(cx.io, hover_content, total_h - view.h);

        // soft-edge scroll effect under toolbar + above path bar
        let cb = th.content_bg();
        let fade = Rect::new(content.x, 0.0, content.w, TB_H + 14.0);
        cx.cv.fill_rect(fade, Paint::VGrad { y0: 0.0, y1: fade.h, c0: cb.fade(0.92), c1: cb.fade(0.0) });
        let bfade = Rect::new(content.x, area.h - bottom_bar - 6.0, content.w, bottom_bar + 6.0);
        cx.cv.fill_rect(bfade, Paint::VGrad { y0: bfade.y, y1: bfade.bottom(), c0: cb.fade(0.0), c1: cb.fade(0.96) });

        // toolbar (floating glass controls)
        let ty = 10.0; let bh = 36.0;
        let mut x = content.x + 14.0;
        let grp = Rect::new(x, ty, 78.0, bh);
        cx.glass(grp, GlassKind::Toolbar, bh * 0.5);
        let can_back = !self.back.is_empty(); let can_fwd = !self.fwd.is_empty();
        let (b1, b2) = (Rect::new(x + 2.0, ty, 38.0, bh), Rect::new(x + 38.0, ty, 38.0, bh));
        let hb1 = if can_back { cx.hit(id_of("fbk"), b1) } else { WidgetResp::none() };
        let hb2 = if can_fwd { cx.hit(id_of("ffw"), b2) } else { WidgetResp::none() };
        if hb1.hovered { cx.cv.fill_rrect(b1.inset_xy(2.0, 3.0), 15.0, th.hover_fill()); }
        if hb2.hovered { cx.cv.fill_rrect(b2.inset_xy(2.0, 3.0), 15.0, th.hover_fill()); }
        draw_icon(cx.cv, Icon::ChevL, Rect::new(b1.cx() - 8.0, b1.cy() - 8.0, 16.0, 16.0), if can_back { th.label() } else { th.label4() });
        draw_icon(cx.cv, Icon::ChevR, Rect::new(b2.cx() - 8.0, b2.cy() - 8.0, 16.0, 16.0), if can_fwd { th.label() } else { th.label4() });
        if hb1.clicked { self.command("back"); }
        if hb2.clicked { self.command("forward"); }
        x += 78.0 + 12.0;
        let title = self.title();
        let tw = cx.measure(&title, 14.0, Weight::Semibold) + 52.0;
        let tr = Rect::new(x, ty, tw, bh);
        cx.glass(tr, GlassKind::Toolbar, bh * 0.5);
        cx.file_icon(FileKind::Folder, Rect::new(tr.x + 8.0, tr.y + 6.0, 24.0, 24.0));
        cx.text_in(Rect::new(tr.x + 36.0, tr.y, tr.w - 42.0, tr.h), &title, 14.0, Weight::Semibold, th.label(), Align::Left);
        let sw = (content.w * 0.22).clamp(130.0, 210.0);
        let sr = Rect::new(content.right() - 10.0 - CAPTION_RESERVE - sw, ty, sw, bh);
        cx.glass(sr, GlassKind::Toolbar, bh * 0.5);
        cx.text_field("fsearch", sr.inset_xy(2.0, 4.0), &mut self.search, "Search", Some(Icon::Search));
        let vr = Rect::new(sr.x - 10.0 - 84.0, ty, 84.0, bh);
        let sel_reg = self.sel.clone().filter(|n| matches!(child(&self.root, &self.path).children.iter().find(|c| &c.name == n).map(|c| c.kind), Some(FileKind::App | FileKind::Exec | FileKind::Driver)) && cx.sys.reg.find_name(n).is_some());
        if let Some(n) = sel_reg.clone() {
            let pb = Rect::new(vr.x - 10.0 - 38.0, ty, 38.0, bh);
            if cx.glass_icon_button("fperm", pb, Icon::Shield, true) { cx.cmds.push(Cmd::OpenPermissions(n)); }
        }
        cx.glass(vr, GlassKind::Toolbar, bh * 0.5);
        let mut sel = self.list_view;
        let seg = Rect::new(vr.x + 4.0, vr.y + 4.0, vr.w - 8.0, vr.h - 8.0);
        let t = cx.anim_p(id_of("fview"), sel as f32, Preset::Snappy);
        let thumb = Rect::new(seg.x + t * seg.w * 0.5, seg.y, seg.w * 0.5, seg.h);
        cx.cv.fill_rrect(thumb, thumb.h * 0.5, th.pick(Color::rgba(255, 255, 255, 190), Color::rgba(255, 255, 255, 46)));
        let hv = cx.hit(id_of("fviewhit"), seg);
        if hv.clicked { sel = (((cx.io.mouse.x - seg.x) / (seg.w * 0.5)) as usize).min(1); }
        draw_icon(cx.cv, Icon::Grid, Rect::new(seg.x + seg.w * 0.25 - 8.0, seg.cy() - 8.0, 16.0, 16.0), th.label());
        draw_icon(cx.cv, Icon::List, Rect::new(seg.x + seg.w * 0.75 - 8.0, seg.cy() - 8.0, 16.0, 16.0), th.label());
        self.list_view = sel;

        // bottom path bar
        let by = area.h - bottom_bar;
        let mut px = content.x + 16.0;
        let mut crumbs: Vec<(String, Vec<String>)> = Vec::new();
        crumbs.push((String::from("Kash HD"), Vec::new()));
        for i in 0..self.path.len() { crumbs.push((self.path[i].clone(), self.path[..=i].to_vec())); }
        let mut nav: Option<Vec<String>> = None;
        for (i, (name, pth)) in crumbs.iter().enumerate() {
            if i > 0 { draw_icon(cx.cv, Icon::ChevR, Rect::new(px, by + 9.0, 12.0, 12.0), th.label3()); px += 14.0; }
            let w = cx.measure(name, 12.0, Weight::Regular);
            let r = Rect::new(px - 3.0, by + 4.0, w + 6.0, 22.0);
            let h = cx.hit(id_of(name) ^ 0xAB ^ (i as u32), r);
            if h.hovered { cx.cv.fill_rrect(r, 6.0, th.hover_fill()); }
            let last = i + 1 == crumbs.len();
            cx.text(px, by + 19.0, name, 12.0, if last { Weight::Medium } else { Weight::Regular }, if last { th.label() } else { th.label2() });
            if h.clicked { nav = Some(pth.clone()); }
            px += w + 8.0;
        }
        if let Some(p) = nav { self.goto(p, true); }
        let mut status = format!("{} item{} · 128 GB available", items.len(), if items.len() == 1 { "" } else { "s" });
        if let Some(n) = sel_reg.as_ref() { if let Some(i) = cx.sys.reg.find_name(n) { let (a, k, dn) = cx.sys.reg.apps[i].counts(); status = format!("{} · {} allowed · {} ask · {} denied", n, a, k, dn); } }
        cx.text_in(Rect::new(content.right() - 400.0, by, 384.0, bottom_bar), &status, 11.5, Weight::Regular, th.label2(), Align::Right);

        // sidebar (edge-to-edge glass, Golden Gate)
        let sb = Rect::new(0.0, 0.0, SB_W, area.h);
        let mut st = th.glass(GlassKind::Sidebar, 0.0);
        st.bezel = 0.0; st.spec = 0.0; st.refraction = 0.0;
        cx.glass_style(sb, &st);
        cx.cv.fill_rect(Rect::new(SB_W - 1.0, 0.0, 1.0, area.h), th.separator());
        let mut y = 58.0;
        let sections: [(&str, &[(&str, Icon, u32, &str)]); 3] = [
            ("Favorites", &[("Applications", Icon::Apps, 0x0A84FF, "Applications"), ("Desktop", Icon::Desktop, 0x5E5CE6, "Desktop"), ("Documents", Icon::Doc, 0x32ADE6, "Documents"),
                ("Downloads", Icon::Download, 0x30D158, "Downloads"), ("Pictures", Icon::Photo, 0xFF9F0A, "Pictures"), ("Music", Icon::Music, 0xFF375F, "Music")]),
            ("Locations", &[("Kash HD", Icon::Disk, 0x8E8E93, ""), ("CLI Applications", Icon::Terminal, 0x30D158, "CLI Applications"), ("Drivers", Icon::Chip, 0xFF9F0A, "Drivers"), ("System", Icon::Chip, 0x64748B, "System"), ("Vault", Icon::Lock, 0xBF5AF2, "Vault")]),
            ("Tags", &[("Red", Icon::Tag, 0xFF453A, "#"), ("Blue", Icon::Tag, 0x0A84FF, "#")]),
        ];
        for (sec, ents) in sections.iter() {
            cx.text(16.0, y + 10.0, sec, 11.5, Weight::Semibold, th.label3());
            y += 20.0;
            for (name, ic, col, target) in ents.iter() {
                let r = Rect::new(8.0, y, SB_W - 16.0, 30.0);
                let cur = if target.is_empty() { self.path.is_empty() } else if *target == "#" { false } else { self.path.first().map(|s| s.as_str()) == Some(*target) && self.path.len() == 1 };
                let h = cx.hit(id_of(name) ^ 0x5B, r);
                let t = cx.anim(id2(id_of(name), 0x5C), if cur { 1.0 } else { 0.0 });
                if t > 0.01 { cx.cv.fill_rrect(r, 10.0, th.pick(Color::rgba(0, 0, 0, 22), Color::rgba(255, 255, 255, 34)).fade(t)); }
                else if h.hovered { cx.cv.fill_rrect(r, 10.0, th.hover_fill()); }
                draw_icon(cx.cv, *ic, Rect::new(r.x + 9.0, r.y + 6.0, 18.0, 18.0), Color::hex(*col));
                cx.text_in(Rect::new(r.x + 36.0, r.y, r.w - 40.0, r.h), name, 13.0, if cur { Weight::Medium } else { Weight::Regular }, th.label(), Align::Left);
                if h.clicked { if target.is_empty() { self.goto(Vec::new(), true); } else if *target != "#" { self.goto(alloc::vec![String::from(*target)], true); } }
                y += 31.0;
            }
            y += 10.0;
        }

        // right-click context menu
        if let Some((pos, name, kind)) = self.ctx.clone() {
            self.ctx_t.set(1.0); self.ctx_t.update(cx.io.dt);
            let t = saturate(self.ctx_t.x);
            let has_reg = cx.sys.reg.find_name(&name).is_some() && matches!(kind, FileKind::App | FileKind::Exec | FileKind::Driver);
            let mut rows: Vec<(&str, u8)> = Vec::new();
            rows.push((match kind { FileKind::Exec => "Run in Terminal", FileKind::Driver => "Get Info", FileKind::Folder | FileKind::Vault => "Open Folder", _ => "Open" }, 0));
            if has_reg { rows.push(("Permissions…", 1)); }
            rows.push(("Copy Path", 2));
            let w = 210.0; let rh = 30.0; let h = rows.len() as f32 * rh + 16.0;
            let mr = Rect::new(pos.x.min(area.w - w - 8.0), pos.y.min(area.h - h - 8.0) + (1.0 - t) * -6.0, w, h);
            cx.cv.shadow_rrect(mr.offset(0.0, 8.0), 16.0, 22.0, th.shadow(0.26 * t), true);
            let mut st = th.glass(GlassKind::Popover, 16.0);
            st.tint.a = (st.tint.a as f32 * t) as u8;
            cx.glass_style(mr, &st);
            let mut fire: Option<u8> = None;
            for (i, (lab, act)) in rows.iter().enumerate() {
                let rr = Rect::new(mr.x + 8.0, mr.y + 8.0 + i as f32 * rh, mr.w - 16.0, rh);
                let hv = cx.hover(rr);
                if hv { *cx.over_widget = true; cx.cv.fill_rrect(rr, 9.0, th.accent()); }
                cx.text(rr.x + 10.0, rr.cy() + 4.7, lab, 13.0, Weight::Regular, if hv { Color::WHITE } else { th.label() }.fade(t));
                if hv && cx.io.released { fire = Some(*act); }
            }
            if cx.hover(mr) { *cx.over_widget = true; }
            let mut close = false;
            if cx.io.pressed && !mr.contains(cx.io.mouse.x, cx.io.mouse.y) { close = true; }
            if let Some(a) = fire {
                close = true;
                match a {
                    0 => { let node = Node { name: name.clone(), kind, size: 0, date: "", children: Vec::new() }; self.open_item(&node, cx); }
                    1 => cx.cmds.push(Cmd::OpenPermissions(name.clone())),
                    _ => cx.cmds.push(Cmd::Toast(format!("Copied /{}/{}", self.path.join("/"), name))),
                }
            }
            if close { self.ctx = None; self.ctx_t.snap(0.0); }
        }
    }
}
