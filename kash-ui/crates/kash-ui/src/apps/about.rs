//! About KashOS.
use alloc::string::String;
use crate::app::*;
use crate::geom::*;
use crate::icons::*;
use crate::mathf::*;
use crate::text::*;
use crate::ui::*;

pub struct About { t: f32 }
impl About { pub fn new() -> About { About { t: 0.0 } } }

impl App for About {
    fn kind(&self) -> AppKind { AppKind::About }
    fn title(&self) -> String { String::from("About KashOS") }
    fn default_size(&self) -> (f32, f32) { (520.0, 440.0) }
    fn min_size(&self) -> (f32, f32) { (520.0, 440.0) }
    fn draw(&mut self, cx: &mut Ctx, area: Rect) {
        self.t += cx.io.dt;
        let th = *cx.th;
        cx.cv.fill_rect(area, th.window_bg());
        let big = Rect::new(area.cx() - 60.0, 46.0, 120.0, 120.0);
        let bob = sin(self.t * 1.6) * 3.0;
        cx.cv.shadow_rrect(big.offset(0.0, 10.0 + bob * 0.5), 28.0, 16.0, th.shadow(0.22), false);
        cx.app_icon(AppKind::About, big.offset(0.0, bob));
        cx.text_in(Rect::new(0.0, 190.0, area.w, 34.0), "KashOS", 28.0, Weight::Bold, th.label(), Align::Center);
        cx.text_in(Rect::new(0.0, 222.0, area.w, 20.0), "Version 27 · Golden Gate", 13.0, Weight::Regular, th.label2(), Align::Center);
        let rows = [("Kernel", "Phantom Kernel 0.2.0"), ("Architecture", "x86-64 · AArch64"), ("Memory", "512 MiB"), ("Security", "Capability-based · kvault · seL4 path")];
        for (i, (k, v)) in rows.iter().enumerate() {
            let y = 268.0 + i as f32 * 26.0;
            cx.text_in(Rect::new(area.cx() - 190.0, y, 150.0, 22.0), k, 12.5, Weight::Medium, th.label2(), Align::Right);
            cx.text_in(Rect::new(area.cx() - 28.0, y, 240.0, 22.0), v, 12.5, Weight::Regular, th.label(), Align::Left);
        }
        if cx.button("about_more", Rect::new(area.cx() - 70.0, area.h - 62.0, 140.0, 32.0), "More Info…", false) { cx.cmds.push(Cmd::OpenSettingsPane(4)); }
    }
}
