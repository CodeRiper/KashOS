//! About KashOS.
use alloc::string::String;
use alloc::format;
use crate::app::*;
use crate::geom::*;
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
        let compact = area.h < 380.0;
        let icon_size = if compact { 76.0 } else { 120.0 };
        let icon_y = if compact { 18.0 } else { 46.0 };
        let title_y = if compact { icon_y + icon_size + 8.0 } else { 190.0 };
        let version_y = if compact { title_y + 31.0 } else { 222.0 };
        let rows_y = if compact { version_y + 29.0 } else { 268.0 };
        let row_step = if compact { 21.0 } else { 26.0 };
        let big = Rect::new(area.cx() - icon_size * 0.5, icon_y, icon_size, icon_size);
        let bob = sin(self.t * 1.6) * 3.0;
        cx.cv.shadow_rrect(big.offset(0.0, 10.0 + bob * 0.5), icon_size * 0.23, 16.0, th.shadow(0.22), false);
        cx.app_icon(AppKind::About, big.offset(0.0, bob));
        cx.text_in(Rect::new(0.0, title_y, area.w, 34.0), "KashOS", if compact { 24.0 } else { 28.0 }, Weight::Bold, th.label(), Align::Center);
        cx.text_in(Rect::new(0.0, version_y, area.w, 20.0), &format!("Development build · {}", env!("CARGO_PKG_VERSION")), 13.0, Weight::Regular, th.label2(), Align::Center);
        #[cfg(target_arch = "x86_64")]
        let arch = "x86-64";
        #[cfg(target_arch = "aarch64")]
        let arch = "AArch64";
        let rows = [("Build", "Experimental prototype"), ("Target", arch), ("Memory", "Runtime total unavailable"), ("Security", "Not independently audited")];
        for (i, (k, v)) in rows.iter().enumerate() {
            let y = rows_y + i as f32 * row_step;
            let row_font = if compact { 10.5 } else { 12.5 };
            cx.text_in(Rect::new(area.cx() - 190.0, y, 150.0, 22.0), k, row_font, Weight::Medium, th.label2(), Align::Right);
            cx.text_in(Rect::new(area.cx() - 28.0, y, 240.0, 22.0), v, row_font, Weight::Regular, th.label(), Align::Left);
        }
        let button_y = if compact { area.h - 42.0 } else { area.h - 62.0 };
        if cx.button("about_more", Rect::new(area.cx() - 70.0, button_y, 140.0, 32.0), "More Info…", false) { cx.cmds.push(Cmd::OpenSettingsPane(4)); }
    }
}
