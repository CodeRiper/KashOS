//! The `App` trait every window content implements, plus menu description types.
use alloc::string::String;
use alloc::vec::Vec;
use crate::geom::*;
use crate::ui::*;

#[derive(Clone, Debug)]
pub enum Action { None, Cmd(Cmd), AppCmd(&'static str), ToggleDark }

#[derive(Clone, Debug)]
pub struct MenuItem { pub label: String, pub shortcut: &'static str, pub action: Action, pub enabled: bool }
impl MenuItem {
    pub fn new(label: &str, shortcut: &'static str, action: Action) -> MenuItem { MenuItem { label: String::from(label), shortcut, action, enabled: true } }
    pub fn off(label: &str, shortcut: &'static str) -> MenuItem { MenuItem { label: String::from(label), shortcut, action: Action::None, enabled: false } }
    pub fn sep() -> MenuItem { MenuItem { label: String::from("-"), shortcut: "", action: Action::None, enabled: false } }
    pub fn is_sep(&self) -> bool { self.label == "-" }
}

/// Horizontal space apps leave free at the top-right of their window for the – □ ✕ caption buttons.
pub const CAPTION_RESERVE: f32 = 128.0;

pub trait App {
    fn kind(&self) -> AppKind;
    fn title(&self) -> String { String::from(self.kind().name()) }
    fn default_size(&self) -> (f32, f32) { (820.0, 560.0) }
    fn min_size(&self) -> (f32, f32) { (460.0, 320.0) }
    /// Draw + handle input. `area` is (0,0,w,h) in layer-local coordinates.
    fn draw(&mut self, cx: &mut Ctx, area: Rect);
    /// Extra menus inserted after the app-name menu (title, items).
    fn extra_menus(&self) -> Vec<(String, Vec<MenuItem>)> { Vec::new() }
    fn command(&mut self, _name: &str) {}
    /// Does this app need continuous frames right now (animation/inertia)? Default: yes (safe).
    fn animating(&self) -> bool { true }
}
