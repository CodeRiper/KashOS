//! Design tokens: light/dark (smoothly blended), accent colours, Liquid-Glass presets.
use crate::color::*;
use crate::glass::GlassStyle;
use crate::mathf::*;

pub const ACCENTS: [(&str, Color, Color); 9] = [
    ("Blue", Color::rgb(0, 122, 255), Color::rgb(10, 132, 255)),
    ("Purple", Color::rgb(175, 82, 222), Color::rgb(191, 90, 242)),
    ("Pink", Color::rgb(255, 45, 85), Color::rgb(255, 55, 95)),
    ("Red", Color::rgb(255, 59, 48), Color::rgb(255, 69, 58)),
    ("Orange", Color::rgb(255, 149, 0), Color::rgb(255, 159, 10)),
    ("Yellow", Color::rgb(255, 204, 0), Color::rgb(255, 214, 10)),
    ("Green", Color::rgb(40, 205, 65), Color::rgb(48, 209, 88)),
    ("Teal", Color::rgb(48, 176, 199), Color::rgb(64, 200, 224)),
    ("Graphite", Color::rgb(142, 142, 147), Color::rgb(152, 152, 157)),
];

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum GlassKind { Dock, MenuBar, Sidebar, Toolbar, Popover, Control, Tooltip, /// Fully see-through glass: no white rim, barely any tint (dock, Spotlight).
    Clear }

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    /// 0 = light, 1 = dark (animated for a smooth cross-fade).
    pub dark_t: f32,
    pub accent_light: Color,
    pub accent_dark: Color,
    /// Liquid Glass: 0 = fully tinted … 1 = fully clear (Golden Gate slider).
    pub clarity: f32,
    pub reduce_transparency: bool,
}

impl Theme {
    pub fn new() -> Theme {
        Theme { dark_t: 0.0, accent_light: ACCENTS[0].1, accent_dark: ACCENTS[0].2, clarity: 0.55, reduce_transparency: false }
    }
    #[inline] pub fn is_dark(&self) -> bool { self.dark_t > 0.5 }
    #[inline] pub fn pick(&self, l: Color, d: Color) -> Color { l.mix(d, self.dark_t) }
    pub fn accent(&self) -> Color { self.accent_light.mix(self.accent_dark, self.dark_t) }

    pub fn label(&self) -> Color { self.pick(Color::rgba(0, 0, 0, 224), Color::rgba(255, 255, 255, 235)) }
    pub fn label2(&self) -> Color { self.pick(Color::rgba(60, 60, 67, 153), Color::rgba(235, 235, 245, 150)) }
    pub fn label3(&self) -> Color { self.pick(Color::rgba(60, 60, 67, 90), Color::rgba(235, 235, 245, 85)) }
    pub fn label4(&self) -> Color { self.pick(Color::rgba(60, 60, 67, 48), Color::rgba(235, 235, 245, 40)) }
    pub fn separator(&self) -> Color { self.pick(Color::rgba(0, 0, 0, 26), Color::rgba(255, 255, 255, 28)) }
    pub fn content_bg(&self) -> Color { self.pick(Color::rgb(255, 255, 255), Color::rgb(30, 30, 33)) }
    pub fn window_bg(&self) -> Color { self.pick(Color::rgb(243, 243, 247), Color::rgb(36, 36, 40)) }
    pub fn group_bg(&self) -> Color { self.pick(Color::rgb(255, 255, 255), Color::rgb(48, 48, 53)) }
    pub fn control_fill(&self) -> Color { self.pick(Color::rgba(0, 0, 0, 14), Color::rgba(255, 255, 255, 30)) }
    pub fn control_fill_hi(&self) -> Color { self.pick(Color::rgba(0, 0, 0, 28), Color::rgba(255, 255, 255, 52)) }
    pub fn hover_fill(&self) -> Color { self.pick(Color::rgba(0, 0, 0, 12), Color::rgba(255, 255, 255, 20)) }
    pub fn on_accent(&self) -> Color { Color::WHITE }
    pub fn field_bg(&self) -> Color { self.pick(Color::rgba(0, 0, 0, 10), Color::rgba(255, 255, 255, 22)) }
    pub fn shadow(&self, a: f32) -> Color { Color::rgba(0, 0, 0, (a * (1.0 + 0.6 * self.dark_t) * 255.0).min(255.0) as u8) }

    /// Liquid Glass preset, driven by the clarity slider.
    pub fn glass(&self, kind: GlassKind, radius: f32) -> GlassStyle {
        let c = if self.reduce_transparency { 0.0 } else { self.clarity };
        let dk = self.dark_t;
        let mut g = GlassStyle::new(radius);
        g.dark = self.is_dark();
        let tint = Color::rgb(250, 250, 253).mix(Color::rgb(24, 25, 30), dk);
        let (ta_clear, ta_tint, blur_clear, blur_tint) = match kind {
            GlassKind::Dock => (0.10, 0.52, 9.0, 18.0),
            GlassKind::MenuBar => (0.06, 0.45, 12.0, 20.0),
            GlassKind::Sidebar => (0.30, 0.78, 14.0, 24.0),
            GlassKind::Toolbar => (0.14, 0.62, 10.0, 18.0),
            GlassKind::Popover => (0.34, 0.80, 16.0, 26.0),
            GlassKind::Control => (0.14, 0.50, 6.0, 12.0),
            GlassKind::Tooltip => (0.30, 0.72, 10.0, 16.0),
            GlassKind::Clear => (0.12, 0.34, 11.0, 18.0),
        };
        let ta = lerp(ta_tint, ta_clear, c);
        let ta = if self.is_dark() { ta * 0.9 } else { ta };
        g.tint = Color { a: (saturate(ta) * 255.0) as u8, ..tint };
        g.blur = lerp(blur_tint, blur_clear, c);
        g.saturation = lerp(1.15, 1.75, c);
        g.refraction = lerp(0.35, 1.0, c);
        g.spec = lerp(0.55, 1.0, c);
        g.bezel = match kind {
            GlassKind::Dock => 14.0, GlassKind::MenuBar => 8.0, GlassKind::Sidebar => 10.0,
            GlassKind::Toolbar => 9.0, GlassKind::Popover => 12.0, GlassKind::Control => 8.0, GlassKind::Tooltip => 8.0, GlassKind::Clear => 10.0,
        };
        if kind == GlassKind::Clear { g.spec = 0.0; g.saturation = lerp(1.1, 1.35, c); }
        if self.reduce_transparency { g.refraction = 0.0; g.bezel = 0.0; g.blur = 24.0; g.tint.a = 235; }
        g
    }
}

// ── Unforgeable Security Theme & Color Tokens (PDF Specification) ────────────

use crate::registry::SecurityColorTag;

#[derive(Clone, Copy, Debug)]
pub struct RgbaColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl RgbaColor {
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    pub const fn to_argb32(&self) -> u32 {
        ((self.a as u32) << 24)
            | ((self.r as u32) << 16)
            | ((self.g as u32) << 8)
            | (self.b as u32)
    }
}

pub struct SecurityTheme {
    pub primary_border: RgbaColor,
    pub header_badge_bg: RgbaColor,
    pub subtle_window_tint: RgbaColor,
    pub label_text: &'static str,
}

pub const fn theme_for_tag(tag: SecurityColorTag) -> SecurityTheme {
    match tag {
        SecurityColorTag::ObsidianAdmin => SecurityTheme {
            primary_border: RgbaColor::new(225, 230, 240, 255),
            header_badge_bg: RgbaColor::new(28, 32, 38, 255),
            subtle_window_tint: RgbaColor::new(18, 20, 24, 245),
            label_text: "DOM0-VERIFIED-ADMIN",
        },
        SecurityColorTag::PurpleVault => SecurityTheme {
            primary_border: RgbaColor::new(197, 138, 249, 255), // #C58AF9
            header_badge_bg: RgbaColor::new(74, 35, 115, 255),
            subtle_window_tint: RgbaColor::new(28, 18, 38, 242),
            label_text: "AIRGAP-VAULT",
        },
        SecurityColorTag::MintPersonal => SecurityTheme {
            primary_border: RgbaColor::new(129, 201, 149, 255), // #81C995
            header_badge_bg: RgbaColor::new(24, 82, 45, 255),
            subtle_window_tint: RgbaColor::new(16, 28, 20, 242),
            label_text: "TRUSTED-PERSONAL",
        },
        SecurityColorTag::BlueWork => SecurityTheme {
            primary_border: RgbaColor::new(26, 115, 232, 255), // #1A73E8
            header_badge_bg: RgbaColor::new(18, 58, 120, 255),
            subtle_window_tint: RgbaColor::new(15, 23, 36, 242),
            label_text: "ISOLATED-WORK",
        },
        SecurityColorTag::AmberUsb => SecurityTheme {
            primary_border: RgbaColor::new(250, 144, 62, 255), // #FA903E
            header_badge_bg: RgbaColor::new(122, 56, 12, 255),
            subtle_window_tint: RgbaColor::new(34, 22, 14, 242),
            label_text: "HW-JAIL-USB",
        },
        SecurityColorTag::RedUntrustedNet => SecurityTheme {
            primary_border: RgbaColor::new(217, 48, 37, 255), // #D93025
            header_badge_bg: RgbaColor::new(115, 20, 16, 255),
            subtle_window_tint: RgbaColor::new(36, 14, 14, 242),
            label_text: "UNTRUSTED-NET",
        },
        SecurityColorTag::MagentaDisposable => SecurityTheme {
            primary_border: RgbaColor::new(245, 56, 160, 255), // #F538A0
            header_badge_bg: RgbaColor::new(112, 18, 70, 255),
            subtle_window_tint: RgbaColor::new(34, 14, 26, 242),
            label_text: "EPHEMERAL-DISP",
        },
    }
}

