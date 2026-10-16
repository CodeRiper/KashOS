use kash_ui::color::*; use kash_ui::geom::*; use kash_ui::gfx::*; use kash_ui::glass::*; use kash_ui::icons::*; use kash_ui::text::*; use kash_ui::ui::AppKind; use kash_ui::theme::*;
pub fn run() {
    let mut cv = Canvas::new(1280, 800);
    kash_ui::wallpaper::paint(&mut cv, 0);
    let mut sc = GlassScratch::default();
    let th = Theme::new();
    macro_rules! t { ($name:expr, $n:expr, $body:block) => {{ let t0 = std::time::Instant::now(); for _ in 0..$n { $body } println!("{:<42} {:>8.3} ms", $name, t0.elapsed().as_secs_f32() * 1000.0 / $n as f32); }}; }
    t!("app_icon 62px x1", 50, { app_icon(&mut cv, AppKind::Files, Rect::new(300.0, 700.0, 62.0, 62.0)); });
    t!("app_icon 62px x9 (dock)", 20, { for i in 0..9 { app_icon(&mut cv, AppKind::Photos, Rect::new(300.0 + i as f32 * 66.0, 700.0, 62.0, 62.0)); } });
    t!("fill_squircle 62px", 50, { cv.fill_squircle(Rect::new(300.0, 700.0, 62.0, 62.0), 5.0, Color::RED_TEST()); });
    t!("glass dock 700x80 (bezel14,blur18)", 30, { cv.glass(Rect::new(290.0, 710.0, 700.0, 80.0), &th.glass(GlassKind::Dock, 30.0), &mut sc); });
    t!("glass menubar 1280x30 (bezel0)", 30, { let mut s = th.glass(GlassKind::MenuBar, 0.0); s.bezel = 0.0; s.refraction = 0.0; s.spec = 0.0; cv.glass(Rect::new(0.0, 0.0, 1280.0, 30.0), &s, &mut sc); });
    t!("glass sidebar 212x600 (bezel0)", 30, { let mut s = th.glass(GlassKind::Sidebar, 0.0); s.bezel = 0.0; s.refraction = 0.0; s.spec = 0.0; cv.glass(Rect::new(100.0, 70.0, 212.0, 600.0), &s, &mut sc); });
    t!("glass small button 36x36", 100, { cv.glass(Rect::new(500.0, 100.0, 36.0, 36.0), &th.glass(GlassKind::Control, 18.0), &mut sc); });
    let mut f = Fonts::new();
    t!("text 40 chars @13px", 500, { f.draw(&mut cv, 100.0, 300.0, "The quick brown fox jumps over the lazy dog!!", 13.0, Weight::Regular, Color::WHITE); });
    t!("shadow dock-sized (skip inside)", 30, { cv.shadow_rrect(Rect::new(290.0, 710.0, 700.0, 80.0).offset(0.0, 8.0), 30.0, 22.0, Color::rgba(0,0,0,70), true); });
    t!("shadow window 900x600 (skip inside)", 30, { cv.shadow_rrect(Rect::new(100.0, 70.0, 900.0, 600.0), 24.0, 30.0, Color::rgba(0,0,0,70), true); });
    let mut layer = Canvas::new(900, 600);
    t!("blit_rounded 900x600", 50, { cv.blit_rounded(&layer, 100, 70, 24.0, 255); });
    t!("backdrop copy 900x600", 50, { for y in 0..600usize { layer.px[y*900..y*900+900].copy_from_slice(&cv.px[(70+y)*1280+100..(70+y)*1280+1000]); } });
    t!("fill_rrect 900x600 solid", 50, { layer.fill_rrect(Rect::new(0.0,0.0,900.0,600.0), 0.0, Color::rgb(240,240,244)); });
    t!("blit_rounded_dim 900x600", 30, { cv.blit_rounded_dim(&layer, 100, 70, 24.0, 255, 30); });
    t!("blit_scaled 720x440 (open anim)", 30, { cv.blit_scaled(&layer, Rect::new(113.0, 100.0, 774.0, 516.0), 22.0, 0.9); });
    t!("stroke_rrect 900x600", 30, { cv.stroke_rrect(Rect::new(100.0, 70.0, 900.0, 600.0), 24.0, 1.0, Color::rgba(0,0,0,60)); });
    t!("shadow 700x430 blur34 (open anim)", 30, { cv.shadow_rrect(Rect::new(300.0, 150.0, 700.0, 430.0), 24.0, 34.0, Color::rgba(0,0,0,70), true); });
    t!("full-screen copy 1280x800", 50, { let a = cv.px.clone(); std::hint::black_box(a); });
}
trait T { fn RED_TEST() -> Color; } impl T for Color { fn RED_TEST() -> Color { Color::rgb(200, 50, 50) } }
