use kash_ui::desktop::Desktop;
use kash_ui::geom::Rect;

#[test]
fn display_defaults_to_fit_mode_and_starts_with_an_empty_desktop() {
    let desktop = Desktop::new(640, 480, false);

    assert_eq!(desktop.sys.display_scale, 0);
    assert!(desktop.sys.pointer_speed > 1.0);
    assert_eq!(desktop.sys.screen, Rect::new(0.0, 0.0, 640.0, 480.0));
    assert_eq!(desktop.window_count(), 0);
}

#[test]
fn resizing_renderer_keeps_physical_output_dimensions() {
    let mut desktop = Desktop::new(640, 480, false);
    desktop.sys.display_output = Rect::new(0.0, 0.0, 1024.0, 768.0);

    desktop.resize(800, 600);

    assert_eq!(desktop.sys.screen, Rect::new(0.0, 0.0, 800.0, 600.0));
    assert_eq!(desktop.sys.display_output, Rect::new(0.0, 0.0, 1024.0, 768.0));
}
