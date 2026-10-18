use kash_ui::desktop::{Desktop, Input};
use kash_ui::geom::Pt;
use kash_ui::ui::{Scroll, Io};

#[test]
fn scroll_inertia_and_limits() {
    let mut scroll = Scroll::default();
    let mut io = Io::default();
    io.dt = 0.016;

    // Simulate mouse wheel tick down
    io.wheel = Pt::new(0.0, 5.0);
    scroll.update(&io, true, 500.0);

    assert!(scroll.y > 0.0);
    assert!(scroll.moving());

    // Stop wheel, update with dt to let inertia settle
    io.wheel = Pt::new(0.0, 0.0);
    for _ in 0..100 {
        scroll.update(&io, true, 500.0);
    }
    assert!(scroll.y > 0.0);
    assert!(scroll.y <= 500.0);
}

#[test]
fn desktop_sys_state_scroll_defaults() {
    let desktop = Desktop::new(640, 480, false);
    assert_eq!(desktop.sys.scroll_speed, 1.0);
    assert!(!desktop.sys.natural_scroll);
    assert!(desktop.sys.trackpad_tap);
}

#[test]
fn desktop_frame_consumes_wheel_input() {
    let mut desktop = Desktop::new(640, 480, false);
    let input = Input {
        mouse: Pt::new(320.0, 240.0),
        left: false,
        right: false,
        wheel: Pt::new(0.0, 3.0),
        keys: Vec::new(),
        dt: 0.016,
    };

    desktop.frame(&input);
    // Desktop frame executed cleanly with wheel delta
    assert_eq!(desktop.sys.screen.w, 640.0);
}
