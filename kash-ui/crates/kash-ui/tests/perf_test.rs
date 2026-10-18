use std::time::Instant;
use kash_ui::desktop::Desktop;

#[test]
fn test_desktop_new_timing() {
    let t0 = Instant::now();
    println!("Starting Desktop::new...");
    let _d = Desktop::new(1024, 768, true);
    let dur = t0.elapsed();
    println!("Desktop::new completed in {:.3} s", dur.as_secs_f32());
    assert!(dur.as_secs_f32() < 10.0);
}
