# Kash UI

Desktop UI for **KashOS**: a `no_std` + `alloc` software-rendered Liquid-Glass shell written entirely in Rust.
Boot/BIOS animation, lock screen (with duress passphrase), menu bar, Dock (recents, Downloads stack, Launchpad),
Files, Settings (22 panes, per-app permission manager), Terminal, Browser, Notes, Photos, Music, Messages,
Activity Monitor, Calculator, Spotlight, Control Center, notifications.

No OS dependencies: it draws into a `Vec<u32>` framebuffer (`0x00RRGGBB`) and consumes plain input structs.
Fonts (Inter, DejaVu Sans Mono) are embedded; all icons and wallpapers are procedural.

## Add it to your kernel

```toml
# kernel/Cargo.toml
[dependencies]
kash-ui = { path = "../kash-ui" }      # or copy the crate folder next to your kernel
```

Requirements on your side:

| Need | Detail |
|---|---|
| Global allocator | `#[global_allocator]` with a real heap. Budget **≥ 64 MiB** at 1440×900 (framebuffer ×4 buffers, window layers, glass scratch, icon cache). A 2 MiB bump arena is not enough. |
| FPU/SSE | Enable SSE2 (x86-64) / FP+NEON (AArch64) for the kernel target. Soft-float works but is far too slow. |
| Framebuffer | Linear 32-bit framebuffer from UEFI GOP / Multiboot2 / VBE. |
| Input | Mouse position + buttons + wheel, and key events (PS/2, USB-HID). |
| Timer | A monotonic `dt` per frame (seconds) and optionally wall-clock seconds. |

## Minimal glue

```rust
use kash_ui::desktop::{Desktop, Input};
use kash_ui::geom::Pt;
use kash_ui::ui::{Key, KeyEv};
use kash_ui::shell::lock::UiEvent;

let (w, h) = (fb.width as i32, fb.height as i32);
let mut ui = Desktop::new(w, h, /* play boot + lock screen */ true);
ui.sys.unix_secs = rtc_unix_seconds();          // wall clock; the UI ticks it itself afterwards
ui.sys.passphrase = load_passphrase_from_kvault();   // demo default is "kash"

loop {
    let dt = timer.elapsed_seconds();            // clamp is done inside
    let input = Input {
        mouse: Pt::new(mouse.x as f32, mouse.y as f32),
        left: mouse.left, right: mouse.right,
        wheel: Pt::new(0.0, mouse.wheel as f32),
        keys: keyboard.drain().map(|k| KeyEv { key: Key::Char, ch: k.ch, ctrl: k.ctrl, shift: k.shift, alt: k.alt }).collect(),
        dt,
    };
    ui.frame(&input);

    // present: copy ui.screen.px (w*h u32, 0x00RRGGBB) into the framebuffer
    fb.blit(&ui.screen.px);

    // react to the shell
    for ev in ui.take_events() {
        match ev {
            UiEvent::Unlocked => {}
            UiEvent::DuressUnlock => kernel::mount_decoy_vault_and_alert(),   // looks identical to the user
            UiEvent::FailedAttempts(n) => kernel::note_failed_unlock(n),
            UiEvent::ShutdownRequested => kernel::power_off(),
            UiEvent::RestartRequested => kernel::reboot(),
            UiEvent::SleepRequested => kernel::sleep(),
            UiEvent::Locked => {}
        }
    }
    if ui.exit_requested { break; }
}
```

Frame cost is ~0.3 ms when nothing changes (retained scene + cursor only) and 4–11 ms while animating on a
2-vCPU x86 host, so you can sleep/`hlt` until the next input or vsync.

## Hooks into the kernel

* **Passphrase / duress** — `ui.sys.passphrase`, `ui.sys.duress_pass`, `ui.sys.duress_active`. Settings → Lock Screen edits them;
  persist them in kvault from your side (read after each `UiEvent`). Never store them in clear text.
* **Permission manager** — `ui.sys.reg` (`registry::Registry`): per-app Allow / Ask / Deny for GUI apps (`/Applications`),
  CLI tools (`/CLI Applications`) and drivers (`/Drivers`). Call `ui.sys.reg.check("curl", Perm::Network)` from your
  capability layer to enforce it; `PS::Allow / Ask / Deny` comes back. Replace the seed data in `Registry::new()` with your
  real installed packages.
* **Settings state** — `ui.sys` (`ui::SysState`): appearance, accent, Dock options, Wi-Fi/Bluetooth flags, Phantom services
  (anonymity gateway, packet filter, kill-switch, key manager). Read it to apply changes in the kernel; write it to mirror kernel state.
* **Apps** — implement `app::App` (draw, command, min/default size) and add a variant to `ui::AppKind` + `desktop::make_app`.
* **Files** — `apps/files.rs::build_fs()` builds the demo tree; replace it with calls into your VFS.

## Layout

```
src/gfx.rs glass.rs comp.rs   software renderer, Liquid Glass (blur, refraction, specular), compositor
src/anim.rs                   spring animation
src/ui.rs                     immediate-mode widgets, SysState
src/desktop.rs                window manager + frame loop (retained / cached rendering)
src/shell/                    dock, menu bar, lock + BIOS + boot logo, Spotlight, Control Center, overlays
src/apps/                     Files, Settings (+ privacy, lock, panes), Terminal, Browser, tools, ...
src/registry.rs               app registry + permission model
```

## Status / known limits

* Verified on the host (Linux x86-64) with the `preview` crate: PNG/MP4 renders and a cached-vs-reference equivalence check.
  It has **not** been built for a bare-metal target in this session (the target was not installed there), so expect to fix
  small things when you first link it into your kernel (allocator, `libm` features, SSE flags).
* The Browser/Messages/Music/Photos apps are UI prototypes with sample content; only Files, Settings, Terminal, Calculator and
  Activity Monitor are functional in structure.
* Fonts are Inter (SIL OFL 1.1) and DejaVu Sans Mono (Bitstream Vera licence); keep their licence notices when you ship.

## Try it on a PC first

```
cargo build --release -p preview
target/release/preview boot out/boot.mp4      # BIOS → logo → lock → duress demo
target/release/preview video out/demo.mp4     # full desktop tour
```
