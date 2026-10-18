# Design Note: T-SCROLL_AND_100MB_HARDWARE — Mouse Wheel / Trackpad Scrolling & 100 MB RAM Compatibility

## Status
- **Author**: Akash <akash.official.j@gmail.com>
- **Date**: 2026-10-18
- **Area**: Input Subsystem, Compositor GUI, Low-Memory Execution, Browser Architecture

## Motivation
1. The mouse driver in `kernel/src/arch/x86_64/input.rs` previously parsed standard 3-byte PS/2 packets, leaving mouse wheel and trackpad vertical scrolling unhandled.
2. In `kernel/src/gui.rs`, the wheel coordinate passed to `desktop.frame` was hardcoded to `Pt::new(0.0, 0.0)`.
3. In `kash-ui`, `SysState` lacked configurable scrolling options (scroll speed multiplier, natural scrolling direction, trackpad tap-to-click).
4. The built-in Browser app in `misc.rs` lacked a `Scroll` instance, preventing users from scrolling down web pages, search results, and articles.
5. Users requested running KashOS on vintage 100 MB RAM hardware and deploying a browser, requiring deep architectural analysis of low-memory constraints and browser requirements.

## Architecture & Implementation

### 1. PS/2 IntelliMouse 4-Byte Packet Protocol
Standard PS/2 mice send 3-byte packets (Flags, dX, dY). The Microsoft IntelliMouse protocol extends this by negotiating sample rates:
- Sequence: `0xF3, 200` -> `0xF3, 100` -> `0xF3, 80` -> `0xF2` (Get Device ID).
- If the mouse returns ID `0x03` (standard wheel) or `0x04` (5-button wheel), it switches to 4-byte packet mode:
  - Byte 1: Flags & buttons (Bit 0: Left, Bit 1: Right, Bit 2: Middle).
  - Byte 2: X movement delta (9-bit sign extended from Byte 1 bit 4).
  - Byte 3: Y movement delta (9-bit sign extended from Byte 1 bit 5).
  - Byte 4: Signed Z movement delta (scroll wheel `dz: i8`).
- In `input.rs`, `Ps2Controller` was extended with `has_wheel: bool`, `mouse_id: u8`, `mouse_packet_len: u8`, and a 4-byte buffer.
- When `dz != 0`, `InputEvent::MouseWheel { dx: 0, dy: dz as i32 }` is queued.

### 2. GUI Wheel Routing & Dynamic Configuration
- In `kernel/src/gui.rs`:
  - `InputEvent::MouseWheel` events are drained and scaled by `desktop.sys.scroll_speed`.
  - Direction is modulated by `desktop.sys.natural_scroll`: traditional scrolling inverts vertical delta so rolling wheel down increments content `y`, while natural scrolling tracks finger direction.
- In `kash-ui`:
  - `SysState` has `scroll_speed: f32`, `natural_scroll: bool`, and `trackpad_tap: bool`.
  - `Settings` app `pane_mouse` exposes interactive sliders and toggles for scrolling speed and natural scrolling.
  - `Browser` app incorporates `scroll: Scroll` and `Scroll::update` for smooth vertical scrolling across web content, search recommendations, and articles.

### 3. 100 MB RAM Hardware Footprint
On low-memory hardware (100 MB RAM):
- Kernel binary (.text + .data + .bss): ~2.8 MiB.
- Real W^X page tables: ~2.0 MiB.
- kcore capability arena: 16.0 MiB.
- Kernel dynamic heap: 16.0 MiB (in low-memory mode).
- Linear framebuffer compositor: Automatically drops to 640x480 resolution when available heap < 32 MiB, reducing software canvas memory from 16 MiB to ~1.2 MiB per layer.
- Total operating set: ~38 MiB, leaving >60 MiB RAM available for userland processes.

## Verification
- Host unit tests in `khal` (`cargo test -p khal`): 4 tests passed verifying IntelliMouse packet decoding and scroll direction.
- UI unit tests in `kash-ui` (`cargo test --test scroll_test -p kash-ui`): 3 tests passed verifying inertia limits, defaults, and frame event handling.
- Kernel target compilation (`cargo check -p kernel --target x86_64-unknown-none`): Succeeded with zero errors.
- Claims linter (`python tools/claims_lint.py`): 0 violations.
