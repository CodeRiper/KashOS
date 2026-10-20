# KashOS GUI Architecture Specification & Userland App Runtime

## 1. Overview & Security Model

KashOS currently runs the **Kash UI** software-rendered desktop compositor and shell in Ring 0. A Ring 3 compositor and capability-mediated framebuffer path are target architecture only; no transition from the normal boot session is implemented. The diagram below describes that target, not the current runtime.

The Ring 3 applications shown below are a design target. Current GUI applications execute within the Ring 0 desktop and do not have the isolation described by this target diagram.

```
┌─────────────────────────────────────────────────────────────────┐
│                    Third-Party Ring 3 Apps                      │
│   (App 1: Files)      (App 2: Browser)      (App 3: Terminal)  │
└────────┬──────────────────────┬──────────────────────┬──────────┘
         │                      │                      │
         │ Shared Buffer Cap    │ Shared Buffer Cap    │ Shared Buffer Cap
         ▼                      ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              Ring 3 Kash UI Compositor Service                  │
│       - Software Rendering Engine (Liquid-Glass Pipeline)       │
│       - Retained Composite Scene Cache & Damage Tracking        │
│       - Input Event Router & Focus Management                   │
└───────────────────────────────┬─────────────────────────────────┘
                                │ Framebuffer Transfer
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KashOS Microkernel (Ring 0)                  │
│       - Linear Framebuffer Driver (BAR0 @ 0xfd000000)           │
│       - Intrusive Quantized Slab & Free-List Allocator (kheap)  │
│       - Lock-Free kipc Capability Channels                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Address Space Isolation & Syscall ABI

### 2.1 Memory Protection ($W \oplus X$)
- All userland application code sections are mapped `RX` (Read + Execute).
- Stack, heap, and IPC buffers are mapped `RW` (Read + Write) with the No-Execute (`NX`) page bit enforced.
- Memory allocation uses `kheap`'s quantized intrusive allocator with mandatory zero-on-free sanitization to eliminate use-after-free information leaks.

### 2.2 GUI Buffer Architecture: Shared Memory Capability
To achieve high framerates (60–200+ FPS) without copying multi-megabyte canvas buffers across address spaces on every frame:
1. **Window Surface Allocation**:
   - The application invokes the `SYS_SURFACE_CREATE` syscall with requested dimensions `(w, h)`.
   - The kernel allocates a physical memory frame backing `w * h * 4` bytes.
   - The kernel maps the pages into the application's page table as `RW` and mints a read-only capability (`CapKind::SharedMemory`) transferred to the Compositor.
2. **Double-Buffering & Damage Notification**:
   - Each surface utilizes double-buffering (Front/Back buffers).
   - Once the application finishes rendering a frame, it issues `SYS_SURFACE_COMMIT(surface_id, damage_rect)`.
   - The compositor reads the damage rectangle from the shared memory page and blits it into the composite scene.

### 2.3 Syscall Interface

| Syscall Name | Number | Registers | Description |
|:---|:---:|:---|:---|
| `SYS_SURFACE_CREATE` | `0x50` | `rdi: width`, `rsi: height`, `rdx: flags` | Allocates a shared surface buffer and returns surface handle `rax`. |
| `SYS_SURFACE_COMMIT` | `0x51` | `rdi: surface_id`, `rsi: *const Rect` | Submits the damage region to the compositor for presentation. |
| `SYS_SURFACE_DESTROY` | `0x52` | `rdi: surface_id` | Frees shared surface memory and unregisters window. |
| `SYS_EVENT_POLL` | `0x53` | `rdi: surface_id`, `rsi: *mut UiEvent` | Retrieves pending mouse, keyboard, or window state events. |

---

## 3. Input Event Delivery

1. **Hardware Ingestion**:
   - The 8042 PS/2 controller and USB xHCI controllers buffer packets in kernel rings.
   - Mouse delta coordinates `(dx, dy)` and button transitions (`left`, `right`) are translated into `InputEvent`.
2. **Compositor Hit-Testing**:
   - The compositor performs 2D hit-testing against window geometry and z-ordering.
   - Global hotkeys (e.g., `Cmd+Space` for Spotlight, `Cmd+Tab` for App Switcher) are consumed by the desktop shell.
3. **Application Delivery**:
   - Targeted events (key presses, clicks, mouse moves relative to window origin) are queued into the application's asynchronous `kipc` event ring.
   - Applications process events in their UI loop via `kash_sdk::poll_event()`.

---

## 4. Building Third-Party Applications with `kash-sdk`

Third-party applications outside the kernel workspace compile against the lightweight, `no_std` userland crate `kash-sdk`.

### 4.1 Sample Application: `main.rs`
```rust
#![no_std]
#![no_main]

extern crate alloc;
use kash_sdk::app::{App, WindowBuilder, Event, Color, Rect};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut window = WindowBuilder::new()
        .title("Secure Vault Notes")
        .dimensions(640, 480)
        .build()
        .expect("Failed to create window surface");

    loop {
        while let Some(event) = window.poll_event() {
            match event {
                Event::Quit => kash_sdk::exit(0),
                Event::KeyDown(key) => {
                    // Handle keyboard input
                }
                Event::MouseDown { x, y, button } => {
                    // Handle mouse click
                }
                _ => {}
            }
        }

        // Render application UI
        let mut canvas = window.back_buffer();
        canvas.fill(Color::hex(0x1E1E2E));
        canvas.draw_rect(Rect::new(20.0, 20.0, 600.0, 60.0), Color::hex(0x313244));
        canvas.draw_text("Confidential Vault Note", 30.0, 50.0, Color::WHITE);

        // Commit damage rectangle to Compositor
        window.commit_damage(Rect::new(0.0, 0.0, 640.0, 480.0));
    }
}
```

### 4.2 Cargo Configuration (`Cargo.toml`)
```toml
[package]
name = "kash-vault-notes"
version = "0.1.0"
edition = "2021"

[dependencies]
kash-sdk = { git = "https://github.com/kashos/kash-sdk", version = "0.1.0" }

[profile.release]
opt-level = 3
lto = true
panic = "abort"
```

---

## 5. Verification Status

- **Phase 0 (Audit)**: Complete.
- **Phase 1 (Graphics Foundation)**: Framebuffer discovery, SSE FPU acceleration, TSC/RTC clock sources verified.
- **Phase 2 (Desktop Engine)**: `Desktop::new()` with quantized slab/free-list intrusive allocator verified. 200+ FPS render loop active.
- **Phase 3 (Input & Visuals)**: BIOS POST, Apple-style boot progress logo, and full Liquid-Glass desktop with Dock, Menu Bar, and Golden Gate wallpaper verified via QEMU screendump.
- **Phase 4 (Services)**: Real hardware ACPI/APM shutdown and CPU reset wired to Menu Bar and desktop shell commands.
- **Phase 5 (Architecture Spec)**: Complete.
