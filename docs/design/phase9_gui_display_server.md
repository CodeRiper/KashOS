# Phase 9: GUI & Display Server — Architectural Specification

**Author**: Akash <akash.official.j@gmail.com>  
**Status**: In Progress (Implementation & Live QEMU Verification)  
**Date**: October 2026  

---

## 1. Executive Summary & Problem Statement

Workstation operating systems typically suffer from fundamental graphical security vulnerabilities:
1. **Screen Scraping**: Malicious background processes can read the entire framebuffer or query another application's window contents.
2. **Keylogging / Eavesdropping**: Unfocused background processes can intercept global keyboard input hooks.
3. **Phishing & UI Redressing (Clickjacking)**: A malicious application can spoof system dialogs, mimic trusted login prompts, or render seamless fullscreen windows that trick the user into entering credentials.

**Phase 9 introduces the High-Assurance Display Server and Secure Input Routing Subsystem for KashOS**:
- **Nitpicker-Style Retained Security Borders**: Every window surface is enclosed in an unforgeable, compositor-enforced security border color-coded to its assigned hardware/kernel domain badge. Client applications cannot occlude, resize, or alter this border.
- **Anti-Fullscreen Spoofing**: The top system menubar and domain indicators are permanently reserved for the trusted display engine; untrusted client surfaces are bounded below the menubar.
- **Strict Secure Input Routing**: Raw keyboard scancodes and translated characters are dispatched **strictly and exclusively** to the window surface holding active focus. Unfocused, background, and obscured windows receive zero keyboard events.
- **Cross-Window SHM Buffer Isolation**: Each client window is backed by an isolated shared-memory surface frame (`shm_buffer_addr`). Direct cross-compartment memory access between surfaces is blocked.
- **Mediated Clipboard Daemon**: Clipboard data is sanitized (stripping dangerous control codes and executable macros) and paste events are mediated strictly to the focused window.

---

## 2. Security Model & Trust Domains

Window borders are rendered according to the domain mapping defined in `docs/THREAT_MODEL.md`:

| Domain ID | Name | Trust Domain | Border Color | Hex Code | Capability Badge |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **0** | `kash-dom0` | Core System | Obsidian Admin | `#00E5FF` | `0x01` |
| **1** | `sys-net` | Untrusted NIC | Red Untrusted Net | `#FF1744` | `0x05` |
| **2** | `personal` | Sovereign Personal | Emerald Green | `#00E676` | `0x02` |
| **3** | `work-app` | Enterprise Work | Blue Work | `#2979FF` | `0x03` |
| **4** | `sys-usb` | Isolated xHCI | Amber USB | `#FA903E` | `0x05` |
| **5** | `disp-vm` | Ephemeral Sandbox | Tangerine / Magenta | `#FF9100` | `0x04` |

---

## 3. Acceptance Gates (T36 – T39)

1. **T36: Unforgeable Nitpicker Domain Border & Anti-Spoofing Gate**:
   - Verify unforgeable color-coded domain border is rendered around each surface based on its capability badge.
   - Verify client surface cannot draw outside its allocated geometry or obscure the system bar.
2. **T37: Secure Input Routing Gate**:
   - Verify that simulated keystrokes are routed strictly and exclusively to the surface with active focus.
   - Verify background/unfocused surfaces observe zero keystrokes.
3. **T38: Cross-Window Buffer Isolation Gate**:
   - Verify distinct client surfaces receive segregated, non-overlapping memory buffers.
   - Sibling processes cannot read another surface's pixel memory.
4. **T39: Mediated Clipboard Daemon Gate**:
   - Verify clipboard daemon strips hostile control codes.
   - Verify paste data is delivered only to the focused surface.
