# KashOS low-resource desktop test

Test image: 	arget/KashOS-LowHW-responsive.iso (GRUB2 bootable, x86-64). The image is built from the current release kernel and launched with one virtual CPU and 100 MiB of guest RAM.

## Display and pointer controls

- Startup detects the boot framebuffer. In the tested QEMU and VirtualBox profiles it is 1024x768; the compositor selects 640x480 in low-memory mode and scales the desktop to fill the detected output. The live VirtualBox screenshot showed the complete menu bar, wallpaper, pointer and dock with no clipping.
- Settings > Displays provides Automatic fit, 640x480, 800x600 and Output-sized compositor modes. Output-sized rendering is capped for memory safety; increasing the canvas is refused when free heap is below 7 MiB. These settings change logical rendering size. The physical framebuffer mode is selected at boot and this build does not dynamically switch a monitor to another hardware mode.
- Settings > Mouse exposes a tracking speed slider from 0.5x to 2.0x (default 1.25x). PS/2 pointer deltas are relative; the compositor no longer multiplies them by the render-to-output scale. Button press and release edges are queued separately so a quick click is not collapsed inside one poll batch.
- The GUI frame pacer uses the existing APIC timer to halt the guest CPU between frames, bounded to two timer ticks. This trades some frame rate for lower idle CPU use on one-core guests.

## Validation on 2026-10-17

- QEMU 11.x: q35, core2duo, 1 vCPU, 100 MiB, -nic none, standard VGA, GTK zoom-to-fit=on. The updated image booted into the 640x480 compositor at the 1024x768 output. After warm-up, isolated log samples reached about 50 FPS; running two hypervisors together reduced throughput. The final sampled heap was about 5 MiB free.
- VirtualBox 7.2.12: 1 vCPU, 100 MiB, 32 MiB VRAM, 1024x768 output, networking/audio/USB disabled, no disk. The updated ISO booted in GUI mode; a live VM screenshot confirmed the complete desktop and dock. Serial samples held about 50 FPS with about 9 MiB heap free.
- Kernel serial logs report all seven capability-core self-tests, heap allocator checks and TRESOR key-storage checks passed, with no panic or allocation failure in the observed runs. These are prototype self-tests, not a complete security evaluation.
- cargo test -p kash-ui passed the two display-scale tests and the desktop performance test. The release x86-64 kernel build succeeded.

QEMU and VirtualBox are each configured with networking disabled. The guest has no complete network stack or internet service, so internet access is unavailable. On the emulated Core 2 Duo profile, hardware RDRAND/RDSEED are unavailable and no virtual RNG is attached; the kernel correctly refuses to seed cryptographic keys from the TSC. Do not rely on crypto operations in this profile.

## Open the test desktop

- QEMU: double-click Run-KashOS-QEMU-LowMemory.bat. It opens the tested image with GTK zoom-to-fit enabled.
- VirtualBox: the disposable VM KashOS-Test-1CPU-100M-20261017 is attached to this updated ISO and was left running in GUI mode. It has no virtual hard disk, so guest changes are volatile. Your separate KashOS VM was not changed.

## Scope

KashOS remains a bootable development prototype, not a complete or production-secure OS. Network services, persistent storage for this test VM, general process/user isolation, and several system settings/services are incomplete or explicitly unavailable in the UI. This validation covers desktop fit, input event delivery, boot and low-resource rendering only; it does not establish broad hardware compatibility, security, or production readiness.
