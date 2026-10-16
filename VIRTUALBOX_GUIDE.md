# KashOS v0.2.0 — Oracle VirtualBox Boot & Interactive Console Guide

![KashOS Interactive Terminal on VGA Display](C:\Users\Akash.J\.gemini\antigravity-ide\brain\39d1b7ad-de2a-4049-8426-831f652e31f9\vbox_kashos_terminal.png)

---

## 1. Root Cause Analysis: Why VirtualBox Stalled on a Black Screen

In the previous boot attempt, Oracle VirtualBox displayed a black screen with a single blinking cursor `_`. Two root causes were identified and resolved:

| Component | Previous State (Caused Black Screen) | Fixed State in `kash-os.iso` |
|---|---|---|
| **Boot Sector / Catalog** | `pycdlib` used a raw 2048-byte stub (`\xeb\x3c\x90` + zeroes) without stage-1/2 bootloader code. VirtualBox BIOS executed the stub and stalled. | Generated a real **GRUB2 Hybrid El Torito ISO** (`grub-mkrescue` + `xorriso`) containing standard MBR boot code (`boot_hybrid.img`) and EFI system partitions. |
| **MMIO Page Table Mapping** | The W^X paging module (`kernel/src/arch/x86_64/mod.rs`) only mapped the Local APIC (`0xFEE00000`). Writing to VGA video memory (`0xB8000`) caused a Page Fault (`#PF`) loop once CR3 switched. | Identity-mapped VGA text buffer (`0xB8000..0xC0000`) with `Perm::Mmio` (Read/Write, No-Execute, Cache-Disabled), keeping VGA console active across the entire boot sequence. |
| **Console Lifecycle** | The kernel executed self-tests and immediately called `arch::shutdown(false)`, halting the VM. | The kernel now transitions directly into an infinite **Interactive REPL Console** (`shell.run_interactive_terminal()`) with PS/2 keyboard polling (`ports 0x64/0x60`) and VGA/Serial dual echoing. |

---

## 2. Boot Features Implemented

### A. Dynamic Loading Screen & Staged Progress Bar
Upon booting, KashOS clears the screen and displays the system banner and staged initialization progress bars with calibrated delays:
1. **[ 10%]** `Initializing hardware architecture & UART console...`
2. **[ 25%]** `Enabling Ring 3 TSS stack isolation & GDT/IDT...`
3. **[ 45%]** `Enabling W^X Paging & Physical Memory capabilities...`
4. **[ 65%]** `Engaging TRESOR DR0-3 Cold-Boot Immunity & DMA IOMMU...`
5. **[ 80%]** `Mounting kvault-fs 4000-stripe AF-split & sDDF drivers...`
6. **[ 95%]** `seL4 CDT & OpenBSD Pledge/Unveil Sandboxes Active...`
7. **[100%]** `All subsystems verified. Starting interactive shell.`

### B. Dual-Input Interactive Root Terminal (`tty0`)
- **VGA Text Renderer (`0xB8000`):** Full 80×25 text mode display with automatic scrolling, backspace character erasure (`0x08`), and color syntax highlighting (Cyan badges, Green headers, Bright White text).
- **PS/2 Keyboard Controller:** Reads scan codes directly from standard I/O port `0x60`, with full Shift-key support (`Shift` + letters = uppercase, `Shift` + numbers = symbols `!@#$%^&*()`, plus punctuation `:-_/.`).
- **Interactive Shell Prompt:** `kash-root@kash-node-01:/vault$ `

---

## 3. How to Boot in Your VirtualBox Window (Step-by-Step)

The bootable ISO has been generated at:
`c:\Users\Akash.J\Documents\KashOS Kernal\kash-kernel\kash-os.iso`

To reload it in your running VirtualBox window:
1. In the VirtualBox window top menu bar, click **Devices** → **Optical Drives** → **Choose a disk file...**.
2. Navigate to `c:\Users\Akash.J\Documents\KashOS Kernal\kash-kernel\kash-os.iso` and click **Open**.
3. In the top menu bar, click **Machine** → **Reset** (or press keyboard shortcut `Right Ctrl + R`).
4. Click **Reset** on the confirmation dialog.
5. VirtualBox will load GRUB2 and automatically start KashOS within 1 second.
6. The loading splash screen and progress bars will render, followed by the interactive root console prompt.
7. Click inside the VirtualBox window to focus input and start typing commands.

---

## 4. Commands Available in the VirtualBox Terminal

You can type any of the following commands in the terminal and press **Enter**:

### Security & Network Diagnostics
- `nmap 192.168.1.1` — Port scanner with Tor killswitch enforcement and service fingerprinting.
- `wol 02:4B:41:53:48:01` — Broadcasts standard 102-byte UDP Wake-on-LAN magic packet.
- `ping 8.8.8.8` — Verifies host reachability and round-trip latency.
- `ifconfig` — Inspects `eth0` and `tor0` interfaces and hardware MAC address rotation.
- `netstat` — Displays active TCP/UDP sockets and Tor daemon bindings.
- `tcpdump` — Deep packet inspection with fail-closed leak prevention.
- `traceroute 1.1.1.1` — Traces routing hops to remote host.
- `curl https://check.torproject.org` — Retrieves web endpoint via isolated Tor tunnel.
- `iptables` — Shows packet filter rules and default-drop firewall policy.
- `sha256sum <text>` — Cryptographic SHA-256 integrity hash.
- `hexdump` — Hexadecimal and ASCII buffer inspector.
- `shred <file>` — DoD 5220.22-M 3-pass cryptographic file destruction.

### Complete Linux POSIX CLI Commands
- `help` — Displays complete categorized command help menu.
- `ls` / `dir` — Lists directory contents with permissions and sizes.
- `pwd` — Prints current working directory.
- `cd <dir>` — Changes directory (e.g., `cd /ext4`, `cd /btrfs`, `cd ..`, `cd /vault`).
- `cat motd` — Reads file contents through Merkle B-tree authenticated VFS.
- `echo <msg>` — Prints text string to the terminal.
- `touch <file>` — Creates secure authenticated inode in VFS.
- `mkdir <dir>` — Creates new directory node.
- `cp <src> <dst>` — Copy-on-Write authenticated file cloning.
- `mv <src> <dst>` — Namespace-isolated file move/rename.
- `rm <file>` — Anti-forensic file deletion.
- `ps` — Lists active processes, sandboxing states, and OpenBSD pledge restrictions.
- `top` — Real-time task manager with CPU%, RAM%, and Capability domains.
- `free` — Memory usage statistics and amnesic scrubbed byte counter.
- `df` — Filesystem disk usage across `/vault`, `/ext4`, `/btrfs`, `/dev`.
- `date` — System clock and UTC date.
- `whoami` — Current user identity (`root`).
- `id` — UID, GID, and CDT Root-Authority capability badge.
- `uptime` — System load average and uptime duration.
- `clear` — Clears VGA screen buffer and resets cursor to top-left.
- `reboot` — Amnesic RAM zeroize and clean system restart.
- `poweroff` — Amnesic RAM zeroize and clean ACPI poweroff.

### Microkernel & OPSEC Commands
- `kctl list` — Lists sandboxed Application Capsules (`.kapp`).
- `kctl run org.system.editor` — Verifies Ed25519 signature and launches isolated editor capsule.
- `kctl disp org.tor.browser` — Spawns disposable RAM-only session and self-destructs on close.
- `kctl audit` — Audits FLASK Mandatory Access Control and Access Vector Cache.
- `multilang` — Verifies execution of C, C++, Python 3.12, and Java 21 runtimes.
- `install-os` — Verifies 10GB disk layout, 1-core SMP, and 100MB RAM budget.
- `status` — Inspects PID 1 Capability Derivation Tree (CDT).
- `opsec` — Deep OPSEC audit (Cold-boot DR0-3, IOMMU DMA, BadUSB gating).
- `graphene` — GrapheneOS memory hardening and BFU auto-reboot simulation.
- `schemes` — Lists RedoxOS URL schemes (`dev:`, `null:`, `random:`, `pipe:`).
- `drivers` — Inspects Tier 4 isolated sDDF user-space driver daemons.
- `fault-test` — Simulates driver panic and proves microkernel resilience without crashing.
- `storage` — Inspects C-LOOK elevator scheduler and kvault encrypted storage.
- `nuke` — Emergency cryptographic zeroize and RAM wipe.
