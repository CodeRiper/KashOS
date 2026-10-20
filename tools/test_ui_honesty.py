#!/usr/bin/env python3
"""Guard user-visible UI text against unsupported privacy/security claims."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MISC = (ROOT / "kash-ui/crates/kash-ui/src/apps/misc.rs").read_text(encoding="utf-8")
LOCK = (ROOT / "kash-ui/crates/kash-ui/src/shell/lock.rs").read_text(encoding="utf-8")
REGISTRY = (ROOT / "kash-ui/crates/kash-ui/src/registry.rs").read_text(encoding="utf-8")
PRIVACY = (ROOT / "kash-ui/crates/kash-ui/src/apps/privacy.rs").read_text(encoding="utf-8")
FILES = (ROOT / "kash-ui/crates/kash-ui/src/apps/files.rs").read_text(encoding="utf-8")
SETTINGS = (ROOT / "kash-ui/crates/kash-ui/src/apps/settings.rs").read_text(encoding="utf-8")
LOCKPANES = (ROOT / "kash-ui/crates/kash-ui/src/apps/lockpanes.rs").read_text(encoding="utf-8")
ABOUT = (ROOT / "kash-ui/crates/kash-ui/src/apps/about.rs").read_text(encoding="utf-8")
PANES = (ROOT / "kash-ui/crates/kash-ui/src/apps/panes.rs").read_text(encoding="utf-8")
UI = (ROOT / "kash-ui/crates/kash-ui/src/ui.rs").read_text(encoding="utf-8")
DESKTOP = (ROOT / "kash-ui/crates/kash-ui/src/desktop.rs").read_text(encoding="utf-8")

checks = [
    ("Browser demo does not claim all permissions are denied", "All Permissions Denied by Default" not in MISC),
    ("Browser demo labels remote networking unavailable", "Remote networking and process-isolated permissions are unavailable" in MISC),
    ("Lock screen does not fabricate a three-hop gateway", "Anonymity Gateway · 3 hops" not in LOCK),
    ("Lock screen reports gateway unavailable", '"Anonymity Gateway unavailable"' in LOCK),
    ("Messages catalog does not claim gateway transport", "Chat over the Anonymity Gateway" not in REGISTRY),
    ("Messages catalog reports no network transport", "Messaging demo; no network transport is connected" in REGISTRY),
    ("Registry does not list fictional CLI packages", all(f'e("{name}",' not in REGISTRY for name in ("ssh", "curl", "nmap", "tcpdump", "kvault", "git", "cargo", "kash-ctl"))),
    ("Registry does not list fictional driver packages", all(f'e("{name}"' not in REGISTRY for name in ("kash-nic.kdrv", "kash-fb.kdrv", "kash-usb-hid.kdrv", "rtl8821-wifi.kdrv"))),
    ("Registry does not seed fake downloads", "let downloads = Vec::new();" in REGISTRY),
    ("Built-in UI demos have no claimed package size or install date", '"Built-in UI demo", false, true, "Unavailable"' in REGISTRY and '"demo", 0' in REGISTRY),
    ("Settings labels demo permissions as not kernel-enforced", "not enforced by the kernel or a process sandbox" in PRIVACY),
    ("Settings does not claim signature verification", "Signature unavailable" in PRIVACY and "Unsigned software is blocked" not in PRIVACY),
    ("Files does not fabricate a loaded driver inventory", 'd("Drivers", "Unavailable", Vec::new())' in FILES and "nvme.drv" not in FILES),
    ("UI does not expose a hard-coded user's real name or fake Kash ID", all("Akash J" not in src and '"Kash ID"' not in src for src in (SETTINGS, LOCKPANES, ABOUT, LOCK))),
    ("About panes do not publish a fabricated hardware serial", "KASH-0027-A1B2C3" not in LOCKPANES and "Unavailable · no firmware inventory" in LOCKPANES),
    ("About panes do not claim unreported capability self-test results", "7 / 7 passed" not in SETTINGS + LOCKPANES and "not reported to UI" in SETTINGS + LOCKPANES),
    ("About panes use the crate version instead of stale hard-coded versions", "0.1.0" not in SETTINGS + LOCKPANES + ABOUT and 'env!("CARGO_PKG_VERSION")' in SETTINGS + LOCKPANES + ABOUT),
    ("Boot status screen does not pose as firmware POST", "Prototype UI · not firmware POST" in LOCK and '"result not reported to UI"' in LOCK and '"Capability core self-test", "passed"' not in LOCK),
    ("Nonfunctional preference rows say unavailable instead of Standard", 'cx.row_value(g, label, "Unavailable in this build")' in PANES and 'cx.row_value(g, label, "Standard")' not in PANES),
    ("Auto-lock is wired to the desktop idle timer and re-auth timing is marked unavailable", "seg_lock_idle" in LOCKPANES and "self.sys.lock_idle" in DESKTOP and "timeout policy not implemented" in LOCKPANES),
    ("Hardware-key and vault key controls report missing services", "no vault key service" in LOCKPANES and "no hardware-key service" in LOCKPANES),
    ("Unused firmware preference state has been removed", "bios_on_boot" not in UI),
    ("Generic settings pane does not claim a default security profile", "Standard operating profile active" not in SETTINGS and "Default configuration" not in SETTINGS and "no service connected" in SETTINGS),
    ("Lock screen does not claim Lockdown Mode protects notification content", "never reveals notification contents while Lockdown Mode is on" not in LOCKPANES and "Notifications are not displayed on this prototype lock screen" in LOCKPANES),
]

for label, passed in checks:
    print(f"{'PASS' if passed else 'FAIL'}: {label}")
failures = [label for label, passed in checks if not passed]
if failures:
    print(f"{len(failures)} UI honesty regression(s) detected.", file=sys.stderr)
    raise SystemExit(1)
print(f"All {len(checks)} UI honesty regression checks passed.")
