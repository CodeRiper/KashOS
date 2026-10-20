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
]

for label, passed in checks:
    print(f"{'PASS' if passed else 'FAIL'}: {label}")
failures = [label for label, passed in checks if not passed]
if failures:
    print(f"{len(failures)} UI honesty regression(s) detected.", file=sys.stderr)
    raise SystemExit(1)
print(f"All {len(checks)} UI honesty regression checks passed.")
