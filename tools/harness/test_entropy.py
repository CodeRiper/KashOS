#!/usr/bin/env python3
"""
tools/harness/test_entropy.py — Test Harness for Task F-01 (Real Entropy for T0).
Validates:
1. T0 baseline (-cpu Conroe -smp 1 -m 1024M):
   - Harvester succeeds without RDRAND/RDSEED.
   - Emits structured KASH-EVT entropy event.
   - Harvested conservative bits >= 256.
   - Sources include 'jitter' and 'rtc'.
2. T2 modern profile (-cpu max -smp 4 -m 1024M):
   - Harvester detects RDSEED/RDRAND and combines with jitter/rtc.
   - Harvested conservative bits >= 256.
"""

import sys
import os

# Add repo root to import path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from tools.harness.runner import QemuHarness

def test_t0_entropy():
    print("[test] Running T0 baseline entropy harvest test (-cpu Conroe)...")
    harness = QemuHarness(profile="T0", timeout_secs=10)
    events = harness.run()

    entropy_evts = [e for e in events if e.get("src") == "kernel" and e.get("ev") == "entropy"]
    assert len(entropy_evts) >= 1, f"Expected at least 1 entropy event on T0, got {len(entropy_evts)}"

    evt = entropy_evts[0]
    bits = evt.get("bits", 0)
    sources = evt.get("sources", [])

    print(f"[test] T0 Event: bits={bits}, sources={sources}")
    assert bits >= 256, f"T0 entropy bits ({bits}) less than required threshold (256)"
    assert "jitter" in sources, "Expected 'jitter' in T0 entropy sources"
    assert "rtc" in sources, "Expected 'rtc' in T0 entropy sources"
    assert "rdrand" not in sources, "RDRAND should not be present on T0 Conroe CPU"
    print("[test] T0 baseline entropy test PASSED.")

def test_t2_entropy():
    print("[test] Running T2 modern entropy harvest test (-cpu max)...")
    harness = QemuHarness(profile="T2", timeout_secs=10)
    events = harness.run()

    entropy_evts = [e for e in events if e.get("src") == "kernel" and e.get("ev") == "entropy"]
    assert len(entropy_evts) >= 1, f"Expected at least 1 entropy event on T2, got {len(entropy_evts)}"

    evt = entropy_evts[0]
    bits = evt.get("bits", 0)
    sources = evt.get("sources", [])

    print(f"[test] T2 Event: bits={bits}, sources={sources}")
    assert bits >= 256, f"T2 entropy bits ({bits}) less than required threshold (256)"
    assert "rdrand" in sources, "Expected 'rdrand' in T2 entropy sources"
    print("[test] T2 modern entropy test PASSED.")

if __name__ == "__main__":
    test_t0_entropy()
    test_t2_entropy()
    print("\n[test] ALL ENTROPY HARNESS TESTS PASSED CLEANLY.")
