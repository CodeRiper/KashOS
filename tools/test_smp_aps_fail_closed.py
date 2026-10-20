#!/usr/bin/env python3
"""Guard AP startup until CPU-local interrupt and task state is installed."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SMP = (ROOT / "kernel/src/arch/x86_64/smp.rs").read_text(encoding="utf-8")
CPUID = (ROOT / "kernel/src/arch/x86_64/cpuid.rs").read_text(encoding="utf-8")
APIC = (ROOT / "kernel/src/arch/x86_64/apic.rs").read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"unterminated function: {signature}")


boot = function_body(SMP, "pub fn boot_secondary_cores(")
ap = function_body(SMP, "pub extern \"C\" fn ap_entry(")
apic_init = function_body(APIC, "pub fn init_ap()")

assert "Secondary CPU startup is disabled" in boot, "AP startup must be explicitly reported as disabled"
assert "prepare_ap_trampoline()" not in boot, "AP trampoline must not be launched before per-CPU setup exists"
assert "send_init_ipi(" not in boot and "send_sipi(" not in boot, "BSP must not send startup IPIs to unconfigured APs"
assert "    1 // The BSP is the only CPU" in boot, "only the BSP may be counted online while AP support is unavailable"
assert "init_ap()" not in ap, "AP entry must not enable the local APIC before its IDT is installed"
assert "AP interrupt setup is disabled" in apic_init and "write32(" not in apic_init, "AP APIC setup must not arm local interrupts"
assert 'asm!("sti"' not in ap, "AP entry must remain interrupt-disabled until local interrupt state exists"
assert "online_flag, 1" not in ap and "PER_CPU[id].online = true" not in ap, "unconfigured APs must not report online"
assert "online_cpu_count()" in SMP and "active / {} discovered" in CPUID, "hardware report must distinguish active from discovered CPUs"

print("[+] SMP AP fail-closed guard passed (9 checks)")
