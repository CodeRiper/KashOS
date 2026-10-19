#!/usr/bin/env python3
"""
tools/claims_lint.py — The KashOS Claims Linter
Enforces Appendix A of KashOS Build Guide v2:
Fails CI if unbacked verification, security, or completion claims appear
in README, docs/**, manifests, or kernel logging without linked evidence.
"""

import sys
import os
import re

# Files permitted to mention the forbidden phrases in an instructional or meta context
EXEMPT_FILES = {
    os.path.normpath("docs/KASHOS_BUILD_GUIDE.md"),
    os.path.normpath("docs/MASTER_PLAN.md"),
    os.path.normpath("tools/claims_lint.py"),
}

# Forbidden unbacked words/phrases (case-insensitive) unless line contains proof/evidence link
FORBIDDEN_PHRASES = [
    r"\bformally verified\b",
    r"\bformal verification\b",
    r"\bmachine-checked\b",
    r"\bmathematically\b",
    r"\bproven\b",
    r"\bproof\b",
    r"\bguaranteed\b",
    r"\bunbreakable\b",
    r"\bunhackable\b",
    r"\bmilitary-grade\b",
    r"100%\s+(?:complete|secure|verified|coverage)",
    r"\bhardware-verified\b",
    r"\bpost-quantum\b",
    r"\bml-kem\b",
    r"\btc_mor\b",
    r"\bxts-aes\b",
    r"\bgrapheneos\b",
]

def check_text_file(filepath):
    """Scan a text file for unbacked forbidden claims."""
    rel_path = os.path.relpath(filepath, ".")
    norm_path = os.path.normpath(rel_path)
    if norm_path in EXEMPT_FILES:
        return []

    violations = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                # Exempt lines that explicitly cite proof files or evidence bundles
                if "proofs/" in line or "docs/EVIDENCE/" in line:
                    continue
                # Exempt lines indicating things that are NOT yet done/implemented
                if "not implemented" in line.lower() or "not available" in line.lower() or "not done" in line.lower():
                    continue

                for pattern in FORBIDDEN_PHRASES:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        violations.append((rel_path, idx, match.group(0), line.strip()))
    except Exception as e:
        print(f"[-] Warning: Failed to read {filepath}: {e}", file=sys.stderr)
    return violations

def check_personal_paths(filepath):
    """Enforce Privacy Gate: block hardcoded developer user directory paths in repository files."""
    rel_path = os.path.relpath(filepath, ".")
    norm_path = os.path.normpath(rel_path)
    if norm_path in EXEMPT_FILES or norm_path.startswith(".git") or norm_path.startswith("target") or "CRITIQUE_AND_VERIFICATION_REPORT" in norm_path:
        return []

    violations = []
    path_regex = re.compile(r"(?:[c-z]:[\\/]Users[\\/][a-zA-Z0-9_\.]+|file:///[c-z]:/Users/[a-zA-Z0-9_\.]+)", re.IGNORECASE)
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                match = path_regex.search(line)
                if match:
                    violations.append((rel_path, idx, "PRIVACY_LEAK: " + match.group(0), line.strip()))
    except Exception:
        pass
    return violations

def check_kernel_prints():
    """Verify that [OK] and check marks in kprintln! only occur inside status.rs."""
    kernel_src = os.path.join("kernel", "src")
    if not os.path.exists(kernel_src):
        return []

    violations = []
    for root, _, files in os.walk(kernel_src):
        for file in files:
            if not file.endswith(".rs"):
                continue
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, ".")
            if rel_path == os.path.normpath("kernel/src/status.rs"):
                continue

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, 1):
                    # Check for [OK] inside kprintln! or kprint!
                    if ("kprintln!" in line or "kprint!" in line) and ("[OK]" in line or "✓" in line):
                        violations.append((rel_path, idx, "[OK]/✓ print", line.strip()))
                    # Check for "Simulating" outside cfg(test)
                    if "Simulating" in line and not line.strip().startswith("//"):
                        violations.append((rel_path, idx, "Simulating print", line.strip()))
    return violations

def check_kernel_budgets():
    """Enforce K0 Hard Budgets: LoC <= 25,000, unsafe <= 450."""
    total_loc = 0
    total_unsafe = 0
    kernel_src = os.path.join("kernel", "src")
    if not os.path.exists(kernel_src):
        return []

    for root, _, files in os.walk(kernel_src):
        for file in files:
            if file.endswith(".rs"):
                fp = os.path.join(root, file)
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    total_loc += len(lines)
                    total_unsafe += sum(1 for l in lines if "unsafe " in l or "unsafe{" in l)
                except Exception:
                    pass

    violations = []
    if total_loc > 25000:
        violations.append(("kernel/src", 0, "LOC_BUDGET_EXCEEDED", f"Kernel has {total_loc} LoC, exceeding hard budget 25,000"))
    if total_unsafe > 450:
        violations.append(("kernel/src", 0, "UNSAFE_BUDGET_EXCEEDED", f"Kernel has {total_unsafe} unsafe blocks, exceeding hard budget 450"))
    return violations

def main():
    print("=" * 70)
    print("  KASHOS CLAIMS LINTER (Build Guide v2 Appendix A)")
    print("=" * 70)

    all_violations = []

    # 1. Check README.md
    if os.path.exists("README.md"):
        all_violations.extend(check_text_file("README.md"))

    # 2. Check docs/
    if os.path.exists("docs"):
        for root, _, files in os.walk("docs"):
            for file in files:
                if file.endswith((".md", ".txt", ".toml")):
                    all_violations.extend(check_text_file(os.path.join(root, file)))

    # 3. Check manifests and configs
    for root_file in ["manifest.toml", "security.conf", "Cargo.toml", "README.md", "Run-KashOS-QEMU-LowMemory.bat", "run_kashos_interactive.bat"]:
        if os.path.exists(root_file):
            all_violations.extend(check_text_file(root_file))
            all_violations.extend(check_personal_paths(root_file))

    # 4. Check kernel prints
    kernel_violations = check_kernel_prints()
    all_violations.extend(kernel_violations)

    # 5. Check personal paths in all markdown docs and scripts
    for folder in ["docs", "scripts"]:
        if os.path.exists(folder):
            for root, _, files in os.walk(folder):
                for file in files:
                    if file.endswith((".md", ".txt", ".bat", ".ps1", ".rs", ".py")):
                        all_violations.extend(check_personal_paths(os.path.join(root, file)))

    # 6. Check K0 Kernel Budgets (LoC <= 25,000, unsafe <= 450)
    budget_violations = check_kernel_budgets()
    all_violations.extend(budget_violations)

    if all_violations:
        print(f"\n[-] FAILED: Found {len(all_violations)} claims violations:\n")
        for filepath, line_no, term, content in all_violations:
            safe_term = str(term).encode("ascii", errors="replace").decode("ascii")
            safe_content = str(content).encode("ascii", errors="replace").decode("ascii")
            print(f"  * {filepath}:{line_no} [{safe_term}]")
            print(f"      {safe_content[:90]}")
        print("\nFix rule: Link claim to a verified file in proofs/ or docs/EVIDENCE/,")
        print("          or replace unbacked claim with honest status (status.rs / NotAvailable).\n")
        return 1
    else:
        print("\n[+] SUCCESS: All documentation, manifests, and prints comply with Claims Policy.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
