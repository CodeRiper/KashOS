# KashOS engineering work log

**Last updated:** 2026-10-20  
**Current task branch:** `codex/a1-remove-fake-network-claims`  
**Current task:** A1 network honesty and boot smoke-test repair

## Completed in this task

- Removed fabricated HTTP(S) success, fake TLS framing on the live path, and
  synthetic Tor/DNS socket rows. Remote HTTP(S) now returns `NotAvailable`;
  gateway state starts down and has no runtime “set Up” API.
- Replaced the empty Dillo/Ladybird windows with explicit unavailable results.
  The terminal HTML parser and local pages identify themselves as prototypes.
- Added a CI source regression check for network fail-closed behavior.
- Fixed boot ordering so the heap exists before allocation-using self-tests;
  allocated large network packet rings off the early kernel stack.
- Updated network self-tests and corrected overconfident self-test messages.
- Updated QEMU smoke helper to use the release kernel built from the current
  worktree instead of a potentially stale `isodir` artifact.
- Added the implementation roadmap and official-source security model research.
- Marked legacy Part A and B0-B6 completion statuses for revalidation.

## Verification

See [`EVIDENCE/A1.md`](EVIDENCE/A1.md) for exact commands and limits. Current
local results: workspace host tests pass, kernel target check/build pass,
network regression guard and claims linter pass, and the QEMU T0 smoke test
reaches the shell. This does not establish TPM, IOMMU, TLS, Tor, browser
isolation, Linux compatibility, or physical-device security.

## Current GitHub state

The task branch is ready to push/open for review. Record the branch and PR URL
here after GitHub accepts it. Do not merge until the user reviews the PR and
the platform CI checks have reported their results.

## Next task

Revalidate A2 and A3 against the current code before changing persistent-data
behavior: inspect vault open/format paths, passphrase lifecycle, derivation,
recovery, and interruption cases. Follow the engineering plan order and add
evidence before marking either task complete. Continue the A4-A21 audit after
those data/key-safety gates.
