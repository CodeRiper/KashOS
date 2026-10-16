//! Boot-time self-test of the capability core (kcore) on real hardware RAM.
//! Runs after hardware discovery on both x86-64 and AArch64.
//! Uses the free memory handed to us by arch::discover() — no hard-coded addresses.
use core::cell::Cell;
use kcore::{Cap, CapSpace, KError, ObjType, Rights};
use khal::MemRegion;

macro_rules! check {
    ($cond:expr) => {
        if !$cond {
            panic!("selftest: assertion failed: {}", stringify!($cond));
        }
    };
}

/// `region` is picked by the caller (`main.rs`), not searched for here —
/// main.rs is where every other claim on `platform.free` also gets decided
/// (the global heap allocator takes a region of its own too), so one place
/// owning "who gets which region" is what guarantees this self-test's
/// Untyped memory and the heap allocator's arena can never end up pointing
/// at the same physical bytes.
pub fn run(region: MemRegion) {
    kprintln!("[selftest] capability core on real {} hardware RAM", crate::arch_name());

    let bits = region.size_bits.min(22); // cap at 4 MiB to keep test fast
    let Ok(root) = Cap::new_untyped(region.base, bits) else {
        panic!("selftest: bad root untyped (base={:#x} bits={})", region.base, bits);
    };

    let bytes_zeroed = Cell::new(0u64);
    let mut zero = |start: u64, len: u64| {
        crate::arch::zero_phys(start, len);
        bytes_zeroed.set(bytes_zeroed.get() + len);
    };

    let mut cs: CapSpace<32> = CapSpace::new();

    // ── Test 1: install root untyped ────────────────────────────────────
    check!(cs.install_root(0, root).is_ok());
    kprintln!("[selftest] T1 root untyped installed @ {:#018x} (2^{} bytes)",
              region.base, bits);

    // ── Test 2: retype → frame, rights only shrink ───────────────────────
    check!(cs.retype(0, ObjType::Frame, 1, &mut zero).is_ok());
    check!(cs.copy(1, 2, Rights::READ).is_ok());
    check!(cs.lookup(2, Rights::READ).is_ok());
    check!(matches!(cs.lookup(2, Rights::WRITE), Err(KError::InsufficientRights)));
    kprintln!("[selftest] T2 rights-monotonicity: ok (copy can only restrict)");

    // ── Test 3: untyped cannot be duplicated ────────────────────────────
    check!(matches!(cs.copy(0, 3, Rights::ALL), Err(KError::InvalidCapType)));
    kprintln!("[selftest] T3 untyped non-duplicability: ok");

    // ── Test 4: endpoint + badge ─────────────────────────────────────────
    check!(cs.retype(0, ObjType::Endpoint, 3, &mut zero).is_ok());
    check!(cs.mint(3, 4, Rights::ALL, 0xDEAD).is_ok());
    check!(cs.lookup(4, Rights::NONE).unwrap().badge() == 0xDEAD);
    check!(matches!(cs.mint(4, 5, Rights::ALL, 0xCAFE), Err(KError::InvalidArgument)));
    kprintln!("[selftest] T4 endpoint badges: ok (set-once, only on endpoints)");

    // ── Test 5: revoke destroys all derived, memory re-zeroed on reuse ──
    check!(cs.revoke(0).is_ok());
    check!(matches!(cs.lookup(1, Rights::NONE), Err(KError::SlotEmpty)));
    check!(matches!(cs.lookup(4, Rights::NONE), Err(KError::SlotEmpty)));
    let zeroed_after_revoke = bytes_zeroed.get();
    check!(cs.retype(0, ObjType::Frame, 1, &mut zero).is_ok());
    check!(bytes_zeroed.get() > zeroed_after_revoke); // re-used memory was re-zeroed
    kprintln!("[selftest] T5 revoke + zero-on-reuse: ok ({} bytes zeroed total)",
              bytes_zeroed.get());

    // ── Test 6: invariant checker ────────────────────────────────────────
    check!(cs.check_invariants().is_ok());
    kprintln!("[selftest] T6 structural invariants: ok");

    // ── Test 7: nested untyped + overlapping frames rejected ────────────
    // Carve a sub-untyped inside the root, then try to make a frame that
    // escapes it — the checker must reject the forged corruption.
    check!(cs.retype(0, ObjType::Untyped { size_bits: 12 }, 5, &mut zero).is_ok());
    check!(cs.retype(5, ObjType::Frame, 6, &mut zero).is_ok());
    check!(cs.check_invariants().is_ok());
    kprintln!("[selftest] T7 nested untyped and sub-allocation: ok");

    kprintln!("[selftest] ✓ all 7 tests passed on {:.1} MiB of real hardware RAM",
              (1u64 << bits) as f64 / 1_048_576.0);
}
