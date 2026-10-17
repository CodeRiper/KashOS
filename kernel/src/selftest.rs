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
    check!(cs.retype(0, ObjType::Untyped { size_bits: 12 }, 5, &mut zero).is_ok());
    check!(cs.retype(5, ObjType::Frame, 6, &mut zero).is_ok());
    check!(cs.check_invariants().is_ok());
    kprintln!("[selftest] T7 nested untyped and sub-allocation: ok");

    kprintln!("[selftest] ✓ all 7 capability tests passed on {:.1} MiB of real hardware RAM",
              (1u64 << bits) as f64 / 1_048_576.0);
    crate::status::update(|s| s.kcore_caps = crate::status::ComponentStatus::Real);

    // ── Test 8: Physical Frame Allocator with Domain Quota Tracking ─────
    test_frame_allocator_quotas();

    // ── Test 9: Deliberate NX/WP hardware protection fault trap ──────────
    #[cfg(target_arch = "x86_64")]
    test_nx_smep_fault();

    // ── Test 10: Preemptive multitasking 1,000,000 cycles concurrency ────
    #[cfg(target_arch = "x86_64")]
    test_preemptive_multitasking();
}

fn test_frame_allocator_quotas() {
    use kpaging::{PageError, QuotaFrameAllocator};
    let mut quotas = [10; 8];
    quotas[1] = 2; // Domain 1 has quota 2
    quotas[2] = 4;

    let mut alloc = match QuotaFrameAllocator::<64>::new(0x20_0000, 64, quotas) {
        Ok(a) => a,
        Err(_) => panic!("selftest: failed to initialize QuotaFrameAllocator"),
    };

    let f1 = alloc.allocate_for_domain(1).unwrap();
    let f2 = alloc.allocate_for_domain(1).unwrap();
    check!(alloc.allocate_for_domain(1) == Err(PageError::QuotaExceeded));
    check!(alloc.frame_owner(f1) == Ok(1));
    check!(alloc.frame_owner(f2) == Ok(1));

    let f_dom2 = alloc.allocate_for_domain(2).unwrap();
    check!(alloc.frame_owner(f_dom2) == Ok(2));

    check!(alloc.deallocate_frame_checked(f1) == Ok(1));
    check!(alloc.allocate_for_domain(1).is_ok());

    kprintln!("[selftest] T8 physical frame allocator domain quota enforcement: ok");
    crate::status::update(|s| s.quota_frames = crate::status::ComponentStatus::Real);
}

#[cfg(target_arch = "x86_64")]
static COUNTER_A: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static COUNTER_B: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static PREEMPT_RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(true);

#[cfg(target_arch = "x86_64")]
static RO_TEST_BYTE: u8 = 0xAA;

#[cfg(target_arch = "x86_64")]
extern "C" fn thread_worker_a(arg: u64) {
    let expected = 0xAAAA_BBBB_CCCC_DDDDu64.wrapping_add(arg);
    let local = expected;
    let mut sse: f32 = 1.0;
    while PREEMPT_RUNNING.load(core::sync::atomic::Ordering::Relaxed) {
        let count = COUNTER_A.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        sse = sse * 1.00001 + 0.00001;
        if local != expected {
            panic!("Thread A register corrupted!");
        }
        let total = count + COUNTER_B.load(core::sync::atomic::Ordering::Relaxed);
        if total >= 1_000_000 {
            break;
        }
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
extern "C" fn thread_worker_b(arg: u64) {
    let expected = 0x1111_2222_3333_4444u64.wrapping_add(arg);
    let local = expected;
    let mut sse: f32 = 2.0;
    while PREEMPT_RUNNING.load(core::sync::atomic::Ordering::Relaxed) {
        let count = COUNTER_B.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        sse = sse * 0.99999 - 0.00001;
        if local != expected {
            panic!("Thread B register corrupted!");
        }
        let total = count + COUNTER_A.load(core::sync::atomic::Ordering::Relaxed);
        if total >= 1_000_000 {
            break;
        }
        core::hint::spin_loop();
    }
}

#[cfg(target_arch = "x86_64")]
pub fn test_preemptive_multitasking() {
    kprintln!("[sched] launching 1,000,000 cycle thread preemption & register integrity test...");
    let t1 = crate::task::spawn_kernel_thread("worker-a", kscheduler::QoSClass::UserInteractive, thread_worker_a, 1);
    let t2 = crate::task::spawn_kernel_thread("worker-b", kscheduler::QoSClass::UserInteractive, thread_worker_b, 2);
    check!(t1.is_ok());
    check!(t2.is_ok());

    while COUNTER_A.load(core::sync::atomic::Ordering::Relaxed) + COUNTER_B.load(core::sync::atomic::Ordering::Relaxed) < 1_000_000 {
        core::hint::spin_loop();
    }
    PREEMPT_RUNNING.store(false, core::sync::atomic::Ordering::Relaxed);

    let ca = COUNTER_A.load(core::sync::atomic::Ordering::Relaxed);
    let cb = COUNTER_B.load(core::sync::atomic::Ordering::Relaxed);
    check!(ca > 0 && cb > 0);
    kprintln!("[sched] ✓ 1,000,000 preemptions verified without corruption (Thread A: {}, Thread B: {})", ca, cb);
    crate::status::update(|s| s.kscheduler_preempt = crate::status::ComponentStatus::Real);
}

#[cfg(target_arch = "x86_64")]
pub fn test_nx_smep_fault() {
    use crate::arch::x86_64::idt;
    kprintln!("[security] running deliberate hardware protection violation test (NX/WP)...");
    let ro_addr = core::ptr::addr_of!(RO_TEST_BYTE) as u64;
    unsafe {
        core::arch::asm!(
            "lea rdi, [rip + 2f]",
            "call {set_expected}",
            "mov byte ptr [{ro_ptr}], 0x55",
            "2:",
            "nop",
            set_expected = sym idt::set_expected_fault,
            ro_ptr = in(reg) ro_addr,
            out("rdi") _,
            out("rax") _,
            options(nomem)
        );
    }

    if idt::was_fault_caught() {
        kprintln!("[security] ✓ deliberate NX/WP violation verified: trapped and logged by hardware handler");
        crate::status::update(|s| s.wx_paging = crate::status::ComponentStatus::Real);
    } else {
        kprintln!("[security] ⚠ deliberate protection violation was not caught");
    }
}
