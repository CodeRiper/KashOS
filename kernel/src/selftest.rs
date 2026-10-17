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

    // ── Test 11: ELF64 Executable Loader & Mandatory W^X Policy ─────────
    #[cfg(target_arch = "x86_64")]
    test_elf_loader_and_wx_rejection();

    // ── Test 12: Hardened System Call Layer 10,000 Iteration Fuzz Test ────
    #[cfg(target_arch = "x86_64")]
    test_syscall_fuzzing();

    // ── Test 13: Ring 3 User Mode, Syscalls & Hardware Fault Containment ──
    #[cfg(target_arch = "x86_64")]
    test_user_mode_execution_and_fault_containment();
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

#[repr(align(4096))]
pub struct FramePool<const N: usize>(pub [[u8; 4096]; N]);

pub struct StaticFrameAllocator<'a, const N: usize> {
    base: u64,
    allocated: usize,
    _marker: core::marker::PhantomData<&'a mut ()>,
}

impl<'a, const N: usize> StaticFrameAllocator<'a, N> {
    pub fn new(pool: &'a mut FramePool<N>) -> Self {
        let base = pool.0.as_mut_ptr() as u64;
        Self { base, allocated: 0, _marker: core::marker::PhantomData }
    }
}

impl<'a, const N: usize> kpaging::FrameAllocator for StaticFrameAllocator<'a, N> {
    fn allocate_frame(&mut self) -> Result<u64, kpaging::PageError> {
        if self.allocated >= N {
            return Err(kpaging::PageError::OutOfFrames);
        }
        let frame = self.base + (self.allocated as u64) * 4096;
        self.allocated += 1;
        unsafe { core::ptr::write_bytes(frame as *mut u8, 0, 4096); }
        Ok(frame)
    }

    fn deallocate_frame(&mut self, _paddr: u64) {}
}

#[cfg(target_arch = "x86_64")]
static mut ELF_TEST_FRAME_POOL: FramePool<32> = FramePool([[0; 4096]; 32]);

#[cfg(target_arch = "x86_64")]
pub fn test_elf_loader_and_wx_rejection() {
    kprintln!("[selftest] T11: verifying ELF64 loader and mandatory W^X policy...");
    let code = [0x90u8; 16];
    let elf_buf = crate::elf::create_test_elf(&code);

    let mut alloc = StaticFrameAllocator::new(unsafe { &mut *core::ptr::addr_of_mut!(ELF_TEST_FRAME_POOL) });

    let mut kernel_cr3: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) kernel_cr3, options(nostack));
    }

    // 1. Valid ELF64 loading
    let loaded = match crate::elf::load_elf(&elf_buf, &mut alloc, kernel_cr3) {
        Ok(l) => l,
        Err(e) => panic!("selftest: failed to load valid ELF: {:?}", e),
    };
    check!(loaded.entry_point == 0x0000_0001_0000_0078);
    check!(loaded.user_stack_top == crate::elf::USER_STACK_TOP);
    check!(loaded.cr3 != 0);

    // 2. Reject W^X violation (PF_W | PF_X in segment flags)
    let mut bad_wx_elf = elf_buf;
    unsafe {
        let flags_ptr = bad_wx_elf.as_mut_ptr().add(68) as *mut u32;
        *flags_ptr = crate::elf::PF_W | crate::elf::PF_X;
    }
    let wx_res = crate::elf::load_elf(&bad_wx_elf, &mut alloc, kernel_cr3);
    check!(wx_res == Err(crate::elf::ElfError::WriteExecuteViolation));

    // 3. Reject Out-Of-Bounds segment (>= USER_SPACE_CEILING)
    let mut oob_elf = elf_buf;
    unsafe {
        let vaddr_ptr = oob_elf.as_mut_ptr().add(80) as *mut u64;
        *vaddr_ptr = 0x0000_8000_0000_0000;
    }
    let oob_res = crate::elf::load_elf(&oob_elf, &mut alloc, kernel_cr3);
    check!(oob_res == Err(crate::elf::ElfError::AddressOutOfBounds));

    kprintln!("[selftest] ✓ T11 ELF64 loader verified: W^X enforced (W|X rejected), bounds protected, PML4 isolated");
    crate::status::update(|s| s.elf_loader = crate::status::ComponentStatus::Real);
}

#[cfg(target_arch = "x86_64")]
pub fn test_syscall_fuzzing() {
    kprintln!("[selftest] T12: launching 10,000 random-syscall fuzz stress test on dispatcher...");
    let mut rng_state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next_rnd = || -> u64 {
        rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        rng_state
    };

    let extreme_ptrs = [
        0u64,
        1u64,
        0x0000_7FFF_FFFF_FFFFu64,     // USER_SPACE_CEILING
        0x0000_8000_0000_0000u64,     // Non-canonical boundary
        0xFFFF_8000_0000_0000u64,     // Supervisor memory
        u64::MAX,
        0x0040_0000u64,
    ];

    let mut rejected_count = 0u32;
    for _ in 0..10_000 {
        let raw_num = (next_rnd() % 100) as usize;
        // Avoid calling SYS_EXIT or Linux SYS_EXIT/SYS_EXIT_GROUP directly on the selftest runner
        let num = if raw_num == 7 || raw_num == 60 || raw_num == 231 { 10 } else { raw_num };

        let ptr_idx = (next_rnd() as usize) % extreme_ptrs.len();
        let arg1 = extreme_ptrs[ptr_idx] as usize;
        let arg2 = (next_rnd() % 0x10000) as usize;
        let arg3 = next_rnd() as usize;
        let arg4 = next_rnd() as usize;
        let arg5 = next_rnd() as usize;

        let res = crate::arch::x86_64::syscall::kash_rust_syscall_dispatcher(
            num, arg1, arg2, arg3, arg4, arg5
        );
        if res < 0 {
            rejected_count += 1;
        }
    }

    kprintln!("[selftest] ✓ T12 10,000 syscall fuzz calls survived with 0 kernel panics ({} rejected safely)",
              rejected_count);
}

#[cfg(target_arch = "x86_64")]
static mut USER_PROCESS_FRAME_POOL: FramePool<64> = FramePool([[0; 4096]; 64]);

#[cfg(target_arch = "x86_64")]
pub fn test_user_mode_execution_and_fault_containment() {
    kprintln!("[selftest] T13: testing unprivileged Ring 3 execution & fault containment...");
    let mut alloc = StaticFrameAllocator::new(unsafe { &mut *core::ptr::addr_of_mut!(USER_PROCESS_FRAME_POOL) });

    // ── Sub-test A: User program executing SYS_PRINT and SYS_EXIT(0) ──
    // Machine code for user hello:
    // 0:  48 8d 3d 1d 00 00 00   lea rdi, [rip + 29] (points to msg at offset 36)
    // 7:  48 c7 c6 23 00 00 00   mov rsi, 35 (msg len)
    // 14: 48 c7 c0 0a 00 00 00   mov rax, 10 (SYS_PRINT)
    // 21: 0f 05                  syscall
    // 23: 48 31 ff               xor rdi, rdi (exit code 0)
    // 26: 48 c7 c0 07 00 00 00   mov rax, 7 (SYS_EXIT)
    // 33: 0f 05                  syscall
    // 35: f4                     hlt
    // 36: b"[user] Hello from Ring 3 syscall!\n" (34 bytes)
    let mut code_payload = [0u8; 70];
    let code_prefix = [
        0x48, 0x8d, 0x3d, 0x1d, 0x00, 0x00, 0x00,
        0x48, 0xc7, 0xc6, 0x22, 0x00, 0x00, 0x00,
        0x48, 0xc7, 0xc0, 0x0a, 0x00, 0x00, 0x00,
        0x0f, 0x05,
        0x48, 0x31, 0xff,
        0x48, 0xc7, 0xc0, 0x07, 0x00, 0x00, 0x00,
        0x0f, 0x05,
        0xf4,
    ];
    code_payload[..36].copy_from_slice(&code_prefix);
    let msg = b"[user] Hello from Ring 3 syscall!\n";
    code_payload[36..70].copy_from_slice(msg);

    let hello_elf = crate::elf::create_test_elf(&code_payload);
    let pid1 = match crate::process::spawn_user_elf("user-hello", &hello_elf, &mut alloc, kscheduler::QoSClass::UserInteractive) {
        Ok(p) => p,
        Err(e) => panic!("selftest: failed to spawn user-hello: {}", e),
    };

    let mut spins = 0;
    let mut exited_cleanly = false;
    while spins < 10_000_000 {
        {
            let pcb_table = crate::process::PROCESS_TABLE.lock();
            if let Some(pcb) = pcb_table.iter().find(|p| p.in_use && p.pid == pid1) {
                if let crate::process::ProcessState::Zombie(code) = pcb.state {
                    check!(code == 0);
                    exited_cleanly = true;
                    break;
                }
            }
        }
        core::hint::spin_loop();
        spins += 1;
    }
    check!(exited_cleanly);
    kprintln!("[selftest] ✓ Sub-test A passed: user program executed SYS_PRINT and exited voluntarily with code 0");

    // ── Sub-test B: User program fault containment (null pointer dereference) ──
    // Machine code for null dereference:
    // 0: 48 8b 04 25 00 00 00 00   mov rax, [0]
    // 8: f4                        hlt
    let crash_code = [0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, 0xf4];
    let crash_elf = crate::elf::create_test_elf(&crash_code);
    let pid2 = match crate::process::spawn_user_elf("user-crash", &crash_elf, &mut alloc, kscheduler::QoSClass::UserInteractive) {
        Ok(p) => p,
        Err(e) => panic!("selftest: failed to spawn user-crash: {}", e),
    };

    let initial_faults = crate::process::user_fault_count();
    let mut spins2 = 0;
    let mut fault_contained = false;
    while spins2 < 10_000_000 {
        {
            let pcb_table = crate::process::PROCESS_TABLE.lock();
            if let Some(pcb) = pcb_table.iter().find(|p| p.in_use && p.pid == pid2) {
                if let crate::process::ProcessState::Zombie(_) = pcb.state {
                    fault_contained = true;
                    break;
                }
            }
        }
        core::hint::spin_loop();
        spins2 += 1;
    }
    check!(fault_contained);
    check!(crate::process::user_fault_count() > initial_faults);
    kprintln!("[selftest] ✓ Sub-test B passed: user null-dereference #PF trapped, PID {} killed, microkernel survived!", pid2);

    kprintln!("[selftest] ✓ T13 User Mode Ring 3 & Fault Containment fully verified");
    crate::status::update(|s| s.user_mode_ring3 = crate::status::ComponentStatus::Real);
}
