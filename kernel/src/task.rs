//! Kernel Task & Thread Management with Preemptive Multitasking.
//!
//! Provides:
//! - Thread Control Blocks (TCBs) with isolated 16 KiB kernel stacks and unmapped guard pages.
//! - Preemptive QoS scheduling integrated with `kscheduler`.
//! - Per-thread FPU/SSE save/restore via `fxsave64`/`fxrstor64`.
//! - Per-CPU current task identity for fail-closed syscall and fault attribution.
#![allow(unsafe_code)]

use crate::arch::x86_64::fpu::FpuState;
use crate::arch::x86_64::gdt::{set_tss_rsp0, KERNEL_CODE_SELECTOR, KERNEL_DATA_SELECTOR};
use crate::arch::x86_64::smp;
use crate::sync::TicketSpinLock;
use kscheduler::{ContextSwitchTarget, QoSClass, QoSScheduler, SchedError, MAX_TASKS};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const KERNEL_STACK_SIZE: usize = 16384;

#[repr(C, align(4096))]
pub struct ThreadStack {
    pub guard_page: [u8; 4096],
    pub stack_memory: [u8; KERNEL_STACK_SIZE],
}

impl ThreadStack {
    pub const fn new() -> Self {
        ThreadStack {
            guard_page: [0u8; 4096],
            stack_memory: [0u8; KERNEL_STACK_SIZE],
        }
    }
}

pub struct Thread {
    pub tid: u32,
    pub name: &'static str,
    pub saved_rsp: u64,
    pub stack_top: u64,
    pub fpu: FpuState,
    pub cr3: u64,
    pub in_use: bool,
}

impl Thread {
    pub const fn empty() -> Self {
        Thread {
            tid: 0,
            name: "",
            saved_rsp: 0,
            stack_top: 0,
            fpu: FpuState::initial(),
            cr3: 0,
            in_use: false,
        }
    }
}

pub static THREAD_STACKS: TicketSpinLock<[ThreadStack; MAX_TASKS]> =
    TicketSpinLock::new([const { ThreadStack::new() }; MAX_TASKS]);

static IDLE_STACKS: TicketSpinLock<[ThreadStack; smp::MAX_CPUS]> =
    TicketSpinLock::new([const { ThreadStack::new() }; smp::MAX_CPUS]);
static CPU_IDLE_RSP: [AtomicU64; smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; smp::MAX_CPUS];
static CPU_IDLE_STACK_TOP: [AtomicU64; smp::MAX_CPUS] =
    [const { AtomicU64::new(0) }; smp::MAX_CPUS];
static IDLE_WAKE_PROBE_TID: AtomicU32 = AtomicU32::new(0);

/// Return the virtual address of each statically reserved thread-stack guard.
/// The kernel currently uses an identity map, so these are also the addresses
/// to remove from the x86 page table before it is installed.
pub fn stack_guard_page_addresses() -> [u64; MAX_TASKS + smp::MAX_CPUS] {
    let thread_stacks = THREAD_STACKS.lock();
    let idle_stacks = IDLE_STACKS.lock();
    core::array::from_fn(|index| {
        if index < MAX_TASKS {
            thread_stacks[index].guard_page.as_ptr() as u64
        } else {
            idle_stacks[index - MAX_TASKS].guard_page.as_ptr() as u64
        }
    })
}

pub static THREADS: TicketSpinLock<[Thread; MAX_TASKS]> =
    TicketSpinLock::new([const { Thread::empty() }; MAX_TASKS]);

pub static SCHEDULER: TicketSpinLock<QoSScheduler> =
    TicketSpinLock::new(QoSScheduler::new());

static CPU_CURRENT_TID: [AtomicU32; smp::MAX_CPUS] =
    [const { AtomicU32::new(0) }; smp::MAX_CPUS];
static PREEMPTION_COUNT: AtomicU64 = AtomicU64::new(0);

fn current_cpu_index() -> Option<usize> {
    smp::cpu_index_for_apic_id(crate::arch::x86_64::apic::current_id())
}

/// Return the TID of the currently executing thread.
///
/// TID 0 means the current processor did not resolve to an initialized CPU slot.
pub fn current_tid() -> u32 {
    current_cpu_index()
        .map(|cpu_index| CPU_CURRENT_TID[cpu_index].load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Set the TID of the currently executing thread (used during dispatch/context switch/tests).
pub fn set_current_tid(tid: u32) {
    if let Some(cpu_index) = current_cpu_index() {
        CPU_CURRENT_TID[cpu_index].store(tid, Ordering::Release);
    }
}

/// Resolve a live task identifier and apply its current-aware wake transition
/// without exposing its reusable scheduler slot.
///
/// Callers must not split TID lookup from wake: another CPU could terminate the
/// task and reuse its scheduler slot between those operations. The scheduler
/// decides whether to restore a still-current task or enqueue a switched-out one.
pub fn wake_task_by_tid(tid: u32) -> Result<(), SchedError> {
    let mut sched = SCHEDULER.lock();
    let task_idx = sched.task_index_for_tid(tid).ok_or(SchedError::NoSuchTask)?;
    sched.wake_task(task_idx)
}

/// Return whether `rsp` falls inside the guarded kernel stack assigned to the
/// current thread. Fast syscall entry checks this before dispatching user input.
pub fn current_thread_stack_contains(rsp: u64) -> bool {
    let tid = current_tid();
    let threads = THREADS.lock();
    let Some(slot) = threads
        .iter()
        .position(|thread| thread.in_use && thread.tid == tid)
    else {
        return false;
    };
    let stacks = THREAD_STACKS.lock();
    let Some(stack) = stacks.get(slot) else {
        return false;
    };
    let bottom = stack.stack_memory.as_ptr() as u64;
    let top = bottom + KERNEL_STACK_SIZE as u64;
    rsp >= bottom && rsp < top
}

/// Total number of successful thread preemptions observed.
pub fn preemption_count() -> u64 {
    PREEMPTION_COUNT.load(Ordering::Relaxed)
}

extern "C" fn thread_entry_stub(entry: extern "C" fn(u64), arg: u64) {
    entry(arg);
    exit_current_thread();
}

extern "C" fn idle_entry(_arg: u64) {
    loop {
        let wake_tid = IDLE_WAKE_PROBE_TID.swap(0, Ordering::AcqRel);
        if wake_tid != 0 && wake_task_by_tid(wake_tid).is_err() {
            kprintln!("[sched] Idle handoff probe could not wake TID {}; halting.", wake_tid);
            crate::arch::shutdown(true);
        }
        unsafe {
            core::arch::asm!("sti; hlt", options(nomem, nostack));
        }
    }
}

/// Exercise a real blocked-task to idle to woken-task timer handoff during the
/// boot self-test. The one-shot wake token is ignored during normal operation.
pub fn test_blocked_task_idle_handoff() {
    let tid = current_tid();
    if tid == 0
        || IDLE_WAKE_PROBE_TID
            .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        panic!("selftest: could not arm blocked-task idle handoff");
    }

    let block_result = {
        let mut sched = SCHEDULER.lock();
        sched
            .task_index_for_tid(tid)
            .ok_or(SchedError::NoSuchTask)
            .and_then(|idx| sched.block_task(idx))
    };
    if let Err(error) = block_result {
        IDLE_WAKE_PROBE_TID.store(0, Ordering::Release);
        panic!("selftest: failed to block idle-handoff task: {:?}", error);
    }

    while IDLE_WAKE_PROBE_TID.load(Ordering::Acquire) != 0 {
        unsafe {
            core::arch::asm!("pause", options(nomem, nostack));
        }
    }
    if current_tid() != tid {
        panic!("selftest: idle wake returned to the wrong task");
    }
    if IDLE_WAKE_PROBE_TID.load(Ordering::Acquire) != 0 {
        panic!("selftest: idle handoff probe token was not consumed");
    }
    let resumed_running = {
        let sched = SCHEDULER.lock();
        sched
            .task_index_for_tid(tid)
            .and_then(|idx| sched.task(idx))
            .map(|task| task.state == kscheduler::ThreadState::Running)
            .unwrap_or(false)
    };
    if !resumed_running {
        panic!("selftest: blocked task did not resume in Running state");
    }
    kprintln!("[sched] PASS: blocked task switched to idle and resumed after wake");
}

fn initialize_idle_context(cpu_index: usize) {
    if cpu_index >= smp::MAX_CPUS {
        crate::arch::shutdown(true);
    }
    let mut stacks = IDLE_STACKS.lock();
    let stack = &mut stacks[cpu_index];
    let stack_top = stack.stack_memory.as_ptr() as u64 + KERNEL_STACK_SIZE as u64;
    let saved_rsp = stack_top - 20 * core::mem::size_of::<u64>() as u64;
    let frame = saved_rsp as *mut u64;

    // SAFETY: this CPU's idle stack is statically reserved, exclusively
    // initialized here, and its guard page is unmapped before interrupts run.
    unsafe {
        core::ptr::write_bytes(frame, 0, 20);
        core::ptr::write_volatile(frame.add(9), idle_entry as *const () as usize as u64);
        core::ptr::write_volatile(frame.add(10), 0);
        core::ptr::write_volatile(frame.add(15), thread_entry_stub as *const () as usize as u64);
        core::ptr::write_volatile(frame.add(16), KERNEL_CODE_SELECTOR as u64);
        core::ptr::write_volatile(frame.add(17), 0x202);
        core::ptr::write_volatile(frame.add(18), stack_top);
        core::ptr::write_volatile(frame.add(19), KERNEL_DATA_SELECTOR as u64);
    }
    CPU_IDLE_RSP[cpu_index].store(saved_rsp, Ordering::Release);
    CPU_IDLE_STACK_TOP[cpu_index].store(stack_top, Ordering::Release);
}

fn switch_to_idle(cpu_index: usize) -> u64 {
    let idle_rsp = CPU_IDLE_RSP[cpu_index].load(Ordering::Acquire);
    let idle_stack_top = CPU_IDLE_STACK_TOP[cpu_index].load(Ordering::Acquire);
    if idle_rsp == 0 || idle_stack_top == 0 {
        kprintln!("[sched] CPU {} has no initialized idle context; halting.", cpu_index);
        crate::arch::shutdown(true);
    }
    set_tss_rsp0(idle_stack_top);
    if !crate::arch::x86_64::syscall::set_current_kernel_stack_top(idle_stack_top) {
        kprintln!("[sched] CPU {} has no valid idle syscall stack; halting.", cpu_index);
        crate::arch::shutdown(true);
    }
    CPU_CURRENT_TID[cpu_index].store(0, Ordering::Release);
    idle_rsp
}

/// Terminate the calling thread and yield.
pub fn exit_current_thread() -> ! {
    let tid = current_tid();
    {
        let mut sched = SCHEDULER.lock();
        let mut threads = THREADS.lock();
        if let Some((idx, t)) = threads.iter_mut().enumerate().find(|(_, t)| t.in_use && t.tid == tid) {
            t.in_use = false;
            let _ = sched.terminate_task(idx);
        }
    }
    loop {
        unsafe {
            core::arch::asm!("sti; hlt", options(nomem, nostack));
        }
    }
}

/// Initialize the task management subsystem with the initial kernel task (TID 1).
pub fn init(initial_rsp: u64) {
    let cpu_index = current_cpu_index()
        .unwrap_or_else(|| panic!("BSP APIC ID is absent from the discovered CPU table"));
    initialize_idle_context(cpu_index);
    let mut sched = SCHEDULER.lock();
    let mut threads = THREADS.lock();

    // Register initial boot thread (TID 1, Root Kernel)
    let slot = 0;
    threads[slot] = Thread {
        tid: 1,
        name: "kernel-init",
        saved_rsp: initial_rsp,
        stack_top: initial_rsp,
        fpu: FpuState::initial(),
        cr3: 0,
        in_use: true,
    };

    let _ = sched.create_task(1, QoSClass::UserInteractive, slot as u64);
    let _ = sched.enqueue_ready(slot);
    let _ = sched.schedule_on_cpu(cpu_index);
    CPU_CURRENT_TID[cpu_index].store(1, Ordering::Release);
    if !crate::arch::x86_64::syscall::set_current_kernel_stack_top(initial_rsp) {
        panic!("task: failed to install the BSP syscall stack");
    }
}

/// Spawn a new kernel thread with its own 16 KiB stack, preemption context, and QoS priority.
pub fn spawn_kernel_thread(
    name: &'static str,
    qos: QoSClass,
    entry: extern "C" fn(u64),
    arg: u64,
) -> Result<u32, SchedError> {
    let mut sched = SCHEDULER.lock();
    let mut threads = THREADS.lock();
    let mut stacks = THREAD_STACKS.lock();

    let slot = threads.iter().position(|t| !t.in_use).ok_or(SchedError::TableFull)?;
    let tid = (slot as u32) + 2;

    let stack_ref = &mut stacks[slot];
    let stack_top = (stack_ref.stack_memory.as_ptr() as u64) + (KERNEL_STACK_SIZE as u64);

    // Initial frame layout for _isr32 context restore:
    // 20 u64 entries (160 bytes):
    // [0..14]: r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax
    // [15]: rip
    // [16]: cs
    // [17]: rflags
    // [18]: rsp
    // [19]: ss
    let initial_frame_size = 20 * 8;
    let saved_rsp = stack_top - initial_frame_size;
    let frame_ptr = saved_rsp as *mut u64;

    unsafe {
        // GPRs: r15..r8, rbp
        core::ptr::write_bytes(frame_ptr, 0, 9);
        // rdi = entry function pointer
        core::ptr::write_volatile(frame_ptr.add(9), entry as usize as u64);
        // rsi = argument
        core::ptr::write_volatile(frame_ptr.add(10), arg);
        // rdx, rcx, rbx, rax
        core::ptr::write_volatile(frame_ptr.add(11), 0);
        core::ptr::write_volatile(frame_ptr.add(12), 0);
        core::ptr::write_volatile(frame_ptr.add(13), 0);
        core::ptr::write_volatile(frame_ptr.add(14), 0);

        // RIP -> thread_entry_stub
        core::ptr::write_volatile(frame_ptr.add(15), thread_entry_stub as *const () as usize as u64);
        // CS
        core::ptr::write_volatile(frame_ptr.add(16), KERNEL_CODE_SELECTOR as u64);
        // RFLAGS (IF=1, bit 1=1 -> 0x202)
        core::ptr::write_volatile(frame_ptr.add(17), 0x202);
        // RSP
        core::ptr::write_volatile(frame_ptr.add(18), stack_top);
        // SS
        core::ptr::write_volatile(frame_ptr.add(19), KERNEL_DATA_SELECTOR as u64);
    }

    threads[slot] = Thread {
        tid,
        name,
        saved_rsp,
        stack_top,
        fpu: FpuState::initial(),
        cr3: 0,
        in_use: true,
    };

    let task_idx = sched.create_task(tid, qos, slot as u64)?;
    sched.enqueue_ready(task_idx)?;

    Ok(tid)
}

/// Invoked from timer ISR `_isr32` on every timer tick.
/// Saves incoming thread registers, checks QoS schedule, performs context switch if planned,
/// and returns the RSP to restore.
pub fn on_timer_tick(
    incoming_rsp: u64,
    incoming_fpu: &FpuState,
    elapsed_us: u32,
    next_fpu_out: &mut *const FpuState,
) -> u64 {
    // Keep the interrupted state as the fail-closed default. The Rust handler
    // may use XMM registers; `_isr32` restores this image after the handler.
    *next_fpu_out = incoming_fpu;
    let Some(cpu_index) = current_cpu_index() else {
        kprintln!("[sched] Timer arrived on an unknown CPU; halting.");
        crate::arch::shutdown(true);
    };
    let mut sched = SCHEDULER.lock();
    let mut threads = THREADS.lock();

    let plan = sched.plan_context_switch_on_cpu(cpu_index, elapsed_us);

    match plan {
        Some(p) => {
            if let Some(prev_idx) = p.prev_task_idx {
                if let Some(prev_thread) = threads.get_mut(prev_idx) {
                    if prev_thread.in_use {
                        prev_thread.saved_rsp = incoming_rsp;
                        prev_thread.fpu = *incoming_fpu;
                    }
                }
            }

            match p.target {
                ContextSwitchTarget::Task { task_idx, cr3, .. } => {
                    if let Some(next_thread) = threads.get_mut(task_idx) {
                        if next_thread.in_use {
                            *next_fpu_out = &next_thread.fpu;
                            set_tss_rsp0(next_thread.stack_top);
                            if !crate::arch::x86_64::syscall::set_current_kernel_stack_top(next_thread.stack_top) {
                                kprintln!("[sched] CPU {} has no valid syscall stack for TID {}; halting.", cpu_index, next_thread.tid);
                                crate::arch::shutdown(true);
                            }
                            CPU_CURRENT_TID[cpu_index].store(next_thread.tid, Ordering::Release);
                            if cr3 != 0 {
                                unsafe {
                                    core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack));
                                }
                            }
                            PREEMPTION_COUNT.fetch_add(1, Ordering::Relaxed);
                            return next_thread.saved_rsp;
                        }
                    }
                    kprintln!("[sched] Selected task {} has no live kernel thread; halting.", task_idx);
                    crate::arch::shutdown(true)
                }
                ContextSwitchTarget::Idle => {
                    PREEMPTION_COUNT.fetch_add(1, Ordering::Relaxed);
                    switch_to_idle(cpu_index)
                }
            }
        }
        None => {
            if let Some(curr_tcb) = sched.current_task_on_cpu(cpu_index) {
                let slot = curr_tcb.context_handle as usize;
                if let Some(thread) = threads.get_mut(slot) {
                    thread.saved_rsp = incoming_rsp;
                    thread.fpu = *incoming_fpu;
                }
                incoming_rsp
            } else if CPU_CURRENT_TID[cpu_index].load(Ordering::Acquire) != 0 {
                // A terminated task may already have cleared the scheduler's
                // current slot. Do not resume it just because no task is ready.
                switch_to_idle(cpu_index)
            } else {
                // The processor was already executing on its idle context.
                incoming_rsp
            }
        }
    }
}

/// Schedule the next runnable task from the supervisor software-reschedule
/// interrupt used by SYS_YIELD. The interrupt frame lives on this thread's
/// kernel stack and becomes its saved context if another task is selected.
pub fn on_voluntary_yield(
    incoming_rsp: u64,
    incoming_fpu: &FpuState,
    next_fpu_out: &mut *const FpuState,
) -> u64 {
    *next_fpu_out = incoming_fpu;
    let Some(cpu_index) = current_cpu_index() else {
        kprintln!("[sched] Yield arrived on an unknown CPU; halting.");
        crate::arch::shutdown(true);
    };
    let mut sched = SCHEDULER.lock();
    let mut threads = THREADS.lock();
    let plan = match sched.plan_voluntary_yield_on_cpu(cpu_index) {
        Ok(plan) => plan,
        Err(error) => {
            kprintln!("[sched] CPU {} voluntary yield planning failed: {:?}; halting.", cpu_index, error);
            crate::arch::shutdown(true);
        }
    };

    let Some(plan) = plan else {
        return incoming_rsp;
    };
    if let Some(prev_idx) = plan.prev_task_idx {
        if let Some(prev_thread) = threads.get_mut(prev_idx) {
            if prev_thread.in_use {
                prev_thread.saved_rsp = incoming_rsp;
                prev_thread.fpu = *incoming_fpu;
            }
        }
    }

    match plan.target {
        ContextSwitchTarget::Task { task_idx, cr3, .. } => {
            if let Some(next_thread) = threads.get_mut(task_idx) {
                if next_thread.in_use {
                    *next_fpu_out = &next_thread.fpu;
                    set_tss_rsp0(next_thread.stack_top);
                    if !crate::arch::x86_64::syscall::set_current_kernel_stack_top(next_thread.stack_top) {
                        kprintln!("[sched] CPU {} has no valid syscall stack for yielded TID {}; halting.", cpu_index, next_thread.tid);
                        crate::arch::shutdown(true);
                    }
                    CPU_CURRENT_TID[cpu_index].store(next_thread.tid, Ordering::Release);
                    if cr3 != 0 {
                        unsafe {
                            core::arch::asm!("mov cr3, {0}", in(reg) cr3, options(nostack));
                        }
                    }
                    PREEMPTION_COUNT.fetch_add(1, Ordering::Relaxed);
                    return next_thread.saved_rsp;
                }
            }
            kprintln!("[sched] Voluntary yield selected task {} without a live thread; halting.", task_idx);
            crate::arch::shutdown(true)
        }
        ContextSwitchTarget::Idle => {
            PREEMPTION_COUNT.fetch_add(1, Ordering::Relaxed);
            switch_to_idle(cpu_index)
        }
    }
}
