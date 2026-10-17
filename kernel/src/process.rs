//! High-Assurance Process Lifecycle & Fault Containment Subsystem.
//!
//! Manages:
//! - Process Control Blocks (PCBs) with isolated CR3 address spaces and dedicated kernel stacks.
//! - Process state machine (Ready, Running, Blocked, Zombie).
//! - Clean termination and exit code tracking.
//! - Sandboxed fault containment: a faulting user application (SIGSEGV, null deref,
//!   illegal opcode) is terminated safely without panicking the microkernel.
#![allow(unsafe_code)]

use crate::arch::x86_64::fpu::FpuState;
use crate::arch::x86_64::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};
use crate::elf::{load_elf, LoadedProcess};
use crate::mmu::BumpFrameAllocator;
use crate::sync::TicketSpinLock;
use crate::task::{current_tid, exit_current_thread, Thread, KERNEL_STACK_SIZE, SCHEDULER, THREADS, THREAD_STACKS};
use kscheduler::{QoSClass, SchedError, MAX_TASKS};
use kcore::{Cap, CapSpace, Rights};
use core::sync::atomic::{AtomicU32, Ordering};

pub const MAX_PROCESSES: usize = MAX_TASKS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Ready,
    Running,
    Blocked,
    Zombie(i32),
}

pub struct ProcessControlBlock {
    pub pid: u32,
    pub name: &'static str,
    pub cr3: u64,
    pub state: ProcessState,
    pub exit_code: Option<i32>,
    pub entry_point: u64,
    pub user_stack_top: u64,
    pub in_use: bool,
}

impl ProcessControlBlock {
    pub const fn empty() -> Self {
        ProcessControlBlock {
            pid: 0,
            name: "",
            cr3: 0,
            state: ProcessState::Ready,
            exit_code: None,
            entry_point: 0,
            user_stack_top: 0,
            in_use: false,
        }
    }
}

pub static PROCESS_TABLE: TicketSpinLock<[ProcessControlBlock; MAX_PROCESSES]> =
    TicketSpinLock::new([const { ProcessControlBlock::empty() }; MAX_PROCESSES]);

pub static PROCESS_CSPACES: TicketSpinLock<[CapSpace<64>; MAX_PROCESSES]> =
    TicketSpinLock::new([const { CapSpace::<64>::new() }; MAX_PROCESSES]);

static NEXT_PID: AtomicU32 = AtomicU32::new(10);
static FAULT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Spawns an unprivileged Ring 3 user process from an ELF64 binary image.
pub fn spawn_user_elf<F: kpaging::FrameAllocator>(
    name: &'static str,
    elf_data: &[u8],
    allocator: &mut F,
    qos: QoSClass,
) -> Result<u32, &'static str> {
    let mut kernel_cr3: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) kernel_cr3, options(nostack));
    }

    let loaded = load_elf(elf_data, allocator, kernel_cr3)
        .map_err(|_| "ELF loading or verification failed")?;

    spawn_user_process(name, loaded, qos)
}

/// Registers and schedules a loaded user process with pre-allocated PML4 and stack.
pub fn spawn_user_process(
    name: &'static str,
    loaded: LoadedProcess,
    qos: QoSClass,
) -> Result<u32, &'static str> {
    let mut sched = SCHEDULER.lock();
    let mut threads = THREADS.lock();
    let mut stacks = THREAD_STACKS.lock();
    let mut pcb_table = PROCESS_TABLE.lock();

    let slot = threads.iter().position(|t| !t.in_use).ok_or("Thread table full")?;
    let pid = NEXT_PID.fetch_add(1, Ordering::Relaxed);

    let stack_ref = &mut stacks[slot];
    let stack_top = (stack_ref.stack_memory.as_ptr() as u64) + (KERNEL_STACK_SIZE as u64);

    // Initial frame layout for _isr32 context restore into user mode:
    // 20 u64 entries (160 bytes):
    // [0..14]: r15..r8, rbp, rdi, rsi, rdx, rcx, rbx, rax (all 0)
    // [15]: rip -> loaded.entry_point
    // [16]: cs  -> USER_CODE_SELECTOR (0x23: RPL=3)
    // [17]: rflags -> 0x202 (IF=1, bit 1=1)
    // [18]: rsp -> loaded.user_stack_top
    // [19]: ss  -> USER_DATA_SELECTOR (0x1B: RPL=3)
    let initial_frame_size = 20 * 8;
    let saved_rsp = stack_top - initial_frame_size;
    let frame_ptr = saved_rsp as *mut u64;

    unsafe {
        core::ptr::write_bytes(frame_ptr, 0, 15);
        // RIP -> user entry point
        core::ptr::write_volatile(frame_ptr.add(15), loaded.entry_point);
        // CS -> User Code Selector (0x23)
        core::ptr::write_volatile(frame_ptr.add(16), USER_CODE_SELECTOR as u64);
        // RFLAGS -> IF=1 (0x202)
        core::ptr::write_volatile(frame_ptr.add(17), 0x202);
        // RSP -> User Stack Top
        core::ptr::write_volatile(frame_ptr.add(18), loaded.user_stack_top);
        // SS -> User Data Selector (0x1B)
        core::ptr::write_volatile(frame_ptr.add(19), USER_DATA_SELECTOR as u64);
    }

    threads[slot] = Thread {
        tid: pid,
        name,
        saved_rsp,
        stack_top,
        fpu: FpuState::empty(),
        cr3: loaded.cr3,
        in_use: true,
    };

    pcb_table[slot] = ProcessControlBlock {
        pid,
        name,
        cr3: loaded.cr3,
        state: ProcessState::Ready,
        exit_code: None,
        entry_point: loaded.entry_point,
        user_stack_top: loaded.user_stack_top,
        in_use: true,
    };

    // Initialize per-process Capability Space (CSpace) with seL4-style authority
    {
        let mut cspaces = PROCESS_CSPACES.lock();
        let mut cs = CapSpace::<64>::new();
        let untyped_base = 0x3000_0000u64 + ((pid as u64) * 0x1_0000u64);
        if let Ok(ut) = Cap::new_untyped(untyped_base, 16) {
            let _ = cs.install_root(0, ut);
        }
        let _ = cs.install_transferred(1, Cap::new_tcb(pid as u64, Rights::ALL));
        let _ = cs.install_transferred(2, Cap::new_frame(loaded.cr3, Rights::ALL));
        let _ = cs.install_transferred(3, Cap::new_endpoint(pid as u64, Rights::ALL, pid as u64));
        cspaces[slot] = cs;
    }

    let task_idx = sched.create_task_with_vspace(pid, qos, slot as u64, loaded.cr3, stack_top)
        .map_err(|_| "Scheduler task creation failed")?;
    sched.enqueue_ready(task_idx)
        .map_err(|_| "Failed to enqueue task")?;

    Ok(pid)
}

/// Invoked when a user process voluntarily exits via `sys_exit(code)`.
pub fn exit_process(exit_code: i32) -> ! {
    let pid = current_tid();
    crate::kprintln!("[process] PID {} exited voluntarily with status {}", pid, exit_code);
    {
        let mut pcb_table = PROCESS_TABLE.lock();
        if let Some(pcb) = pcb_table.iter_mut().find(|p| p.in_use && p.pid == pid) {
            pcb.state = ProcessState::Zombie(exit_code);
            pcb.exit_code = Some(exit_code);
        }
    }
    {
        let mut cspaces = PROCESS_CSPACES.lock();
        let idx = (pid as usize) % MAX_PROCESSES;
        let _ = cspaces[idx].revoke(0);
        cspaces[idx] = CapSpace::new();
    }
    exit_current_thread()
}

/// Invoked from the hardware exception handler when a Ring 3 user process faults.
/// Enforces fault containment: marks process as dead, increments fault counter,
/// and yields to the next ready task.
pub fn on_user_process_fault(pid: u32, exit_code: i32) {
    FAULT_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::kprintln!("[process] Fault containment: PID {} terminated with signal {} (#PF/#GP)", pid, exit_code);
    {
        let mut pcb_table = PROCESS_TABLE.lock();
        if let Some(pcb) = pcb_table.iter_mut().find(|p| p.in_use && p.pid == pid) {
            pcb.state = ProcessState::Zombie(exit_code);
            pcb.exit_code = Some(exit_code);
        }
    }
    let restarted = crate::driver::DRIVER_SUPERVISOR.lock().handle_driver_fault(pid, exit_code);
    if restarted.is_none() {
        let mut cspaces = PROCESS_CSPACES.lock();
        let idx = (pid as usize) % MAX_PROCESSES;
        let _ = cspaces[idx].revoke(0);
        cspaces[idx] = CapSpace::new();
    }
    {
        let mut sched = SCHEDULER.lock();
        let mut threads = THREADS.lock();
        if let Some((idx, t)) = threads.iter_mut().enumerate().find(|(_, t)| t.in_use && t.tid == pid) {
            t.in_use = false;
            let _ = sched.terminate_task(idx);
        }
    }
}

/// Return total number of contained user-mode faults observed.
pub fn user_fault_count() -> u32 {
    FAULT_COUNT.load(Ordering::Relaxed)
}

/// Trampoline called when redirecting a faulting user-mode thread back into the scheduler.
pub extern "C" fn user_fault_terminate_trampoline() -> ! {
    loop {
        unsafe {
            core::arch::asm!("sti; hlt", options(nomem, nostack));
        }
    }
}
