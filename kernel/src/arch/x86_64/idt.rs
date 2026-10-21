//! x86-64 IDT — Interrupt Descriptor Table.
//! Installs handlers for all 32 CPU exceptions. Any unexpected exception
//! prints full CPU state and halts (fail-closed). This is the x86-64 equivalent
//! of the RISC-V trap vector built in the original capkern.
#![allow(unsafe_code)]
use super::fpu::FpuState;
use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const IDT_ENTRIES: usize = 256;

/// An IDT gate descriptor (16 bytes in 64-bit mode).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IdtGate {
    offset_lo: u16,
    selector: u16,
    ist: u8,
    attr: u8, // type + DPL + present
    offset_mid: u16,
    offset_hi: u32,
    _zero: u32,
}

impl IdtGate {
    const fn interrupt_gate(handler: u64, ist: u8) -> Self {
        IdtGate {
            offset_lo: (handler & 0xFFFF) as u16,
            selector: 0x08, // kernel code segment
            ist,
            attr: 0x8E, // P=1 DPL=0 type=0b1110 (64-bit interrupt gate)
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_hi: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _zero: 0,
        }
    }
}

#[repr(C, align(16))]
struct Idt([IdtGate; IDT_ENTRIES]);

impl Idt {
    const fn new() -> Self {
        Self(
            [IdtGate {
                offset_lo: 0,
                selector: 0,
                ist: 0,
                attr: 0,
                offset_mid: 0,
                offset_hi: 0,
                _zero: 0,
            }; IDT_ENTRIES],
        )
    }
}

struct CpuInterruptState {
    idt: Idt,
    expected_fault: AtomicBool,
    expected_fault_rip: AtomicU64,
    fault_caught: AtomicBool,
    fault_recovery_rip: AtomicU64,
    user_fault_recovery_rip: AtomicU64,
    timer_ticks: AtomicU64,
}

impl CpuInterruptState {
    const fn new() -> Self {
        Self {
            idt: Idt::new(),
            expected_fault: AtomicBool::new(false),
            expected_fault_rip: AtomicU64::new(0),
            fault_caught: AtomicBool::new(false),
            fault_recovery_rip: AtomicU64::new(0),
            user_fault_recovery_rip: AtomicU64::new(0),
            timer_ticks: AtomicU64::new(0),
        }
    }
}

static mut CPU_INTERRUPT_STATE: [CpuInterruptState; super::smp::MAX_CPUS] =
    [const { CpuInterruptState::new() }; super::smp::MAX_CPUS];
static CPU_IDT_READY: [AtomicBool; super::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; super::smp::MAX_CPUS];

fn cpu_interrupt_state(cpu_index: usize) -> Option<&'static CpuInterruptState> {
    if cpu_index >= super::smp::MAX_CPUS || !CPU_IDT_READY[cpu_index].load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: readiness is published only after this CPU's immutable IDT is
    // fully populated and loaded. The remaining fields are atomic.
    unsafe { Some(&*core::ptr::addr_of!(CPU_INTERRUPT_STATE[cpu_index])) }
}

fn current_cpu_interrupt_state() -> Option<&'static CpuInterruptState> {
    let apic_id = super::apic::current_id();
    let cpu_index = super::smp::cpu_index_for_apic_id(apic_id)?;
    cpu_interrupt_state(cpu_index)
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// CPU state pushed by the exception stubs below.
#[repr(C)]
pub struct ExceptionFrame {
    // Saved by stub (in reverse push order)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    // Exception vector and error code (inserted by stub)
    pub vector: u64,
    pub error: u64,
    // Pushed automatically by the CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// Exception names for the panic banner.
static EXCEPTION_NAMES: [&str; 32] = [
    "#DE Divide Error",
    "#DB Debug",
    "#NMI Non-Maskable Interrupt",
    "#BP Breakpoint",
    "#OF Overflow",
    "#BR Bound Range",
    "#UD Invalid Opcode",
    "#NM Device Not Available",
    "#DF Double Fault",
    "#CS Coprocessor Segment Overrun",
    "#TS Invalid TSS",
    "#NP Segment Not Present",
    "#SS Stack Fault",
    "#GP General Protection",
    "#PF Page Fault",
    "#15 Reserved",
    "#MF x87 FP Error",
    "#AC Alignment Check",
    "#MC Machine Check",
    "#XM SIMD FP Error",
    "#VE Virtualisation",
    "#CP Control Protection",
    "#22",
    "#23",
    "#24",
    "#25",
    "#26",
    "#27",
    "#HV Hypervisor Injection",
    "#VC VMM Communication",
    "#SX Security",
    "#31 Reserved",
];

/// Arms an expected deliberate fault (e.g. NX, SMEP, WP test) that recovers to `recovery_rip`.
pub fn set_expected_fault(fault_rip: u64, recovery_rip: u64) {
    let Some(state) = current_cpu_interrupt_state() else {
        return;
    };
    state
        .fault_recovery_rip
        .store(recovery_rip, Ordering::SeqCst);
    state.expected_fault_rip.store(fault_rip, Ordering::SeqCst);
    state.fault_caught.store(false, Ordering::SeqCst);
    state.expected_fault.store(true, Ordering::SeqCst);
}

/// Disarm a deliberate-fault expectation when the guarded instruction returns normally.
pub fn clear_expected_fault() {
    if let Some(state) = current_cpu_interrupt_state() {
        state.expected_fault.store(false, Ordering::SeqCst);
        state.expected_fault_rip.store(0, Ordering::SeqCst);
    }
}

/// Returns whether an armed deliberate fault was caught and logged.
pub fn was_fault_caught() -> bool {
    current_cpu_interrupt_state()
        .map(|state| state.fault_caught.load(Ordering::SeqCst))
        .unwrap_or(false)
}

/// Arms an expected user fault recovery target RIP for selftests.
pub fn set_user_fault_recovery(recovery_rip: u64) {
    if let Some(state) = current_cpu_interrupt_state() {
        state
            .user_fault_recovery_rip
            .store(recovery_rip, Ordering::SeqCst);
    }
}

/// Common C handler called from every exception stub.
#[no_mangle]
pub extern "C" fn x86_exception_handler(frame: &mut ExceptionFrame) {
    let vec = frame.vector as usize;
    let name = if vec < 32 {
        EXCEPTION_NAMES[vec]
    } else {
        "#?? Unknown"
    };

    let Some(state) = current_cpu_interrupt_state() else {
        kprintln!("[EXCEPTION] CPU has no initialized local interrupt state; halting.");
        crate::arch::shutdown(true);
    };

    if vec == 14
        && (frame.error & 0b111) == 0b011
        && state.expected_fault.load(Ordering::SeqCst)
        && frame.rip == state.expected_fault_rip.load(Ordering::SeqCst)
    {
        state.expected_fault.store(false, Ordering::SeqCst);
        kprintln!("\n[security] deliberate {} violation caught and logged (vector={:#x} err={:#x} fault_rip={:#018x})",
                  name, vec, frame.error, frame.rip);
        state.fault_caught.store(true, Ordering::SeqCst);
        frame.rip = state.fault_recovery_rip.load(Ordering::SeqCst);
        return;
    }

    let is_user_mode = (frame.cs & 3) != 0;
    if is_user_mode {
        let pid = crate::task::current_tid();
        kprintln!(
            "\n[USER-FAULT] Exception in user mode process (PID {}): {} (vector={:#x} err={:#x})",
            pid,
            name,
            vec,
            frame.error
        );
        kprintln!(
            "  Faulting User RIP={:#018x} RSP={:#018x} RFLAGS={:#018x}",
            frame.rip,
            frame.rsp,
            frame.rflags
        );
        if vec == 14 {
            let cr2: u64;
            unsafe {
                core::arch::asm!("mov {0}, cr2", out(reg) cr2, options(nostack));
            }
            kprintln!("  Faulting Address (CR2)={:#018x}", cr2);
        }
        kprintln!("[USER-FAULT] Terminating faulting process safely (fail-closed) — microkernel continues running.");
        crate::process::on_user_process_fault(pid, -((vec as i32) + 1));

        let rec_rip = state.user_fault_recovery_rip.swap(0, Ordering::SeqCst);
        let target_rip = if rec_rip != 0 {
            rec_rip
        } else {
            crate::process::user_fault_terminate_trampoline as *const () as usize as u64
        };

        // Redirect execution to safe termination trampoline or test recovery in supervisor mode
        frame.rip = target_rip;
        frame.cs = super::gdt::KERNEL_CODE_SELECTOR as u64;
        frame.rflags = 0x202;
        frame.ss = super::gdt::KERNEL_DATA_SELECTOR as u64;
        frame.rsp = (frame as *const ExceptionFrame as u64) & !0xF;
        return;
    }

    kprintln!(
        "\n[KERNEL-PANIC] Unrecoverable Supervisor Exception: {} (vector={:#x} err={:#x})",
        name,
        vec,
        frame.error
    );
    kprintln!(
        "  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#018x}",
        frame.rip,
        frame.rsp,
        frame.rflags
    );
    kprintln!(
        "  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}  RDX={:#018x}",
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx
    );
    kprintln!(
        "  RSI={:#018x}  RDI={:#018x}  RBP={:#018x}",
        frame.rsi,
        frame.rdi,
        frame.rbp
    );
    kprintln!(
        "  R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}  R11={:#018x}",
        frame.r8,
        frame.r9,
        frame.r10,
        frame.r11
    );
    kprintln!(
        "  R12={:#018x}  R13={:#018x}  R14={:#018x}  R15={:#018x}",
        frame.r12,
        frame.r13,
        frame.r14,
        frame.r15
    );
    kprintln!("  CS={:#06x}  SS={:#06x}", frame.cs, frame.ss);
    kprintln!("[EXCEPTION] Halting — fail closed.");
    crate::arch::shutdown(true)
}

pub fn timer_ticks() -> u64 {
    current_cpu_interrupt_state()
        .map(|state| state.timer_ticks.load(Ordering::Relaxed))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn x86_timer_handler(
    incoming_rsp: u64,
    incoming_fpu: *const FpuState,
    next_fpu_out: *mut *const FpuState,
) -> u64 {
    // SAFETY: `_isr32` passes a 16-byte-aligned 512-byte FXSAVE image and a
    // writable pointer slot in its live interrupt stack frame.
    let incoming_fpu = unsafe { &*incoming_fpu };
    // SAFETY: `_isr32` passes the address of the pointer slot just beyond the
    // 512-byte FXSAVE image, which remains live until this handler returns.
    let next_fpu_out = unsafe { &mut *next_fpu_out };
    *next_fpu_out = incoming_fpu;
    if let Some(state) = current_cpu_interrupt_state() {
        state.timer_ticks.fetch_add(1, Ordering::Relaxed);
    } else {
        kprintln!("[IRQ] Timer arrived on a CPU without local interrupt state; halting.");
        crate::arch::shutdown(true);
    }
    super::apic::eoi();
    crate::task::on_timer_tick(incoming_rsp, incoming_fpu, 10_000, next_fpu_out)
}

#[no_mangle]
pub extern "C" fn x86_tlb_shootdown_handler() {
    super::smp::handle_tlb_shootdown();
}

// ── Assembly stubs ────────────────────────────────────────────────────────────
global_asm!(
    r#"
.macro isr_no_err vec
.global _isr\vec
_isr\vec:
    push 0          /* dummy error code */
    push \vec
    jmp  _isr_common
.endm

.macro isr_err vec
.global _isr\vec
_isr\vec:
    push \vec       /* error code already on stack from CPU */
    jmp  _isr_common
.endm

/* CPU exceptions 0–31 */
isr_no_err 0 ; isr_no_err 1 ; isr_no_err 2 ; isr_no_err 3
isr_no_err 4 ; isr_no_err 5 ; isr_no_err 6 ; isr_no_err 7
isr_err    8 ; isr_no_err 9
isr_err   10 ; isr_err   11 ; isr_err   12 ; isr_err   13 ; isr_err   14
isr_no_err 15; isr_no_err 16; isr_err   17 ; isr_no_err 18; isr_no_err 19
isr_no_err 20; isr_err   21 ; isr_no_err 22; isr_no_err 23; isr_no_err 24
isr_no_err 25; isr_no_err 26; isr_no_err 27; isr_no_err 28; isr_no_err 29
isr_err   30 ; isr_no_err 31

/* Timer (IRQ 0, vector 32) with preemption context switch */
.global _isr32
_isr32:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cld
    mov rdi, rsp
    and rsp, -16
    sub rsp, 528
    fxsave64 [rsp]
    mov rsi, rsp
    mov [rsp + 512], rsi
    lea rdx, [rsp + 512]
    call x86_timer_handler
    mov rsi, [rsp + 512]
    fxrstor64 [rsi]
    mov rsp, rax
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    iretq

/* TLB Shootdown (vector 251) */
.global _isr251
_isr251:
    push rax ; push rcx ; push rdx ; push rsi ; push rdi
    push r8  ; push r9  ; push r10 ; push r11
    cld
    call x86_tlb_shootdown_handler
    pop r11  ; pop r10 ; pop r9  ; pop r8
    pop rdi  ; pop rsi ; pop rdx ; pop rcx ; pop rax
    iretq

_isr_common:
    push rax ; push rbx ; push rcx ; push rdx
    push rbp ; push rsi ; push rdi
    push r8  ; push r9  ; push r10 ; push r11
    push r12 ; push r13 ; push r14 ; push r15
    mov  rdi, rsp               /* arg0 = &mut ExceptionFrame */
    call x86_exception_handler
    /* In case of deliberate expected fault recovery */
    pop r15 ; pop r14 ; pop r13 ; pop r12
    pop r11 ; pop r10 ; pop r9  ; pop r8
    pop rdi ; pop rsi ; pop rbp
    pop rdx ; pop rcx ; pop rbx ; pop rax
    add rsp, 16                 /* skip vector & error code */
    iretq
"#
);

extern "C" {
    fn _isr0();
    fn _isr1();
    fn _isr2();
    fn _isr3();
    fn _isr4();
    fn _isr5();
    fn _isr6();
    fn _isr7();
    fn _isr8();
    fn _isr9();
    fn _isr10();
    fn _isr11();
    fn _isr12();
    fn _isr13();
    fn _isr14();
    fn _isr15();
    fn _isr16();
    fn _isr17();
    fn _isr18();
    fn _isr19();
    fn _isr20();
    fn _isr21();
    fn _isr22();
    fn _isr23();
    fn _isr24();
    fn _isr25();
    fn _isr26();
    fn _isr27();
    fn _isr28();
    fn _isr29();
    fn _isr30();
    fn _isr31();
    fn _isr32();
    fn _isr251();
}

/// Build and load the IDT assigned to the current CPU.
pub fn init(cpu_index: usize) -> bool {
    if cpu_index >= super::smp::MAX_CPUS || CPU_IDT_READY[cpu_index].load(Ordering::Acquire) {
        return false;
    }
    let raw_handlers: [unsafe extern "C" fn(); 33] = [
        _isr0, _isr1, _isr2, _isr3, _isr4, _isr5, _isr6, _isr7, _isr8, _isr9, _isr10, _isr11,
        _isr12, _isr13, _isr14, _isr15, _isr16, _isr17, _isr18, _isr19, _isr20, _isr21, _isr22,
        _isr23, _isr24, _isr25, _isr26, _isr27, _isr28, _isr29, _isr30, _isr31, _isr32,
    ];
    unsafe {
        let idt = core::ptr::addr_of_mut!(CPU_INTERRUPT_STATE[cpu_index].idt);
        for (i, &h) in raw_handlers.iter().enumerate() {
            let addr = h as *const () as usize as u64;
            // Dedicated IST stacks (Part A9):
            // Vector 8 (#DF Double Fault) -> IST 1
            // Vector 2 (#NMI Non-Maskable Interrupt) -> IST 2
            // Vector 18 (#MC Machine Check) -> IST 3
            let ist = if i == 8 {
                1
            } else if i == 2 {
                2
            } else if i == 18 {
                3
            } else {
                0
            };
            (*idt).0[i] = IdtGate::interrupt_gate(addr, ist);
        }

        // Install Vector 251 for SMP TLB shootdown
        (*idt).0[251] = IdtGate::interrupt_gate(_isr251 as *const () as usize as u64, 0);

        let ptr = IdtPointer {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: idt as u64,
        };
        // SAFETY: installing a well-formed IDT with valid handlers.
        core::arch::asm!("lidt [{0}]", in(reg) &ptr, options(nostack, preserves_flags));
        CPU_IDT_READY[cpu_index].store(true, Ordering::Release);
    }
    kprintln!("[idt] CPU {}: 34 gates installed (IST1: #DF, IST2: #NMI, IST3: #MC, Vector 251: TLB Shootdown)", cpu_index);
    true
}
