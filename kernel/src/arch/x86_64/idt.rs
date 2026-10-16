//! x86-64 IDT — Interrupt Descriptor Table.
//! Installs handlers for all 32 CPU exceptions. Any unexpected exception
//! prints full CPU state and halts (fail-closed). This is the x86-64 equivalent
//! of the RISC-V trap vector built in the original capkern.
#![allow(unsafe_code)]
use core::arch::global_asm;

const IDT_ENTRIES: usize = 256;

/// An IDT gate descriptor (16 bytes in 64-bit mode).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IdtGate {
    offset_lo: u16,
    selector:  u16,
    ist:       u8,
    attr:      u8,   // type + DPL + present
    offset_mid: u16,
    offset_hi:  u32,
    _zero:      u32,
}

impl IdtGate {
    const fn interrupt_gate(handler: u64, ist: u8) -> Self {
        IdtGate {
            offset_lo:  (handler & 0xFFFF) as u16,
            selector:   0x08, // kernel code segment
            ist,
            attr:       0x8E, // P=1 DPL=0 type=0b1110 (64-bit interrupt gate)
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_hi:  ((handler >> 32) & 0xFFFF_FFFF) as u32,
            _zero:      0,
        }
    }
}

#[repr(C, align(16))]
struct Idt([IdtGate; IDT_ENTRIES]);

static mut IDT: Idt = Idt([IdtGate {
    offset_lo: 0, selector: 0, ist: 0, attr: 0,
    offset_mid: 0, offset_hi: 0, _zero: 0,
}; IDT_ENTRIES]);

#[repr(C, packed)]
struct IdtPointer { limit: u16, base: u64 }

/// CPU state pushed by the exception stubs below.
#[repr(C)]
pub struct ExceptionFrame {
    // Saved by stub (in reverse push order)
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9:  u64, pub r8:  u64,
    pub rdi: u64, pub rsi: u64, pub rbp: u64, pub rdx: u64,
    pub rcx: u64, pub rbx: u64, pub rax: u64,
    // Exception vector and error code (inserted by stub)
    pub vector: u64,
    pub error:  u64,
    // Pushed automatically by the CPU
    pub rip: u64, pub cs: u64, pub rflags: u64, pub rsp: u64, pub ss: u64,
}

// Exception names for the panic banner.
static EXCEPTION_NAMES: [&str; 32] = [
    "#DE Divide Error",         "#DB Debug",
    "#NMI Non-Maskable Interrupt","#BP Breakpoint",
    "#OF Overflow",             "#BR Bound Range",
    "#UD Invalid Opcode",       "#NM Device Not Available",
    "#DF Double Fault",         "#CS Coprocessor Segment Overrun",
    "#TS Invalid TSS",          "#NP Segment Not Present",
    "#SS Stack Fault",          "#GP General Protection",
    "#PF Page Fault",           "#15 Reserved",
    "#MF x87 FP Error",         "#AC Alignment Check",
    "#MC Machine Check",        "#XM SIMD FP Error",
    "#VE Virtualisation",       "#CP Control Protection",
    "#22","#23","#24","#25","#26","#27",
    "#HV Hypervisor Injection", "#VC VMM Communication",
    "#SX Security",             "#31 Reserved",
];

/// Common C handler called from every exception stub.
#[no_mangle]
pub extern "C" fn x86_exception_handler(frame: &ExceptionFrame) -> ! {
    let vec = frame.vector as usize;
    let name = if vec < 32 { EXCEPTION_NAMES[vec] } else { "#?? Unknown" };
    kprintln!("\n[EXCEPTION] {} (vector={:#x} err={:#x})", name, vec, frame.error);
    kprintln!("  RIP={:#018x}  RSP={:#018x}  RFLAGS={:#018x}",
              frame.rip, frame.rsp, frame.rflags);
    kprintln!("  RAX={:#018x}  RBX={:#018x}  RCX={:#018x}  RDX={:#018x}",
              frame.rax, frame.rbx, frame.rcx, frame.rdx);
    kprintln!("  RSI={:#018x}  RDI={:#018x}  RBP={:#018x}",
              frame.rsi, frame.rdi, frame.rbp);
    kprintln!("  R8 ={:#018x}  R9 ={:#018x}  R10={:#018x}  R11={:#018x}",
              frame.r8, frame.r9, frame.r10, frame.r11);
    kprintln!("  R12={:#018x}  R13={:#018x}  R14={:#018x}  R15={:#018x}",
              frame.r12, frame.r13, frame.r14, frame.r15);
    kprintln!("  CS={:#06x}  SS={:#06x}", frame.cs, frame.ss);
    kprintln!("[EXCEPTION] Halting — fail closed.");
    crate::arch::shutdown(true)
}

static TIMER_TICKS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed)
}

#[no_mangle]
pub extern "C" fn x86_timer_handler() {
    TIMER_TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    super::apic::eoi();
}

// ── Assembly stubs ────────────────────────────────────────────────────────────
// Each exception gets a stub that pushes a dummy error code (if none), pushes
// the vector number, saves all GPRs, and calls x86_exception_handler.
//
// Macros: isr_no_err!(n) for exceptions without an error code,
//         isr_err!(n)    for exceptions that push an error code automatically.
global_asm!(r#"
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

/* Timer (IRQ 0, vector 32) */
.global _isr32
_isr32:
    push rax ; push rcx ; push rdx ; push rsi ; push rdi
    push r8  ; push r9  ; push r10 ; push r11
    cld
    call x86_timer_handler
    pop r11  ; pop r10 ; pop r9  ; pop r8
    pop rdi  ; pop rsi ; pop rdx ; pop rcx ; pop rax
    iretq

_isr_common:
    /* Save all GPRs (rsp is stale here — CPU pushed it above) */
    push rax ; push rbx ; push rcx ; push rdx
    push rbp ; push rsi ; push rdi
    push r8  ; push r9  ; push r10 ; push r11
    push r12 ; push r13 ; push r14 ; push r15
    mov  rdi, rsp               /* arg0 = &ExceptionFrame */
    call x86_exception_handler
    /* never returns */

"#);

extern "C" {
    fn _isr0();  fn _isr1();  fn _isr2();  fn _isr3();
    fn _isr4();  fn _isr5();  fn _isr6();  fn _isr7();
    fn _isr8();  fn _isr9();  fn _isr10(); fn _isr11();
    fn _isr12(); fn _isr13(); fn _isr14(); fn _isr15();
    fn _isr16(); fn _isr17(); fn _isr18(); fn _isr19();
    fn _isr20(); fn _isr21(); fn _isr22(); fn _isr23();
    fn _isr24(); fn _isr25(); fn _isr26(); fn _isr27();
    fn _isr28(); fn _isr29(); fn _isr30(); fn _isr31();
    fn _isr32();
}

/// Install the IDT and enable interrupts.
pub fn init() {
    let raw_handlers: [unsafe extern "C" fn(); 33] = [
        _isr0,  _isr1,  _isr2,  _isr3,
        _isr4,  _isr5,  _isr6,  _isr7,
        _isr8,  _isr9,  _isr10, _isr11,
        _isr12, _isr13, _isr14, _isr15,
        _isr16, _isr17, _isr18, _isr19,
        _isr20, _isr21, _isr22, _isr23,
        _isr24, _isr25, _isr26, _isr27,
        _isr28, _isr29, _isr30, _isr31,
        _isr32,
    ];
    unsafe {
        for (i, &h) in raw_handlers.iter().enumerate() {
            let addr = h as *const () as usize as u64;
            // Vector 8 (#DF Double Fault) uses dedicated IST 1 stack from TSS
            let ist = if i == 8 { 1 } else { 0 };
            IDT.0[i] = IdtGate::interrupt_gate(addr, ist);
        }
        let ptr = IdtPointer {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base:  core::ptr::addr_of!(IDT) as u64,
        };
        // SAFETY: installing a well-formed IDT with valid handlers.
        core::arch::asm!("lidt [{0}]", in(reg) &ptr, options(nostack, preserves_flags));
    }
    kprintln!("[idt] 33 gates installed (vectors 0..32)");
}
