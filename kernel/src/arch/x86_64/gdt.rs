//! x86-64 GDT — CPU-local Global Descriptor Table and Task State Segment.
//!
//! Each initialized CPU owns its GDT, TSS, and IST stacks. AP startup remains
//! disabled until the IDT, syscall entry, and scheduler are CPU-local as well.
#![allow(unsafe_code)]

use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_DATA_SELECTOR: u16 = 0x18 | 3;
pub const USER_CODE_SELECTOR: u16 = 0x20 | 3;
pub const TSS_SELECTOR: u16 = 0x28;

pub const SEL_NULL: u16 = 0x00;
pub const SEL_CODE64: u16 = KERNEL_CODE_SELECTOR;
pub const SEL_DATA64: u16 = KERNEL_DATA_SELECTOR;
pub const SEL_TSS: u16 = TSS_SELECTOR;

#[repr(C, packed)]
pub struct TaskStateSegment {
    pub reserved_0: u32,
    pub rsp0: u64,
    pub rsp1: u64,
    pub rsp2: u64,
    pub reserved_1: u64,
    pub ist1: u64,
    pub ist2: u64,
    pub ist3: u64,
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    pub reserved_2: u64,
    pub reserved_3: u16,
    pub iomap_base: u16,
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        Self {
            reserved_0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved_1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            reserved_2: 0,
            reserved_3: 0,
            iomap_base: size_of::<Self>() as u16,
        }
    }
}

pub type Tss = TaskStateSegment;

#[repr(C, packed)]
pub struct Gdt {
    pub null: u64,
    pub kernel_code: u64,
    pub kernel_data: u64,
    pub user_data: u64,
    pub user_code: u64,
    pub tss_low: u64,
    pub tss_high: u64,
}

impl Gdt {
    const fn new() -> Self {
        Self {
            null: 0,
            kernel_code: 0x00AF_9A00_0000_FFFF,
            kernel_data: 0x00CF_9200_0000_FFFF,
            user_data: 0x00CF_F200_0000_FFFF,
            user_code: 0x00AF_FA00_0000_FFFF,
            tss_low: 0,
            tss_high: 0,
        }
    }
}

#[repr(C, align(4096))]
struct IstStack([u8; 8192]);

struct CpuGdtState {
    gdt: Gdt,
    tss: TaskStateSegment,
    double_fault_stack: IstStack,
    nmi_stack: IstStack,
    machine_check_stack: IstStack,
}

impl CpuGdtState {
    const fn new() -> Self {
        Self {
            gdt: Gdt::new(),
            tss: TaskStateSegment::new(),
            double_fault_stack: IstStack([0; 8192]),
            nmi_stack: IstStack([0; 8192]),
            machine_check_stack: IstStack([0; 8192]),
        }
    }
}

static mut CPU_GDT: [CpuGdtState; crate::arch::x86_64::smp::MAX_CPUS] =
    [const { CpuGdtState::new() }; crate::arch::x86_64::smp::MAX_CPUS];
static CPU_GDT_READY: [AtomicBool; crate::arch::x86_64::smp::MAX_CPUS] =
    [const { AtomicBool::new(false) }; crate::arch::x86_64::smp::MAX_CPUS];

#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

/// Initialize and install the GDT and TSS for one CPU.
///
/// `cpu_index` must be the slot assigned by `smp::init`. This installs only
/// the current CPU's tables; it does not start or enable any secondary CPU.
pub fn init(kernel_stack_top: u64, cpu_index: usize) -> bool {
    if cpu_index >= crate::arch::x86_64::smp::MAX_CPUS {
        return false;
    }

    unsafe {
        let state = core::ptr::addr_of_mut!(CPU_GDT[cpu_index]);
        (*state).tss.rsp0 = kernel_stack_top;
        (*state).tss.ist1 = core::ptr::addr_of!((*state).double_fault_stack) as u64 + 8192;
        (*state).tss.ist2 = core::ptr::addr_of!((*state).nmi_stack) as u64 + 8192;
        (*state).tss.ist3 = core::ptr::addr_of!((*state).machine_check_stack) as u64 + 8192;

        let tss_ptr = core::ptr::addr_of!((*state).tss) as u64;
        let tss_size = (size_of::<TaskStateSegment>() - 1) as u64;
        (*state).gdt.tss_low = (tss_size & 0xFFFF)
            | ((tss_ptr & 0x00FF_FFFF) << 16)
            | (0x89_u64 << 40)
            | ((tss_size & 0x000F_0000) << 32)
            | ((tss_ptr & 0xFF00_0000) << 32);
        (*state).gdt.tss_high = tss_ptr >> 32;

        let gdt_ptr = GdtPointer {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: core::ptr::addr_of!((*state).gdt) as u64,
        };

        core::arch::asm!(
            "lgdt [{ptr}]",
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ax, 0x28",
            "ltr ax",
            ptr = in(reg) &gdt_ptr,
            out("rax") _,
        );
        CPU_GDT_READY[cpu_index].store(true, Ordering::Release);
    }
    true
}

/// Update the current CPU's privilege-transition stack after a context switch.
pub fn set_tss_rsp0(rsp0: u64) {
    let apic_id = crate::arch::x86_64::apic::current_id();
    let Some(cpu_index) = crate::arch::x86_64::smp::cpu_index_for_apic_id(apic_id) else {
        return;
    };
    if !CPU_GDT_READY[cpu_index].load(Ordering::Acquire) {
        return;
    }
    unsafe {
        CPU_GDT[cpu_index].tss.rsp0 = rsp0;
    }
}
