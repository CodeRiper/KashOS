//! x86-64 GDT — Global Descriptor Table and Task State Segment (TSS).
//!
//! Provides hardware privilege boundaries between supervisor mode (Ring 0)
//! and unprivileged user space (Ring 3), as required for high-assurance isolation.
//!
//! Layout matches the exact order mandated by the x86-64 `sysretq` instruction:
//!   - 0x00: Null Descriptor
//!   - 0x08: 64-bit Kernel Code (Ring 0, DPL=0)
//!   - 0x10: 64-bit Kernel Data (Ring 0, DPL=0)
//!   - 0x18: 64-bit User Data   (Ring 3, DPL=3, selector 0x18 | 3 = 0x1B)
//!   - 0x20: 64-bit User Code   (Ring 3, DPL=3, selector 0x20 | 3 = 0x23)
//!   - 0x28: 64-bit TSS (16 bytes, covers 0x28 and 0x30)
#![allow(unsafe_code)]

use core::mem::size_of;

pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_DATA_SELECTOR: u16 = 0x18 | 3; // RPL = 3 (0x1B)
pub const USER_CODE_SELECTOR: u16 = 0x20 | 3; // RPL = 3 (0x23)
pub const TSS_SELECTOR: u16 = 0x28;

// Backward-compatibility aliases
pub const SEL_NULL:   u16 = 0x00;
pub const SEL_CODE64: u16 = KERNEL_CODE_SELECTOR;
pub const SEL_DATA64: u16 = KERNEL_DATA_SELECTOR;
pub const SEL_TSS:    u16 = TSS_SELECTOR;

/// 64-bit Task State Segment (TSS) holding privilege-level stacks and ISTs.
#[repr(C, packed)]
pub struct TaskStateSegment {
    pub reserved_0: u32,
    pub rsp0: u64, // Supervisor stack loaded on Ring 3 -> Ring 0 transitions
    pub rsp1: u64,
    pub rsp2: u64,
    pub reserved_1: u64,
    pub ist1: u64, // Dedicated Stack: Double Fault (#DF)
    pub ist2: u64, // Dedicated Stack: Non-Maskable Interrupt (#NMI)
    pub ist3: u64, // Dedicated Stack: Machine Check (#MC)
    pub ist4: u64,
    pub ist5: u64,
    pub ist6: u64,
    pub ist7: u64,
    pub reserved_2: u64,
    pub reserved_3: u16,
    pub iomap_base: u16, // I/O Permission Bit Map Offset
}

impl TaskStateSegment {
    pub const fn new() -> Self {
        TaskStateSegment {
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
            iomap_base: size_of::<TaskStateSegment>() as u16,
        }
    }
}

// Backward-compatibility alias
pub type Tss = TaskStateSegment;

/// 7-entry 64-bit GDT layout.
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

pub static mut GDT: Gdt = Gdt {
    null: 0,
    kernel_code: 0x00AF_9A00_0000_FFFF, // 64-bit Ring 0 Code (Executable, Readable, Long Mode)
    kernel_data: 0x00CF_9200_0000_FFFF, // 64-bit Ring 0 Data (Writable)
    user_data:   0x00CF_F200_0000_FFFF, // 64-bit Ring 3 Data (DPL=3, Writable)
    user_code:   0x00AF_FA00_0000_FFFF, // 64-bit Ring 3 Code (DPL=3, Executable, Long Mode)
    tss_low: 0,
    tss_high: 0,
};

#[repr(align(4096))]
#[allow(dead_code)]
struct DoubleFaultStack([u8; 8192]);
static mut DOUBLE_FAULT_STACK: DoubleFaultStack = DoubleFaultStack([0; 8192]);

pub static mut TSS: TaskStateSegment = TaskStateSegment::new();

/// GDTR descriptor format for `lgdt`.
#[repr(C, packed)]
struct GdtPointer {
    limit: u16,
    base: u64,
}

/// Initialize and install the complete GDT and TSS for supervisor and user mode.
pub fn init(kernel_stack_top: u64) {
    unsafe {
        // Point TSS RSP0 at supervisor stack for Ring 3 -> Ring 0 entries.
        TSS.rsp0 = kernel_stack_top;
        // Dedicated stack for Double Fault (#DF) exception handler (IST 1)
        TSS.ist1 = core::ptr::addr_of!(DOUBLE_FAULT_STACK) as u64 + 8192;

        let tss_ptr = core::ptr::addr_of!(TSS) as u64;
        let tss_size = (size_of::<TaskStateSegment>() - 1) as u64;

        // Construct 16-byte TSS descriptor in GDT
        GDT.tss_low = (tss_size & 0xFFFF)
            | ((tss_ptr & 0x00FF_FFFF) << 16)
            | (0x89_u64 << 40) // Present, 64-bit Available TSS (type=0b1001, DPL=0)
            | ((tss_size & 0x000F_0000) << 32)
            | ((tss_ptr & 0xFF00_0000) << 32);
        GDT.tss_high = tss_ptr >> 32;

        let gdt_ptr = GdtPointer {
            limit: (size_of::<Gdt>() - 1) as u16,
            base: core::ptr::addr_of!(GDT) as u64,
        };

        // Reload GDTR, reload code/data segments, and load Task Register (TR)
        core::arch::asm!(
            "lgdt [{ptr}]",
            // Reload CS via far return
            "push 0x08",
            "lea  rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            // Reload segment registers with Kernel Data (0x10)
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            // Load Task Register with TSS selector (0x28)
            "mov ax, 0x28",
            "ltr ax",
            ptr = in(reg) &gdt_ptr,
            out("rax") _,
        );
    }
}
