//! Fast System Call Subsystem & User Memory Validation (x86-64).
//!
//! Uses IA32_STAR, IA32_LSTAR, and IA32_FMASK for hardware fast-syscall transitions
//! via `syscall` / `sysretq`. Enforces strict canonical user memory boundaries
//! to prevent Confused Deputy privilege escalation attacks.
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU64, Ordering};

pub const IA32_STAR: u32  = 0xC000_0081;
pub const IA32_LSTAR: u32 = 0xC000_0082;
pub const IA32_FMASK: u32 = 0xC000_0084;

/// User space ceiling: unprivileged applications cannot touch addresses >= 0x0000_8000_0000_0000.
pub const USER_SPACE_CEILING: usize = 0x0000_7FFF_FFFF_FFFF;

/// System call error codes returned across the user boundary.
#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallError {
    Success = 0,
    InvalidMemoryAccess = -1,
    PrivilegeEscalationAttempted = -2,
    InvalidCapability = -3,
    InsufficientRights = -4,
    PledgeViolation = -5,
    NamespaceViolation = -6,
    InvalidArgument = -7,
    NoSuchSyscall = -8,
}

/// System call IDs.
pub mod nr {
    pub const SYS_CAP_INVOKE: usize = 1;
    pub const SYS_IPC_SEND:   usize = 2;
    pub const SYS_IPC_RECV:   usize = 3;
    pub const SYS_PLEDGE:     usize = 4;
    pub const SYS_UNVEIL:     usize = 5;
    pub const SYS_YIELD:      usize = 6;
    pub const SYS_EXIT:       usize = 7;
}

/// Validates that a user memory buffer resides strictly within the canonical user space.
#[inline(always)]
pub fn validate_user_memory_region(ptr: *const u8, len: usize) -> Result<(), SyscallError> {
    let start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(SyscallError::InvalidMemoryAccess),
    };
    if start == 0 || start > USER_SPACE_CEILING || end > USER_SPACE_CEILING {
        return Err(SyscallError::PrivilegeEscalationAttempted);
    }
    Ok(())
}

/// Safely copies bytes from an unprivileged user memory region into a kernel buffer.
pub unsafe fn copy_from_user(dst: &mut [u8], src_user: *const u8) -> Result<(), SyscallError> {
    validate_user_memory_region(src_user, dst.len())?;
    unsafe {
        core::ptr::copy_nonoverlapping(src_user, dst.as_mut_ptr(), dst.len());
    }
    Ok(())
}

/// Safely copies bytes from a kernel buffer out to an unprivileged user memory region.
pub unsafe fn copy_to_user(dst_user: *mut u8, src: &[u8]) -> Result<(), SyscallError> {
    validate_user_memory_region(dst_user, src.len())?;
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst_user, src.len());
    }
    Ok(())
}

/// Read an x86 Model-Specific Register (MSR).
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

/// Write an x86 Model-Specific Register (MSR).
#[inline]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    let low = val as u32;
    let high = (val >> 32) as u32;
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
}

static SYSCALL_INVOCATIONS: AtomicU64 = AtomicU64::new(0);

/// Rust-side system call dispatcher.
/// Rust-side system call dispatcher.
/// Called from assembly after user registers are saved.
#[no_mangle]
pub extern "sysv64" fn kash_rust_syscall_dispatcher(
    num: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> i64 {
    SYSCALL_INVOCATIONS.fetch_add(1, Ordering::Relaxed);

    struct SyncCell<T>(core::cell::UnsafeCell<T>);
    unsafe impl<T> Sync for SyncCell<T> {}
    static ROOT_SANDBOX: SyncCell<Option<crate::linux::ProcessSandbox>> =
        SyncCell(core::cell::UnsafeCell::new(None));

    let cell_ptr = ROOT_SANDBOX.0.get();
    let sandbox = unsafe {
        if (*cell_ptr).is_none() {
            *cell_ptr = Some(crate::linux::ProcessSandbox::new(1));
        }
        (*cell_ptr).as_mut().unwrap()
    };

    crate::linux::handle_linux_syscall(sandbox, num, arg1, arg2, arg3, arg4, arg5)
}

#[repr(align(4096))]
pub struct SyscallKernelStack(pub [u8; 16384]);

#[no_mangle]
pub static mut SYSCALL_KERNEL_STACK: SyscallKernelStack = SyscallKernelStack([0; 16384]);

#[no_mangle]
pub static mut USER_RSP_SCRATCH: u64 = 0;

pub const IA32_EFER: u32 = 0xC000_0080;

// Global assembly system call entrypoint.
core::arch::global_asm!(
    r#"
    .global kash_syscall_entry_dispatcher
    .type kash_syscall_entry_dispatcher, @function
    kash_syscall_entry_dispatcher:
        // 1. Switch GS to kernel space
        swapgs

        // 2. Switch from untrusted user RSP to dedicated kernel syscall stack
        mov [rip + USER_RSP_SCRATCH], rsp
        lea rsp, [rip + SYSCALL_KERNEL_STACK + 16384]

        // 3. Save user RSP and user registers on the trusted kernel stack
        push qword ptr [rip + USER_RSP_SCRATCH] // User RSP (slot 1)
        push rcx                                // User RIP (slot 2)
        push r11                                // User RFLAGS (slot 3)
        push rbp                                // (slot 4)
        push rbx                                // (slot 5)
        push r12                                // (slot 6)
        push r13                                // (slot 7)
        push r14                                // (slot 8)
        push r15                                // (slot 9)
        push rdx                                // User Arg 3 (slot 10)
        push rsi                                // User Arg 2 (slot 11)
        push rdi                                // User Arg 1 (slot 12)
        // 12 pushes * 8 bytes = 96 bytes (96 % 16 == 0 -> RSP is 16-byte aligned for call)

        // 4. Prepare System V ABI arguments:
        // rdi = Syscall number (passed in rax)
        // rsi = Arg 1 (original rdi, currently at [rsp])
        // rdx = Arg 2 (original rsi, currently at [rsp + 8])
        // rcx = Arg 3 (original rdx, currently at [rsp + 16])
        // r8  = Arg 4 (passed in r10 in Linux syscall convention)
        // r9  = Arg 5 (passed in r8 in Linux syscall convention)
        mov rdi, rax
        mov rsi, [rsp]
        mov rdx, [rsp + 8]
        mov rcx, [rsp + 16]
        mov r9, r8            // Move user Arg 5 (in r8) to r9 FIRST
        mov r8, r10           // Move user Arg 4 (in r10) to r8

        cld
        call kash_rust_syscall_dispatcher

        // 5. Restore user registers in reverse order
        pop rdi
        pop rsi
        pop rdx
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        pop r11               // Restore user RFLAGS
        pop rcx               // Restore user RIP
        pop rsp               // Restore user RSP

        // 6. Restore user GS base
        swapgs

        // 7. Fast return to Ring 3 (drops privilege, restores RIP from RCX and RFLAGS from R11)
        sysretq
    "#
);

extern "C" {
    fn kash_syscall_entry_dispatcher();
}

/// Initialize fast system call MSR registers and enable SCE.
pub fn init() {
    unsafe {
        // Ensure IA32_EFER.SCE (System Call Enable, bit 0) is active
        let efer = rdmsr(IA32_EFER);
        if efer & 1 == 0 {
            wrmsr(IA32_EFER, efer | 1);
        }

        // IA32_STAR:
        // Bits 47:32 = Kernel Code (0x08)
        // Bits 63:48 = User Base (0x10 -> sysret uses 0x10+8=0x18 for User Data, 0x10+16=0x20 for User Code)
        let star: u64 = ((0x10_u64) << 48) | ((0x08_u64) << 32);
        wrmsr(IA32_STAR, star);

        // IA32_LSTAR: Target RIP for syscall instruction
        let lstar = kash_syscall_entry_dispatcher as *const () as usize as u64;
        wrmsr(IA32_LSTAR, lstar);

        // IA32_FMASK: Mask CPU flags on entry (clears IF, DF, TF, AC)
        // 0x200 (IF), 0x400 (DF), 0x100 (TF), 0x40000 (AC)
        let fmask: u64 = 0x200 | 0x400 | 0x100 | 0x40000;
        wrmsr(IA32_FMASK, fmask);
    }
}
