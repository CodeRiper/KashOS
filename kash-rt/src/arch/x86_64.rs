//! x86_64 raw system call primitives using fast `syscall` instruction.

#[inline(always)]
pub unsafe fn raw_syscall0(nr: usize) -> isize {
    let ret: isize;
    // SAFETY: Executes the fast user-space syscall instruction with system call number in RAX.
    // Preserves non-clobbered registers.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall1(nr: usize, a1: usize) -> isize {
    let ret: isize;
    // SAFETY: Fast user-space syscall with 1 argument in RDI.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    // SAFETY: Fast user-space syscall with 2 arguments in RDI and RSI.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    // SAFETY: Fast user-space syscall with 3 arguments in RDI, RSI, RDX.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    // SAFETY: Fast user-space syscall with 4 arguments (RDI, RSI, RDX, R10).
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    // SAFETY: Fast user-space syscall with 5 arguments (RDI, RSI, RDX, R10, R8).
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let ret: isize;
    // SAFETY: Fast user-space syscall with 6 arguments (RDI, RSI, RDX, R10, R8, R9).
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags)
        );
    }
    ret
}
