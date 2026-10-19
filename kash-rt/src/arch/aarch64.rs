//! AArch64 raw system call primitives using Supervisor Call (`svc #0`).

#[inline(always)]
pub unsafe fn raw_syscall0(nr: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            lateout("x0") ret,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall1(nr: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            in("x0") a1,
            lateout("x0") ret,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            in("x0") a1,
            in("x1") a2,
            lateout("x0") ret,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            in("x0") a1,
            in("x1") a2,
            in("x2") a3,
            lateout("x0") ret,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            in("x0") a1,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            lateout("x0") ret,
            options(nostack, preserves_flags)
        );
    }
    ret
}

#[inline(always)]
pub unsafe fn raw_syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            in("x0") a1,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            lateout("x0") ret,
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
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            in("x0") a1,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            lateout("x0") ret,
            options(nostack, preserves_flags)
        );
    }
    ret
}
