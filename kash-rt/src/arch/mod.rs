//! Architecture-specific system call entry and raw assembly primitives.

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use self::x86_64::*;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use self::aarch64::*;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod generic {
    #[inline(always)]
    pub unsafe fn raw_syscall0(_nr: usize) -> isize { -38 /* ENOSYS */ }
    #[inline(always)]
    pub unsafe fn raw_syscall1(_nr: usize, _a1: usize) -> isize { -38 }
    #[inline(always)]
    pub unsafe fn raw_syscall2(_nr: usize, _a1: usize, _a2: usize) -> isize { -38 }
    #[inline(always)]
    pub unsafe fn raw_syscall3(_nr: usize, _a1: usize, _a2: usize, _a3: usize) -> isize { -38 }
    #[inline(always)]
    pub unsafe fn raw_syscall4(_nr: usize, _a1: usize, _a2: usize, _a3: usize, _a4: usize) -> isize { -38 }
    #[inline(always)]
    pub unsafe fn raw_syscall5(_nr: usize, _a1: usize, _a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize { -38 }
    #[inline(always)]
    pub unsafe fn raw_syscall6(_nr: usize, _a1: usize, _a2: usize, _a3: usize, _a4: usize, _a5: usize, _a6: usize) -> isize { -38 }
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use self::generic::*;
