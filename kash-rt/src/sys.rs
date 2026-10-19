//! System call numbers and low-level dispatch routines.

// ── Linux Syscall Numbers (x86_64 ABI) ────────────────────────────────────────

pub const SYS_READ: usize          = 0;
pub const SYS_WRITE: usize         = 1;
pub const SYS_OPEN: usize          = 2;
pub const SYS_CLOSE: usize         = 3;
pub const SYS_STAT: usize          = 4;
pub const SYS_FSTAT: usize         = 5;
pub const SYS_LSTAT: usize         = 6;
pub const SYS_POLL: usize          = 7;
pub const SYS_LSEEK: usize         = 8;
pub const SYS_MMAP: usize          = 9;
pub const SYS_MPROTECT: usize      = 10;
pub const SYS_MUNMAP: usize        = 11;
pub const SYS_BRK: usize           = 12;
pub const SYS_IOCTL: usize         = 16;
pub const SYS_ACCESS: usize        = 21;
pub const SYS_PIPE: usize          = 22;
pub const SYS_SCHED_YIELD: usize   = 24;
pub const SYS_NANOSLEEP: usize     = 35;
pub const SYS_GETPID: usize        = 39;
pub const SYS_SOCKET: usize        = 41;
pub const SYS_CONNECT: usize       = 42;
pub const SYS_EXIT: usize          = 60;
pub const SYS_UNAME: usize         = 63;
pub const SYS_FCNTL: usize         = 72;
pub const SYS_GETCWD: usize        = 79;
pub const SYS_GETTIMEOFDAY: usize  = 96;
pub const SYS_GETUID: usize        = 102;
pub const SYS_GETGID: usize        = 104;
pub const SYS_GETEUID: usize       = 107;
pub const SYS_GETEGID: usize       = 108;
pub const SYS_GETPPID: usize       = 110;
pub const SYS_CLOCK_GETTIME: usize = 228;
pub const SYS_EXIT_GROUP: usize    = 231;

// KashOS Extended Security Syscalls
pub const SYS_PLEDGE: usize        = 400;
pub const SYS_UNVEIL: usize        = 401;

// ── Host Testing Emulation ───────────────────────────────────────────────────

#[cfg(any(test, feature = "host_testing"))]
pub mod mock {
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[repr(align(4096))]
    struct Arena([u8; 4 * 1024 * 1024]);
    static mut MOCK_ARENA: Arena = Arena([0; 4 * 1024 * 1024]);

    pub static MOCK_BRK: AtomicUsize = AtomicUsize::new(0);
    pub static LAST_SYSCALL: AtomicUsize = AtomicUsize::new(0);

    pub fn arena_base() -> usize {
        unsafe { core::ptr::addr_of_mut!(MOCK_ARENA.0) as *mut u8 as usize }
    }

    pub fn reset() {
        MOCK_BRK.store(arena_base(), Ordering::SeqCst);
        LAST_SYSCALL.store(0, Ordering::SeqCst);
        crate::alloc::USER_HEAP.lock().reset();
    }
}

// ── Unified Syscall Invocation ────────────────────────────────────────────────

#[inline]
pub unsafe fn syscall0(nr: usize) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        match nr {
            SYS_GETPID => 100,
            SYS_GETPPID => 1,
            SYS_SCHED_YIELD => 0,
            _ => 0,
        }
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall0(nr) }
    }
}

#[inline]
pub unsafe fn syscall1(nr: usize, a1: usize) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        match nr {
            SYS_EXIT | SYS_EXIT_GROUP => a1 as isize,
            SYS_BRK => {
                let current = mock::MOCK_BRK.load(core::sync::atomic::Ordering::SeqCst);
                let cur = if current == 0 {
                    let base = mock::arena_base();
                    mock::MOCK_BRK.store(base, core::sync::atomic::Ordering::SeqCst);
                    base
                } else {
                    current
                };

                if a1 == 0 {
                    cur as isize
                } else {
                    mock::MOCK_BRK.store(a1, core::sync::atomic::Ordering::SeqCst);
                    a1 as isize
                }
            }
            SYS_CLOSE => 0,
            SYS_PLEDGE => 0,
            _ => 0,
        }
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall1(nr, a1) }
    }
}

#[inline]
#[allow(unused_variables)]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        match nr {
            SYS_UNVEIL => 0,
            SYS_ACCESS => 0,
            SYS_CLOCK_GETTIME => 0,
            SYS_GETTIMEOFDAY => 0,
            SYS_MUNMAP => 0,
            _ => 0,
        }
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall2(nr, a1, a2) }
    }
}

#[inline]
#[allow(unused_variables)]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        match nr {
            SYS_READ => a3 as isize,
            SYS_WRITE => a3 as isize,
            SYS_OPEN => 3, // mock file descriptor
            SYS_LSEEK => a2 as isize,
            SYS_MPROTECT => 0,
            _ => 0,
        }
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall3(nr, a1, a2, a3) }
    }
}

#[inline]
#[allow(unused_variables)]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        0
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall4(nr, a1, a2, a3, a4) }
    }
}

#[inline]
#[allow(unused_variables)]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        0
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall5(nr, a1, a2, a3, a4, a5) }
    }
}

#[inline]
#[allow(unused_variables)]
pub unsafe fn syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    #[cfg(any(test, feature = "host_testing"))]
    {
        mock::LAST_SYSCALL.store(nr, core::sync::atomic::Ordering::SeqCst);
        match nr {
            SYS_MMAP => {
                let cur = mock::MOCK_BRK.load(core::sync::atomic::Ordering::SeqCst);
                if cur == 0 {
                    mock::MOCK_BRK.store(mock::arena_base(), core::sync::atomic::Ordering::SeqCst);
                }
                let prev = mock::MOCK_BRK.fetch_add((a2 + 4095) & !4095, core::sync::atomic::Ordering::SeqCst);
                prev as isize
            }
            _ => 0,
        }
    }
    #[cfg(not(any(test, feature = "host_testing")))]
    {
        unsafe { crate::arch::raw_syscall6(nr, a1, a2, a3, a4, a5, a6) }
    }
}
