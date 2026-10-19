//! CRT0 Process Runtime Initialization and Stack Parsing.

use crate::posix;

/// Parses initial process stack frame provided by the kernel ELF loader.
///
/// Stack layout on entry:
/// `[sp]`     = `argc`
/// `[sp + 1]` = `argv[0]`
/// ...
/// `[sp + argc]` = `argv[argc - 1]`
/// `[sp + argc + 1]` = `NULL`
/// `[sp + argc + 2]` = `envp[0]`
/// ...
/// `NULL`
pub unsafe fn parse_stack(sp: *const usize) -> (isize, *const *const u8, *const *const u8) {
    if sp.is_null() {
        return (0, core::ptr::null(), core::ptr::null());
    }

    let argc = unsafe { *sp } as isize;
    let argv = unsafe { sp.add(1) } as *const *const u8;
    let envp = unsafe { sp.add(1 + (argc.max(0) as usize) + 1) } as *const *const u8;

    (argc, argv, envp)
}

/// Generic C runtime entrypoint called from `_start` assembly.
pub unsafe fn crt0_main(sp: *const usize, user_main: fn(isize, *const *const u8, *const *const u8) -> i32) -> ! {
    let (argc, argv, envp) = unsafe { parse_stack(sp) };

    // Initialize user heap
    crate::alloc::USER_HEAP.lock().init();

    // Call user application
    let exit_code = user_main(argc, argv, envp);

    // Terminate process cleanly
    posix::exit(exit_code);
}

/// Helper macro to generate `_start` symbol for a `#![no_std]` user binary.
#[macro_export]
macro_rules! kash_main {
    ($user_main:path) => {
        #[no_mangle]
        pub unsafe extern "C" fn _start() -> ! {
            let sp: *const usize;
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack));
            #[cfg(target_arch = "aarch64")]
            core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            let sp = core::ptr::null();

            $crate::crt0::crt0_main(sp, $user_main);
        }
    };
}
