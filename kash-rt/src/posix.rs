//! POSIX C-ABI System Call Interfaces and Kernel Bridge.

use crate::sys;

// ── POSIX Error Numbers ──────────────────────────────────────────────────────

pub const EPERM: i32   = 1;
pub const ENOENT: i32  = 2;
pub const ESRCH: i32   = 3;
pub const EINTR: i32   = 4;
pub const EIO: i32     = 5;
pub const EBADF: i32   = 9;
pub const ENOMEM: i32  = 12;
pub const EACCES: i32  = 13;
pub const EFAULT: i32  = 14;
pub const EBUSY: i32   = 16;
pub const EEXIST: i32  = 17;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32  = 21;
pub const EINVAL: i32  = 22;
pub const EMFILE: i32  = 24;
pub const ENOSYS: i32  = 38;

// ── Open & File Flags ────────────────────────────────────────────────────────

pub const O_RDONLY: i32   = 0;
pub const O_WRONLY: i32   = 1;
pub const O_RDWR: i32     = 2;
pub const O_CREAT: i32    = 64;
pub const O_EXCL: i32     = 128;
pub const O_NOCTTY: i32   = 256;
pub const O_TRUNC: i32    = 512;
pub const O_APPEND: i32   = 1024;
pub const O_NONBLOCK: i32 = 2048;

// ── Memory Protection & Mapping Flags ────────────────────────────────────────

pub const PROT_NONE: i32  = 0;
pub const PROT_READ: i32  = 1;
pub const PROT_WRITE: i32 = 2;
pub const PROT_EXEC: i32  = 4;

pub const MAP_SHARED: i32    = 1;
pub const MAP_PRIVATE: i32   = 2;
pub const MAP_FIXED: i32     = 16;
pub const MAP_ANONYMOUS: i32 = 32;

// ── Seek Whence ──────────────────────────────────────────────────────────────

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

// ── POSIX Structures ─────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeVal {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UtsName {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        }
    }
}

// ── Result Conversion Helper ─────────────────────────────────────────────────

#[inline(always)]
pub fn check_err(ret: isize) -> Result<usize, i32> {
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(ret as usize)
    }
}

// ── Standard POSIX APIs (Safe Wrappers) ───────────────────────────────────────

/// Write up to `buf.len()` bytes from `buf` to file descriptor `fd`.
pub fn write(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    // SAFETY: buf points to valid memory for buf.len() bytes.
    let ret = unsafe {
        sys::syscall3(sys::SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len())
    };
    check_err(ret)
}

/// Read up to `buf.len()` bytes from file descriptor `fd` into `buf`.
pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: buf points to valid mutable memory for buf.len() bytes.
    let ret = unsafe {
        sys::syscall3(sys::SYS_READ, fd as usize, buf.as_mut_ptr() as usize, buf.len())
    };
    check_err(ret)
}

/// Open or create a file at `path`. Null-terminates string if necessary.
pub fn open(path: &str, flags: i32, mode: u32) -> Result<i32, i32> {
    // Stack-allocated null-terminated buffer for path
    let mut buf = [0u8; 256];
    let bytes = path.as_bytes();
    if bytes.len() >= buf.len() {
        return Err(EINVAL);
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;

    // SAFETY: buf is null-terminated and resides on the stack.
    let ret = unsafe {
        sys::syscall3(sys::SYS_OPEN, buf.as_ptr() as usize, flags as usize, mode as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(ret as i32)
    }
}

/// Close a file descriptor.
pub fn close(fd: i32) -> Result<(), i32> {
    // SAFETY: Simple syscall passing fd integer.
    let ret = unsafe { sys::syscall1(sys::SYS_CLOSE, fd as usize) };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Reposition file offset.
pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, i32> {
    // SAFETY: Repositions seek pointer in open file table.
    let ret = unsafe {
        sys::syscall3(sys::SYS_LSEEK, fd as usize, offset as usize, whence as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(ret as i64)
    }
}

/// Get file status by pathname.
pub fn stat(path: &str, statbuf: &mut Stat) -> Result<(), i32> {
    let mut buf = [0u8; 256];
    let bytes = path.as_bytes();
    if bytes.len() >= buf.len() {
        return Err(EINVAL);
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;

    // SAFETY: buf is null-terminated, statbuf is valid mutable reference.
    let ret = unsafe {
        sys::syscall2(sys::SYS_STAT, buf.as_ptr() as usize, statbuf as *mut Stat as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Get file status by descriptor.
pub fn fstat(fd: i32, statbuf: &mut Stat) -> Result<(), i32> {
    // SAFETY: statbuf is valid mutable reference.
    let ret = unsafe {
        sys::syscall2(sys::SYS_FSTAT, fd as usize, statbuf as *mut Stat as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Change the location of the program break.
pub fn brk(addr: *const u8) -> *mut u8 {
    // SAFETY: brk updates or queries the user break address.
    let ret = unsafe { sys::syscall1(sys::SYS_BRK, addr as usize) };
    ret as *mut u8
}

/// Map pages of memory.
pub fn mmap(
    addr: *mut u8,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: i64,
) -> Result<*mut u8, i32> {
    // SAFETY: mmap requests virtual memory mapping within user canonical range.
    let ret = unsafe {
        sys::syscall6(
            sys::SYS_MMAP,
            addr as usize,
            length,
            prot as usize,
            flags as usize,
            fd as usize,
            offset as usize,
        )
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(ret as *mut u8)
    }
}

/// Unmap pages of memory.
pub fn munmap(addr: *mut u8, length: usize) -> Result<(), i32> {
    // SAFETY: munmap unmaps user memory.
    let ret = unsafe { sys::syscall2(sys::SYS_MUNMAP, addr as usize, length) };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Set protection on a region of memory.
pub fn mprotect(addr: *mut u8, length: usize, prot: i32) -> Result<(), i32> {
    // SAFETY: Sets permissions on allocated page range.
    let ret = unsafe {
        sys::syscall3(sys::SYS_MPROTECT, addr as usize, length, prot as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Terminate the calling process.
pub fn exit(status: i32) -> ! {
    // SAFETY: SYS_EXIT never returns.
    unsafe {
        let _ = sys::syscall1(sys::SYS_EXIT, status as usize);
        loop {
            core::arch::asm!("ud2", options(noreturn));
        }
    }
}

/// Get the calling process ID.
pub fn getpid() -> i32 {
    // SAFETY: Read-only query for current process ID.
    unsafe { sys::syscall0(sys::SYS_GETPID) as i32 }
}

/// Get parent process ID.
pub fn getppid() -> i32 {
    // SAFETY: Read-only query for parent process ID.
    unsafe { sys::syscall0(sys::SYS_GETPPID) as i32 }
}

/// Yield processor time slice.
pub fn sched_yield() -> i32 {
    // SAFETY: Yields time slice to other scheduled tasks.
    unsafe { sys::syscall0(sys::SYS_SCHED_YIELD) as i32 }
}

/// Sleep for specified high-resolution duration.
pub fn nanosleep(req: &TimeSpec, rem: Option<&mut TimeSpec>) -> Result<(), i32> {
    let rem_ptr = rem.map_or(0, |r| r as *mut TimeSpec as usize);
    // SAFETY: req points to valid TimeSpec, rem points to valid TimeSpec or null.
    let ret = unsafe {
        sys::syscall2(sys::SYS_NANOSLEEP, req as *const TimeSpec as usize, rem_ptr)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Retrieve clock time.
pub fn clock_gettime(clk_id: i32, tp: &mut TimeSpec) -> Result<(), i32> {
    // SAFETY: tp points to valid TimeSpec structure.
    let ret = unsafe {
        sys::syscall2(sys::SYS_CLOCK_GETTIME, clk_id as usize, tp as *mut TimeSpec as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Get system information (sysname, nodename, release, etc.).
pub fn uname(name: &mut UtsName) -> Result<(), i32> {
    // SAFETY: name points to valid UtsName structure.
    let ret = unsafe {
        sys::syscall1(sys::SYS_UNAME, name as *mut UtsName as usize)
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Restrict process capabilities (OpenBSD / KashOS pledge security enforcement).
pub fn pledge(promises_mask: u32) -> Result<(), i32> {
    // SAFETY: SYS_PLEDGE passes integer bitmask of promises to restrict.
    let ret = unsafe { sys::syscall1(sys::SYS_PLEDGE, promises_mask as usize) };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}

/// Unveil filesystem paths with restricted permissions (OpenBSD / KashOS unveil enforcement).
pub fn unveil(path: &str) -> Result<(), i32> {
    // SAFETY: path is valid string slice within user space.
    let ret = unsafe {
        sys::syscall2(sys::SYS_UNVEIL, path.as_ptr() as usize, path.len())
    };
    if ret < 0 {
        Err((-ret) as i32)
    } else {
        Ok(())
    }
}
