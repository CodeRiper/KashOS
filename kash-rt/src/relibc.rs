//! Relibc Adaptation Substrate for KashOS.
//!
//! Provides the system call hook interfaces required by `relibc::platform::sys`
//! to bind relibc's C-library implementation to the KashOS kernel.

use crate::posix::{self, Stat, TimeSpec};

pub type Errno = i32;

/// System call interface matching `relibc::platform::sys`.
pub struct RelibcSys;

impl RelibcSys {
    #[inline]
    pub fn open(path: &str, flags: i32, mode: u32) -> Result<i32, Errno> {
        posix::open(path, flags, mode)
    }

    #[inline]
    pub fn close(fd: i32) -> Result<(), Errno> {
        posix::close(fd)
    }

    #[inline]
    pub fn read(fd: i32, buf: &mut [u8]) -> Result<usize, Errno> {
        posix::read(fd, buf)
    }

    #[inline]
    pub fn write(fd: i32, buf: &[u8]) -> Result<usize, Errno> {
        posix::write(fd, buf)
    }

    #[inline]
    pub fn lseek(fd: i32, offset: i64, whence: i32) -> Result<i64, Errno> {
        posix::lseek(fd, offset, whence)
    }

    #[inline]
    pub fn fstat(fd: i32, statbuf: &mut Stat) -> Result<(), Errno> {
        posix::fstat(fd, statbuf)
    }

    #[inline]
    pub fn brk(addr: *const u8) -> *mut u8 {
        posix::brk(addr)
    }

    #[inline]
    pub fn mmap(
        addr: *mut u8,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<*mut u8, Errno> {
        posix::mmap(addr, length, prot, flags, fd, offset)
    }

    #[inline]
    pub fn munmap(addr: *mut u8, length: usize) -> Result<(), Errno> {
        posix::munmap(addr, length)
    }

    #[inline]
    pub fn mprotect(addr: *mut u8, length: usize, prot: i32) -> Result<(), Errno> {
        posix::mprotect(addr, length, prot)
    }

    #[inline]
    pub fn exit(status: i32) -> ! {
        posix::exit(status)
    }

    #[inline]
    pub fn getpid() -> i32 {
        posix::getpid()
    }

    #[inline]
    pub fn sched_yield() -> i32 {
        posix::sched_yield()
    }

    #[inline]
    pub fn clock_gettime(clk_id: i32, tp: &mut TimeSpec) -> Result<(), Errno> {
        posix::clock_gettime(clk_id, tp)
    }

    #[inline]
    pub fn pledge(promises_mask: u32) -> Result<(), Errno> {
        posix::pledge(promises_mask)
    }

    #[inline]
    pub fn unveil(path: &str) -> Result<(), Errno> {
        posix::unveil(path)
    }
}
