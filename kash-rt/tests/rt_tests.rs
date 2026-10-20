//! Integration tests for KashOS userland runtime (kash-rt).

use kash_rt::sys;
use kash_rt::posix;
use kash_rt::alloc::{self, CANARY_MAGIC, ChunkHeader};
use kash_rt::string;
use kash_rt::relibc::RelibcSys;

// These integration tests share one process-wide mock syscall state and heap.
// Keep resets and allocator assertions from racing across Rust's test threads.
static MOCK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_sys_mock_primitives() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    // Verify GETPID returns mock PID
    let pid = unsafe { sys::syscall0(sys::SYS_GETPID) };
    assert_eq!(pid, 100);

    // Verify BRK query and update
    let initial_brk = unsafe { sys::syscall1(sys::SYS_BRK, 0) } as usize;
    assert_eq!(initial_brk, sys::mock::arena_base());

    let target = initial_brk + 0x1000;
    let new_brk = unsafe { sys::syscall1(sys::SYS_BRK, target) } as usize;
    assert_eq!(new_brk, target);
}

#[test]
fn test_posix_io_wrappers() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    // Test write
    let msg = b"Hello KashOS Userland!\n";
    let written = posix::write(1, msg).expect("write failed");
    assert_eq!(written, msg.len());

    // Test read
    let mut buf = [0u8; 32];
    let nread = posix::read(0, &mut buf).expect("read failed");
    assert_eq!(nread, buf.len());

    // Test open and close
    let fd = posix::open("/bin/sh", posix::O_RDONLY, 0).expect("open failed");
    assert_eq!(fd, 3);
    posix::close(fd).expect("close failed");

    // Test lseek
    let off = posix::lseek(fd, 1024, posix::SEEK_SET).expect("lseek failed");
    assert_eq!(off, 1024);
}

#[test]
fn test_posix_security_and_system() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    // Test pledge and unveil
    assert!(posix::pledge(0x01 | 0x02).is_ok());
    assert!(posix::unveil("/etc/ssl").is_ok());

    // Test getpid and getppid
    assert_eq!(posix::getpid(), 100);
    assert_eq!(posix::getppid(), 1);
    assert_eq!(posix::sched_yield(), 0);

    // Test clock_gettime
    let mut ts = posix::TimeSpec::default();
    assert!(posix::clock_gettime(0, &mut ts).is_ok());

    // Test uname
    let mut uts = posix::UtsName::default();
    assert!(posix::uname(&mut uts).is_ok());
}

#[test]
fn test_memory_allocator_basic_and_alignment() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    // Allocate 32 bytes
    let ptr = unsafe { alloc::malloc(32) };
    assert!(!ptr.is_null());
    // Must be 16-byte aligned
    assert_eq!((ptr as usize) % 16, 0);

    // Verify chunk header and canary
    let header = unsafe { ChunkHeader::from_payload(ptr) };
    assert_eq!(unsafe { (*header).canary }, CANARY_MAGIC);
    assert!(unsafe { (*header).is_in_use() });

    // Write data pattern to payload
    unsafe {
        core::ptr::write_bytes(ptr, 0xAA, 32);
        for i in 0..32 {
            assert_eq!(*ptr.add(i), 0xAA);
        }
    }

    // Free memory
    unsafe { alloc::free(ptr) };
    assert!(!unsafe { (*header).is_in_use() });
}

#[test]
fn test_memory_allocator_realloc_and_calloc() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    // Allocate 16 bytes
    let ptr = unsafe { alloc::malloc(16) };
    assert!(!ptr.is_null());
    unsafe {
        core::ptr::copy_nonoverlapping(b"0123456789abcdef".as_ptr(), ptr, 16);
    }

    // Reallocate to 64 bytes
    let new_ptr = unsafe { alloc::realloc(ptr, 64) };
    assert!(!new_ptr.is_null());
    assert_eq!((new_ptr as usize) % 16, 0);

    // Verify preserved prefix data
    unsafe {
        let prefix = core::slice::from_raw_parts(new_ptr, 16);
        assert_eq!(prefix, b"0123456789abcdef");
    }

    unsafe { alloc::free(new_ptr) };

    // Test calloc (cleared to zero)
    let cptr = unsafe { alloc::calloc(8, 4) };
    assert!(!cptr.is_null());
    unsafe {
        for i in 0..32 {
            assert_eq!(*cptr.add(i), 0);
        }
        alloc::free(cptr);
    }
}

#[test]
fn test_memory_allocator_large_mmap() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    // 128 KiB allocation (exceeds MMAP_THRESHOLD = 64 KiB)
    let large_ptr = unsafe { alloc::malloc(128 * 1024) };
    assert!(!large_ptr.is_null());

    let header = unsafe { ChunkHeader::from_payload(large_ptr) };
    assert_eq!(unsafe { (*header).canary }, CANARY_MAGIC);
    assert!(unsafe { (*header).is_mmap() });

    unsafe { alloc::free(large_ptr) };
}

#[test]
fn test_string_and_memory_routines() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let s1 = b"Hello, World!\0";
    let s2 = b"Hello, World!\0";
    let s3 = b"Hello, KashOS!\0";

    assert_eq!(unsafe { string::strlen(s1.as_ptr()) }, 13);
    assert_eq!(unsafe { string::strnlen(s1.as_ptr(), 5) }, 5);
    assert_eq!(unsafe { string::strcmp(s1.as_ptr(), s2.as_ptr()) }, 0);
    assert!(unsafe { string::strcmp(s1.as_ptr(), s3.as_ptr()) } > 0);
    assert_eq!(unsafe { string::strncmp(s1.as_ptr(), s3.as_ptr(), 7) }, 0);

    let mut buf = [0u8; 32];
    unsafe {
        string::strcpy(buf.as_mut_ptr(), s3.as_ptr());
    }
    assert_eq!(unsafe { string::strlen(buf.as_ptr()) }, 14);

    // Test strchr
    let chr_ptr = unsafe { string::strchr(s1.as_ptr(), b',' as i32) };
    assert!(!chr_ptr.is_null());
    assert_eq!(unsafe { *chr_ptr }, b',');

    // Test memcpy and memcmp
    let mut mem_buf = [0u8; 16];
    unsafe {
        string::memcpy(mem_buf.as_mut_ptr(), b"abcdefghijklmnop".as_ptr(), 16);
    }
    assert_eq!(unsafe { string::memcmp(mem_buf.as_ptr(), b"abcdefghijklmnop".as_ptr(), 16) }, 0);

    // Test atoi
    assert_eq!(unsafe { string::atoi(b"12345\0".as_ptr()) }, 12345);
    assert_eq!(unsafe { string::atoi(b"-9876\0".as_ptr()) }, -9876);
    assert_eq!(unsafe { string::atoi(b"  +42\0".as_ptr()) }, 42);

    // Test itoa
    let mut num_buf = [0u8; 16];
    assert_eq!(string::itoa(1337, &mut num_buf), "1337");
    assert_eq!(string::itoa(-42, &mut num_buf), "-42");
    assert_eq!(string::itoa(0, &mut num_buf), "0");
}

#[test]
fn test_relibc_sys_bridge() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sys::mock::reset();

    assert!(RelibcSys::open("/var/log/messages", posix::O_RDONLY, 0).is_ok());
    assert!(RelibcSys::write(1, b"Test Relibc\n").is_ok());

    let mut buf = [0u8; 16];
    assert!(RelibcSys::read(0, &mut buf).is_ok());
    assert!(RelibcSys::close(3).is_ok());

    let brk_val = RelibcSys::brk(core::ptr::null());
    assert_eq!(brk_val as usize, sys::mock::arena_base());

    assert_eq!(RelibcSys::getpid(), 100);
    assert_eq!(RelibcSys::sched_yield(), 0);
    assert!(RelibcSys::pledge(0x01).is_ok());
    assert!(RelibcSys::unveil("/home").is_ok());
}

#[test]
fn test_crt0_stack_parser() {
    let _guard = MOCK_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    // Construct mock stack frame:
    // [0]: argc = 2
    // [1]: argv[0] -> "test_bin"
    // [2]: argv[1] -> "--verbose"
    // [3]: NULL (terminates argv)
    // [4]: envp[0] -> "PATH=/bin"
    // [5]: NULL (terminates envp)
    let arg0 = b"test_bin\0";
    let arg1 = b"--verbose\0";
    let env0 = b"PATH=/bin\0";

    let stack: [usize; 6] = [
        2,
        arg0.as_ptr() as usize,
        arg1.as_ptr() as usize,
        0,
        env0.as_ptr() as usize,
        0,
    ];

    let (argc, argv, envp) = unsafe { kash_rt::crt0::parse_stack(stack.as_ptr()) };
    assert_eq!(argc, 2);
    assert_eq!(unsafe { *argv }, arg0.as_ptr());
    assert_eq!(unsafe { *argv.add(1) }, arg1.as_ptr());
    assert_eq!(unsafe { *envp }, env0.as_ptr());
}
