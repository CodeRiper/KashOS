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
    WouldBlock = -9,
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
    pub const SYS_RETYPE:     usize = 8;
    pub const SYS_REVOKE:     usize = 9;
    pub const SYS_PRINT:      usize = 10;
    pub const SYS_DEV_PORT:   usize = 11;
    pub const SYS_DEV_MMIO:   usize = 12;
}

/// Validates that a user memory buffer resides strictly within the canonical user space.
#[inline(always)]
pub fn validate_user_memory_region(ptr: *const u8, len: usize) -> Result<(), SyscallError> {
    let start = ptr as usize;
    let end = match start.checked_add(len) {
        Some(e) => e,
        None => return Err(SyscallError::InvalidMemoryAccess),
    };
    if start == 0 || (start as u64) < crate::elf::USER_SPACE_FLOOR || end > USER_SPACE_CEILING {
        return Err(SyscallError::PrivilegeEscalationAttempted);
    }
    Ok(())
}

/// Safely copies bytes from an unprivileged user memory region into a kernel buffer.
/// Enforces STAC/CLAC SMAP user-access toggle when supported by hardware.
pub unsafe fn copy_from_user(dst: &mut [u8], src_user: *const u8) -> Result<(), SyscallError> {
    validate_user_memory_region(src_user, dst.len())?;
    let has_smap = super::cpuid::detect().has_smap;
    unsafe {
        if has_smap {
            core::arch::asm!("stac", options(nomem, nostack, preserves_flags));
        }
        core::ptr::copy_nonoverlapping(src_user, dst.as_mut_ptr(), dst.len());
        if has_smap {
            core::arch::asm!("clac", options(nomem, nostack, preserves_flags));
        }
    }
    Ok(())
}

/// Safely copies bytes from a kernel buffer out to an unprivileged user memory region.
/// Enforces STAC/CLAC SMAP user-access toggle when supported by hardware.
pub unsafe fn copy_to_user(dst_user: *mut u8, src: &[u8]) -> Result<(), SyscallError> {
    validate_user_memory_region(dst_user, src.len())?;
    let has_smap = super::cpuid::detect().has_smap;
    unsafe {
        if has_smap {
            core::arch::asm!("stac", options(nomem, nostack, preserves_flags));
        }
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst_user, src.len());
        if has_smap {
            core::arch::asm!("clac", options(nomem, nostack, preserves_flags));
        }
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
static SYSCALL_STACK_OWNERSHIP_REPORTED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// Multi-process sandbox table (Part A5 & A8: One sandbox per process, not global)
pub struct ProcessSandboxTable {
    pub sandboxes: [Option<crate::linux::ProcessSandbox>; 16],
}

impl ProcessSandboxTable {
    pub const fn new() -> Self {
        Self {
            sandboxes: [None, None, None, None, None, None, None, None,
                        None, None, None, None, None, None, None, None],
        }
    }

    pub fn get_or_create(&mut self, pid: u64) -> &mut crate::linux::ProcessSandbox {
        let idx = (pid as usize) % 16;
        if self.sandboxes[idx].is_none() {
            self.sandboxes[idx] = Some(crate::linux::ProcessSandbox::new(pid));
        }
        self.sandboxes[idx].as_mut().unwrap()
    }
}

struct SyncCell<T>(core::cell::UnsafeCell<T>);
unsafe impl<T> Sync for SyncCell<T> {}
static PROCESS_SANDBOXES: SyncCell<ProcessSandboxTable> = SyncCell(core::cell::UnsafeCell::new(ProcessSandboxTable::new()));

/// Validate the user-visible IPC receive capacity before the endpoint is
/// inspected or a waiting sender can be woken. The requested capacity is
/// bounded by the kernel's maximum message size.
pub(crate) fn validate_ipc_user_buffer(
    user_buf: *mut u64,
    user_words: usize,
) -> Result<usize, SyscallError> {
    if user_words == 0 {
        return Ok(0);
    }
    if user_buf.is_null() {
        return Err(SyscallError::InvalidMemoryAccess);
    }

    let bounded_words = user_words.min(crate::ipc::MAX_IPC_WORDS);
    let byte_len = bounded_words
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(SyscallError::InvalidMemoryAccess)?;
    validate_user_memory_region(user_buf.cast::<u8>(), byte_len)
        .map_err(|_| SyscallError::InvalidMemoryAccess)?;
    Ok(bounded_words)
}

/// Rust-side system call dispatcher called from assembly after user registers are saved.
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

    let tid = crate::task::current_tid();
    if tid >= kscheduler::MAX_TASKS as u32 + 2 {
        let stack_pointer: u64;
        // SAFETY: reading RSP is side-effect free; the syscall entry is already
        // executing on the kernel stack selected for this current user task.
        unsafe {
            core::arch::asm!(
                "mov {}, rsp",
                out(reg) stack_pointer,
                options(nomem, nostack, preserves_flags)
            );
        }
        if !crate::task::current_thread_stack_contains(stack_pointer) {
            crate::kprintln!(
                "[syscall] PID {} entered on a kernel stack not owned by its thread; halting.",
                tid
            );
            crate::arch::shutdown(true);
        }
        if !SYSCALL_STACK_OWNERSHIP_REPORTED.swap(true, Ordering::AcqRel) {
            crate::kprintln!(
                "[syscall] PASS: Ring 3 syscall used its owning thread kernel stack"
            );
        }
    }

    match num {
        nr::SYS_CAP_INVOKE => {
            let cptr = arg1;
            let op = arg2;
            let current_pid = crate::task::current_tid();
            let cspace_idx = match crate::process::process_slot_for_pid(current_pid as u32) {
                Some(slot) => slot,
                None => return SyscallError::InvalidCapability as i64,
            };
            let mut cspaces = crate::process::PROCESS_CSPACES.lock();
            let cs = &mut cspaces[cspace_idx];

            match op {
                0 => {
                    // Lookup / inspect
                    match cs.lookup(cptr, kcore::Rights::NONE) {
                        Ok(cap) => cap.badge() as i64,
                        Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                        Err(_) => SyscallError::InvalidCapability as i64,
                    }
                }
                1 => {
                    // Copy: src = cptr, dst = arg3, mask = arg4
                    let mask = match kcore::Rights::from_bits(arg4 as u8) {
                        Some(mask) => mask,
                        None => return SyscallError::InvalidArgument as i64,
                    };
                    match cs.copy(cptr, arg3, mask) {
                        Ok(()) => 0,
                        Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                        Err(_) => SyscallError::InvalidCapability as i64,
                    }
                }
                2 => {
                    // Mint: src = cptr, dst = arg3, mask = arg4, badge = arg5
                    let mask = match kcore::Rights::from_bits(arg4 as u8) {
                        Some(mask) => mask,
                        None => return SyscallError::InvalidArgument as i64,
                    };
                    match cs.mint(cptr, arg3, mask, arg5 as u64) {
                        Ok(()) => 0,
                        Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                        Err(_) => SyscallError::InvalidCapability as i64,
                    }
                }
                3 => {
                    // Delete: slot = cptr
                    match cs.delete(cptr) {
                        Ok(()) => 0,
                        Err(_) => SyscallError::InvalidCapability as i64,
                    }
                }
                4 => {
                    // Revoke: slot = cptr
                    match cs.revoke(cptr) {
                        Ok(()) => 0,
                        Err(_) => SyscallError::InvalidCapability as i64,
                    }
                }
                _ => SyscallError::InvalidArgument as i64,
            }
        }
        nr::SYS_IPC_SEND => {
            let endpoint_cptr = arg1;
            let tag = arg2 as u64;
            let words_ptr = arg3 as *const u64;
            let words_len = arg4;
            let cap_to_transfer = if arg5 != 0 { Some(arg5) } else { None };

            let mut words_buf = [0u64; crate::ipc::MAX_IPC_WORDS];
            let count = words_len.min(crate::ipc::MAX_IPC_WORDS);
            if count > 0 {
                if count == 1 && (words_ptr as usize) < crate::elf::USER_SPACE_FLOOR as usize {
                    // Fast single-word in register argument
                    words_buf[0] = arg3 as u64;
                } else if validate_user_memory_region(words_ptr as *const u8, count * 8).is_ok() {
                    let copy_result = unsafe {
                        copy_from_user(
                            core::slice::from_raw_parts_mut(words_buf.as_mut_ptr() as *mut u8, count * 8),
                            words_ptr as *const u8,
                        )
                    };
                    if let Err(error) = copy_result {
                        return error as i64;
                    }
                } else {
                    return SyscallError::InvalidMemoryAccess as i64;
                }
            }

            match crate::ipc::sys_ipc_send(endpoint_cptr, tag, &words_buf[..count], cap_to_transfer) {
                Ok(()) => 0,
                Err(e) => e as i64,
            }
        }
        nr::SYS_IPC_RECV => {
            let endpoint_cptr = arg1;
            let dest_cap_slot = if arg2 != 0 { Some(arg2) } else { None };
            let user_buf = arg3 as *mut u64;
            let user_buf_len = arg4;
            let receive_capacity = match validate_ipc_user_buffer(user_buf, user_buf_len) {
                Ok(capacity) => capacity,
                Err(error) => return error as i64,
            };

            match crate::ipc::sys_ipc_recv(endpoint_cptr, dest_cap_slot) {
                Ok(msg) => {
                    let count = receive_capacity.min(msg.words_len);
                    if count > 0 {
                        let copy_result = unsafe {
                            copy_to_user(
                                user_buf.cast::<u8>(),
                                core::slice::from_raw_parts(msg.words.as_ptr() as *const u8, count * 8),
                            )
                        };
                        if let Err(error) = copy_result {
                            return error as i64;
                        }
                    }
                    msg.sender_badge as i64
                }
                Err(e) => e as i64,
            }
        }
        nr::SYS_RETYPE => {
            let untyped_slot = arg1;
            let obj_type_raw = arg2;
            let dest_slot = arg3;
            let target_type = match obj_type_raw {
                0 => kcore::ObjType::Frame,
                1 => kcore::ObjType::Endpoint,
                2 => kcore::ObjType::Notification,
                3 => kcore::ObjType::TCB,
                _ => return SyscallError::InvalidArgument as i64,
            };
            let current_pid = crate::task::current_tid();
            let cspace_idx = match crate::process::process_slot_for_pid(current_pid as u32) {
                Some(slot) => slot,
                None => return SyscallError::InvalidCapability as i64,
            };
            let mut cspaces = crate::process::PROCESS_CSPACES.lock();
            let cs = &mut cspaces[cspace_idx];
            match cs.retype(untyped_slot, target_type, dest_slot, &mut |_paddr, _len| {}) {
                Ok(()) => 0,
                Err(kcore::KError::NoMemory) => -12, // ENOMEM
                Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                Err(_) => SyscallError::InvalidCapability as i64,
            }
        }
        nr::SYS_REVOKE => {
            let slot_idx = arg1;
            let current_pid = crate::task::current_tid();
            let cspace_idx = match crate::process::process_slot_for_pid(current_pid as u32) {
                Some(slot) => slot,
                None => return SyscallError::InvalidCapability as i64,
            };
            let mut cspaces = crate::process::PROCESS_CSPACES.lock();
            let cs = &mut cspaces[cspace_idx];
            match cs.revoke(slot_idx) {
                Ok(()) => 0,
                Err(_) => SyscallError::InvalidCapability as i64,
            }
        }
        nr::SYS_YIELD => 0,
        nr::SYS_EXIT => {
            let code = arg1 as i32;
            crate::process::exit_process(code);
        }
        nr::SYS_PRINT => {
            let ptr = arg1 as *const u8;
            let len = arg2;
            if validate_user_memory_region(ptr, len).is_err() {
                return SyscallError::InvalidMemoryAccess as i64;
            }
            let mut buf = [0u8; 256];
            let to_copy = len.min(buf.len());
            if unsafe { copy_from_user(&mut buf[..to_copy], ptr) }.is_ok() {
                if let Ok(s) = core::str::from_utf8(&buf[..to_copy]) {
                    crate::kprint!("{}", s);
                }
                len as i64
            } else {
                SyscallError::InvalidMemoryAccess as i64
            }
        }
        nr::SYS_DEV_PORT => {
            let port = arg1 as u16;
            let val = arg2 as u32;
            let is_write = arg3 != 0;
            let size = (arg4 as u8).max(1);
            let current_pid = crate::task::current_tid();
            match crate::driver::DRIVER_SUPERVISOR.lock().execute_port_io(current_pid, port, val, is_write, size) {
                Ok(res) => res as i64,
                Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                Err(_) => SyscallError::InvalidArgument as i64,
            }
        }
        nr::SYS_DEV_MMIO => {
            let paddr = arg1 as u64;
            let val = arg2 as u64;
            let is_write = arg3 != 0;
            let size = (arg4 as u8).max(1);
            let current_pid = crate::task::current_tid();
            if is_write {
                match crate::driver::DRIVER_SUPERVISOR.lock().execute_mmio_write(current_pid, paddr, val, size) {
                    Ok(()) => 0,
                    Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                    Err(_) => SyscallError::InvalidArgument as i64,
                }
            } else {
                match crate::driver::DRIVER_SUPERVISOR.lock().execute_mmio_read(current_pid, paddr, size) {
                    Ok(res) => res as i64,
                    Err(kcore::KError::InsufficientRights) => SyscallError::InsufficientRights as i64,
                    Err(_) => SyscallError::InvalidArgument as i64,
                }
            }
        }
        _ => {
            let table = unsafe { &mut *PROCESS_SANDBOXES.0.get() };
            // Unknown CPU/task identity must not inherit the root task's sandbox.
            let current_pid = crate::task::current_tid();
            if current_pid == 0 {
                return SyscallError::InvalidArgument as i64;
            }
            let sandbox = table.get_or_create(current_pid as u64);
            crate::linux::handle_linux_syscall(sandbox, num, arg1, arg2, arg3, arg4, arg5)
        }
    }
}

#[repr(align(4096))]
/// Per-CPU bootstrap stacks used only until task setup installs the running
/// task's own guarded stack top in `SyscallCpuState`.
pub struct SyscallKernelStack(pub [u8; 16384]);

#[repr(C, align(16))]
pub struct SyscallCpuState {
    pub user_rsp: u64,
    pub kernel_stack_top: AtomicU64,
}

const _: () = assert!(core::mem::offset_of!(SyscallCpuState, kernel_stack_top) == 8);

pub static mut SYSCALL_KERNEL_STACKS: [SyscallKernelStack; crate::arch::x86_64::smp::MAX_CPUS] =
    [const { SyscallKernelStack([0; 16384]) }; crate::arch::x86_64::smp::MAX_CPUS];
pub static mut SYSCALL_CPU_STATE: [SyscallCpuState; crate::arch::x86_64::smp::MAX_CPUS] =
    [const { SyscallCpuState { user_rsp: 0, kernel_stack_top: AtomicU64::new(0) } }; crate::arch::x86_64::smp::MAX_CPUS];

pub const IA32_EFER: u32 = 0xC000_0080;
pub const IA32_GS_BASE: u32 = 0xC000_0101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

// Global assembly system call entrypoint.
core::arch::global_asm!(
    r#"
    .global kash_syscall_entry_dispatcher
    .type kash_syscall_entry_dispatcher, @function
    kash_syscall_entry_dispatcher:
        // 1. Switch GS to kernel space
        swapgs

        // 2. Save user RSP and switch to the current task's stack selected in
        //    this CPU's GS-local entry state.
        mov gs:[0], rsp
        mov rsp, gs:[8]

        // 3. Save user RSP and user registers on the trusted kernel stack
        push qword ptr gs:[0]                  // User RSP (slot 1)
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

        // 5. Restore non-scratch user registers in reverse order
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
        pop r10               // Keep user RSP in a scratch register until return validation

        // 6. Security Check (Part A8): Verify that RCX is a canonical user address (<= 0x00007FFFFFFFFFFF).
        // If non-canonical, construct an IRET frame on the kernel stack.
        mov r9, 0x00007FFFFFFFFFFF
        cmp rcx, r9
        ja 1f

        // Clear scratch registers before returning to user mode to prevent kernel information leakage
        xor rdx, rdx
        xor rsi, rsi
        xor rdi, rdi
        xor r8, r8
        xor r9, r9
        mov rsp, r10
        xor r10, r10

        // Restore user GS base
        swapgs

        // Fast return to Ring 3
        sysretq

    1:
        // Keep this frame on the trusted kernel stack, not the user RSP.
        push 0x1B                               // User SS (0x18 | 3)
        push r10                                // User RSP
        push r11                                // User RFLAGS
        push 0x23                               // User CS (0x20 | 3)
        push rcx                                // User RIP (non-canonical target)
        xor rdx, rdx
        xor rsi, rsi
        xor rdi, rdi
        xor r8, r8
        xor r9, r9
        xor r10, r10
        swapgs
        iretq
    "#
);

extern "C" {
    fn kash_syscall_entry_dispatcher();
}

/// Initialize fast system call MSR registers and enable SCE.
pub fn init() {
    let apic_id = crate::arch::x86_64::apic::current_id();
    let Some(cpu_index) = crate::arch::x86_64::smp::cpu_index_for_apic_id(apic_id) else {
        crate::kprintln!("[syscall] CPU-local entry state unavailable for APIC ID {}; fast syscalls remain disabled.", apic_id);
        return;
    };

    unsafe {
        let cpu_state = core::ptr::addr_of_mut!(SYSCALL_CPU_STATE[cpu_index]);
        let stack = core::ptr::addr_of_mut!(SYSCALL_KERNEL_STACKS[cpu_index]);
        (*cpu_state).user_rsp = 0;
        (*cpu_state).kernel_stack_top.store(
            stack as u64 + core::mem::size_of::<SyscallKernelStack>() as u64,
            Ordering::Release,
        );

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

        // SWAPGS obtains this CPU's entry state before any GPR is saved.
        wrmsr(IA32_GS_BASE, 0);
        wrmsr(IA32_KERNEL_GS_BASE, cpu_state as u64);
    }
}

/// Select the current thread's guarded kernel stack for the next fast syscall.
/// The return frame remains on the thread stack if syscall-side suspension is added.
pub fn set_current_kernel_stack_top(stack_top: u64) -> bool {
    if stack_top == 0 || stack_top & 0xF != 0 {
        return false;
    }
    let apic_id = crate::arch::x86_64::apic::current_id();
    let Some(cpu_index) = crate::arch::x86_64::smp::cpu_index_for_apic_id(apic_id) else {
        return false;
    };
    // SAFETY: CPU-local syscall state was initialized before task scheduling;
    // the aligned AtomicU64 is read by entry assembly at byte offset 8.
    unsafe {
        let state = core::ptr::addr_of_mut!(SYSCALL_CPU_STATE[cpu_index]);
        (*state)
            .kernel_stack_top
            .store(stack_top, Ordering::Release);
    }
    true
}

/// Transition current thread of execution into unprivileged Ring 3 (User Space).
/// Pushes User SS (0x1B), User RSP, RFLAGS (0x202 with IF enabled), User CS (0x23),
/// and User RIP, and executes iretq.
#[no_mangle]
pub unsafe extern "C" fn enter_user_mode(entry_point: usize, user_stack_top: usize) -> ! {
    unsafe {
        core::arch::asm!(
            "mov ax, 0x1B", // User Data Segment (RPL=3)
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "push 0x1B",    // User SS (0x18 | 3)
            "push {stack}", // User RSP
            "push 0x202",   // RFLAGS (IF enabled, interrupts unmasked in user mode)
            "push 0x23",    // User CS (0x20 | 3)
            "push {entry}", // User RIP
            "iretq",
            stack = in(reg) user_stack_top,
            entry = in(reg) entry_point,
            options(noreturn)
        );
    }
}
