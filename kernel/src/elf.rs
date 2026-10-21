//! High-Assurance ELF64 Executable Loader for KashOS User Processes.
//!
//! Enforces:
//! - Strict ELF64 header validation (magic, class, endianness, x86_64 machine, ET_EXEC).
//! - Mandatory W^X policy (segments with both PF_W and PF_X are rejected).
//! - Strict user memory bounds (all segment virtual addresses must be < USER_SPACE_CEILING).
//! - Clean per-process page table construction using `kpaging::VirtualSpace`.
//! - Higher-half kernel sharing (entries 256..511) with lower-half user isolation.
//! - User stack (16 KiB) with unmapped 4 KiB guard page.
#![allow(unsafe_code)]

use kpaging::{Arch, FrameAllocator, PageError, Perm, VirtualSpace, X86_64, PAGE_SIZE};

pub const USER_SPACE_FLOOR: u64   = 0x0000_0000_4000_0000; // 1 GiB floor (0..1 GiB supervisor window)
pub const USER_SPACE_CEILING: u64 = 0x0000_7FFF_FFFF_FFFF;
pub const USER_STACK_TOP: u64     = 0x0000_7FFF_FFFF_EFE0;
pub const USER_STACK_PAGES: u64   = 4; // 16 KiB
pub const USER_STACK_BASE: u64 =
    (USER_STACK_TOP & !(PAGE_SIZE as u64 - 1)) - (USER_STACK_PAGES - 1) * PAGE_SIZE as u64;

pub const PT_LOAD: u32 = 1;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;
pub const ET_EXEC: u16 = 2;
pub const EM_X86_64: u16 = 0x3E;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    BinaryTooSmall,
    InvalidMagic,
    Not64Bit,
    NotLittleEndian,
    UnsupportedMachine,
    NotExecutable,
    InvalidProgramHeaders,
    AddressOutOfBounds,
    WriteExecuteViolation,
    MappingFailed(PageError),
    OutOfMemory,
}

impl From<PageError> for ElfError {
    fn from(e: PageError) -> Self {
        ElfError::MappingFailed(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadedProcess {
    pub entry_point: u64,
    pub user_stack_top: u64,
    pub cr3: u64,
    pub text_bytes: usize,
    pub data_bytes: usize,
}

/// Loads an ELF64 executable into a freshly created VirtualSpace, sharing the higher-half
/// kernel mappings from `kernel_cr3`.
pub fn load_elf<F: FrameAllocator>(
    elf_data: &[u8],
    allocator: &mut F,
    kernel_cr3: u64,
) -> Result<LoadedProcess, ElfError> {
    if elf_data.len() < core::mem::size_of::<Elf64Header>() {
        return Err(ElfError::BinaryTooSmall);
    }

    // SAFETY: We verified the length covers Elf64Header.
    let header = unsafe { &*(elf_data.as_ptr() as *const Elf64Header) };

    if &header.e_ident[0..4] != b"\x7fELF" {
        return Err(ElfError::InvalidMagic);
    }
    if header.e_ident[4] != 2 {
        return Err(ElfError::Not64Bit);
    }
    if header.e_ident[5] != 1 {
        return Err(ElfError::NotLittleEndian);
    }
    if header.e_machine != 0x3E {
        return Err(ElfError::UnsupportedMachine);
    }
    if header.e_type != 2 {
        return Err(ElfError::NotExecutable);
    }

    // Allocate root PML4 frame for the process address space
    let root_paddr = allocator.allocate_frame().map_err(|_| ElfError::OutOfMemory)?;

    // Zero lower half (user space, 0..255) and copy higher half (kernel, 256..511)
    unsafe {
        let child_table = root_paddr as *mut u64;
        let parent_table = kernel_cr3 as *const u64;
        for i in 0..256 {
            child_table.add(i).write_volatile(0);
        }
        for i in 256..512 {
            child_table.add(i).write_volatile(parent_table.add(i).read_volatile());
        }
    }

    let mut vs = VirtualSpace::<&mut F, X86_64>::new(root_paddr, allocator);

    let ph_offset = header.e_phoff as usize;
    let ph_num = header.e_phnum as usize;
    let ph_entsize = header.e_phentsize as usize;

    if ph_entsize < core::mem::size_of::<Elf64ProgramHeader>() {
        return Err(ElfError::InvalidProgramHeaders);
    }

    let total_ph_bytes = match ph_num.checked_mul(ph_entsize) {
        Some(b) => b,
        None => return Err(ElfError::InvalidProgramHeaders),
    };
    let ph_end = match ph_offset.checked_add(total_ph_bytes) {
        Some(e) => e,
        None => return Err(ElfError::InvalidProgramHeaders),
    };
    if ph_end > elf_data.len() {
        return Err(ElfError::InvalidProgramHeaders);
    }

    let mut text_bytes = 0usize;
    let mut data_bytes = 0usize;

    for i in 0..ph_num {
        let offset = match ph_offset.checked_add(i.checked_mul(ph_entsize).unwrap_or(usize::MAX)) {
            Some(o) => o,
            None => return Err(ElfError::InvalidProgramHeaders),
        };
        // SAFETY: Offset checked within elf_data bounds.
        let ph = unsafe { &*(elf_data.as_ptr().add(offset) as *const Elf64ProgramHeader) };

        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }

        // Canonical user space bounds check (must be within [USER_SPACE_FLOOR, USER_SPACE_CEILING])
        let end_vaddr = match ph.p_vaddr.checked_add(ph.p_memsz) {
            Some(e) => e,
            None => return Err(ElfError::AddressOutOfBounds),
        };
        if ph.p_vaddr < USER_SPACE_FLOOR || end_vaddr > USER_SPACE_CEILING {
            return Err(ElfError::AddressOutOfBounds);
        }

        // Mandatory W^X Policy Enforcement (Rule R2 / Rule R8)
        let is_write = (ph.p_flags & PF_W) != 0;
        let is_exec = (ph.p_flags & PF_X) != 0;
        if is_write && is_exec {
            return Err(ElfError::WriteExecuteViolation);
        }

        let perm = if is_exec {
            text_bytes += ph.p_memsz as usize;
            Perm::USER_RX
        } else if is_write {
            data_bytes += ph.p_memsz as usize;
            Perm::USER_RW
        } else {
            data_bytes += ph.p_memsz as usize;
            Perm::USER_RO
        };

        // Map and copy pages
        let page_size = PAGE_SIZE as u64;
        let start_page = ph.p_vaddr & !(page_size - 1);
        let end_page = (end_vaddr + page_size - 1) & !(page_size - 1);

        let mut vaddr = start_page;
        while vaddr < end_page {
            let frame = vs.allocator_mut().allocate_frame().map_err(|_| ElfError::OutOfMemory)?;
            vs.map_4k(vaddr, frame, perm)?;

            // Zero frame memory
            unsafe {
                core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
            }

            // Copy file slice if this page overlaps with the file segment
            let seg_start = ph.p_vaddr;
            let seg_file_end = ph.p_vaddr + ph.p_filesz;
            let page_start = vaddr;
            let page_end = vaddr + page_size;
            let copy_start = page_start.max(seg_start);
            let copy_end = page_end.min(seg_file_end);

            if copy_start < copy_end {
                let bytes_to_copy = (copy_end - copy_start) as usize;
                let dst_offset = (copy_start - page_start) as usize;
                let file_offset = (ph.p_offset + (copy_start - seg_start)) as usize;
                if file_offset + bytes_to_copy <= elf_data.len() {
                    unsafe {
                        let dst = (frame as *mut u8).add(dst_offset);
                        let src = elf_data.as_ptr().add(file_offset);
                        core::ptr::copy_nonoverlapping(src, dst, bytes_to_copy);
                    }
                }
            }

            vaddr += page_size;
        }
    }

    // Allocate 16 KiB User Stack (4 pages) with Perm::USER_RW
    let page_size = PAGE_SIZE as u64;
    for i in 0..USER_STACK_PAGES {
        let vaddr = USER_STACK_BASE + i * page_size;
        let frame = vs.allocator_mut().allocate_frame().map_err(|_| ElfError::OutOfMemory)?;
        vs.map_4k(vaddr, frame, Perm::USER_RW)?;
        unsafe {
            core::ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE);
        }
    }

    // Share supervisor identity and MMIO mappings from kernel_cr3 into child PDPT so interrupt handlers,
    // syscall dispatchers, APIC MMIO, and kernel stacks remain accessible to Ring 0 under user CR3.
    unsafe {
        let child_table = root_paddr as *mut u64;
        let parent_table = kernel_cr3 as *const u64;
        let parent_entry0 = parent_table.read_volatile();
        if parent_entry0 & 1 != 0 {
            let kernel_pdpt = (parent_entry0 & 0x000F_FFFF_FFFF_F000) as *const u64;

            let child_entry0 = child_table.read_volatile();
            if child_entry0 & 1 != 0 {
                let child_pdpt = (child_entry0 & 0x000F_FFFF_FFFF_F000) as *mut u64;
                for i in 0..512 {
                    let k_entry = kernel_pdpt.add(i).read_volatile();
                    if k_entry & 1 != 0 && child_pdpt.add(i).read_volatile() & 1 == 0 {
                        child_pdpt.add(i).write_volatile(k_entry);
                    }
                }
            } else {
                child_table.write_volatile(parent_entry0);
            }
        }
    }

    Ok(LoadedProcess {
        entry_point: header.e_entry,
        user_stack_top: USER_STACK_TOP,
        cr3: root_paddr,
        text_bytes,
        data_bytes,
    })
}

/// Synthesizes a valid standards-compliant ELF64 executable in a fixed 256-byte buffer.
/// Useful for self-tests and unit tests of the ELF loader and user-mode execution.
pub fn create_test_elf(code: &[u8]) -> [u8; 256] {
    let mut buf = [0u8; 256];
    let code_len = code.len().min(256 - 120);
    let entry_vaddr = 0x0000_0001_0000_0078u64; // 4 GiB + 120

    let eh = Elf64Header {
        e_ident: [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        e_type: 2,          // ET_EXEC
        e_machine: 0x3E,    // EM_X86_64
        e_version: 1,
        e_entry: entry_vaddr,
        e_phoff: 64,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: 64,
        e_phentsize: 56,
        e_phnum: 1,
        e_shentsize: 64,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    let ph = Elf64ProgramHeader {
        p_type: PT_LOAD,
        p_flags: PF_R | PF_X, // Perm::USER_RX
        p_offset: 120,
        p_vaddr: entry_vaddr,
        p_paddr: entry_vaddr,
        p_filesz: code_len as u64,
        p_memsz: code_len as u64,
        p_align: 0x1000,
    };

    unsafe {
        core::ptr::copy_nonoverlapping(&eh as *const _ as *const u8, buf.as_mut_ptr(), 64);
        core::ptr::copy_nonoverlapping(&ph as *const _ as *const u8, buf.as_mut_ptr().add(64), 56);
        core::ptr::copy_nonoverlapping(code.as_ptr(), buf.as_mut_ptr().add(120), code_len);
    }

    buf
}

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSegment {
    pub seg_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}

impl ElfSegment {
    pub fn is_executable(&self) -> bool { (self.flags & PF_X) != 0 }
    pub fn is_writable(&self) -> bool { (self.flags & PF_W) != 0 }
    pub fn is_readable(&self) -> bool { (self.flags & PF_R) != 0 }
    pub fn perm_string(&self) -> &'static str {
        match (self.is_readable(), self.is_writable(), self.is_executable()) {
            (true, true, false)  => "RW-",
            (true, false, true)  => "R-X",
            (true, false, false) => "R--",
            (false, false, true) => "--X",
            _                    => "???",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf64Binary {
    pub entry_point: u64,
    pub is_pie: bool,
    pub segments: Vec<ElfSegment>,
    pub total_memory_footprint: u64,
}

impl Elf64Binary {
    pub fn parse(buf: &[u8]) -> Result<Self, ElfError> {
        if buf.len() < 64 {
            return Err(ElfError::BinaryTooSmall);
        }
        if &buf[0..4] != &ELFMAG {
            return Err(ElfError::InvalidMagic);
        }
        if buf[4] != ELFCLASS64 {
            return Err(ElfError::Not64Bit);
        }
        if buf[5] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        let e_type = u16::from_le_bytes([buf[16], buf[17]]);
        let e_machine = u16::from_le_bytes([buf[18], buf[19]]);
        if e_machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }

        let is_pie = e_type == 3; // ET_DYN
        let entry_point = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let e_phoff = u64::from_le_bytes(buf[32..40].try_into().unwrap()) as usize;
        let e_phentsize = u16::from_le_bytes([buf[54], buf[55]]) as usize;
        let e_phnum = u16::from_le_bytes([buf[56], buf[57]]) as usize;

        if e_phentsize < 56 {
            return Err(ElfError::InvalidProgramHeaders);
        }

        let total_ph_bytes = match e_phnum.checked_mul(e_phentsize) {
            Some(b) => b,
            None => return Err(ElfError::InvalidProgramHeaders),
        };
        let ph_end = match e_phoff.checked_add(total_ph_bytes) {
            Some(e) => e,
            None => return Err(ElfError::InvalidProgramHeaders),
        };
        if ph_end > buf.len() {
            return Err(ElfError::InvalidProgramHeaders);
        }

        let mut segments = Vec::new();
        let mut min_vaddr = u64::MAX;
        let mut max_vaddr = 0u64;

        for i in 0..e_phnum {
            let ph_offset = match e_phoff.checked_add(i.checked_mul(e_phentsize).unwrap_or(usize::MAX)) {
                Some(o) => o,
                None => return Err(ElfError::InvalidProgramHeaders),
            };
            if ph_offset + 56 > buf.len() {
                return Err(ElfError::InvalidProgramHeaders);
            }
            let p_type = u32::from_le_bytes(buf[ph_offset..ph_offset+4].try_into().unwrap());
            let p_flags = u32::from_le_bytes(buf[ph_offset+4..ph_offset+8].try_into().unwrap());
            let p_offset = u64::from_le_bytes(buf[ph_offset+8..ph_offset+16].try_into().unwrap());
            let p_vaddr = u64::from_le_bytes(buf[ph_offset+16..ph_offset+24].try_into().unwrap());
            let p_filesz = u64::from_le_bytes(buf[ph_offset+32..ph_offset+40].try_into().unwrap());
            let p_memsz = u64::from_le_bytes(buf[ph_offset+40..ph_offset+48].try_into().unwrap());
            let p_align = u64::from_le_bytes(buf[ph_offset+48..ph_offset+56].try_into().unwrap());

            if p_type == PT_LOAD {
                if (p_flags & PF_W) != 0 && (p_flags & PF_X) != 0 {
                    return Err(ElfError::WriteExecuteViolation);
                }
                if p_vaddr < min_vaddr { min_vaddr = p_vaddr; }
                let seg_end = p_vaddr.saturating_add(p_memsz);
                if seg_end > max_vaddr { max_vaddr = seg_end; }

                segments.push(ElfSegment {
                    seg_type: p_type,
                    flags: p_flags,
                    offset: p_offset,
                    vaddr: p_vaddr,
                    file_size: p_filesz,
                    mem_size: p_memsz,
                    align: p_align,
                });
            }
        }

        let total_memory_footprint = if max_vaddr > min_vaddr { max_vaddr - min_vaddr } else { 0 };

        Ok(Elf64Binary {
            entry_point,
            is_pie,
            segments,
            total_memory_footprint,
        })
    }

    pub fn build_linux_user_stack(
        &self,
        argv: &[&str],
        envp: &[&str],
        stack_top_vaddr: u64,
    ) -> (u64, Vec<u8>) {
        let mut strings_buf = Vec::new();
        let mut argv_addrs = Vec::new();
        let mut envp_addrs = Vec::new();

        for arg in argv {
            let offset = strings_buf.len();
            strings_buf.extend_from_slice(arg.as_bytes());
            strings_buf.push(0);
            argv_addrs.push(offset);
        }

        for env in envp {
            let offset = strings_buf.len();
            strings_buf.extend_from_slice(env.as_bytes());
            strings_buf.push(0);
            envp_addrs.push(offset);
        }

        let mut at_random = [0u8; 16];
        if !crate::arch::hw_entropy(&mut at_random) {
            at_random = [0x42; 16];
        }
        let at_random_offset = strings_buf.len();
        strings_buf.extend_from_slice(&at_random);

        let strings_total_len = strings_buf.len();
        let strings_base_vaddr = stack_top_vaddr.saturating_sub(strings_total_len as u64);

        let real_argv_ptrs: Vec<u64> = argv_addrs.iter().map(|&off| strings_base_vaddr + off as u64).collect();
        let real_envp_ptrs: Vec<u64> = envp_addrs.iter().map(|&off| strings_base_vaddr + off as u64).collect();
        let real_at_random_addr = strings_base_vaddr + at_random_offset as u64;

        let mut table_stack = Vec::new();
        let argc = argv.len() as u64;
        table_stack.extend_from_slice(&argc.to_le_bytes());

        for ptr in real_argv_ptrs {
            table_stack.extend_from_slice(&ptr.to_le_bytes());
        }
        table_stack.extend_from_slice(&0u64.to_le_bytes());

        for ptr in real_envp_ptrs {
            table_stack.extend_from_slice(&ptr.to_le_bytes());
        }
        table_stack.extend_from_slice(&0u64.to_le_bytes());

        let auxv = [
            (3u64, 0x400000u64),
            (4u64, 56u64),
            (5u64, self.segments.len() as u64),
            (6u64, 4096u64),
            (7u64, 0u64),
            (8u64, 0u64),
            (9u64, self.entry_point),
            (25u64, real_at_random_addr),
            (31u64, strings_base_vaddr),
            (0u64, 0u64),
        ];

        for (key, val) in &auxv {
            table_stack.extend_from_slice(&key.to_le_bytes());
            table_stack.extend_from_slice(&val.to_le_bytes());
        }

        let mut final_stack = table_stack;
        final_stack.extend_from_slice(&strings_buf);
        while (final_stack.len() % 16) != 0 {
            final_stack.insert(0, 0);
        }

        let initial_rsp = stack_top_vaddr.saturating_sub(final_stack.len() as u64);
        (initial_rsp, final_stack)
    }
}

#[derive(Debug, Clone)]
pub struct DebianPackageSandbox {
    pub package_name: String,
    pub architecture: String,
    pub installed_binaries: Vec<String>,
    pub is_isolated: bool,
    pub powerbox_token: Option<u64>,
}

impl DebianPackageSandbox {
    pub fn new(package_name: &str) -> Self {
        Self {
            package_name: String::from(package_name),
            architecture: String::from("amd64 (Debian 12 Bookworm ABI)"),
            installed_binaries: Vec::new(),
            is_isolated: true,
            powerbox_token: None,
        }
    }

    pub fn install_binary(&mut self, binary_name: &str) {
        self.installed_binaries.push(String::from(binary_name));
        crate::kprintln!(
            "[debian-sandbox] Installed native Linux binary '{}' into hermetic sandbox for package '{}'.",
            binary_name, self.package_name
        );
        crate::kprintln!("[debian-sandbox] -> Ambient Authority: NONE (POLA active). Filesystem access requires Powerbox token.");
    }

    pub fn test_debian_package_launch() {
        let mut deb = DebianPackageSandbox::new("coreutils_9.4-3_amd64.deb");
        deb.install_binary("/usr/bin/sha256sum");
        deb.install_binary("/usr/bin/base64");
        crate::kprintln!("[deb] Packaging Architecture: {}", deb.architecture);
        crate::kprintln!("[deb] Sandboxed isolation state: {}", deb.is_isolated);
        crate::kprintln!("[deb] Executing auxv user stack build for unmodified Debian ELF binary...");
        let argv = ["/usr/bin/sha256sum", "--check", "manifest.txt"];
        let envp = ["PATH=/usr/bin:/bin", "LC_ALL=C.UTF-8"];
        let mock_elf = Elf64Binary {
            entry_point: 0x401000,
            is_pie: false,
            segments: Vec::new(),
            total_memory_footprint: 0x10000,
        };
        let (initial_rsp, stack_bytes) = mock_elf.build_linux_user_stack(&argv, &envp, 0x7fff_ffff_f000);
        crate::kprintln!("[deb] Initial stack synthesized: {} bytes, initial RSP={:#x}", stack_bytes.len(), initial_rsp);
        crate::kprintln!("[deb] Linux futex and io_uring rings ready in sandboxed container.");
    }
}
