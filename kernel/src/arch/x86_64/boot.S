/* Kash Kernel — x86-64 boot stub.
 *
 * This file is assembled by the system `as` (GNU binutils) and linked into
 * the kernel binary by build.rs — NOT compiled via rustc's global_asm!.
 * Rationale: this file assembles cleanly and correctly with GNU as, but the
 * same Intel-syntax source (far jmp with an immediate target, a bare symbol
 * used as a 32-bit immediate address) is rejected by LLVM's integrated
 * assembler ("unexpected token in argument list"). Using the real GNU
 * assembler for this one file sidesteps that gap entirely rather than
 * fighting LLVM MC's narrower Intel-syntax support. Everything else in the
 * kernel still goes through rustc as normal; only this boot stub is special.
 *
 * Boot sequence: BIOS/UEFI -> GRUB2 or QEMU `-kernel` (direct Multiboot2) ->
 * 32-bit protected-mode _start -> identity-map 0..2GiB with 2MiB pages ->
 * enable PAE + long mode + paging -> far jump to 64-bit _start64 ->
 * zero BSS -> call rust_entry(hartid=0, multiboot2_info_ptr).
 */
.intel_syntax noprefix

/* -- Xen PVH ELF Note (enables direct QEMU x86-64 -kernel loading) -- */
.section .note.Xen, "a", @note
.align 4
    .long  4                                         /* namesz: "Xen\0"          */
    .long  4                                         /* descsz: 4 bytes          */
    .long  18                                        /* type: XEN_ELFNOTE_PHYS32_ENTRY (18) */
    .asciz "Xen"                                     /* name                     */
.align 4
    .long  _start                                    /* physical entry point     */
.align 4

/* -- Multiboot2 header (MUST be within the first 32 KiB of the image) -- */
.section .multiboot2_header, "a"
.align 8
_mb2_start:
    .long  0xe85250d6                            /* magic: Multiboot2        */
    .long  0                                     /* architecture: i386       */
    .long  _mb2_end - _mb2_start                 /* header length            */
    .long  -(0xe85250d6 + (_mb2_end - _mb2_start))  /* checksum              */

    /* Framebuffer request tag (type 5) */
    .align 8
    .word  5                                     /* type: framebuffer request */
    .word  0                                     /* flags: required          */
    .long  20                                    /* size: 20 bytes           */
    .long  1024                                  /* width: 1024 px           */
    .long  768                                   /* height: 768 px           */
    .long  32                                    /* depth: 32 bpp            */

    /* end tag */
    .align 8
    .word  0
    .word  0
    .long  8
_mb2_end:

/* -- BSS: boot-time page tables + boot stack -- */
.section .bss
.align 4096
_boot_pml4:  .skip 4096
_boot_pdpt:  .skip 4096
_boot_pd0:   .skip 4096       /* 512 entries of 2 MiB = 1 GiB (0..1 GiB) */
_boot_pd3:   .skip 4096       /* 512 entries of 2 MiB = 1 GiB (3..4 GiB for APIC 0xFEE00000) */
.align 4096
.global _boot_stack_guard
_boot_stack_guard:  .skip 4096
.align 16
_boot_stack_bottom: .skip 65536
.global _boot_stack_top        /* referenced from Rust (arch::boot_stack_top) */
_boot_stack_top:
.quad  0
.global _boot_magic
_boot_magic:
.quad  0

/* -- 64-bit GDT (code + data, flat, DPL=0) -- */
.section .data
.align 8
_gdt64:
    .quad  0x0000000000000000
    .quad  0x00AF9A000000FFFF
    .quad  0x00AF92000000FFFF
_gdt64_end:

_gdt64_ptr:
    .word  _gdt64_end - _gdt64 - 1
    .long  _gdt64

/* -- 32-bit protected-mode entry -- */
.section .text.entry32, "ax"
.code32
.global _start
_start:
    mov   edx, ebx              /* stash boot info ptr (ebx) */
    mov   esi, eax              /* stash boot magic (eax) */

    cli
    cld

    /* Zero .bss BEFORE paging/page tables exist. */
    lea   edi, [__bss_start]
    lea   ecx, [__bss_end]
    sub   ecx, edi
    xor   eax, eax
    rep   stosb

    mov   [_boot_stack_top], edx   /* info ptr */
    mov   [_boot_magic], esi       /* boot magic */

    mov   esp, _boot_stack_top

    /* == Hardware Feature Checks (Task F-02 / Rule 17) ==
     * Verify CPUID, MSR, PAE, APIC, SSE2, Long Mode, and NX before touching EFER. */
    pushfd
    pop   eax
    mov   ecx, eax
    xor   eax, 0x00200000
    push  eax
    popfd
    pushfd
    pop   eax
    push  ecx
    popfd
    xor   eax, ecx
    jz    _cpu_missing_cpuid

    mov   eax, 1
    cpuid
    test  edx, 0x00000020     /* bit 5: MSR */
    jz    _cpu_missing_msr
    test  edx, 0x00000040     /* bit 6: PAE */
    jz    _cpu_missing_pae
    test  edx, 0x00000200     /* bit 9: APIC */
    jz    _cpu_missing_apic
    test  edx, 0x04000000     /* bit 26: SSE2 */
    jz    _cpu_missing_sse2

    mov   eax, 0x80000000
    cpuid
    cmp   eax, 0x80000001
    jb    _cpu_missing_longmode

    mov   eax, 0x80000001
    cpuid
    test  edx, 0x20000000     /* bit 29: Long Mode */
    jz    _cpu_missing_longmode
    test  edx, 0x00100000     /* bit 20: No-Execute (NX) */
    jz    _cpu_missing_nx

    lgdt  [_gdt64_ptr]

    mov   eax, cr4
    or    eax, 0x20
    mov   cr4, eax

    /* PML4[0] -> PDPT */
    lea   edi, [_boot_pml4]
    lea   eax, [_boot_pdpt]
    or    eax, 3                   /* PRESENT | WRITABLE */
    mov   [edi], eax

    /* PDPT[0] -> PD0 (0..1 GiB) */
    lea   edi, [_boot_pdpt]
    lea   eax, [_boot_pd0]
    or    eax, 3
    mov   [edi], eax

    /* PDPT[3] -> PD3 (3..4 GiB for APIC 0xFEE00000) */
    lea   eax, [_boot_pd3]
    or    eax, 3
    mov   [edi + 24], eax

    /* Fill PD0: 512 entries of 2 MiB (0..1 GiB) with bit 7 (PS=2MB page).
     * Supported on ALL x86-64 CPUs including vintage Core 2 Duo and Athlon 64! */
    lea   edi, [_boot_pd0]
    mov   eax, 0x83                /* PRESENT | WRITABLE | PAGE_SIZE (2 MiB) */
    mov   ecx, 512
_fill_pd0:
    mov   dword ptr [edi],   eax
    mov   dword ptr [edi+4], 0
    add   edi, 8
    add   eax, 0x00200000          /* next 2 MiB */
    loop  _fill_pd0

    /* Fill PD3: 512 entries of 2 MiB (3..4 GiB, covers 0xFEE00000 APIC) */
    lea   edi, [_boot_pd3]
    mov   eax, 0xC0000083          /* start at 3 GiB */
    mov   ecx, 512
_fill_pd3:
    mov   dword ptr [edi],   eax
    mov   dword ptr [edi+4], 0
    add   edi, 8
    add   eax, 0x00200000          /* next 2 MiB */
    loop  _fill_pd3

    lea   eax, [_boot_pml4]
    mov   cr3, eax

    /* EFER: LME (bit 8, long mode enable) and NXE (bit 11, no-execute enable) */
    mov   ecx, 0xC0000080
    rdmsr
    or    eax, 0x901          /* SCE (bit 0) + LME (bit 8) + NXE (bit 11) */
    wrmsr

    mov   eax, cr0
    or    eax, 0x80000001
    mov   cr0, eax

    .att_syntax prefix
    ljmpl $0x08, $_start64
    .intel_syntax noprefix

_cpu_missing_cpuid:
    lea   esi, [_str_err_cpuid]
    jmp   _boot_refusal_halt

_cpu_missing_msr:
    lea   esi, [_str_err_msr]
    jmp   _boot_refusal_halt

_cpu_missing_pae:
    lea   esi, [_str_err_pae]
    jmp   _boot_refusal_halt

_cpu_missing_apic:
    lea   esi, [_str_err_apic]
    jmp   _boot_refusal_halt

_cpu_missing_sse2:
    lea   esi, [_str_err_sse2]
    jmp   _boot_refusal_halt

_cpu_missing_longmode:
    lea   esi, [_str_err_longmode]
    jmp   _boot_refusal_halt

_cpu_missing_nx:
    lea   esi, [_str_err_nx]
    jmp   _boot_refusal_halt

_boot_refusal_halt:
    mov   edi, 0x000B8000
    mov   ah, 0x4F

_refusal_loop:
    lodsb
    test  al, al
    jz    _refusal_done
    mov   [edi], ax
    add   edi, 2
    mov   bl, al
_wait_serial:
    mov   dx, 0x3FD
    in    al, dx
    test  al, 0x20
    jz    _wait_serial
    mov   al, bl
    mov   dx, 0x3F8
    out   dx, al
    jmp   _refusal_loop

_refusal_done:
_refusal_hang:
    cli
    hlt
    jmp   _refusal_hang

_boot32_hang:
    hlt
    jmp   _boot32_hang

.section .rodata.boot_err, "a"
_str_err_cpuid:
    .asciz "\r\n[KashOS Boot Error] CPU lacks CPUID support. KashOS requires an x86_64 CPU with NX. System halted.\r\n"
_str_err_msr:
    .asciz "\r\n[KashOS Boot Error] CPU lacks MSR support. KashOS requires an x86_64 CPU with NX. System halted.\r\n"
_str_err_pae:
    .asciz "\r\n[KashOS Boot Error] CPU lacks PAE support. KashOS requires an x86_64 CPU with NX. System halted.\r\n"
_str_err_apic:
    .asciz "\r\n[KashOS Boot Error] CPU lacks on-chip APIC. KashOS requires an x86_64 CPU with NX. System halted.\r\n"
_str_err_sse2:
    .asciz "\r\n[KashOS Boot Error] CPU lacks SSE2 support. KashOS requires an x86_64 CPU with NX. System halted.\r\n"
_str_err_longmode:
    .asciz "\r\n[KashOS Boot Error] This CPU lacks 64-bit Long Mode (32-bit CPU detected). KashOS requires x86_64 with NX. System halted.\r\n"
_str_err_nx:
    .asciz "\r\n[KashOS Boot Error] This CPU lacks No-Execute (NX) page protection. KashOS requires x86_64 with NX. System halted.\r\n"

/* -- 64-bit entry -- */
.section .text
.code64
.global _start64
_start64:
    mov   ax, 0x10
    mov   ds, ax
    mov   es, ax
    mov   ss, ax
    xor   ax, ax
    mov   fs, ax
    mov   gs, ax

    lea   rsp, [rip + _boot_stack_top]

    push  0
    popfq

    /* .bss (including the boot page tables) was already zeroed in 32-bit
     * mode, before paging was enabled — see the comment at _start. Doing it
     * again here, now, would zero out the live PML4/PDPT/PD that CR3 is
     * actively pointing at. */

    xor   rdi, rdi
    lea   rax, [rip + _boot_stack_top]
    mov   esi, dword ptr [rax]
    call  rust_entry

_hang64:
    cli
    hlt
    jmp   _hang64

.att_syntax prefix
