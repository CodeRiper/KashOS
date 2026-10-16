/* Phantom Kernel — x86-64 linker script
 * Load address: 1 MiB (0x100000) — standard for Multiboot2 kernels.
 * The Multiboot2 header MUST appear in the first 32KiB of the image.
 * QEMU q35 boots this directly with -kernel; GRUB2 can also load it for VirtualBox.
 */
OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

BASE = 0x100000;   /* 1 MiB */

SECTIONS {
    . = BASE;

    /* PVH ELF Note for direct QEMU x86-64 booting */
    .note.Xen : ALIGN(4) {
        KEEP(*(.note.Xen))
    }

    /* Multiboot2 header — within 32 KiB of start */
    .multiboot2_header : ALIGN(8) {
        KEEP(*(.multiboot2_header))
    }

    /* 32-bit entry stub (multiboot boots us in protected mode). Part of the
     * executable region — the kernel still needs it readable+executable
     * even after the W^X live page-table switchover, since _start/_start64
     * live here and nothing re-enters 32-bit mode to need it afterward, but
     * leaving it mapped RX rather than unmapping it is the simpler, equally
     * correct choice. */
    __text_start = .;
    .text.entry32 : ALIGN(4) {
        KEEP(*(.text.entry32))
    }

    /* 64-bit kernel code */
    .text : ALIGN(4K) {
        *(.text .text.*)
    }
    . = ALIGN(4K);
    __text_end = .;

    __rodata_start = .;
    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }
    . = ALIGN(4K);
    __rodata_end = .;

    __data_start = .;
    .data : ALIGN(4K) {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }
    . = ALIGN(4K);
    __data_end = .;

    /* Boot-time page tables — MUST be page-aligned and zero-initialised */
    .bss : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4K);
        __bss_end = .;
    }

    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) *(.note*) *(.comment) }
}
