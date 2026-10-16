/* Phantom Kernel — AArch64 linker script
 * QEMU virt machine loads the kernel ELF at 0x40000000 (physical).
 * No OpenSBI layer on ARM64 — QEMU hands control directly to _start at EL2.
 */
OUTPUT_ARCH(aarch64)
ENTRY(_start)

BASE = 0x40000000;

SECTIONS {
    . = BASE;

    __text_start = .;
    .text.entry : ALIGN(4) {
        KEEP(*(.text.entry))
        KEEP(*(.text.entry.*))
    }

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
    }
    . = ALIGN(4K);
    __data_end = .;

    .bss (NOLOAD) : ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    /* Kernel stack — placed after BSS */
    .stack (NOLOAD) : ALIGN(4K) {
        __stack_bottom = .;
        . += 32K;
        __stack_top = .;
    }

    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) *(.comment) }
}
