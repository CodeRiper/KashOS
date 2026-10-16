//! x86-64 boot glue: the Rust side of the handoff from the assembly boot stub.
//!
//! The actual 32-to-64-bit transition (Multiboot2 header, page tables, long
//! mode, GDT) lives in `boot.S`, assembled by `build.rs` with the system
//! `as` and linked in directly -- see that file's header comment for why
//! this one piece is not a rustc `global_asm!` block like every other arch
//! file in this kernel.

/// Called by `_start64` (in boot.S) once the 64-bit stack and BSS are ready.
/// `info` is the physical address of the Multiboot2 information structure.
#[no_mangle]
pub extern "C" fn rust_entry(hartid: usize, info: u64) -> ! {
    crate::kmain(hartid, info as usize)
}
