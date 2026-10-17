use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let script = match target.as_str() {
        "x86_64" => "linker-x86_64.ld",
        "aarch64" => "linker-aarch64.ld",
        _ => "linker-riscv64.ld",
    };
    println!("cargo:rustc-link-arg-bins=-T{dir}/{script}");
    println!("cargo:rerun-if-changed={dir}/{script}");

    if target == "x86_64" {
        // The x86-64 boot stub (Multiboot2 header + 32->64-bit transition) is
        // hand-written Intel-syntax assembly in boot.S, assembled with the
        // system `as` and linked in directly, rather than compiled through
        // rustc's `global_asm!`. See boot.S's header comment: this file
        // assembles cleanly with GNU as, but LLVM's integrated assembler
        // (what `global_asm!` uses) rejects some of the same, valid Intel
        // syntax ("unexpected token in argument list" on a far jmp with an
        // immediate target and on a bare symbol used as a 32-bit immediate
        // address) — using the real assembler for this one file sidesteps
        // that gap rather than rewriting working, GNU-as-verified boot code
        // around an LLVM MC limitation.
        let asm_src = format!("{dir}/src/arch/x86_64/boot.S");
        let obj_out = out_dir.join("boot_x86_64.o");
        println!("cargo:rerun-if-changed={asm_src}");

        let as_cmd = if Command::new("as").arg("--version").output().is_ok() {
            "as"
        } else if Command::new("x86_64-w64-mingw32-as").arg("--version").output().is_ok() {
            "x86_64-w64-mingw32-as"
        } else {
            "as"
        };

        // Assemble boot.S with GNU as (--64) or clang
        let mut assembled = false;
        for assembler in [as_cmd, "as", "x86_64-linux-gnu-as", "x86_64-elf-as", "x86_64-w64-mingw32-as"] {
            let res = Command::new(assembler)
                .args(["--64", "-o"])
                .arg(&obj_out)
                .arg(&asm_src)
                .status();
            if let Ok(s) = res {
                if s.success() && obj_out.exists() {
                    assembled = true;
                    break;
                }
            }
        }

        if !assembled {
            let res = Command::new("clang")
                .args(["-c", "-target", "x86_64-unknown-none", "-o"])
                .arg(&obj_out)
                .arg(&asm_src)
                .status();
            if let Ok(s) = res {
                if s.success() && obj_out.exists() {
                    assembled = true;
                }
            }
        }

        assert!(
            assembled && obj_out.exists(),
            "assembling boot.S failed: could not produce {}",
            obj_out.display()
        );

        println!("cargo:rustc-link-arg-bins={}", obj_out.display());
    }
}
