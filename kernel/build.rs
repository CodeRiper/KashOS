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

        let mut cmd = Command::new(as_cmd);
        cmd.args(["-c", "-target", "x86_64-unknown-none", "-o"])
            .arg(&obj_out)
            .arg(&asm_src);

        let status = match cmd.status() {
            Ok(s) if s.success() => s,
            _ => {
                // Fallback to GNU as syntax
                Command::new(as_cmd)
                    .args(["--64", "-o"])
                    .arg(&obj_out)
                    .arg(&asm_src)
                    .status()
                    .expect("failed to run assembler on boot.S")
            }
        };
        assert!(
            status.success(),
            "assembling boot.S failed (see `as` output above)"
        );

        println!("cargo:rustc-link-arg-bins={}", obj_out.display());
    }
}
