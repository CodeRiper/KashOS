# Kash Kernel — Makefile
#
# Targets:
#   make all          — build both architectures
#   make x86          — build x86-64 ELF
#   make arm          — build AArch64 ELF
#   make iso          — build x86 + wrap in a GRUB2 Multiboot2 ISO
#   make run-x86      — boot the ISO in QEMU q35 (BIOS + GRUB path)
#   make run-arm      — boot the ELF directly in QEMU virt (AArch64)
#   make test         — host unit/fuzz tests (kcore + kvault)
#   make test-x86     — build ISO + boot + grep for PASS banner
#   make test-arm     — build ELF + boot + grep for PASS banner
#   make full-test     — all of the above
#   make clean
#
# NOTE on x86 boot method: QEMU's `-kernel` direct-boot flag does NOT accept
# this kernel on this QEMU build ("Error loading uncompressed kernel without
# PVH ELF Note" — confirmed by testing; QEMU's x86 direct-kernel loader wants
# a Linux bzImage or a Xen PVH note, not a bare Multiboot2 ELF). The correct,
# more portable route — which is also exactly what VirtualBox needs — is a
# GRUB2-bootable ISO: BIOS/VirtualBox boots GRUB from the CD, GRUB reads the
# Multiboot2 header and loads the kernel per spec. `run-x86`/`test-x86`
# therefore boot via `-cdrom`, not `-kernel`. AArch64 has no such issue:
# QEMU virt's direct `-kernel` ELF boot works for the kernel as built.

TARGET_X86  := x86_64-unknown-none
TARGET_ARM  := aarch64-unknown-none-softfloat

BIN_X86     := target/$(TARGET_X86)/release/kernel
BIN_ARM     := target/$(TARGET_ARM)/release/kernel

BSTD := -Zbuild-std=core,alloc,compiler_builtins \
        -Zbuild-std-features=compiler-builtins-mem

QEMU_ARM  := qemu-system-aarch64 \
             -machine virt,gic-version=3 \
             -cpu cortex-a57 \
             -m 512M \
             -nographic \
             -no-reboot \
             -kernel $(BIN_ARM)

ISOFILE := kash-kernel.iso
ISODIR  := target/isodir

QEMU_X86 := qemu-system-x86_64 \
            -machine q35 \
            -cpu max \
            -m 512M \
            -nographic \
            -no-reboot \
            -cdrom $(ISOFILE)

.PHONY: all x86 arm iso run-x86 run-arm test test-x86 test-arm full-test \
        disasm-x86 size-x86 size-arm clean

all: x86 arm

x86:
	cargo build --release -p kernel --target $(TARGET_X86)
	@echo "✓ x86-64 kernel: $(BIN_X86)"
	@ls -lh $(BIN_X86)

arm:
	cargo build --release -p kernel --target $(TARGET_ARM) --features kernel/qemu-virt
	@echo "✓ AArch64 kernel: $(BIN_ARM)"
	@ls -lh $(BIN_ARM)

# Requires: grub-pc-bin grub-common xorriso (apt install them)
iso: x86
	@mkdir -p $(ISODIR)/boot/grub
	@cp $(BIN_X86) $(ISODIR)/boot/phantom-kernel
	@printf 'set default=0\nset timeout=1\nmenuentry "Kash Kernel" {\n  multiboot2 /boot/phantom-kernel\n  boot\n}\n' \
		> $(ISODIR)/boot/grub/grub.cfg
	@grub-mkrescue -o $(ISOFILE) $(ISODIR) 2>/dev/null || \
		(echo "⚠  grub-mkrescue not found. Install: sudo apt install grub-pc-bin grub-common xorriso" && false)
	@echo "✓ ISO: $(ISOFILE)"
	@ls -lh $(ISOFILE)

# How to use with VirtualBox:
# 1. New VM → Type: Linux → Version: Other Linux (64-bit)
# 2. Memory: 512 MB · No hard disk (amnesic by design)
# 3. Settings → Storage → Add optical drive → kash-kernel.iso
# 4. Start — BIOS loads GRUB from the ISO, GRUB loads the Multiboot2 kernel.

run-arm: arm
	$(QEMU_ARM)

run-x86: iso
	$(QEMU_X86)

test:
	RUSTC_BOOTSTRAP=1 cargo test -p kcore -p kvault
	@echo "✓ kcore + kvault host tests passed"

test-arm: arm
	@timeout 30 $(QEMU_ARM) > /tmp/phantom_arm_boot.log 2>&1 || true
	@grep -q "all milestone-2 self-tests passed" /tmp/phantom_arm_boot.log && \
		echo "✓ AArch64 BOOT TEST PASSED" || \
		(echo "✗ AArch64 BOOT TEST FAILED"; cat /tmp/phantom_arm_boot.log; exit 1)

test-x86: iso
	@timeout 30 $(QEMU_X86) > /tmp/phantom_x86_boot.log 2>&1 || true
	@grep -q "all milestone-2 self-tests passed" /tmp/phantom_x86_boot.log && \
		echo "✓ x86-64 BOOT TEST PASSED" || \
		(echo "✗ x86-64 BOOT TEST FAILED"; cat /tmp/phantom_x86_boot.log; exit 1)

full-test: test test-arm test-x86
	@echo "✓ ALL TESTS PASSED (host + AArch64 + x86-64)"

disasm-x86: x86
	llvm-objdump -d -M intel --no-show-raw-insn $(BIN_X86) | head -200

size-x86: x86
	llvm-size $(BIN_X86)

size-arm: arm
	llvm-size $(BIN_ARM)

clean:
	cargo clean
	rm -rf $(ISOFILE) $(ISODIR) /tmp/phantom_*.log
