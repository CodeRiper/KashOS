# A10 syscall entry state design

Audit date: 2026-10-20. Scope: x86-64 fast syscall entry state only.

- AMD's AMD64 Architecture Programmer's Manual, Volume 2, revision 3.44
  (March 2026), explains that SYSCALL supplies no kernel stack. SWAPGS is the
  intended way to obtain a kernel pointer without first clobbering a register.
- Intel SDM version 093 (updated 2026-10-09), section 31.10.4.4, describes
  SWAPGS exchanging IA32_GS_BASE and IA32_KERNEL_GS_BASE for fast syscall use.
- Current KashOS switches from user RSP to a single global stack and stores
  user RSP in a single global word. Concurrent entries would overwrite both.
- Give each syscall-enabled CPU its own entry state containing its saved user
  RSP and kernel stack top. After SWAPGS, assembly accesses these fields via
  GS-relative offsets; no GPR must be saved before the stack switch.
- Keep user RSP in a caller-saved register until the return RIP is validated.
  Construct an IRET frame on the trusted kernel stack, never on user memory.
- Map the BSP's current APIC ID to the firmware-discovered CPU slot before
  installing its GS base. Initialize SMP discovery before syscall MSRs.
- APs currently do not install the kernel GDT/IDT/TSS or enable user tasks.
  This change must not claim SMP userland support; any future AP syscall setup
  must explicitly install that CPU's own state after per-CPU architecture setup.
- T0/QEMU remains the required real path; source guards cover that per-core
  state is present and that malformed return state cannot select a user stack
  while the kernel constructs an IRET frame.

Sources:

- [AMD64 Architecture Programmer's Manual, Volume 2, rev. 3.44](https://docs.amd.com/v/u/en-US/24593_3.44_APM_Vol2)
- [Intel 64 and IA-32 Architectures Software Developer Manuals, version 093](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
