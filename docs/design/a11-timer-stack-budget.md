# A11 x86-64 timer interrupt stack budget

## Question

The timer ISR reserves 528 bytes for an FXSAVE image and a pointer slot after
saving the interrupted GPRs. Establish how much additional stack the compiled
normal scheduler path consumes and whether the available stack size alone
proves that arbitrary timer interruptions are safe.

## Measurement method

- Inspect `_isr32` in `kernel/src/arch/x86_64/idt.rs` and its current IDT gate.
- Emit LLVM stack-size metadata for the optimized x86-64 kernel crate and
  `kscheduler`, retaining symbols for analysis. Check compiler output against
  disassembly of the linked kernel and scheduler object.
- Sum the interrupt frame, GPR pushes, worst-case alignment loss, FXSAVE area,
  compiler-reported Rust frames, call return addresses, and the nested ready-
  queue fallback call.
- Compare only the interrupt delta with the 16 KiB per-thread and 64 KiB boot
  stacks. Do not infer a bound for the already active call chain.

## Result

For the release optimization level used by the kernel, the known normal timer
path adds at most 935 bytes from the pre-interrupt RSP, using the conservative
40-byte privilege-transition frame:

| Component | Bytes | Basis |
|---|---:|---|
| CPU interrupt frame | 40 | Ring 3 to Ring 0 transition; same-CPL path is 24 |
| Saved GPRs | 120 | 15 pushes in `_isr32` |
| Alignment adjustment | 15 | `and rsp, -16` worst case |
| FXSAVE area and pointer/padding | 528 | `sub rsp, 528`; FXSAVE payload is 512 bytes |
| `x86_timer_handler` frame | 8 | compiler stack-size metadata; it tail-jumps to task handler |
| `task::on_timer_tick` frame | 104 | compiler metadata (`0x68`) |
| `plan_context_switch_on_cpu` frame | 40 | scheduler metadata (`0x28`) |
| scheduler timer frame | 24 | scheduler metadata (`0x18`) |
| `schedule_on_cpu` fallback frame | 24 | scheduler metadata (`0x18`) |
| Active call return addresses | 32 | four nested calls, 8 bytes each |
| **Known timer-path increment** | **935** | Sum of the rows above |

The 935-byte figure is not a complete stack bound. A timer can interrupt any
Ring 0 code at any existing stack depth; that depth is added to this figure.
The interrupt gate disables maskable interrupts during the handler, so a
second ordinary timer IRQ does not nest on the same stack. NMI, double fault,
and machine check use their configured IST stacks. Synchronous faults and
panic/logging paths are outside this normal-path sum. The 16 KiB thread stack
therefore has roughly 15.1 KiB left only when interrupted at its top; this
does not establish that arbitrary preemption points retain that much headroom.

## Decision

Keep AP startup disabled. Do not claim stack safety from the 528-byte scratch
size or from the nominal 16 KiB allocation. A later stack-safety task needs a
bounded call-depth strategy for all Ring 0 paths, stack high-water evidence
under worst-case workloads, and fault-path treatment. Continue A11 with
explicit scheduler/TCB ownership and lock-order design while retaining the
single-BSP execution gate.

## References

- Intel SDM Vol. 3A, interrupt and exception handling (same-privilege interrupt
  frames, interrupt gates, and TSS IST stack selection):
  <https://cdrdv2-public.intel.com/843836/325384-sdm-vol-3abcd-dec-24.pdf>
- Rust compiler stack-size metadata (`-Z emit-stack-sizes`) is compiler
  output for the selected optimization/configuration, not a formal bound for
  all call paths or runtime interrupt depths.
