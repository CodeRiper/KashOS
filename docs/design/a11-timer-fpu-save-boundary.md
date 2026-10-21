# A11 timer-interrupt FPU save boundary

## Finding

The timer ISR called `x86_timer_handler` before saving the interrupted task's
x87/SSE state. That Rust code can use caller-saved XMM registers, so saving the
registers later in `task::on_timer_tick` may capture handler state rather than
the interrupted task's state.

## Design

- Save a 512-byte FXSAVE image in a 16-byte-aligned temporary area on the
  interrupted kernel stack before the first Rust call.
- Pass the image and a pointer-sized result slot to the Rust timer handler.
- Copy the saved image into the outgoing TCB before scheduling.
- Have the scheduler choose which saved image should be restored. If there is
  no switch or selection fails, choose the interrupt's temporary image.
- Restore the selected FPU image in assembly after all Rust code returns and
  immediately before loading the selected GPR/IRET frame.
- Keep AP startup disabled. Each interrupt uses its own stack scratch area; this
  change does not make shared scheduler or TCB state safe for concurrent CPUs.

## Stack and alignment

The temporary area is 528 bytes: 512 bytes for FXSAVE and 8 bytes for the
selected image pointer, with the allocation rounded to a 16-byte multiple. The
x86-64 bare-metal target disables the red zone. Its current kernel stacks are
16 KiB; QEMU T0 must still boot and run the timer path after the added stack
usage. Worst-case stack-depth and overflow analysis is outside this change.

## Verification boundary

The regression guard checks ordering, argument wiring, and fallback selection.
The x86-64 release build and T0 QEMU smoke check validate assembly integration
and boot. These checks do not prove FPU isolation under concurrent CPUs or
architectural correctness across every processor model. APs remain parked.
