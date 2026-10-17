# Design Note: Phase 4 — Userspace Services and Drivers

**Date:** Oct 17, 2026  
**Author:** Akash <akash.official.j@gmail.com>  
**Status:** In Progress (Phase 4: Userspace Services and Drivers)

---

## 1. Overview & Goals

Phase 4 moves device drivers (storage, network, input, display) out of Ring 0 into unprivileged Ring 3 microkernel services, governed entirely by capability-based access control and hardware-enforced IOMMU DMA containment.

In accordance with the *KashOS Build Guide* and the 10 Non-Negotiable Rules:
1. **Zero Ambient Authority for Hardware**: No driver process possesses ambient permissions to execute x86 `in`/`out` port I/O, touch arbitrary physical memory, or initiate DMA. All device access requires explicit capability tokens:
   - `CapKind::IOPort { start_port, end_port }` for x86 port ranges.
   - `CapKind::Frame { paddr }` for memory-mapped I/O (MMIO).
   - `CapKind::Notification { addr }` for hardware IRQ forwarding.
   - `CapKind::IOSpace { pci_bdf, domain_id }` for IOMMU DMA translation windows.
2. **Real Hardware IOMMU (Intel VT-d & AMD-Vi)**:
   - ACPI DMAR discovery and root table / context table parsing.
   - 4-level Second-Level Page Tables (SLPT) dedicated per PCI Bus:Device:Function (BDF).
   - DMA requests outside granted SLPT windows are trapped by the IOMMU hardware, recorded in Fault Recording Registers (FRCD), and blocked from corrupting host physical memory.
3. **Driver Resilience & Restartability**:
   - Device drivers execute in de-privileged Ring 3 processes.
   - If a driver faults (null dereference, page fault, arithmetic exception) or is terminated, the microkernel supervisor catches the fault, revokes all derived capabilities, zeroes and recycles the process's Untyped memory quota, and restarts the driver service without panicking the microkernel or interrupting sibling services.
4. **Acceptance Gate Criteria**:
   - **Driver Isolation**: Each driver (storage, network, input, display) operates exclusively within its granted capability boundaries; attempting out-of-bounds port or MMIO access is rejected.
   - **IOMMU DMA Containment**: Unauthorized DMA transfers outside granted windows are blocked and logged by the VT-d controller.
   - **Driver Resilience**: Killing or crashing a driver service does not crash the microkernel; the driver supervisor revokes capabilities, recycles memory, and restarts the service transparently.

---

## 2. Architecture & Device Capabilities

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Ring 3 User Services                            │
│                                                                        │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌─────────────┐ │
│  │  Storage Srv  │ │  Network Srv  │ │   Input Srv   │ │ Display Srv │ │
│  │ (IDE/VirtIO)  │ │ (Intel e1000) │ │  (PS/2 / HID) │ │ (BGA/Linear)│ │
│  │  [IOPort 1F0] │ │  [Frame MMIO] │ │  [IOPort 60]  │ │[Frame BGA]  │ │
│  │  [IOSpace #1] │ │  [IOSpace #2] │ │  [Notification│ │[IOPort 1CE] │ │
│  └───────┬───────┘ └───────┬───────┘ └───────┬───────┘ └──────┬──────┘ │
└──────────┼─────────────────┼─────────────────┼────────────────┼────────┘
           │                 │                 │                │
           ▼                 ▼                 ▼                ▼
══════════════════════════════════════════════════════════════════════════ [Privilege Boundary]
┌────────────────────────────────────────────────────────────────────────┐
│                      KashOS Microkernel (Ring 0)                       │
│                                                                        │
│  ┌───────────────────────────────┐  ┌───────────────────────────────┐  │
│  │       Driver Supervisor       │  │     Capability Engine         │  │
│  │ - Service health monitoring   │  │ - IOPort bounds validation    │  │
│  │ - Automatic restart on fault  │  │ - MMIO frame access rights    │  │
│  │ - Untyped memory recycling    │  │ - Irq notification routing    │  │
│  └───────────────┬───────────────┘  └───────────────┬───────────────┘  │
│                  │                                  │                  │
│  ┌───────────────┴──────────────────────────────────┴───────────────┐  │
│  │            Intel VT-d / AMD-Vi Hardware IOMMU Engine             │  │
│  │ - Root Table & Context Table second-level translation (SLPT)     │  │
│  │ - Hardware Fault Recording (FRCD) & rogue DMA containment        │  │
│  └───────────────────────────────┬──────────────────────────────────┘  │
└──────────────────────────────────┼─────────────────────────────────────┘
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Hardware Devices / Bus                         │
│   PCI Bus 00:03.0 (e1000)   │   PCI Bus 00:01.0 (IDE)   │   I/O Ports  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Capability-Based Device Access Rules
- **IOPort Capabilities**:
  A capability of type `CapKind::IOPort { start_port, end_port }` grants authority to read and write ports strictly within `start_port..=end_port`. Any attempt to access a port outside this range returns `SyscallError::InsufficientRights`.
- **Frame MMIO Capabilities**:
  A capability of type `CapKind::Frame { paddr }` grants access to map and interact with a specific 4 KiB physical device register page (e.g., e1000 NIC control registers or linear framebuffer video memory).
- **Notification Capabilities**:
  Interrupts are acknowledged in Ring 0 and converted into capability-mediated asynchronous signals delivered to the driver's notification object, waking its event loop.
- **IOSpace Capabilities**:
  Specifies the device's PCI Bus:Device:Function (BDF) and its isolated domain ID. All device DMA buffers must be registered with the IOMMU under this IOSpace capability before DMA is permitted.

---

## 3. Hardware IOMMU Subsystem (Intel VT-d)

### 3.1 Translation Hierarchy
1. **Root Table**: 256 entries indexed by PCI Bus (0..255). Points to Context Tables.
2. **Context Table**: 256 entries indexed by PCI Device and Function (`dev << 3 | func`). Points to the device's SLPT PML4.
3. **Second-Level Page Tables (SLPT)**:
   - 4-level paging: `PML4 -> PDPT -> PD -> PT -> Leaf SLPTE`.
   - Each leaf SLPTE specifies `READ` (bit 0), `WRITE` (bit 1), `SNOOP` (bit 11), and 4-KiB aligned physical address.

### 3.2 Fault Recording & Rogue DMA Containment
- The controller monitors translation requests issued by bus-master peripherals.
- When an unauthorized DMA transfer is attempted (e.g. peripheral attempts DMA into kernel text, stack, or another process's memory):
  1. The VT-d hardware aborts the bus transaction.
  2. The fault is recorded in the Fault Recording Register (FRCD), containing the faulting address, PCI BDF, and fault reason code.
  3. The `fault_count` is incremented and logged by the kernel.
  4. Host memory remains uncorrupted.

---

## 4. Driver Resilience & Restartability

The `DriverSupervisor` manages user driver service lifecycles:
1. **Registration**: Provisions an isolated CSpace with designated device capabilities and memory quota.
2. **Monitoring**: Intercepts process termination signals (#PF, #GP, exit).
3. **Teardown**: Recursively revokes the driver's capability derivation tree (`CapSpace::revoke`), detaching all device handles and zeroing memory buffers.
4. **Re-spawning**: Recycles the driver's Untyped memory quota and spawns a fresh driver instance with a new PID and clean state.
5. **Transparency**: The microkernel and sibling applications continue running uninterrupted.
