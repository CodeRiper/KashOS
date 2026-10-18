# KashOS Structured Event Protocol (KASH-EVT)

Version: 1.0  
Status: Active  
Reference: KashOS Build Guide v2, Section 7  

---

## 1. Overview
The KashOS microkernel and its subsystem services emit single-line JSON events over the serial console (`COM1` / `ttyS0`) prefixed with `KASH-EVT `.

Human-readable logging statements (e.g. `[boot] Linear Framebuffer active...`) remain for developer inspection, but the external test harness (`tools/harness/`) parses **only** `KASH-EVT` lines.

---

## 2. Event Envelope Format

Every structured event is formatted as a single line:
```
KASH-EVT <valid JSON object>\n
```

### Mandatory Fields in Envelope
- `t`: uint64 — Timestamp in microseconds since boot or seconds since UNIX epoch.
- `src`: string — Originating subsystem or process identifier (`"kernel"`, `"init"`, `"kvault"`, `"net"`, `"compositor"`, etc.).
- `ev`: string — Event type descriptor (lowercase alphanumeric with underscores).

---

## 3. Standard Event Definitions

### 3.1 Kernel Boot & Hardware Lifecycle
- **`cpu_online`**:
  ```json
  {"t": 1200, "src": "kernel", "ev": "cpu_online", "cpu_id": 0, "total_cpus": 4, "arch": "x86_64"}
  ```
- **`memory_map`**:
  ```json
  {"t": 2500, "src": "kernel", "ev": "memory_map", "usable_ram_mib": 1024, "kernel_paddr": "0x100000"}
  ```
- **`entropy`**:
  ```json
  {"t": 3100, "src": "kernel", "ev": "entropy", "bits": 312, "sources": ["jitter", "rtc", "rdtsc"]}
  ```
- **`boot_complete`**:
  ```json
  {"t": 89000, "src": "kernel", "ev": "boot_complete", "status_real_count": 18, "status_stub_count": 2}
  ```

### 3.2 Process & Capability Lifecycle
- **`proc_spawn`**:
  ```json
  {"t": 45000, "src": "kernel", "ev": "proc_spawn", "pid": 1, "name": "init", "cpl": 3, "cr3": "0x2000000"}
  ```
- **`proc_fault`**:
  ```json
  {"t": 92000, "src": "kernel", "ev": "proc_fault", "pid": 51, "signal": 11, "cr2": "0x00000000"}
  ```
- **`proc_exit`**:
  ```json
  {"t": 93000, "src": "kernel", "ev": "proc_exit", "pid": 51, "exit_code": 139}
  ```
- **`cap_revoke`**:
  ```json
  {"t": 56000, "src": "kernel", "ev": "cap_revoke", "count": 1000, "duration_us": 320}
  ```

### 3.3 Security & IOMMU Violations
- **`dma_blocked`**:
  ```json
  {"t": 67000, "src": "kernel", "ev": "dma_blocked", "pci_bdf": "00:03.0", "target_paddr": "0x100000", "reason": "translation_not_present"}
  ```
- **`net_drop`**:
  ```json
  {"t": 78000, "src": "net", "ev": "net_drop", "rule": "R2_kill_switch", "port": 443}
  ```
- **`tamper_detected`**:
  ```json
  {"t": 81000, "src": "kvault", "ev": "tamper_detected", "block": 42, "reason": "poly1305_mismatch"}
  ```

---

## 4. Harness Invariants
1. Event names and fields are fixed by this specification. The builder agent may NOT change event names or types without human approval.
2. The harness fails any test where an event is malformed JSON or contains missing mandatory fields.
