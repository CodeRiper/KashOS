# KashOS Phase 8 Design Document: Compartments & Mandatory Access Control

**Author**: @Akash . J  
**Date**: October 17, 2026  
**Status**: Implementation Phase  
**Target Milestone**: Phase 8 Acceptance Gates (T32–T35)

---

## 1. Architectural Objectives

Phase 8 elevates KashOS from capability primitives to a comprehensive **Compartment Architecture** adhering to the Principle of Least Authority (POLA):

1. **FLASK Mandatory Access Control (MAC) on all IPC**:
   - Every synchronous IPC exchange (`sys_ipc_send`, `sys_ipc_recv`) is evaluated against the FLASK Security Server (`kernel/src/flask.rs`).
   - Access decisions are cached in a nanosecond Access Vector Cache (AVC) indexed by `(source_sid, target_sid, class)`.
   - Untrusted application capsules (`SID_UNTRUSTED_KAPP`) and disposable sandboxes (`SID_DISPOSABLE`) are prevented from directly messaging critical system compartments unless explicitly authorized in the security policy matrix.

2. **Ephemeral Disposable Domains (`SID_DISPOSABLE`, Domain 5 `disp-vm`)**:
   - Sandboxes operate strictly within isolated RAM scratchpads with zero ambient access to persistent `/vault` or `/personal` storage.
   - Memory quotas are strictly bounded.
   - Upon domain exit, 100% of the domain's physical pages, capability tables, and message buffers are scrubbed, cache lines flushed (`clflush`), and zeroized, guaranteeing zero forensic remanence.

3. **Zero-Trust Out-of-Process Powerbox Broker**:
   - Replaces ambient filesystem calls (`open("/path")`) with explicit user-delegated capability tokens (`kernel/src/powerbox.rs`).
   - When an application requests file access, the request is dispatched to the `PowerboxBroker`.
   - The trusted desktop compositor displays an isolated out-of-process file picker. The requesting app has zero access to the picker's memory, input events, or display surface.
   - Upon explicit user consent, an unforgeable `GrantedCapabilityToken` is issued for that exact file. Parent folders and sibling files remain 100% invisible.
   - Tokens can be revoked dynamically by the user or security supervisor.

---

## 2. FLASK Type Enforcement Matrix

| Source SID | Target SID | Class | Perms | Verdict | Rationale |
| :--- | :--- | :--- | :--- | :---: | :--- |
| `SID_SYSTEM` | Any | Any | ALL | **Allow** | Trusted microkernel root plane |
| `SID_UNTRUSTED_KAPP` | `SID_SYSTEM` | `IpcChannel` | `IPC_SEND` | **Allow** | Syscall dispatcher & powerbox proxy |
| `SID_UNTRUSTED_KAPP` | `SID_STORAGE_DOMAIN` | `File` | `FILE_READ` | **Denied** | Must use Powerbox broker |
| `SID_UNTRUSTED_KAPP` | `SID_NET_DOMAIN` | `Socket` | `NET_CONNECT` | **Policy** | Gated by network permission |
| `SID_DISPOSABLE` | `SID_STORAGE_DOMAIN` | `File` | Any | **Denied** | Air-gapped from persistent storage |
| `SID_DISPOSABLE` | `SID_DISPOSABLE` | `IpcChannel` | `IPC_SEND` | **Allow** | Internal intra-compartment IPC |

---

## 3. Acceptance Gates (T32–T35)

- **T32: FLASK MAC IPC Enforcement Gate**:
  - Validates IPC transmission across security contexts.
  - Verifies unauthorized IPC between isolated domains is blocked with `KError::PermissionDenied`.
  - Verifies AVC cache hit rate and atomic policy reload.

- **T33: Disposable Domain RAM Scratchpad & Zero-Remanence Teardown Gate**:
  - Provisions a disposable domain in RAM with test secret patterns.
  - Terminates domain and performs an exhaustive physical memory audit scan.
  - Verifies 100% of domain memory is zeroized with zero byte remanence.

- **T34: Out-of-Process Powerbox User-Approval & Token Minting Gate**:
  - Sandboxed capsule attempts to read `/personal/secret.txt` without consent -> blocked.
  - User confirms consent in out-of-process dialog -> single-file token minted.
  - Verifies read access is granted for target file, but denied for sibling `/personal/passwords.txt`.

- **T35: Powerbox Token Revocation & Isolation Gate**:
  - Token is revoked by user/broker.
  - Subsequent read operations with the revoked token are immediately rejected (`KError::PermissionDenied`).
