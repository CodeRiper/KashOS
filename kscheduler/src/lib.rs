//! kscheduler — 3-band strict-priority QoS scheduler.
//!
//! Three bands, highest priority first:
//! - `UserInteractive` (2 ms slice) — compositor, direct input. Preempts
//!   everything else the instant it has something ready.
//! - `RealTimeIO` (5 ms slice) — block/network drivers, audio.
//! - `Background` (20 ms slice) — indexers, batch work. Yields instantly to
//!   either band above it.
//!
//! This crate decides *who* runs next and for how long — ordinary, fully
//! safe, host-testable Rust (see `tests/`). It does **not** do the actual
//! context switch (saving/restoring registers, switching the active page
//! table): that's inherently architecture-specific, unsafe, and not yet
//! written — this crate is the scheduling policy a future `arch`-side
//! `switch_to(tcb)` assembly routine would call into, not a replacement for
//! writing that routine.
#![no_std]
#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedError {
    /// No free task-control-block slot (`MAX_TASKS` reached).
    TableFull,
    /// A band's ready queue is at capacity (can't happen in practice since
    /// it's sized to `MAX_TASKS` and a task is only ever in one queue at a
    /// time, but checked explicitly rather than assumed).
    QueueFull,
    NoSuchTask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QoSClass {
    UserInteractive = 0,
    RealTimeIO = 1,
    Background = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Terminated,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CalleeSavedRegisters {
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cr3: u64,
    pub rsp0: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextSwitchPlan {
    pub prev_task_idx: Option<usize>,
    pub next_task_idx: usize,
    pub next_context_handle: u64,
    pub next_cr3: u64,
    pub next_rsp0: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct TaskControlBlock {
    pub tid: u32,
    pub qos: QoSClass,
    pub state: ThreadState,
    /// Opaque, architecture-side identifier for this task's saved register context.
    pub context_handle: u64,
    /// Virtual address space (CR3) root for this task's isolated VSpace.
    pub cr3: u64,
    /// Dedicated 16 KiB per-thread kernel stack loaded into TSS.RSP0.
    pub rsp0: u64,
    /// CPU affinity bitmask (bit N = Core N permitted; !0u64 = all cores permitted).
    pub cpu_affinity: u64,
    pub slice_budget_us: u32,
    pub consumed_slice_us: u32,
    pub in_use: bool,
}

impl TaskControlBlock {
    const EMPTY: TaskControlBlock = TaskControlBlock {
        tid: 0,
        qos: QoSClass::Background,
        state: ThreadState::Terminated,
        context_handle: 0,
        cr3: 0,
        rsp0: 0,
        cpu_affinity: !0u64,
        slice_budget_us: 0,
        consumed_slice_us: 0,
        in_use: false,
    };
}

pub const MAX_TASKS: usize = 64;
const BAND_COUNT: usize = 3;

fn band_slice_us(qos: QoSClass) -> u32 {
    match qos {
        QoSClass::UserInteractive => 2_000,
        QoSClass::RealTimeIO => 5_000,
        QoSClass::Background => 20_000,
    }
}

struct BandQueue {
    ring: [u32; MAX_TASKS],
    head: usize,
    tail: usize,
    len: usize,
}
impl BandQueue {
    const fn new() -> Self {
        BandQueue { ring: [0; MAX_TASKS], head: 0, tail: 0, len: 0 }
    }
    fn push(&mut self, task_idx: u32) -> Result<(), SchedError> {
        if self.len >= MAX_TASKS {
            return Err(SchedError::QueueFull);
        }
        if let Some(slot) = self.ring.get_mut(self.tail) {
            *slot = task_idx;
        }
        self.tail = (self.tail + 1) % MAX_TASKS;
        self.len += 1;
        Ok(())
    }
    fn pop(&mut self) -> Option<u32> {
        if self.len == 0 {
            return None;
        }
        let v = self.ring.get(self.head).copied();
        self.head = (self.head + 1) % MAX_TASKS;
        self.len -= 1;
        v
    }
}

pub struct QoSScheduler {
    tasks: [TaskControlBlock; MAX_TASKS],
    queues: [BandQueue; BAND_COUNT],
    current: Option<usize>,
    system_ticks_us: AtomicU64,
}

impl QoSScheduler {
    pub const fn new() -> Self {
        QoSScheduler {
            tasks: [TaskControlBlock::EMPTY; MAX_TASKS],
            queues: [BandQueue::new(), BandQueue::new(), BandQueue::new()],
            current: None,
            system_ticks_us: AtomicU64::new(0),
        }
    }

    /// Create a task in a free slot. Does not make it ready to run — call
    /// `enqueue_ready` for that, separately, once (e.g.) its initial stack
    /// and context are set up.
    /// Create a task in a free slot with default kernel address space.
    pub fn create_task(&mut self, tid: u32, qos: QoSClass, context_handle: u64) -> Result<usize, SchedError> {
        self.create_task_with_vspace(tid, qos, context_handle, 0, 0)
    }

    /// Create a task with isolated CR3 virtual address space and dedicated TSS RSP0 stack.
    pub fn create_task_with_vspace(
        &mut self,
        tid: u32,
        qos: QoSClass,
        context_handle: u64,
        cr3: u64,
        rsp0: u64,
    ) -> Result<usize, SchedError> {
        let idx = self.tasks.iter().position(|t| !t.in_use).ok_or(SchedError::TableFull)?;
        if let Some(slot) = self.tasks.get_mut(idx) {
            *slot = TaskControlBlock {
                tid,
                qos,
                state: ThreadState::Blocked,
                context_handle,
                cr3,
                rsp0,
                cpu_affinity: !0u64,
                slice_budget_us: 0,
                consumed_slice_us: 0,
                in_use: true,
            };
        }
        Ok(idx)
    }

    /// Sets the CPU core affinity mask for a task.
    pub fn set_task_affinity(&mut self, idx: usize, affinity_mask: u64) -> Result<(), SchedError> {
        let t = self.tasks.get_mut(idx).ok_or(SchedError::NoSuchTask)?;
        t.cpu_affinity = if affinity_mask == 0 { !0u64 } else { affinity_mask };
        Ok(())
    }

    /// Checks if a task is permitted to run on the specified CPU core ID.
    pub fn can_run_on_core(&self, idx: usize, core_id: usize) -> bool {
        self.tasks.get(idx)
            .map(|t| (t.cpu_affinity & (1 << (core_id % 64))) != 0)
            .unwrap_or(false)
    }

    pub fn terminate_task(&mut self, idx: usize) -> Result<(), SchedError> {
        let t = self.tasks.get_mut(idx).ok_or(SchedError::NoSuchTask)?;
        t.state = ThreadState::Terminated;
        t.in_use = false;
        if self.current == Some(idx) {
            self.current = None;
        }
        Ok(())
    }

    pub fn enqueue_ready(&mut self, task_idx: usize) -> Result<(), SchedError> {
        let qos = self.tasks.get(task_idx).ok_or(SchedError::NoSuchTask)?.qos;
        if let Some(q) = self.queues.get_mut(qos as usize) {
            q.push(task_idx as u32)?;
        }
        if let Some(t) = self.tasks.get_mut(task_idx) {
            t.state = ThreadState::Ready;
        }
        Ok(())
    }

    fn dequeue_next(&mut self) -> Option<usize> {
        for q in self.queues.iter_mut() {
            if let Some(idx) = q.pop() {
                return Some(idx as usize);
            }
        }
        None
    }

    fn ready_count(&self, band: usize) -> usize {
        self.queues.get(band).map(|q| q.len).unwrap_or(0)
    }

    pub fn task(&self, idx: usize) -> Option<&TaskControlBlock> {
        self.tasks.get(idx)
    }

    pub fn current_task(&self) -> Option<&TaskControlBlock> {
        self.current.and_then(|i| self.tasks.get(i))
    }

    pub fn system_ticks_us(&self) -> u64 {
        self.system_ticks_us.load(Ordering::Relaxed)
    }

    /// Pick the highest-priority ready task, arm its slice, and make it
    /// current. Loops past any queue entry whose task was terminated after
    /// being enqueued — `terminate_task` marks the task dead but, by
    /// design, does not walk every band queue removing it (that would be an
    /// O(MAX_TASKS) scan on every termination for a case `schedule` can
    /// instead just skip past lazily, here, the one place that matters).
    pub fn schedule(&mut self) -> Option<usize> {
        loop {
            match self.dequeue_next() {
                Some(idx) => {
                    let live = self.tasks.get(idx).map(|t| t.in_use).unwrap_or(false);
                    if !live {
                        continue; // stale entry for a now-terminated task
                    }
                    if let Some(t) = self.tasks.get_mut(idx) {
                        t.state = ThreadState::Running;
                        t.slice_budget_us = band_slice_us(t.qos);
                        t.consumed_slice_us = 0;
                    }
                    self.current = Some(idx);
                    return Some(idx);
                }
                None => {
                    self.current = None;
                    return None;
                }
            }
        }
    }

    /// Call on every timer interrupt with the microseconds elapsed since the
    /// last call. Returns the task index that should be running after this
    /// tick (may be unchanged from before). A caller's arch-side IRQ handler
    /// is expected to context-switch to whatever this returns if it differs
    /// from what was running going in.
    pub fn on_timer_tick(&mut self, elapsed_us: u32) -> Option<usize> {
        self.system_ticks_us.fetch_add(elapsed_us as u64, Ordering::Relaxed);

        let Some(curr_idx) = self.current else {
            return self.schedule();
        };
        // Extract the Copy fields we need and let this mutable borrow of
        // `self.tasks` end here, before `ready_count` below needs `&self`.
        let (qos, consumed, budget) = match self.tasks.get_mut(curr_idx) {
            Some(t) => {
                t.consumed_slice_us += elapsed_us;
                (t.qos, t.consumed_slice_us, t.slice_budget_us)
            }
            None => return self.schedule(),
        };

        let higher_priority_waiting = match qos {
            QoSClass::Background => self.ready_count(0) > 0 || self.ready_count(1) > 0,
            QoSClass::RealTimeIO => self.ready_count(0) > 0,
            QoSClass::UserInteractive => false,
        };

        if consumed >= budget || higher_priority_waiting {
            if let Some(c) = self.tasks.get_mut(curr_idx) {
                c.consumed_slice_us = 0;
            }
            let _ = self.enqueue_ready(curr_idx);
            self.schedule()
        } else {
            Some(curr_idx)
        }
    }

    /// Evaluates timer tick and computes a hardware context switch plan
    /// (callee-saved registers, CR3 page table reload, and TSS.RSP0 stack).
    pub fn plan_context_switch(&mut self, elapsed_us: u32) -> Option<ContextSwitchPlan> {
        let prev = self.current;
        let next = self.on_timer_tick(elapsed_us)?;
        if Some(next) != prev {
            let tcb = self.tasks.get(next)?;
            Some(ContextSwitchPlan {
                prev_task_idx: prev,
                next_task_idx: next,
                next_context_handle: tcb.context_handle,
                next_cr3: tcb.cr3,
                next_rsp0: tcb.rsp0,
            })
        } else {
            None
        }
    }
}

impl Default for QoSScheduler {
    fn default() -> Self {
        Self::new()
    }
}
