use kscheduler::{ContextSwitchTarget, QoSClass, QoSScheduler, SchedError, ThreadState};

fn spawn_ready(s: &mut QoSScheduler, tid: u32, qos: QoSClass) -> usize {
    let idx = s.create_task(tid, qos, 0).unwrap();
    s.enqueue_ready(idx).unwrap();
    idx
}

#[test]
fn voluntary_yield_rotates_same_band_tasks_without_charging_timer_time() {
    let mut s = QoSScheduler::new();
    let first = spawn_ready(&mut s, 101, QoSClass::Background);
    let second = spawn_ready(&mut s, 102, QoSClass::Background);
    assert_eq!(s.schedule_on_cpu(0), Some(first));

    let plan = s.plan_voluntary_yield_on_cpu(0).unwrap().unwrap();
    assert_eq!(plan.prev_task_idx, Some(first));
    assert_eq!(plan.target, ContextSwitchTarget::Task { task_idx: second, cr3: 0 });
    assert_eq!(s.task(first).unwrap().state, ThreadState::Ready);
    assert_eq!(s.task(second).unwrap().state, ThreadState::Running);
    assert_eq!(s.system_ticks_us(), 0, "voluntary yield must not invent elapsed time");

    let plan = s.plan_voluntary_yield_on_cpu(0).unwrap().unwrap();
    assert_eq!(plan.prev_task_idx, Some(second));
    assert_eq!(plan.target, ContextSwitchTarget::Task { task_idx: first, cr3: 0 });
}

#[test]
fn voluntary_yield_with_only_current_task_does_not_switch_or_duplicate_queue_entry() {
    let mut s = QoSScheduler::new();
    let only = spawn_ready(&mut s, 103, QoSClass::UserInteractive);
    assert_eq!(s.schedule_on_cpu(0), Some(only));

    assert_eq!(s.plan_voluntary_yield_on_cpu(0), Ok(None));
    assert_eq!(s.current_task_on_cpu(0).unwrap().tid, 103);
    assert_eq!(s.task(only).unwrap().state, ThreadState::Running);
    assert_eq!(s.plan_voluntary_yield_on_cpu(kscheduler::MAX_CPUS), Err(SchedError::NoSuchTask));
}

#[test]
fn highest_band_always_wins_regardless_of_enqueue_order() {
    let mut s = QoSScheduler::new();
    // Deliberately enqueue lowest-priority first, to make sure band order —
    // not arrival order — decides who runs.
    let bg = spawn_ready(&mut s, 1, QoSClass::Background);
    let rt = spawn_ready(&mut s, 2, QoSClass::RealTimeIO);
    let ui = spawn_ready(&mut s, 3, QoSClass::UserInteractive);

    assert_eq!(s.schedule(), Some(ui));
    assert_eq!(s.current_task().unwrap().tid, 3);

    // ui is now Running, not back in any queue; next pick should be rt.
    assert_eq!(s.schedule(), Some(rt));
    assert_eq!(s.schedule(), Some(bg));
    assert_eq!(s.schedule(), None, "nothing left ready");
}

#[test]
fn fifo_order_within_the_same_band() {
    let mut s = QoSScheduler::new();
    let a = spawn_ready(&mut s, 10, QoSClass::Background);
    let b = spawn_ready(&mut s, 11, QoSClass::Background);
    let c = spawn_ready(&mut s, 12, QoSClass::Background);
    assert_eq!(s.schedule(), Some(a));
    assert_eq!(s.schedule(), Some(b));
    assert_eq!(s.schedule(), Some(c));
}

#[test]
fn higher_priority_arrival_preempts_immediately_even_mid_slice() {
    let mut s = QoSScheduler::new();
    let bg = spawn_ready(&mut s, 1, QoSClass::Background);
    assert_eq!(s.schedule(), Some(bg));

    // Only 1us into a 20ms budget — nowhere near slice expiry.
    assert_eq!(s.on_timer_tick(1), Some(bg));

    // A UserInteractive task becomes ready mid-flight.
    let ui = spawn_ready(&mut s, 2, QoSClass::UserInteractive);
    let picked = s.on_timer_tick(1).unwrap();
    assert_eq!(picked, ui, "UserInteractive must preempt Background immediately, not wait for a slice to expire");

    // The preempted task went back to Ready, not Blocked/Terminated.
    assert_eq!(s.task(bg).unwrap().state, ThreadState::Ready);
}

#[test]
fn slice_expiry_requeues_and_resets_consumed_time() {
    let mut s = QoSScheduler::new();
    let only = spawn_ready(&mut s, 1, QoSClass::UserInteractive); // 2_000us budget
    assert_eq!(s.schedule(), Some(only));

    // Tick past the budget with nothing else competing — it should still
    // be the one picked (only task), but via a requeue, with its counter
    // reset for the next slice.
    let picked = s.on_timer_tick(2_500).unwrap();
    assert_eq!(picked, only);
    assert_eq!(s.task(only).unwrap().consumed_slice_us, 0, "slice counter must reset after requeue");
}

#[test]
fn realtimeio_is_preempted_only_by_userinteractive_not_by_background() {
    let mut s = QoSScheduler::new();
    let rt = spawn_ready(&mut s, 1, QoSClass::RealTimeIO);
    assert_eq!(s.schedule(), Some(rt));

    let _bg = spawn_ready(&mut s, 2, QoSClass::Background);
    // Background waiting must NOT preempt RealTimeIO.
    assert_eq!(s.on_timer_tick(100), Some(rt));

    let ui = spawn_ready(&mut s, 3, QoSClass::UserInteractive);
    // UserInteractive waiting MUST preempt RealTimeIO.
    assert_eq!(s.on_timer_tick(100), Some(ui));
}

#[test]
fn terminated_task_is_never_scheduled_again() {
    let mut s = QoSScheduler::new();
    let a = spawn_ready(&mut s, 1, QoSClass::Background);
    s.terminate_task(a).unwrap();
    assert_eq!(s.schedule(), None);
}

#[test]
fn terminating_a_still_queued_task_is_skipped_by_schedule_not_resurrected() {
    let mut s = QoSScheduler::new();
    let doomed = spawn_ready(&mut s, 1, QoSClass::Background);
    let survivor = spawn_ready(&mut s, 2, QoSClass::Background);
    // `doomed` is still sitting in the Background ready queue (schedule()
    // was never called to pop it out) when it gets terminated.
    s.terminate_task(doomed).unwrap();
    // schedule() must skip the now-stale queue entry for `doomed` and land
    // on `survivor`, not resurrect a terminated task.
    assert_eq!(s.schedule(), Some(survivor));
}

#[test]
fn enqueue_on_unknown_task_index_is_rejected_not_panicking() {
    let mut s = QoSScheduler::new();
    assert_eq!(s.enqueue_ready(999), Err(SchedError::NoSuchTask));
}

#[test]
fn task_identifier_resolves_to_live_slot_without_modulo_aliasing() {
    let mut s = QoSScheduler::new();
    let slot = s.create_task(211, QoSClass::Background, 0).unwrap();
    assert_ne!(slot, 211 % kscheduler::MAX_TASKS);
    assert_eq!(s.task_index_for_tid(211), Some(slot));
    assert_eq!(s.task_index_for_tid(211 + kscheduler::MAX_TASKS as u32), None);
    s.terminate_task(slot).unwrap();
    assert_eq!(s.task_index_for_tid(211), None);
}

#[test]
fn task_table_full_is_reported_not_panicking() {
    let mut s = QoSScheduler::new();
    for i in 0..kscheduler::MAX_TASKS as u32 {
        s.create_task(i, QoSClass::Background, 0).unwrap();
    }
    assert_eq!(s.create_task(999, QoSClass::Background, 0), Err(SchedError::TableFull));
}

#[test]
fn no_task_ready_yields_none_and_idle_is_a_valid_steady_state() {
    let mut s = QoSScheduler::new();
    assert_eq!(s.schedule(), None);
    assert_eq!(s.on_timer_tick(1000), None);
    assert!(s.current_task().is_none());
}

#[test]
fn task_cpu_affinity_filtering_and_pinning() {
    let mut s = QoSScheduler::new();
    let t0 = s.create_task(100, QoSClass::UserInteractive, 0).unwrap();
    let t1 = s.create_task(101, QoSClass::RealTimeIO, 0).unwrap();

    // Default affinity allows all cores
    assert!(s.can_run_on_core(t0, 0));
    assert!(s.can_run_on_core(t0, 3));

    // Pin t0 to Core 0 only (mask = 1 << 0)
    s.set_task_affinity(t0, 1 << 0).unwrap();
    assert!(s.can_run_on_core(t0, 0));
    assert!(!s.can_run_on_core(t0, 1));
    assert!(!s.can_run_on_core(t0, 3));

    // Pin t1 to Core 2 and Core 3 (mask = (1 << 2) | (1 << 3))
    s.set_task_affinity(t1, (1 << 2) | (1 << 3)).unwrap();
    assert!(!s.can_run_on_core(t1, 0));
    assert!(!s.can_run_on_core(t1, 1));
    assert!(s.can_run_on_core(t1, 2));
    assert!(s.can_run_on_core(t1, 3));
}

#[test]
fn duplicate_ready_enqueue_is_rejected_without_scheduling_one_task_twice() {
    let mut s = QoSScheduler::new();
    let only = s.create_task(91, QoSClass::Background, 0).unwrap();
    assert_eq!(s.enqueue_ready(only), Ok(()));
    assert_eq!(s.enqueue_ready(only), Err(SchedError::AlreadyReady));

    assert_eq!(s.schedule(), Some(only));
    assert_eq!(s.schedule(), None, "a running task must not remain queued");
}

#[test]
fn cpu_local_current_tasks_respect_affinity_and_are_distinct() {
    let mut s = QoSScheduler::new();
    let cpu0_task = s.create_task(301, QoSClass::Background, 0).unwrap();
    let cpu1_task = s.create_task(302, QoSClass::UserInteractive, 0).unwrap();
    s.set_task_affinity(cpu0_task, 1 << 0).unwrap();
    s.set_task_affinity(cpu1_task, 1 << 1).unwrap();
    s.enqueue_ready(cpu1_task).unwrap();
    s.enqueue_ready(cpu0_task).unwrap();

    assert_eq!(s.schedule_on_cpu(0), Some(cpu0_task));
    assert_eq!(s.current_task_on_cpu(0).unwrap().tid, 301);
    assert_eq!(s.schedule_on_cpu(1), Some(cpu1_task));
    assert_eq!(s.current_task_on_cpu(1).unwrap().tid, 302);
    assert_eq!(s.current_task().unwrap().tid, 301, "legacy current_task refers to CPU 0");
}

#[test]
fn scheduling_rejects_cpu_indices_outside_the_per_cpu_table() {
    let mut s = QoSScheduler::new();
    assert_eq!(s.schedule_on_cpu(kscheduler::MAX_CPUS), None);
    assert!(s.current_task_on_cpu(kscheduler::MAX_CPUS).is_none());
    assert_eq!(s.on_timer_tick_on_cpu(kscheduler::MAX_CPUS, 100), None);
}

#[test]
fn timer_tick_on_one_cpu_does_not_preempt_for_another_cpus_affinity_queue() {
    let mut s = QoSScheduler::new();
    let cpu0_background = s.create_task(401, QoSClass::Background, 0).unwrap();
    let cpu1_interactive = s.create_task(402, QoSClass::UserInteractive, 0).unwrap();
    s.set_task_affinity(cpu0_background, 1 << 0).unwrap();
    s.set_task_affinity(cpu1_interactive, 1 << 1).unwrap();
    s.enqueue_ready(cpu0_background).unwrap();
    assert_eq!(s.schedule_on_cpu(0), Some(cpu0_background));

    s.enqueue_ready(cpu1_interactive).unwrap();
    assert_eq!(s.on_timer_tick_on_cpu(0, 1), Some(cpu0_background));
    assert_eq!(s.current_task_on_cpu(0).unwrap().tid, 401);
    assert_eq!(s.schedule_on_cpu(1), Some(cpu1_interactive));
}

#[test]
fn blocking_ready_task_removes_it_from_dispatch_until_woken() {
    let mut s = QoSScheduler::new();
    let task = s.create_task(120, QoSClass::Background, 0x120).unwrap();
    s.enqueue_ready(task).unwrap();

    s.block_task(task).unwrap();
    assert_eq!(s.task(task).unwrap().state, ThreadState::Blocked);
    assert_eq!(s.schedule(), None);

    s.wake_task(task).unwrap();
    assert_eq!(s.task(task).unwrap().state, ThreadState::Ready);
    assert_eq!(s.schedule(), Some(task));
    assert_eq!(s.task(task).unwrap().state, ThreadState::Running);
}

#[test]
fn timer_switches_away_from_blocked_current_without_requeueing_it() {
    let mut s = QoSScheduler::new();
    let blocked = s.create_task(121, QoSClass::Background, 0x121).unwrap();
    let runnable = s.create_task(122, QoSClass::Background, 0x122).unwrap();
    s.enqueue_ready(blocked).unwrap();
    assert_eq!(s.schedule(), Some(blocked));
    s.enqueue_ready(runnable).unwrap();

    s.block_task(blocked).unwrap();
    assert_eq!(s.on_timer_tick(1), Some(runnable));
    assert_eq!(s.task(blocked).unwrap().state, ThreadState::Blocked);
    assert_eq!(s.current_task().unwrap().tid, 122);

    s.wake_task(blocked).unwrap();
    assert_eq!(s.task(blocked).unwrap().state, ThreadState::Ready);
    assert_eq!(s.on_timer_tick(20_000), Some(blocked));
    assert_eq!(s.task(blocked).unwrap().state, ThreadState::Running);
}

#[test]
fn wake_before_blocked_current_is_switched_out_does_not_duplicate_queue_entry() {
    let mut s = QoSScheduler::new();
    let task = s.create_task(123, QoSClass::Background, 0x123).unwrap();
    s.enqueue_ready(task).unwrap();
    assert_eq!(s.schedule(), Some(task));

    s.block_task(task).unwrap();
    s.wake_task(task).unwrap();
    assert_eq!(s.task(task).unwrap().state, ThreadState::Running);
    assert_eq!(s.on_timer_tick(1), Some(task));
    assert_eq!(s.task(task).unwrap().state, ThreadState::Running);
}

#[test]
fn blocked_last_task_produces_an_explicit_idle_switch_plan() {
    let mut s = QoSScheduler::new();
    let task = s.create_task(124, QoSClass::Background, 0x124).unwrap();
    s.enqueue_ready(task).unwrap();
    assert_eq!(s.schedule_on_cpu(0), Some(task));
    s.block_task(task).unwrap();

    let plan = s.plan_context_switch_on_cpu(0, 10_000).unwrap();
    assert_eq!(plan.prev_task_idx, Some(task));
    assert_eq!(plan.target, ContextSwitchTarget::Idle);
    assert!(s.current_task_on_cpu(0).is_none());
}

#[test]
fn waking_from_idle_produces_task_switch_plan_without_previous_task() {
    let mut s = QoSScheduler::new();
    let task = s.create_task(125, QoSClass::Background, 0x125).unwrap();
    s.enqueue_ready(task).unwrap();
    assert_eq!(s.schedule_on_cpu(0), Some(task));
    s.block_task(task).unwrap();
    let idle = s.plan_context_switch_on_cpu(0, 1).unwrap();
    assert_eq!(idle.target, ContextSwitchTarget::Idle);

    s.wake_task(task).unwrap();
    let wake = s.plan_context_switch_on_cpu(0, 1).unwrap();
    assert_eq!(wake.prev_task_idx, None);
    assert_eq!(wake.target, ContextSwitchTarget::Task { task_idx: task, cr3: 0 });
}

#[test]
fn blocked_current_handoff_switches_to_next_ready_task() {
    let mut s = QoSScheduler::new();
    let blocked = spawn_ready(&mut s, 601, QoSClass::Background);
    let runnable = spawn_ready(&mut s, 602, QoSClass::Background);
    assert_eq!(s.schedule_on_cpu(0), Some(blocked));
    s.block_task(blocked).unwrap();

    let plan = s.plan_blocked_current_handoff_on_cpu(0).unwrap().unwrap();
    assert_eq!(plan.prev_task_idx, Some(blocked));
    assert_eq!(plan.target, ContextSwitchTarget::Task { task_idx: runnable, cr3: 0 });
    assert_eq!(s.task(blocked).unwrap().state, ThreadState::Blocked);
    assert_eq!(s.task(runnable).unwrap().state, ThreadState::Running);
    assert_eq!(s.current_task_on_cpu(0).unwrap().tid, 602);
}

#[test]
fn blocked_current_handoff_uses_idle_when_no_task_is_ready() {
    let mut s = QoSScheduler::new();
    let blocked = spawn_ready(&mut s, 603, QoSClass::Background);
    assert_eq!(s.schedule_on_cpu(0), Some(blocked));
    s.block_task(blocked).unwrap();

    let plan = s.plan_blocked_current_handoff_on_cpu(0).unwrap().unwrap();
    assert_eq!(plan.prev_task_idx, Some(blocked));
    assert_eq!(plan.target, ContextSwitchTarget::Idle);
    assert!(s.current_task_on_cpu(0).is_none());
}

#[test]
fn wake_before_blocked_handoff_keeps_current_context_running() {
    let mut s = QoSScheduler::new();
    let task = spawn_ready(&mut s, 604, QoSClass::Background);
    assert_eq!(s.schedule_on_cpu(0), Some(task));
    s.block_task(task).unwrap();
    s.wake_task(task).unwrap();

    assert_eq!(s.plan_blocked_current_handoff_on_cpu(0), Ok(None));
    assert_eq!(s.current_task_on_cpu(0).unwrap().tid, 604);
    assert_eq!(s.task(task).unwrap().state, ThreadState::Running);
}

#[test]
fn blocked_current_handoff_rejects_missing_current_task_and_bad_cpu() {
    let mut s = QoSScheduler::new();
    assert_eq!(s.plan_blocked_current_handoff_on_cpu(0), Err(SchedError::NoSuchTask));
    assert_eq!(
        s.plan_blocked_current_handoff_on_cpu(kscheduler::MAX_CPUS),
        Err(SchedError::NoSuchTask)
    );
}

#[test]
fn terminated_slot_reuse_does_not_leave_duplicate_ready_entries() {
    let mut s = QoSScheduler::new();
    let old = s.create_task(501, QoSClass::Background, 0).unwrap();
    s.enqueue_ready(old).unwrap();
    s.terminate_task(old).unwrap();

    let replacement = s.create_task(502, QoSClass::Background, 0).unwrap();
    assert_eq!(replacement, old, "the test must reuse the terminated slot");
    s.enqueue_ready(replacement).unwrap();

    assert_eq!(s.schedule(), Some(replacement));
    assert_eq!(s.schedule(), None, "stale slot entries must not schedule the replacement twice");
}
