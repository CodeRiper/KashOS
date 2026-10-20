use kscheduler::{QoSClass, QoSScheduler, SchedError, ThreadState};

fn spawn_ready(s: &mut QoSScheduler, tid: u32, qos: QoSClass) -> usize {
    let idx = s.create_task(tid, qos, 0).unwrap();
    s.enqueue_ready(idx).unwrap();
    idx
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
