use kipc::{ChannelError, RingChannel};
use std::sync::Arc;
use std::thread;

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Msg {
    seq: u64,
    payload: [u8; 16],
}

#[test]
fn fifo_order_is_preserved() {
    let ch: RingChannel<Msg, 8> = RingChannel::new(Msg::default());
    for i in 0..5u64 {
        ch.send(&Msg { seq: i, payload: [0; 16] }).unwrap();
    }
    for i in 0..5u64 {
        assert_eq!(ch.try_receive().unwrap().seq, i);
    }
    assert_eq!(ch.try_receive(), Err(ChannelError::Empty));
}

#[test]
fn capacity_is_n_minus_one_and_full_is_detected() {
    let ch: RingChannel<Msg, 4> = RingChannel::new(Msg::default());
    assert_eq!(ch.capacity(), 3);
    for i in 0..3u64 {
        ch.send(&Msg { seq: i, payload: [0; 16] }).unwrap();
    }
    assert!(ch.is_full());
    assert_eq!(ch.send(&Msg { seq: 99, payload: [0; 16] }), Err(ChannelError::Full));
    // Draining one slot makes room for exactly one more.
    assert_eq!(ch.try_receive().unwrap().seq, 0);
    assert!(!ch.is_full());
    ch.send(&Msg { seq: 3, payload: [0; 16] }).unwrap();
    assert!(ch.is_full());
}

#[test]
fn empty_channel_reports_empty() {
    let ch: RingChannel<Msg, 8> = RingChannel::new(Msg::default());
    assert!(ch.is_empty());
    assert_eq!(ch.try_receive(), Err(ChannelError::Empty));
}

#[test]
fn wraps_around_the_backing_array_correctly() {
    // Send/receive enough times that the index wraps past N more than
    // once — this is exactly the kind of off-by-one a naive port gets
    // subtly wrong (e.g. using `% (N-1)` somewhere instead of `% N`).
    let ch: RingChannel<Msg, 4> = RingChannel::new(Msg::default());
    let mut next_send = 0u64;
    let mut next_recv = 0u64;
    for _ in 0..1000 {
        // Fill to capacity.
        while ch.send(&Msg { seq: next_send, payload: [0; 16] }).is_ok() {
            next_send += 1;
        }
        // Drain completely.
        while let Ok(m) = ch.try_receive() {
            assert_eq!(m.seq, next_recv);
            next_recv += 1;
        }
    }
    assert_eq!(next_send, next_recv);
    assert!(next_send > 1000, "the wraparound loop should have moved a meaningful number of messages");
}

#[test]
fn len_tracks_sends_and_receives() {
    let ch: RingChannel<Msg, 8> = RingChannel::new(Msg::default());
    assert_eq!(ch.len(), 0);
    ch.send(&Msg::default()).unwrap();
    ch.send(&Msg::default()).unwrap();
    assert_eq!(ch.len(), 2);
    ch.try_receive().unwrap();
    assert_eq!(ch.len(), 1);
}

/// The real point of this crate: a producer on one OS thread and a consumer
/// on another, hammering the same channel with no lock, for enough
/// iterations and enough runs that a genuine ordering bug would show up as
/// a flaky or failing assertion rather than staying hidden in a
/// single-threaded test.
#[test]
fn concurrent_producer_and_consumer_preserve_order_and_lose_nothing() {
    const N: u64 = 200_000;
    for _run in 0..20 {
        let ch: Arc<RingChannel<Msg, 64>> = Arc::new(RingChannel::new(Msg::default()));

        let producer = {
            let ch = Arc::clone(&ch);
            thread::spawn(move || {
                let mut seq = 0u64;
                while seq < N {
                    if ch.send(&Msg { seq, payload: [(seq % 256) as u8; 16] }).is_ok() {
                        seq += 1;
                    } else {
                        thread::yield_now(); // channel full — let the consumer catch up
                    }
                }
            })
        };

        let consumer = {
            let ch = Arc::clone(&ch);
            thread::spawn(move || {
                let mut expected = 0u64;
                while expected < N {
                    match ch.try_receive() {
                        Ok(m) => {
                            assert_eq!(m.seq, expected, "out-of-order or dropped message");
                            assert_eq!(m.payload[0], (expected % 256) as u8, "payload corruption");
                            expected += 1;
                        }
                        Err(_) => thread::yield_now(), // try_receive only ever returns Empty
                    }
                }
            })
        };

        producer.join().unwrap();
        consumer.join().unwrap();
        assert!(ch.is_empty());
    }
}
