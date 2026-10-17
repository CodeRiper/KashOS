use kblock::{
    BlockError, BlockOperation, BlockRequest, ElevatorScheduler,
    IoOperation, KBlockScheduler, PersistentBlockDriver,
};

struct MockBlockDriver {
    storage: Vec<u8>,
    capacity: u64,
}

impl MockBlockDriver {
    fn new(sectors: u64) -> Self {
        Self {
            storage: vec![0u8; (sectors as usize) * 512],
            capacity: sectors,
        }
    }
}

impl PersistentBlockDriver for MockBlockDriver {
    fn driver_name(&self) -> &'static str {
        "MockBlockDriver"
    }
    fn capacity_sectors(&self) -> u64 {
        self.capacity
    }
    fn read_sectors(&mut self, lba: u64, count: u16, buf: &mut [u8]) -> Result<(), BlockError> {
        let start = (lba as usize) * 512;
        let end = start + (count as usize) * 512;
        if end > self.storage.len() {
            return Err(BlockError::OutOfBounds);
        }
        buf.copy_from_slice(&self.storage[start..end]);
        Ok(())
    }
    fn write_sectors(&mut self, lba: u64, count: u16, buf: &[u8]) -> Result<(), BlockError> {
        let start = (lba as usize) * 512;
        let end = start + (count as usize) * 512;
        if end > self.storage.len() {
            return Err(BlockError::OutOfBounds);
        }
        self.storage[start..end].copy_from_slice(buf);
        Ok(())
    }
    fn flush_cache(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

#[test]
fn elevator_coalesces_contiguous_writes() {
    let mut elevator = ElevatorScheduler::new();

    let req1 = BlockRequest {
        op: BlockOperation::Write,
        start_sector: 1000,
        sector_count: 8,
        memory_buffer: core::ptr::null_mut(),
        callback: None,
    };
    let req2 = BlockRequest {
        op: BlockOperation::Write,
        start_sector: 1008,
        sector_count: 8,
        memory_buffer: core::ptr::null_mut(),
        callback: None,
    };

    elevator.insert_and_coalesce(req1);
    elevator.insert_and_coalesce(req2);

    let coalesced = elevator.pop_next_request().expect("expected coalesced request");
    assert_eq!(coalesced.start_sector, 1000);
    assert_eq!(coalesced.sector_count, 16);
    assert!(elevator.is_empty());
}

#[test]
fn elevator_c_look_sweeps_ascending_platter_sectors() {
    let mut elevator = ElevatorScheduler::new();

    let sectors = [5000, 100, 3000, 200, 4000];
    for &sec in &sectors {
        elevator.insert_and_coalesce(BlockRequest {
            op: BlockOperation::Read,
            start_sector: sec,
            sector_count: 1,
            memory_buffer: core::ptr::null_mut(),
            callback: None,
        });
    }

    let mut popped = Vec::new();
    while let Some(req) = elevator.pop_next_request() {
        popped.push(req.start_sector);
    }
    assert_eq!(popped, vec![100, 200, 3000, 4000, 5000]);
}

#[test]
fn kblock_scheduler_read_write_zero_roundtrip() {
    let mock = Box::new(MockBlockDriver::new(1024));
    let mut sched = KBlockScheduler::new(mock);

    assert_eq!(sched.driver.capacity_sectors(), 1024);
    assert_eq!(sched.driver.driver_name(), "MockBlockDriver");

    let mut write_buf = [0x5Au8; 512];
    write_buf[0] = 0xAA;
    write_buf[511] = 0xBB;

    sched.driver.write_sectors(10, 1, &write_buf).expect("write failed");

    let mut read_buf = [0u8; 512];
    sched.driver.read_sectors(10, 1, &mut read_buf).expect("read failed");

    assert_eq!(read_buf[0], 0xAA);
    assert_eq!(read_buf[511], 0xBB);
    assert_eq!(read_buf[100], 0x5A);

    // Test C-LOOK elevator submission & coalescing
    sched.submit(100, 4, IoOperation::Write, 1).expect("submit 1 failed");
    sched.submit(104, 4, IoOperation::Write, 1).expect("submit 2 failed (coalesce)");

    let slot_idx = sched.next_scheduled_slot().expect("slot expected");
    let slot = sched.get_slot(slot_idx).expect("active slot expected");
    assert_eq!(slot.lba, 100);
    assert_eq!(slot.sector_count, 8); // Coalesced 4 + 4

    // Test deterministic zeroing
    sched.deterministic_zero_lba(10, 1).expect("zero failed");
    sched.driver.read_sectors(10, 1, &mut read_buf).expect("read after zero failed");
    assert_eq!(read_buf, [0u8; 512]);
}
