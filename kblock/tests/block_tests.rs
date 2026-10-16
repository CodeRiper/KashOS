use kblock::{BlockDevice, BlockOperation, BlockRequest, ElevatorScheduler, MemBlockDevice};

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

    // After coalescing, there should only be 1 request with 16 sectors!
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

    // Should pop in ascending order: 100, 200, 3000, 4000, 5000
    let mut popped = Vec::new();
    while let Some(req) = elevator.pop_next_request() {
        popped.push(req.start_sector);
    }
    assert_eq!(popped, vec![100, 200, 3000, 4000, 5000]);
}

#[test]
fn mem_block_device_read_write_roundtrip() {
    let dev = MemBlockDevice::new(1024, 512);
    assert_eq!(dev.sector_size_bytes(), 512);
    assert_eq!(dev.total_sectors(), 1024);

    let mut write_buf = [0x5Au8; 512];
    write_buf[0] = 0xAA;
    write_buf[511] = 0xBB;

    dev.submit_request(BlockRequest {
        op: BlockOperation::Write,
        start_sector: 10,
        sector_count: 1,
        memory_buffer: write_buf.as_mut_ptr(),
        callback: None,
    }).unwrap();

    let mut read_buf = [0u8; 512];
    dev.submit_request(BlockRequest {
        op: BlockOperation::Read,
        start_sector: 10,
        sector_count: 1,
        memory_buffer: read_buf.as_mut_ptr(),
        callback: None,
    }).unwrap();

    assert_eq!(read_buf[0], 0xAA);
    assert_eq!(read_buf[511], 0xBB);
    assert_eq!(read_buf[100], 0x5A);
}
