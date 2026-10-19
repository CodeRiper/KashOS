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

#[test]
fn ahci_controller_fis_serialization_and_metadata() {
    use kblock::ahci::{AhciController, FisRegH2D, ATA_CMD_READ_DMA_EXT};

    let mut controller = AhciController::new(0);
    assert_eq!(controller.capacity_sectors(), 16_777_216);
    assert_eq!(controller.driver_name(), "SATA AHCI PCIe Controller (FIS DMA)");
    assert_eq!(controller.probe(), Err(BlockError::DeviceNotFound));

    // Test FisRegH2D serialization for 48-bit LBA read
    let mut fis = FisRegH2D::default();
    fis.fis_type = 0x27;
    fis.pmport_c = 1 << 7;
    fis.command = ATA_CMD_READ_DMA_EXT;
    fis.device = 1 << 6;
    fis.lba0 = 0x12;
    fis.lba1 = 0x34;
    fis.lba2 = 0x56;
    fis.lba3 = 0x78;
    fis.lba4 = 0x9A;
    fis.lba5 = 0xBC;
    fis.count_low = 8;
    fis.count_high = 0;

    let mut buf = [0u8; 64];
    fis.write_to_bytes(&mut buf);
    assert_eq!(buf[0], 0x27); // FIS type
    assert_eq!(buf[1], 0x80); // Command bit
    assert_eq!(buf[2], ATA_CMD_READ_DMA_EXT);
    assert_eq!(buf[4], 0x12); // LBA0
    assert_eq!(buf[5], 0x34); // LBA1
    assert_eq!(buf[6], 0x56); // LBA2
    assert_eq!(buf[7], 0x40); // Device LBA
    assert_eq!(buf[8], 0x78); // LBA3
    assert_eq!(buf[9], 0x9A); // LBA4
    assert_eq!(buf[10], 0xBC); // LBA5
    assert_eq!(buf[12], 8);    // Sector count low
}

#[test]
fn virtio_block_device_metadata_and_capabilities() {
    use kblock::virtio_blk::VirtioBlockDevice;

    let vblk = VirtioBlockDevice::new(0x1000);
    assert_eq!(vblk.capacity_sectors(), 2_097_152);
    assert_eq!(vblk.driver_name(), "VirtIO-Block Paravirtualized Disk (OASIS v1.0)");
}

#[test]
fn crc32_standard_check_vector() {
    use kblock::crc32;
    // Standard IEEE 802.3 CRC32 check vector for "123456789" is 0xCBF43926
    let check = crc32(b"123456789");
    assert_eq!(check, 0xCBF4_3926);
}

#[test]
fn mbr_partition_parsing_and_vault_discovery() {
    use kblock::{find_vault_partition, parse_mbr, PartitionRole, PartitionScheme};

    let mut sector0 = [0u8; 512];
    sector0[510] = 0x55;
    sector0[511] = 0xAA;

    // Partition 1: ESP (type 0xEF, LBA 2048, 131072 sectors = 64 MiB)
    let p1 = 446;
    sector0[p1 + 4] = 0xEF; // ESP
    sector0[p1 + 8..p1 + 12].copy_from_slice(&2048u32.to_le_bytes());
    sector0[p1 + 12..p1 + 16].copy_from_slice(&131072u32.to_le_bytes());

    // Partition 2: Boot (type 0x83, LBA 133120, 131072 sectors = 64 MiB)
    let p2 = 446 + 16;
    sector0[p2 + 4] = 0x83; // Linux / Boot
    sector0[p2 + 8..p2 + 12].copy_from_slice(&133120u32.to_le_bytes());
    sector0[p2 + 12..p2 + 16].copy_from_slice(&131072u32.to_le_bytes());

    // Partition 3: kvault Root (type 0x83, LBA 264192, 1048576 sectors = 512 MiB)
    let p3 = 446 + 32;
    sector0[p3 + 4] = 0x83; // Linux / Vault
    sector0[p3 + 8..p3 + 12].copy_from_slice(&264192u32.to_le_bytes());
    sector0[p3 + 12..p3 + 16].copy_from_slice(&1048576u32.to_le_bytes());

    let parts = parse_mbr(&sector0).expect("failed to parse valid MBR");
    assert_eq!(parts.len(), 3);

    assert_eq!(parts[0].partition_number, 1);
    assert_eq!(parts[0].scheme, PartitionScheme::Mbr);
    assert_eq!(parts[0].role, PartitionRole::Esp);
    assert_eq!(parts[0].start_lba, 2048);
    assert_eq!(parts[0].sector_count, 131072);
    assert_eq!(parts[0].end_lba(), 2048 + 131072 - 1);
    assert!(parts[0].contains_lba(2048));
    assert!(parts[0].contains_lba(2048 + 131072 - 1));
    assert!(!parts[0].contains_lba(2047));
    assert!(!parts[0].contains_lba(2048 + 131072));

    assert_eq!(parts[1].partition_number, 2);
    assert_eq!(parts[1].role, PartitionRole::Boot);
    assert_eq!(parts[1].start_lba, 133120);

    assert_eq!(parts[2].partition_number, 3);
    assert_eq!(parts[2].role, PartitionRole::VaultRoot);
    assert_eq!(parts[2].start_lba, 264192);

    let vault = find_vault_partition(&parts).expect("vault partition should be found");
    assert_eq!(vault.partition_number, 3);
    assert_eq!(vault.start_lba, 264192);
}

#[test]
fn gpt_partition_scanning_and_boundary_containment() {
    use kblock::{
        crc32, find_vault_partition, scan_partitions, PartitionRole, PartitionScheme,
        GUID_ESP, GUID_KASH_BOOT, GUID_KASH_VAULT,
    };

    let total_sectors = 2_097_152u64; // 1 GiB disk
    let mut driver = MockBlockDriver::new(total_sectors);

    // LBA 0: Protective MBR
    let mut mbr = [0u8; 512];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    mbr[446 + 4] = 0xEE; // GPT Protective
    mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // Start LBA 1
    mbr[446 + 12..446 + 16].copy_from_slice(&((total_sectors as u32) - 1).to_le_bytes());
    driver.write_sectors(0, 1, &mbr).unwrap();

    // Prepare GPT Entries (LBA 2..33, 128 entries x 128 bytes = 16384 bytes = 32 sectors)
    let mut entries = vec![0u8; 128 * 128];

    // Entry 1: ESP (LBA 2048..133119)
    let e1 = 0;
    entries[e1..e1 + 16].copy_from_slice(&GUID_ESP);
    entries[e1 + 32..e1 + 40].copy_from_slice(&2048u64.to_le_bytes());
    entries[e1 + 40..e1 + 48].copy_from_slice(&133119u64.to_le_bytes());

    // Entry 2: Boot (LBA 133120..264191)
    let e2 = 128;
    entries[e2..e2 + 16].copy_from_slice(&GUID_KASH_BOOT);
    entries[e2 + 32..e2 + 40].copy_from_slice(&133120u64.to_le_bytes());
    entries[e2 + 40..e2 + 48].copy_from_slice(&264191u64.to_le_bytes());

    // Entry 3: kvault Root (LBA 264192..1312767)
    let e3 = 256;
    entries[e3..e3 + 16].copy_from_slice(&GUID_KASH_VAULT);
    entries[e3 + 32..e3 + 40].copy_from_slice(&264192u64.to_le_bytes());
    entries[e3 + 40..e3 + 48].copy_from_slice(&1312767u64.to_le_bytes());

    let entries_crc = crc32(&entries);
    driver.write_sectors(2, 32, &entries).unwrap();

    // LBA 1: GPT Header (92 bytes used)
    let mut gpt = [0u8; 512];
    gpt[0..8].copy_from_slice(b"EFI PART");
    gpt[8..12].copy_from_slice(&0x00010000u32.to_le_bytes()); // Revision
    gpt[12..16].copy_from_slice(&92u32.to_le_bytes()); // Header size
    gpt[24..32].copy_from_slice(&1u64.to_le_bytes()); // Current LBA
    gpt[32..40].copy_from_slice(&(total_sectors - 1).to_le_bytes()); // Backup LBA
    gpt[40..48].copy_from_slice(&34u64.to_le_bytes()); // First usable LBA
    gpt[48..56].copy_from_slice(&(total_sectors - 34).to_le_bytes()); // Last usable LBA
    gpt[72..80].copy_from_slice(&2u64.to_le_bytes()); // Partition entries LBA
    gpt[80..84].copy_from_slice(&128u32.to_le_bytes()); // Number of entries
    gpt[84..88].copy_from_slice(&128u32.to_le_bytes()); // Entry size
    gpt[88..92].copy_from_slice(&entries_crc.to_le_bytes()); // Partition array CRC

    let header_crc = crc32(&gpt[..92]);
    gpt[16..20].copy_from_slice(&header_crc.to_le_bytes());
    driver.write_sectors(1, 1, &gpt).unwrap();

    // Scan partitions via driver
    let parts = scan_partitions(&mut driver).expect("scan partitions failed");
    assert_eq!(parts.len(), 3);

    assert_eq!(parts[0].scheme, PartitionScheme::Gpt);
    assert_eq!(parts[0].role, PartitionRole::Esp);
    assert_eq!(parts[0].start_lba, 2048);
    assert_eq!(parts[0].sector_count, 133119 - 2048 + 1);

    assert_eq!(parts[1].scheme, PartitionScheme::Gpt);
    assert_eq!(parts[1].role, PartitionRole::Boot);
    assert_eq!(parts[1].start_lba, 133120);

    assert_eq!(parts[2].scheme, PartitionScheme::Gpt);
    assert_eq!(parts[2].role, PartitionRole::VaultRoot);
    assert_eq!(parts[2].start_lba, 264192);

    let vault = find_vault_partition(&parts).expect("vault partition expected");
    assert_eq!(vault.role, PartitionRole::VaultRoot);
    assert_eq!(vault.start_lba, 264192);
}

#[test]
fn raw_disk_fallback_when_no_partition_table_found() {
    use kblock::{find_vault_partition, scan_partitions, PartitionScheme};

    let mut driver = MockBlockDriver::new(10_000);
    // Unpartitioned raw drive (all zeros)
    let parts = scan_partitions(&mut driver).expect("scan raw disk should succeed");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].scheme, PartitionScheme::RawDisk);
    assert_eq!(parts[0].start_lba, 0);
    assert_eq!(parts[0].sector_count, 10_000);

    let vault = find_vault_partition(&parts).expect("fallback should return root partition");
    assert_eq!(vault.start_lba, 0);
    assert_eq!(vault.sector_count, 10_000);
}

#[test]
fn usb_msc_cbw_csw_serialization_and_invariants() {
    use kblock::usb_msc::{
        CommandBlockWrapper, CommandStatusWrapper, CBW_FLAG_DATA_IN, CBW_SIGNATURE,
        CSW_SIGNATURE, CSW_STATUS_PASSED, SCSI_CMD_READ_10,
    };

    let mut cb = [0u8; 16];
    cb[0] = SCSI_CMD_READ_10;
    cb[2] = 0x00;
    cb[3] = 0x00;
    cb[4] = 0x08;
    cb[5] = 0x00; // LBA 2048
    cb[7] = 0x00;
    cb[8] = 0x08; // 8 sectors

    let cbw = CommandBlockWrapper {
        signature: CBW_SIGNATURE,
        tag: 0x1234_5678,
        data_transfer_len: 4096,
        flags: CBW_FLAG_DATA_IN,
        lun: 0,
        cb_length: 10,
        cb,
    };

    let bytes = cbw.to_bytes();
    assert_eq!(bytes.len(), 31);
    assert_eq!(&bytes[0..4], b"USBC");

    let parsed_cbw = CommandBlockWrapper::from_bytes(&bytes).expect("failed to parse valid CBW");
    let cbw_sig = parsed_cbw.signature;
    let cbw_tag = parsed_cbw.tag;
    let cbw_len = parsed_cbw.data_transfer_len;
    let cbw_flags = parsed_cbw.flags;
    let cbw_cmd = parsed_cbw.cb[0];
    assert_eq!(cbw_sig, CBW_SIGNATURE);
    assert_eq!(cbw_tag, 0x1234_5678);
    assert_eq!(cbw_len, 4096);
    assert_eq!(cbw_flags, CBW_FLAG_DATA_IN);
    assert_eq!(cbw_cmd, SCSI_CMD_READ_10);

    let csw = CommandStatusWrapper {
        signature: CSW_SIGNATURE,
        tag: 0x1234_5678,
        data_residue: 0,
        status: CSW_STATUS_PASSED,
    };

    let csw_bytes = csw.to_bytes();
    assert_eq!(csw_bytes.len(), 13);
    assert_eq!(&csw_bytes[0..4], b"USBS");

    let parsed_csw = CommandStatusWrapper::from_bytes(&csw_bytes).expect("failed to parse valid CSW");
    let csw_sig = parsed_csw.signature;
    let csw_tag = parsed_csw.tag;
    let csw_status = parsed_csw.status;
    assert_eq!(csw_sig, CSW_SIGNATURE);
    assert_eq!(csw_tag, 0x1234_5678);
    assert_eq!(csw_status, CSW_STATUS_PASSED);
}

struct MockUsbTransport {
    storage: Vec<u8>,
    last_tag: u32,
    last_lba: u64,
    last_count: u16,
    is_write: bool,
}

impl MockUsbTransport {
    fn new(sectors: usize) -> Self {
        Self {
            storage: vec![0u8; sectors * 512],
            last_tag: 0,
            last_lba: 0,
            last_count: 0,
            is_write: false,
        }
    }
}

impl kblock::usb_msc::UsbBulkTransport for MockUsbTransport {
    fn bulk_out(&mut self, _ep: u8, data: &[u8]) -> Result<(), BlockError> {
        if data.len() == 31 {
            // CBW
            let mut cbw_buf = [0u8; 31];
            cbw_buf.copy_from_slice(data);
            let cbw = kblock::usb_msc::CommandBlockWrapper::from_bytes(&cbw_buf).unwrap();
            self.last_tag = cbw.tag;
            let cmd = cbw.cb[0];
            if cmd == kblock::usb_msc::SCSI_CMD_READ_10 {
                let lba = ((cbw.cb[2] as u64) << 24) | ((cbw.cb[3] as u64) << 16) | ((cbw.cb[4] as u64) << 8) | (cbw.cb[5] as u64);
                let count = ((cbw.cb[7] as u16) << 8) | (cbw.cb[8] as u16);
                self.last_lba = lba;
                self.last_count = count;
                self.is_write = false;
            } else if cmd == kblock::usb_msc::SCSI_CMD_WRITE_10 {
                let lba = ((cbw.cb[2] as u64) << 24) | ((cbw.cb[3] as u64) << 16) | ((cbw.cb[4] as u64) << 8) | (cbw.cb[5] as u64);
                let count = ((cbw.cb[7] as u16) << 8) | (cbw.cb[8] as u16);
                self.last_lba = lba;
                self.last_count = count;
                self.is_write = true;
            }
        } else if self.is_write {
            // Data Out
            let start = (self.last_lba as usize) * 512;
            let end = start + data.len();
            if end <= self.storage.len() {
                self.storage[start..end].copy_from_slice(data);
            }
        }
        Ok(())
    }

    fn bulk_in(&mut self, _ep: u8, buf: &mut [u8]) -> Result<usize, BlockError> {
        if buf.len() == 8 {
            // READ CAPACITY (10) response
            let total_sectors = (self.storage.len() / 512) as u32;
            let last_lba = total_sectors - 1;
            buf[0..4].copy_from_slice(&last_lba.to_be_bytes());
            buf[4..8].copy_from_slice(&512u32.to_be_bytes());
            Ok(8)
        } else if buf.len() == 13 {
            // CSW
            let csw = kblock::usb_msc::CommandStatusWrapper {
                signature: kblock::usb_msc::CSW_SIGNATURE,
                tag: self.last_tag,
                data_residue: 0,
                status: kblock::usb_msc::CSW_STATUS_PASSED,
            };
            buf.copy_from_slice(&csw.to_bytes());
            Ok(13)
        } else {
            // Data In
            let start = (self.last_lba as usize) * 512;
            let end = start + buf.len();
            if end <= self.storage.len() {
                buf.copy_from_slice(&self.storage[start..end]);
            }
            Ok(buf.len())
        }
    }
}

#[test]
fn usb_mass_storage_device_scsi_roundtrip() {
    let transport = Box::new(MockUsbTransport::new(2048));
    let mut dev = kblock::UsbMassStorageDevice::with_transport(transport, 0x81, 0x02);

    let capacity = dev.probe_capacity().expect("probe capacity failed");
    assert_eq!(capacity, 2048);
    assert_eq!(dev.sector_size, 512);

    let write_data = [0x42u8; 512];
    dev.write_sectors(10, 1, &write_data).expect("write failed");

    let mut read_data = [0u8; 512];
    dev.read_sectors(10, 1, &mut read_data).expect("read failed");
    assert_eq!(read_data, write_data);

    dev.flush_cache().expect("flush cache failed");
}


