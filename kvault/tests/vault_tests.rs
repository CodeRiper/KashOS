use kvault::*;
use rand_core::{CryptoRng, Error, RngCore};

/// Deterministic test RNG (splitmix64). NOT for production: the kernel must feed hardware entropy.
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for c in dest.chunks_mut(8) {
            let b = self.next_u64().to_le_bytes();
            c.copy_from_slice(&b[..c.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for TestRng {}

const OUTER: &[u8] = b"outer-passphrase";
const HIDDEN: &[u8] = b"hidden-passphrase";
const DURESS: &[u8] = b"duress-passphrase";

fn opts(hidden_percent: u8) -> FormatOptions {
    FormatOptions { params: KdfParams::TEST_ONLY_INSECURE_FAST, hidden_percent }
}

fn make(blocks: u64, hidden: bool, duress: bool, rng: &mut TestRng) -> MemDevice {
    Vault::format(
        MemDevice::new(blocks),
        rng,
        &opts(if hidden { 40 } else { 0 }),
        OUTER,
        hidden.then_some(HIDDEN),
        duress.then_some(DURESS),
    )
    .unwrap()
}

fn unlock(dev: MemDevice, rng: &mut TestRng, pw: &[u8]) -> Vault<MemDevice> {
    match Vault::open(dev, rng, pw).unwrap() {
        OpenOutcome::Unlocked(v) => v,
        OpenOutcome::Duress(_) => panic!("unexpected duress"),
    }
}

fn clone_dev(d: &MemDevice) -> MemDevice {
    let mut c = MemDevice::new(d.block_count());
    c.raw_mut().copy_from_slice(d.raw());
    c
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn roundtrip_and_wrong_password() {
    let mut rng = TestRng(1);
    let dev = make(128, false, false, &mut rng);
    let err = Vault::open(clone_dev(&dev), &mut rng, b"nope").err().unwrap();
    assert_eq!(err.error, VaultError::BadPassword);

    let mut v = unlock(dev, &mut rng, OUTER);
    v.create_folder(&mut rng, "docs", None).unwrap();
    v.write_file(&mut rng, "docs", "a.txt", b"hello vault").unwrap();
    let big: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    v.write_file(&mut rng, "docs", "big.bin", &big).unwrap();
    v.write_file(&mut rng, "docs", "empty", b"").unwrap();

    let v = unlock(v.into_device(), &mut rng, OUTER); // reopen from disk
    assert_eq!(&**v.read_file("docs", "a.txt").unwrap(), b"hello vault");
    assert_eq!(&**v.read_file("docs", "big.bin").unwrap(), &big[..]);
    assert_eq!(v.read_file("docs", "empty").unwrap().len(), 0);
    assert_eq!(v.read_file("docs", "missing").unwrap_err(), VaultError::NotFound);
    assert_eq!(v.list_files("docs").unwrap().len(), 3);
}

#[test]
fn nothing_readable_on_disk() {
    let mut rng = TestRng(2);
    let mut v = unlock(make(128, false, false, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "TaxReturns", None).unwrap();
    v.write_file(&mut rng, "TaxReturns", "passport.pdf", b"TOP-SECRET-PAYLOAD-0123456789").unwrap();
    let dev = v.into_device();
    for needle in [&b"TOP-SECRET-PAYLOAD"[..], b"TaxReturns", b"passport.pdf", OUTER, b"kvault"] {
        assert!(!contains(dev.raw(), needle), "leaked {:?}", String::from_utf8_lossy(needle));
    }
}

#[test]
fn folder_password_protects_even_from_the_volume_password() {
    let mut rng = TestRng(3);
    let mut v = unlock(make(128, false, false, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "open", None).unwrap();
    v.create_folder(&mut rng, "private", Some(b"folder-pass")).unwrap();
    v.write_file(&mut rng, "private", "diary.txt", b"dear diary").unwrap();
    v.write_file(&mut rng, "open", "note.txt", b"not secret").unwrap();

    // Reopen with the volume password only: private folder is listed but locked.
    let mut v = unlock(v.into_device(), &mut rng, OUTER);
    let info = v.list_folders();
    assert!(info.iter().any(|f| f.name == "private" && f.password_protected && !f.unlocked));
    assert_eq!(v.read_file("private", "diary.txt").unwrap_err(), VaultError::FolderLocked);
    assert_eq!(v.list_files("private").err().unwrap(), VaultError::FolderLocked);
    assert_eq!(&**v.read_file("open", "note.txt").unwrap(), b"not secret");

    assert_eq!(v.unlock_folder("private", b"wrong").unwrap_err(), VaultError::BadPassword);
    v.unlock_folder("private", b"folder-pass").unwrap();
    assert_eq!(&**v.read_file("private", "diary.txt").unwrap(), b"dear diary");
    v.lock_folder("private").unwrap();
    assert_eq!(v.read_file("private", "diary.txt").unwrap_err(), VaultError::FolderLocked);

    v.change_folder_password(&mut rng, "private", b"folder-pass", b"new-pass").unwrap();
    let mut v = unlock(v.into_device(), &mut rng, OUTER);
    assert_eq!(v.unlock_folder("private", b"folder-pass").unwrap_err(), VaultError::BadPassword);
    v.unlock_folder("private", b"new-pass").unwrap();
    assert_eq!(&**v.read_file("private", "diary.txt").unwrap(), b"dear diary");
}

#[test]
fn hidden_volume_is_separate_and_survives_the_outer_one_filling_up() {
    let mut rng = TestRng(4);
    let dev = make(256, true, false, &mut rng);

    let mut hid = unlock(clone_dev(&dev), &mut rng, HIDDEN);
    hid.create_folder(&mut rng, "real", None).unwrap();
    hid.write_file(&mut rng, "real", "secret.txt", b"the real data").unwrap();
    let dev = hid.into_device();

    // Using the outer (decoy) volume until it is completely full must not touch the hidden one.
    let mut out = unlock(dev, &mut rng, OUTER);
    assert!(out.list_folders().is_empty()); // outer sees none of the hidden data
    out.create_folder(&mut rng, "decoy", None).unwrap();
    let chunk = vec![0xAAu8; 40_000];
    let mut i = 0;
    loop {
        match out.write_file(&mut rng, "decoy", &format!("f{i}"), &chunk) {
            Ok(()) => i += 1,
            Err(VaultError::NoSpace) => break,
            Err(e) => panic!("{e:?}"),
        }
        assert!(i < 1000);
    }
    assert!(i > 5);

    let hid = unlock(out.into_device(), &mut rng, HIDDEN);
    assert_eq!(&**hid.read_file("real", "secret.txt").unwrap(), b"the real data");
    assert!(hid.list_folders().iter().all(|f| f.name != "decoy"));
}

#[test]
fn duress_password_destroys_every_key() {
    let mut rng = TestRng(5);
    let mut v = unlock(make(128, true, true, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "docs", None).unwrap();
    v.write_file(&mut rng, "docs", "a", b"precious").unwrap();
    let dev = v.into_device();

    let dev = match Vault::open(dev, &mut rng, DURESS).unwrap() {
        OpenOutcome::Duress(d) => d,
        OpenOutcome::Unlocked(_) => panic!("duress password must not unlock"),
    };
    // Now even the CORRECT passwords fail, and fail exactly like a wrong password.
    for pw in [OUTER, HIDDEN, DURESS] {
        let e = Vault::open(clone_dev(&dev), &mut rng, pw).err().unwrap();
        assert_eq!(e.error, VaultError::BadPassword);
    }
}

#[test]
fn any_single_bitflip_or_block_swap_is_detected_never_silently_accepted() {
    let mut rng = TestRng(6);
    let mut v = unlock(make(40, false, false, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "d", None).unwrap();
    let a: Vec<u8> = (0..9000u32).map(|i| (i * 7) as u8).collect();
    let b: Vec<u8> = (0..9000u32).map(|i| (i * 13 + 5) as u8).collect();
    v.write_file(&mut rng, "d", "a", &a).unwrap();
    v.write_file(&mut rng, "d", "b", &b).unwrap();
    let good = v.into_device();
    let last = 20u64; // everything the vault wrote lives below this

    let check = |dev: MemDevice, rng: &mut TestRng| {
        // Either the vault refuses, or it returns exactly the original bytes. Never wrong bytes.
        if let Ok(OpenOutcome::Unlocked(v)) = Vault::open(dev, rng, OUTER) {
            for (n, want) in [("a", &a), ("b", &b)] {
                if let Ok(got) = v.read_file("d", n) {
                    assert_eq!(&**got, &want[..], "silent corruption of {n}");
                }
            }
        }
    };
    let bs = BLOCK_SIZE;
    for blk in 1..last {
        let mut d = clone_dev(&good);
        d.raw_mut()[blk as usize * bs + 100] ^= 0x01;
        check(d, &mut rng);
    }
    for i in 1..last {
        for j in (i + 1)..last {
            let mut d = clone_dev(&good);
            let raw = d.raw_mut();
            for k in 0..bs {
                raw.swap(i as usize * bs + k, j as usize * bs + k);
            }
            check(d, &mut rng);
        }
    }
}

#[test]
fn crash_at_any_write_leaves_a_consistent_vault() {
    struct Failing {
        inner: MemDevice,
        left: Option<usize>,
    }
    impl BlockDevice for Failing {
        fn block_count(&self) -> u64 {
            self.inner.block_count()
        }
        fn read_block(&self, i: u64, o: &mut [u8; BLOCK_SIZE]) -> Result<(), VaultError> {
            self.inner.read_block(i, o)
        }
        fn write_block(&mut self, i: u64, d: &[u8; BLOCK_SIZE]) -> Result<(), VaultError> {
            if let Some(n) = self.left.as_mut() {
                if *n == 0 {
                    return Err(VaultError::Io);
                }
                *n -= 1;
            }
            self.inner.write_block(i, d)
        }
    }

    let mut rng = TestRng(7);
    let mut v = unlock(make(64, false, false, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "d", None).unwrap();
    v.write_file(&mut rng, "d", "f", b"OLD-CONTENT").unwrap();
    let base = v.into_device();
    let new_data = vec![0x55u8; 20_000];

    let mut crashed_at_least_once = false;
    for n in 0..40 {
        let dev = Failing { inner: clone_dev(&base), left: None };
        let v = match Vault::open(dev, &mut rng, OUTER).unwrap() {
            OpenOutcome::Unlocked(v) => v,
            _ => unreachable!(),
        };
        // Arm the failure after opening, then overwrite the file.
        let dev = v.into_device();
        let dev = Failing { left: Some(n), ..dev };
        let mut v = match Vault::open(dev, &mut rng, OUTER).unwrap() {
            OpenOutcome::Unlocked(v) => v,
            _ => unreachable!(),
        };
        let res = v.write_file(&mut rng, "d", "f", &new_data);
        crashed_at_least_once |= res.is_err();
        let mut dev = v.into_device();
        dev.left = None; // power is back
        let v = match Vault::open(dev, &mut rng, OUTER).unwrap() {
            OpenOutcome::Unlocked(v) => v,
            _ => unreachable!(),
        };
        let got = v.read_file("d", "f").unwrap();
        assert!(&**got == b"OLD-CONTENT" || &**got == &new_data[..], "crash at write {n} left garbage");
        if res.is_ok() {
            assert_eq!(&**got, &new_data[..]);
        }
    }
    assert!(crashed_at_least_once);
}

#[test]
fn change_password_works() {
    let mut rng = TestRng(8);
    let mut v = unlock(make(64, true, false, &mut rng), &mut rng, OUTER);
    assert_eq!(v.change_password(&mut rng, HIDDEN).unwrap_err(), VaultError::InvalidParams); // collision
    v.change_password(&mut rng, b"brand-new").unwrap();
    let dev = v.into_device();
    assert!(Vault::open(clone_dev(&dev), &mut rng, OUTER).is_err());
    assert!(matches!(Vault::open(dev, &mut rng, b"brand-new").unwrap(), OpenOutcome::Unlocked(_)));
}

#[test]
fn format_rejects_bad_input() {
    let mut rng = TestRng(9);
    let f = |dev, hp, o: &[u8], h: Option<&[u8]>, d: Option<&[u8]>, rng: &mut TestRng| {
        Vault::format(dev, rng, &opts(hp), o, h, d).err()
    };
    assert_eq!(f(MemDevice::new(128), 0, OUTER, None, Some(OUTER), &mut rng), Some(VaultError::InvalidParams)); // duplicate pw
    assert_eq!(f(MemDevice::new(128), 0, b"", None, None, &mut rng), Some(VaultError::InvalidParams));
    assert_eq!(f(MemDevice::new(128), 30, OUTER, None, None, &mut rng), Some(VaultError::InvalidParams)); // hidden % without pw
    assert_eq!(f(MemDevice::new(8), 0, OUTER, None, None, &mut rng), Some(VaultError::DeviceTooSmall));
    let bad = FormatOptions { params: KdfParams { m_kib: 1, t: 1, p: 1 }, hidden_percent: 0 };
    assert_eq!(Vault::format(MemDevice::new(64), &mut rng, &bad, OUTER, None, None).err(), Some(VaultError::InvalidParams));
}

#[test]
fn delete_erases_data_and_returns_space() {
    let mut rng = TestRng(10);
    let mut v = unlock(make(64, false, false, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "d", None).unwrap();
    let before = v.free_blocks();
    v.write_file(&mut rng, "d", "x", &vec![1u8; 30_000]).unwrap();
    assert!(v.free_blocks() < before);
    v.delete_file(&mut rng, "d", "x").unwrap();
    assert_eq!(v.free_blocks(), before);
    assert_eq!(v.read_file("d", "x").unwrap_err(), VaultError::NotFound);
    v.write_file(&mut rng, "d", "x", &vec![2u8; 30_000]).unwrap(); // space is reusable
    v.delete_folder(&mut rng, "d").unwrap();
    assert_eq!(v.free_blocks(), before);
}

#[test]
fn out_of_space_is_clean() {
    let mut rng = TestRng(11);
    let mut v = unlock(make(48, false, false, &mut rng), &mut rng, OUTER);
    v.create_folder(&mut rng, "d", None).unwrap();
    v.write_file(&mut rng, "d", "keep", b"still here").unwrap();
    assert_eq!(v.write_file(&mut rng, "d", "huge", &vec![0u8; 1_000_000]).unwrap_err(), VaultError::NoSpace);
    assert_eq!(&**v.read_file("d", "keep").unwrap(), b"still here");
    assert_eq!(v.list_files("d").unwrap().len(), 1);
}

#[test]
fn garbage_and_hostile_headers_never_panic() {
    let mut rng = TestRng(12);
    for seed in 0..30u64 {
        let mut d = MemDevice::new(40);
        TestRng(seed).fill_bytes(d.raw_mut());
        let e = Vault::open(d, &mut rng, OUTER).err().unwrap();
        assert_eq!(e.error, VaultError::BadPassword);
    }
    // A header that asks for 4 GiB of Argon2 memory must be refused before any work is done.
    let mut d = MemDevice::new(40);
    d.raw_mut()[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    d.raw_mut()[4..8].copy_from_slice(&1u32.to_le_bytes());
    d.raw_mut()[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(Vault::open(d, &mut rng, OUTER).err().unwrap().error, VaultError::BadPassword);
}

#[test]
fn keyfile_is_a_real_second_factor_not_decoration() {
    let mut rng = TestRng(14);
    const KEYFILE: &[u8] = b"an arbitrary file's bytes, could be a photo, a binary, anything";
    const WRONG_KEYFILE: &[u8] = b"a different file entirely";

    let dev = Vault::format_with_keyfile(
        MemDevice::new(64),
        &mut rng,
        &opts(0),
        OUTER,
        Some(KEYFILE),
        None,
        None,
    )
    .unwrap();

    // Right password, right keyfile: opens.
    let mut v = match Vault::open_with_keyfile(clone_dev(&dev), &mut rng, OUTER, Some(KEYFILE)).unwrap() {
        OpenOutcome::Unlocked(v) => v,
        OpenOutcome::Duress(_) => panic!("unexpected duress"),
    };
    v.create_folder(&mut rng, "d", None).unwrap();
    v.write_file(&mut rng, "d", "f", b"secret").unwrap();
    let dev = v.into_device();

    // Right password, WRONG keyfile: must fail exactly like a wrong password.
    let err = Vault::open_with_keyfile(clone_dev(&dev), &mut rng, OUTER, Some(WRONG_KEYFILE)).err().unwrap();
    assert_eq!(err.error, VaultError::BadPassword);

    // Right password, NO keyfile (forgetting the second factor): also fails.
    let err = Vault::open_with_keyfile(clone_dev(&dev), &mut rng, OUTER, None).err().unwrap();
    assert_eq!(err.error, VaultError::BadPassword);

    // The plain (non-keyfile) open() with the right password alone must
    // likewise fail — the keyfile is a real requirement, not optional sugar
    // that `open()` would satisfy some other way.
    let err = Vault::open(clone_dev(&dev), &mut rng, OUTER).err().unwrap();
    assert_eq!(err.error, VaultError::BadPassword);

    // Right password and right keyfile again: still opens, and the data survived.
    let v = match Vault::open_with_keyfile(dev, &mut rng, OUTER, Some(KEYFILE)).unwrap() {
        OpenOutcome::Unlocked(v) => v,
        OpenOutcome::Duress(_) => panic!("unexpected duress"),
    };
    assert_eq!(&**v.read_file("d", "f").unwrap(), b"secret");
}

#[test]
fn keyfile_change_password_requires_old_keyfile_and_installs_new_one() {
    let mut rng = TestRng(15);
    const OLD_KF: &[u8] = b"old-keyfile-bytes";
    const NEW_KF: &[u8] = b"new-keyfile-bytes";

    let dev = Vault::format_with_keyfile(MemDevice::new(64), &mut rng, &opts(0), OUTER, Some(OLD_KF), None, None)
        .unwrap();
    let mut v = match Vault::open_with_keyfile(dev, &mut rng, OUTER, Some(OLD_KF)).unwrap() {
        OpenOutcome::Unlocked(v) => v,
        OpenOutcome::Duress(_) => panic!("unexpected duress"),
    };
    v.change_password_with_keyfile(&mut rng, OUTER, Some(NEW_KF)).unwrap();
    let dev = v.into_device();

    // Old keyfile no longer works.
    assert_eq!(
        Vault::open_with_keyfile(clone_dev(&dev), &mut rng, OUTER, Some(OLD_KF)).err().unwrap().error,
        VaultError::BadPassword
    );
    // New keyfile does.
    assert!(matches!(
        Vault::open_with_keyfile(dev, &mut rng, OUTER, Some(NEW_KF)).unwrap(),
        OpenOutcome::Unlocked(_)
    ));
}

#[test]
fn invalid_names_are_rejected() {
    let mut rng = TestRng(13);
    let mut v = unlock(make(64, false, false, &mut rng), &mut rng, OUTER);
    for bad in ["", "a/b", "a\\b", "a\0b", &"x".repeat(65)] {
        assert_eq!(v.create_folder(&mut rng, bad, None).unwrap_err(), VaultError::InvalidName);
    }
    v.create_folder(&mut rng, "ok", None).unwrap();
    assert_eq!(v.create_folder(&mut rng, "ok", None).unwrap_err(), VaultError::Exists);
}

#[test]
fn open_failure_does_not_mutate_or_format_device() {
    let mut rng = TestRng(42);
    let dev = make(64, false, false, &mut rng);
    let initial_bytes = dev.raw().to_vec();

    // Attempt to open with wrong password
    let res = Vault::open(clone_dev(&dev), &mut rng, b"completely-wrong-password");
    let fail = match res {
        Err(f) => f,
        Ok(_) => panic!("expected open failure with wrong password"),
    };
    assert_eq!(fail.error, VaultError::BadPassword);

    // Verify the device raw storage was NOT mutated by the failed open attempt
    assert_eq!(fail.device.raw(), initial_bytes.as_slice());
}

