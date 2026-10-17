use kvault::kvaultfs::{
    AfSplit, KfsInode, MerkleBlockPointer, StealthVolumeManager, AF_SPLIT_SECTORS,
};
use kvault::VaultError;
use sha2::{Digest, Sha256};

#[test]
fn merkle_tree_node_integrity_passes_on_correct_digest() {
    let mut inode = KfsInode::new(101, 4096);
    let sample_block = [0x42u8; 4096];

    let mut hasher = Sha256::new();
    hasher.update(&sample_block);
    let digest: [u8; 32] = hasher.finalize().into();

    inode.direct_blocks[0] = MerkleBlockPointer {
        sector_address: 500,
        child_hash: digest,
    };

    // Validating against identical block data succeeds
    assert!(inode.verify_and_fetch_block(0, &sample_block).is_ok());
}

#[test]
fn merkle_tree_node_integrity_fails_immediately_on_single_bit_flip() {
    let mut inode = KfsInode::new(102, 4096);
    let sample_block = [0x42u8; 4096];

    let mut hasher = Sha256::new();
    hasher.update(&sample_block);
    let digest: [u8; 32] = hasher.finalize().into();

    inode.direct_blocks[0] = MerkleBlockPointer {
        sector_address: 500,
        child_hash: digest,
    };

    // Flip a single bit in the data block
    let mut tampered_block = sample_block;
    tampered_block[1337] ^= 0x01;

    // Must immediately fail closed with IntegrityViolation error!
    assert_eq!(
        inode.verify_and_fetch_block(0, &tampered_block),
        Err(VaultError::IntegrityViolation)
    );
}

#[test]
fn af_split_dispersal_and_reconstruction_roundtrips() {
    let mut master_key = [0u8; 64];
    for (i, b) in master_key.iter_mut().enumerate() {
        *b = (i * 3 + 7) as u8;
    }
    let pwhash_key = [0x42u8; 32];

    let total_bytes = AF_SPLIT_SECTORS * 512;
    let mut stripes = vec![0u8; total_bytes];

    // Disperse key across all 4,000 sectors using RNG
    let mut counter = 1u8;
    AfSplit::split_with_rng(&master_key, &pwhash_key, &mut stripes, |s| {
        for b in s.iter_mut() {
            *b = counter;
            counter = counter.wrapping_add(1);
        }
        true
    }).expect("split failed");

    // Reconstruct key with correct password key
    let reconstructed = AfSplit::reconstruct(&stripes, &pwhash_key).expect("reconstruct failed");
    assert_eq!(reconstructed, master_key);

    // Wrong password key fails recovery
    let wrong_pwhash_key = [0x99u8; 32];
    let bad_key = AfSplit::reconstruct(&stripes, &wrong_pwhash_key).expect("reconstruct failed");
    assert_ne!(bad_key, master_key);
}

#[test]
fn af_split_destroying_any_one_stripe_makes_key_recovery_impossible() {
    let master_key = [0xA5u8; 64];
    let pwhash_key = [0x55u8; 32];
    let total_bytes = AF_SPLIT_SECTORS * 512;
    let mut stripes = vec![0u8; total_bytes];

    let mut counter = 0x11u8;
    AfSplit::split_with_rng(&master_key, &pwhash_key, &mut stripes, |s| {
        for b in s.iter_mut() {
            *b = counter;
            counter = counter.wrapping_add(3);
        }
        true
    }).unwrap();

    // Destroy one single stripe (sector 17 completely wiped / zeroed)
    for b in &mut stripes[17 * 512..(17 + 1) * 512] {
        *b = 0;
    }

    let corrupted_key = AfSplit::reconstruct(&stripes, &pwhash_key).unwrap();
    // Tampering / wiping any single stripe makes key recovery completely impossible
    assert_ne!(corrupted_key, master_key);
}

#[test]
fn emergency_nuke_scrubs_all_stripe_bytes() {
    let mut stripes = vec![0xEFu8; 1024];
    StealthVolumeManager::emergency_nuke(&mut stripes);
    assert!(stripes.iter().all(|&b| b == 0));
}
