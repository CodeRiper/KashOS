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

    let total_bytes = AF_SPLIT_SECTORS * 512;
    let mut stripes = vec![0u8; total_bytes];

    // Disperse key across all 4,000 sectors
    AfSplit::split(&master_key, &mut stripes).expect("split failed");

    // Reconstruct key
    let reconstructed = AfSplit::reconstruct(&stripes).expect("reconstruct failed");
    assert_eq!(reconstructed, master_key);
}

#[test]
fn af_split_fails_reconstruction_if_even_one_byte_is_altered() {
    let master_key = [0xA5u8; 64];
    let total_bytes = AF_SPLIT_SECTORS * 512;
    let mut stripes = vec![0u8; total_bytes];

    AfSplit::split(&master_key, &mut stripes).unwrap();

    // Corrupt one single byte in sector 17
    stripes[17 * 512 + 42] ^= 0x01;

    let corrupted_key = AfSplit::reconstruct(&stripes).unwrap();
    // The reconstructed key MUST NOT match master key (tampering completely breaks key)
    assert_ne!(corrupted_key, master_key);
}

#[test]
fn emergency_nuke_scrubs_all_stripe_bytes() {
    let mut stripes = vec![0xEFu8; 1024];
    StealthVolumeManager::emergency_nuke(&mut stripes);
    assert!(stripes.iter().all(|&b| b == 0));
}
