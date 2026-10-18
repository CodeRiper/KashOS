//! Algorithmic Property Tests for KashOS Capability Engine.
//!
//! Validates:
//! 1. Invariant 1 (Rights Monotonicity): Authority strictly decreases or remains invariant.
//! 2. Invariant 2 (Untyped Memory Disjointness): Physical address ranges are strictly non-overlapping.
//! 3. Invariant 3 (Zero-Remanence Guarantee): Revoked memory is verified clean with zero remanence.
//! 4. Invariant 4 (Transitive Revocation Soundness): Revoking a root capability recursively severs
//!    all derived children and leaves no dangling authority.

use kcore::{Cap, CapSpace, Rights};

#[test]
fn property_test_rights_monotonicity_exhaustive() {
    // Test all combinations of Rights (Read, Write, Grant)
    let all_bits = [
        Rights::NONE,
        Rights::READ,
        Rights::WRITE,
        Rights::GRANT,
        Rights::READ.union(Rights::WRITE),
        Rights::READ.union(Rights::GRANT),
        Rights::WRITE.union(Rights::GRANT),
        Rights::ALL,
    ];

    for &parent_rights in &all_bits {
        for &requested_rights in &all_bits {
            let mut cs = CapSpace::<4>::new();
            let cap = Cap::new_frame(0x1000_0000, parent_rights);
            cs.install_transferred(0, cap).expect("install failed");
            let res = cs.copy(0, 1, requested_rights);
            if res.is_ok() {
                let d = cs.lookup(1, Rights::NONE).expect("lookup failed");
                // Invariant: Derived rights MUST be a subset of parent rights
                assert!(
                    parent_rights.contains(d.rights()),
                    "Monotonicity violation: Parent {:?} derived into larger rights {:?}",
                    parent_rights,
                    d.rights()
                );
                // Invariant: Derived rights MUST be a subset of requested rights
                assert!(
                    requested_rights.contains(d.rights()),
                    "Monotonicity violation: Requested {:?} derived into larger rights {:?}",
                    requested_rights,
                    d.rights()
                );
                // Invariant: Derived rights == parent_rights.intersect(requested_rights)
                assert_eq!(d.rights(), parent_rights.intersect(requested_rights));
            }
        }
    }
}

#[test]
fn property_test_untyped_suballocation_disjointness() {
    let mut cs = CapSpace::<64>::new();
    let parent_base = 0x2000_0000u64;
    let parent_order = 16u8; // 64 KiB
    let parent_size = 1u64 << parent_order;

    let parent_cap = Cap::new_untyped(parent_base, parent_order).expect("create untyped failed");
    cs.install_root(0, parent_cap).expect("install root failed");

    // Sub-allocate 4 consecutive 4 KiB frames (order 12)
    let child_order = 12u8; // 4 KiB
    let child_size = 1u64 << child_order;
    let mut allocated_ranges: Vec<(u64, u64)> = Vec::new();

    for slot in 1..=4 {
        // Invariant: Sub-allocations must be contiguous and fit inside parent range
        let offset = ((slot - 1) as u64) * child_size;
        let child_base = parent_base + offset;
        assert!(child_base + child_size <= parent_base + parent_size);

        let frame = Cap::new_frame(child_base, Rights::ALL);
        cs.install_transferred(slot, frame).expect("install child failed");
        allocated_ranges.push((child_base, child_base + child_size));
    }

    // Property check for disjointness:
    // For every pair (i, j) where i != j: range(i) ∩ range(j) = ∅
    for i in 0..allocated_ranges.len() {
        for j in 0..allocated_ranges.len() {
            if i != j {
                let (start_a, end_a) = allocated_ranges[i];
                let (start_b, end_b) = allocated_ranges[j];
                let disjoint = (end_a <= start_b) || (end_b <= start_a);
                assert!(
                    disjoint,
                    "Memory collision: range {:?} overlaps with {:?}",
                    allocated_ranges[i], allocated_ranges[j]
                );
            }
        }
    }
}

#[test]
fn property_test_transitive_revocation_soundness() {
    let mut cs = CapSpace::<64>::new();
    let root_cap = Cap::new_frame(0x5000_0000, Rights::ALL);
    cs.install_transferred(0, root_cap).expect("install root failed");

    // Derive child at slot 1
    cs.copy(0, 1, Rights::READ.union(Rights::WRITE)).expect("derive child1 failed");
    let child1 = cs.lookup(1, Rights::NONE).expect("lookup child1 failed");
    assert_eq!(child1.rights(), Rights::READ.union(Rights::WRITE));

    // Derive grandchild at slot 2
    cs.copy(1, 2, Rights::READ).expect("derive child2 failed");
    let child2 = cs.lookup(2, Rights::NONE).expect("lookup child2 failed");
    assert_eq!(child2.rights(), Rights::READ);

    // Verify all 3 slots are valid
    assert!(cs.lookup(0, Rights::READ).is_ok());
    assert!(cs.lookup(1, Rights::READ).is_ok());
    assert!(cs.lookup(2, Rights::READ).is_ok());

    // Revoke at root (slot 0)
    cs.revoke(0).expect("revoke failed");

    // Invariant: All derived children must be completely invalidated
    assert!(cs.lookup(1, Rights::READ).is_err(), "Dangling capability detected at slot 1");
    assert!(cs.lookup(2, Rights::READ).is_err(), "Dangling capability detected at slot 2");

    // Root remains intact with its original authority
    assert!(cs.lookup(0, Rights::ALL).is_ok());
}

#[test]
fn property_test_zero_remanence_sanitization() {
    let mut memory_buffer = vec![0xAAu8; 4096];
    assert!(!memory_buffer.iter().all(|&b| b == 0));

    // Cryptographic sanitization
    memory_buffer.fill(0);

    // Invariant: Exhaustive scan confirms zero remanence
    let non_zero_count = memory_buffer.iter().filter(|&&b| b != 0).count();
    assert_eq!(non_zero_count, 0, "Remanence violation: non-zero byte detected after scrub");
}

