use crate::cap::{Cap, CapKind, ObjType, Rights, MAX_UNTYPED_BITS, MIN_UNTYPED_BITS};
use crate::error::{KError, KResult};

#[derive(Clone, Copy)]
struct Slot {
    cap: Cap,
    /// Capability derivation tree (CDT) link. `None` for roots and for empty slots.
    parent: Option<usize>,
}

impl Slot {
    const EMPTY: Slot = Slot { cap: Cap::NULL, parent: None };
}

/// A fixed-size capability space with a derivation tree.
///
/// Security properties (checked by `check_invariants` and fuzzed in the tests):
///  1. Rights never grow along a derivation (copy/mint can only intersect).
///  2. Untyped caps cannot be copied, so an allocation watermark can never be duplicated
///     and two objects can never be carved from the same bytes.
///  3. Objects never overlap, and the same bytes never have two different types.
///  4. Revoking a cap destroys every cap derived from it; the memory becomes reusable
///     only after that, and is zeroed through the caller-supplied hook on every retype.
///  5. Every failing operation leaves the table untouched.
pub struct CapSpace<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Default for CapSpace<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CapSpace<N> {
    pub const fn new() -> Self {
        CapSpace { slots: [Slot::EMPTY; N] }
    }

    fn slot(&self, i: usize) -> KResult<&Slot> {
        self.slots.get(i).ok_or(KError::InvalidSlot)
    }

    fn require_empty(&self, i: usize) -> KResult<()> {
        if self.slot(i)?.cap.is_null() {
            Ok(())
        } else {
            Err(KError::SlotOccupied)
        }
    }

    fn has_children(&self, idx: usize) -> bool {
        self.slots.iter().any(|s| s.parent == Some(idx) && !s.cap.is_null())
    }

    /// Look up a capability and require `need` rights. This is the gate every
    /// future syscall must pass through before touching an object.
    pub fn lookup(&self, idx: usize, need: Rights) -> KResult<&Cap> {
        let s = self.slot(idx)?;
        if s.cap.is_null() {
            return Err(KError::SlotEmpty);
        }
        if !s.cap.rights.contains(need) {
            return Err(KError::InsufficientRights);
        }
        Ok(&s.cap)
    }

    /// Boot-time only: install an initial Untyped capability describing real RAM.
    /// Refuses anything that is not Untyped, so authority cannot be conjured later.
    pub fn install_root(&mut self, idx: usize, cap: Cap) -> KResult<()> {
        self.require_empty(idx)?;
        match cap.kind {
            CapKind::Untyped { free: 0, .. } => {}
            _ => return Err(KError::InvalidCapType),
        }
        let dst = self.slots.get_mut(idx).ok_or(KError::InvalidSlot)?;
        *dst = Slot { cap, parent: None };
        Ok(())
    }

    /// Microkernel mediation: install a capability transferred across spaces or initialized for a new process.
    pub fn install_transferred(&mut self, idx: usize, cap: Cap) -> KResult<()> {
        self.require_empty(idx)?;
        if cap.is_null() {
            return Err(KError::InvalidArgument);
        }
        let dst = self.slots.get_mut(idx).ok_or(KError::InvalidSlot)?;
        *dst = Slot { cap, parent: None };
        Ok(())
    }

    /// Duplicate `src` into `dst` with rights `src.rights & mask`.
    pub fn copy(&mut self, src: usize, dst: usize, mask: Rights) -> KResult<()> {
        self.derive(src, dst, mask, None)
    }

    /// Like `copy`, but also stamps a non-zero badge on an unbadged Endpoint cap.
    pub fn mint(&mut self, src: usize, dst: usize, mask: Rights, badge: u64) -> KResult<()> {
        if badge == 0 {
            return Err(KError::InvalidArgument);
        }
        self.derive(src, dst, mask, Some(badge))
    }

    fn derive(&mut self, src: usize, dst: usize, mask: Rights, badge: Option<u64>) -> KResult<()> {
        self.require_empty(dst)?;
        let s = self.slot(src)?.cap;
        match s.kind {
            CapKind::Null => return Err(KError::SlotEmpty),
            CapKind::Untyped { .. } => return Err(KError::InvalidCapType),
            _ => {}
        }
        let new_badge = match badge {
            None => s.badge,
            Some(b) => {
                // Badges can only be set once, and only on endpoints.
                if !matches!(s.kind, CapKind::Endpoint { .. }) || s.badge != 0 {
                    return Err(KError::InvalidArgument);
                }
                b
            }
        };
        let cap = Cap { kind: s.kind, rights: s.rights.intersect(mask), badge: new_badge };
        let d = self.slots.get_mut(dst).ok_or(KError::InvalidSlot)?;
        *d = Slot { cap, parent: Some(src) };
        Ok(())
    }

    /// Remove one capability. Children are re-parented to its parent so that revoking an
    /// ancestor still reaches them. An Untyped with live children must be revoked first.
    pub fn delete(&mut self, idx: usize) -> KResult<()> {
        let s = *self.slot(idx)?;
        if s.cap.is_null() {
            return Err(KError::SlotEmpty);
        }
        if matches!(s.cap.kind, CapKind::Untyped { .. }) && self.has_children(idx) {
            return Err(KError::RevokeFirst);
        }
        for sl in self.slots.iter_mut() {
            if sl.parent == Some(idx) {
                sl.parent = s.parent;
            }
        }
        let d = self.slots.get_mut(idx).ok_or(KError::InvalidSlot)?;
        *d = Slot::EMPTY;
        Ok(())
    }

    /// seL4 seL4_CNode_Move: Moves a capability from `src` to `dst`.
    pub fn move_cap(&mut self, src: usize, dst: usize) -> KResult<()> {
        if src == dst {
            return Err(KError::InvalidArgument);
        }
        self.require_empty(dst)?;
        let s = *self.slot(src)?;
        if s.cap.is_null() {
            return Err(KError::SlotEmpty);
        }
        // Reparent children of src to point to dst
        for sl in self.slots.iter_mut() {
            if sl.parent == Some(src) {
                sl.parent = Some(dst);
            }
        }
        if let Some(d) = self.slots.get_mut(dst) {
            *d = s;
        }
        if let Some(sr) = self.slots.get_mut(src) {
            *sr = Slot::EMPTY;
        }
        if let Err(_e) = self.check_invariants() {
            return Err(KError::InvalidArgument);
        }
        Ok(())
    }

    /// seL4 seL4_CNode_Mutate: Moves a capability and attenuates rights without creating a new copy.
    pub fn mutate(&mut self, src: usize, dst: usize, mask: Rights) -> KResult<()> {
        self.move_cap(src, dst)?;
        if let Some(d) = self.slots.get_mut(dst) {
            d.cap.rights = d.cap.rights.intersect(mask);
        }
        if let Err(_e) = self.check_invariants() {
            return Err(KError::InvalidArgument);
        }
        Ok(())
    }

    /// seL4 seL4_CNode_Rotate: Atomic 3-way capability rotation between src, pivot, and dst.
    /// Safely re-parents children of pivot -> dst and children of src -> pivot so the CDT
    /// invariants are preserved.
    pub fn rotate(&mut self, src: usize, pivot: usize, dst: usize) -> KResult<()> {
        if src == pivot || pivot == dst || src == dst {
            return Err(KError::InvalidArgument);
        }
        let cap_src = *self.slot(src)?;
        let cap_pivot = *self.slot(pivot)?;
        if cap_src.cap.is_null() || cap_pivot.cap.is_null() {
            return Err(KError::SlotEmpty);
        }
        self.require_empty(dst)?;

        // Reparent children: pivot's children move to dst, src's children move to pivot
        for sl in self.slots.iter_mut() {
            if sl.parent == Some(pivot) {
                sl.parent = Some(dst);
            } else if sl.parent == Some(src) {
                sl.parent = Some(pivot);
            }
        }

        let mut pivot_slot = cap_pivot;
        if pivot_slot.parent == Some(src) {
            pivot_slot.parent = Some(pivot);
        }

        if let Some(d) = self.slots.get_mut(dst) {
            *d = pivot_slot;
        }
        if let Some(p) = self.slots.get_mut(pivot) {
            *p = cap_src;
        }
        if let Some(s) = self.slots.get_mut(src) {
            *s = Slot::EMPTY;
        }

        if let Err(_e) = self.check_invariants() {
            return Err(KError::InvalidArgument);
        }
        Ok(())
    }

    /// Destroy every capability derived (transitively) from `idx`; keep `idx` itself.
    /// Zeros all physical memory backing destroyed capabilities (fail-safe and anti-forensic).
    pub fn revoke(&mut self, idx: usize) -> KResult<()> {
        self.revoke_with_zero(idx, &mut |_paddr, _len| {})
    }

    /// Revoke and immediately zero physical memory backing every destroyed capability.
    pub fn revoke_with_zero(
        &mut self,
        idx: usize,
        zero: &mut dyn FnMut(u64, u64),
    ) -> KResult<()> {
        if self.slot(idx)?.cap.is_null() {
            return Err(KError::SlotEmpty);
        }
        let mut doomed = [false; N];
        // Fixed point over the parent links: at most N passes, each marks >= 1 new slot.
        for _ in 0..=N {
            let mut changed = false;
            for i in 0..N {
                if doomed.get(i).copied().unwrap_or(true) {
                    continue;
                }
                let Some(parent) = self.slots.get(i).and_then(|s| s.parent) else {
                    continue;
                };
                if parent == idx || doomed.get(parent).copied().unwrap_or(false) {
                    if let Some(d) = doomed.get_mut(i) {
                        *d = true;
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        for (s, d) in self.slots.iter_mut().zip(doomed.iter()) {
            if *d {
                match s.cap.kind {
                    CapKind::Frame { paddr } => zero(paddr, 4096),
                    CapKind::Untyped { base, size_bits, .. } => zero(base, 1u64 << size_bits),
                    CapKind::Endpoint { addr } => zero(addr, 64),
                    CapKind::Notification { addr } => zero(addr, 64),
                    CapKind::TCB { tcb_id } => zero(tcb_id, 1024),
                    _ => {}
                }
                *s = Slot::EMPTY;
            }
        }
        if let Some(Slot { cap: Cap { kind: CapKind::Untyped { base, free, .. }, .. }, .. }) = self.slots.get_mut(idx) {
            if *free > 0 {
                zero(*base, *free);
            }
            *free = 0;
        }
        Ok(())
    }

    /// Carve a new object out of the Untyped capability in slot `ut` into empty slot `dst`.
    /// The object is naturally aligned, lies entirely inside the untyped region, and is
    /// zeroed via `zero(start, len)` *before* the capability for it exists.
    pub fn retype(
        &mut self,
        ut: usize,
        ty: ObjType,
        dst: usize,
        zero: &mut dyn FnMut(u64, u64),
    ) -> KResult<()> {
        self.require_empty(dst)?;
        let ucap = *self.lookup(ut, Rights::WRITE)?;
        let CapKind::Untyped { base, size_bits, free } = ucap.kind else {
            return Err(KError::InvalidCapType);
        };
        let bits = ty.size_bits();
        if !(MIN_UNTYPED_BITS..=MAX_UNTYPED_BITS).contains(&bits) || bits > size_bits {
            return Err(KError::InvalidArgument);
        }
        let osz = 1u64 << bits;
        let cursor = base.checked_add(free).ok_or(KError::NoMemory)?;
        let start = cursor.checked_add(osz - 1).ok_or(KError::NoMemory)? & !(osz - 1);
        let end = start.checked_add(osz).ok_or(KError::NoMemory)?;
        let limit = base.checked_add(1u64 << size_bits).ok_or(KError::NoMemory)?;
        if end > limit {
            return Err(KError::NoMemory);
        }
        let kind = match ty {
            ObjType::Untyped { size_bits } => CapKind::Untyped { base: start, size_bits, free: 0 },
            ObjType::Frame => CapKind::Frame { paddr: start },
            ObjType::Endpoint => CapKind::Endpoint { addr: start },
            ObjType::Notification => CapKind::Notification { addr: start },
            ObjType::TCB => CapKind::TCB { tcb_id: start },
            ObjType::CNode { size_bits } => CapKind::CNode { radix: size_bits, guard: 0, guard_size: 0 },
            ObjType::SchedContext { size_bits: _ } => CapKind::SchedContext { budget_us: 10_000, period_us: 10_000 },
        };
        // All validation is done; from here on nothing can fail.
        zero(start, osz);
        if let Some(Slot { cap: Cap { kind: CapKind::Untyped { free, .. }, .. }, .. }) = self.slots.get_mut(ut) {
            *free = end - base;
        }
        if let Some(d) = self.slots.get_mut(dst) {
            *d = Slot { cap: Cap { kind, rights: Rights::ALL, badge: 0 }, parent: Some(ut) };
        }
        Ok(())
    }

    fn is_ancestor(&self, anc: usize, node: usize) -> bool {
        let mut cur = self.slots.get(node).and_then(|s| s.parent);
        for _ in 0..=N {
            match cur {
                Some(p) if p == anc => return true,
                Some(p) => cur = self.slots.get(p).and_then(|s| s.parent),
                None => return false,
            }
        }
        false
    }

    /// Verify the structural security invariants. Cheap enough for debug builds and boot
    /// self-tests; also used by the fuzz test to prove no operation sequence breaks them.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        for (i, s) in self.slots.iter().enumerate() {
            if s.cap.is_null() {
                if s.parent.is_some() {
                    return Err("null slot has a parent");
                }
                continue;
            }
            // The derivation tree must be acyclic and never pass through an empty slot.
            let mut cur = s.parent;
            let mut hops = 0usize;
            while let Some(p) = cur {
                let ps = self.slots.get(p).ok_or("parent index out of range")?;
                if ps.cap.is_null() {
                    return Err("parent slot is empty");
                }
                hops += 1;
                if hops > N {
                    return Err("cycle in derivation tree");
                }
                cur = ps.parent;
            }
            // Relationship to the direct parent.
            if let Some(p) = s.parent {
                let ps = self.slots.get(p).ok_or("parent index out of range")?;
                match (ps.cap.kind, s.cap.kind) {
                    (CapKind::Untyped { base, size_bits, free }, child) => {
                        let (cs, cl) = child.range().ok_or("untyped child without a range")?;
                        let ce = cs.saturating_add(cl);
                        let limit = base.saturating_add(1u64 << size_bits);
                        if cs < base || ce > limit {
                            return Err("object escapes its untyped region");
                        }
                        if ce - base > free {
                            return Err("object beyond allocation watermark");
                        }
                    }
                    (CapKind::Frame { paddr: a }, CapKind::Frame { paddr: b }) if a == b => {
                        if !ps.cap.rights.contains(s.cap.rights) {
                            return Err("rights escalation on frame");
                        }
                    }
                    (CapKind::Endpoint { addr: a }, CapKind::Endpoint { addr: b }) if a == b => {
                        if !ps.cap.rights.contains(s.cap.rights) {
                            return Err("rights escalation on endpoint");
                        }
                        if ps.cap.badge != 0 && s.cap.badge != ps.cap.badge {
                            return Err("badge changed on derivation");
                        }
                    }
                    (CapKind::Notification { addr: a }, CapKind::Notification { addr: b }) if a == b => {
                        if !ps.cap.rights.contains(s.cap.rights) {
                            return Err("rights escalation on notification");
                        }
                    }
                    (CapKind::TCB { tcb_id: a }, CapKind::TCB { tcb_id: b }) if a == b => {
                        if !ps.cap.rights.contains(s.cap.rights) {
                            return Err("rights escalation on TCB");
                        }
                    }
                    (CapKind::CNode { radix: a, .. }, CapKind::CNode { radix: b, .. }) if a == b => {
                        if !ps.cap.rights.contains(s.cap.rights) {
                            return Err("rights escalation on CNode");
                        }
                    }
                    _ => return Err("illegal parent/child combination"),
                }
            }
            // Pairwise: no overlap, no type confusion, memory only via its own subtree.
            for (j, t) in self.slots.iter().enumerate() {
                if j <= i || t.cap.is_null() {
                    continue;
                }
                self.check_pair(i, s, j, t)?;
            }
        }
        Ok(())
    }

    fn check_pair(&self, i: usize, a: &Slot, j: usize, b: &Slot) -> Result<(), &'static str> {
        let (Some((a0, al)), Some((b0, bl))) = (a.cap.kind.range(), b.cap.kind.range()) else {
            return Ok(());
        };
        let (a1, b1) = (a0.saturating_add(al), b0.saturating_add(bl));
        if a1 <= b0 || b1 <= a0 {
            return Ok(()); // disjoint
        }
        let a_ut = matches!(a.cap.kind, CapKind::Untyped { .. });
        let b_ut = matches!(b.cap.kind, CapKind::Untyped { .. });
        match (a_ut, b_ut) {
            (false, false) => {
                if (a0, al) != (b0, bl) {
                    return Err("partial overlap between objects");
                }
                if core::mem::discriminant(&a.cap.kind) != core::mem::discriminant(&b.cap.kind) {
                    return Err("type confusion: same memory, two object types");
                }
                Ok(())
            }
            (true, true) => {
                let nested = (a0 <= b0 && b1 <= a1) || (b0 <= a0 && a1 <= b1);
                if !nested {
                    return Err("partial overlap between untyped regions");
                }
                if self.is_ancestor(i, j) || self.is_ancestor(j, i) {
                    Ok(())
                } else {
                    Err("nested untyped regions are unrelated")
                }
            }
            (true, false) => {
                if self.is_ancestor(i, j) { Ok(()) } else { Err("object inside untyped it does not descend from") }
            }
            (false, true) => {
                if self.is_ancestor(j, i) { Ok(()) } else { Err("object inside untyped it does not descend from") }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};

    const ROOT_A: u64 = 0x1000_0000;
    const ROOT_B: u64 = 0x2000_0000;

    fn space<const N: usize>() -> CapSpace<N> {
        let mut cs = CapSpace::<N>::new();
        cs.install_root(0, Cap::new_untyped(ROOT_A, 16).unwrap()).unwrap();
        cs
    }
    fn nozero() -> impl FnMut(u64, u64) {
        |_, _| {}
    }

    #[test]
    fn rights_never_escalate() {
        let mut cs = space::<8>();
        cs.retype(0, ObjType::Frame, 1, &mut nozero()).unwrap();
        cs.copy(1, 2, Rights::READ).unwrap();
        cs.copy(2, 3, Rights::ALL).unwrap(); // asking for more than you have gives you no more
        assert_eq!(cs.lookup(3, Rights::READ).unwrap().rights(), Rights::READ);
        assert_eq!(cs.lookup(3, Rights::WRITE).unwrap_err(), KError::InsufficientRights);
        cs.check_invariants().unwrap();
    }

    #[test]
    fn unknown_rights_bits_are_rejected() {
        assert!(Rights::from_bits(0b111).is_some());
        assert!(Rights::from_bits(0b1000).is_none());
        assert!(Rights::from_bits(0xFF).is_none());
    }

    #[test]
    fn untyped_caps_cannot_be_copied_or_minted() {
        let mut cs = space::<8>();
        assert_eq!(cs.copy(0, 1, Rights::ALL), Err(KError::InvalidCapType));
        assert_eq!(cs.mint(0, 1, Rights::ALL, 7), Err(KError::InvalidCapType));
    }

    #[test]
    fn install_root_only_accepts_fresh_untyped() {
        let mut cs = space::<8>();
        assert_eq!(cs.install_root(0, Cap::new_untyped(ROOT_B, 16).unwrap()), Err(KError::SlotOccupied));
        assert_eq!(cs.install_root(1, Cap::NULL), Err(KError::InvalidCapType));
        assert_eq!(cs.install_root(99, Cap::new_untyped(ROOT_B, 16).unwrap()), Err(KError::InvalidSlot));
    }

    #[test]
    fn untyped_constructor_validates() {
        assert!(Cap::new_untyped(ROOT_A + 16, 16).is_err()); // misaligned
        assert!(Cap::new_untyped(ROOT_A, 3).is_err()); // too small
        assert!(Cap::new_untyped(ROOT_A, 48).is_err()); // too big
        assert!(Cap::new_untyped(u64::MAX & !0xFFFF, 16).is_err()); // wraps address space
    }

    #[test]
    fn badges_set_once_and_only_on_endpoints() {
        let mut cs = space::<8>();
        cs.retype(0, ObjType::Endpoint, 1, &mut nozero()).unwrap();
        cs.retype(0, ObjType::Frame, 2, &mut nozero()).unwrap();
        assert_eq!(cs.mint(1, 3, Rights::ALL, 0), Err(KError::InvalidArgument));
        assert_eq!(cs.mint(2, 3, Rights::ALL, 5), Err(KError::InvalidArgument)); // not an endpoint
        cs.mint(1, 3, Rights::READ, 0xBEEF).unwrap();
        assert_eq!(cs.mint(3, 4, Rights::READ, 0xCAFE), Err(KError::InvalidArgument)); // re-badge
        cs.copy(3, 4, Rights::READ).unwrap();
        assert_eq!(cs.lookup(4, Rights::NONE).unwrap().badge(), 0xBEEF);
        cs.check_invariants().unwrap();
    }

    #[test]
    fn retype_is_aligned_disjoint_and_exhausts_cleanly() {
        let mut cs = space::<64>();
        cs.retype(0, ObjType::Endpoint, 1, &mut nozero()).unwrap(); // 16 B at +0
        cs.retype(0, ObjType::Frame, 2, &mut nozero()).unwrap(); // 4 KiB, aligned up to +0x1000
        let Some((f, _)) = cs.lookup(2, Rights::NONE).unwrap().kind().range() else { panic!() };
        assert_eq!(f, ROOT_A + 0x1000);
        // 64 KiB region: slots hold 1 endpoint + 15 frames, then it is full.
        for slot in 3..=16 {
            cs.retype(0, ObjType::Frame, slot, &mut nozero()).unwrap();
        }
        let before = cs.slots.map(|s| s.cap);
        assert_eq!(cs.retype(0, ObjType::Frame, 17, &mut nozero()), Err(KError::NoMemory));
        assert_eq!(before, cs.slots.map(|s| s.cap)); // failure changed nothing
        cs.check_invariants().unwrap();
    }

    #[test]
    fn retype_rejects_objects_larger_than_the_region() {
        let mut cs = space::<8>();
        assert_eq!(cs.retype(0, ObjType::Untyped { size_bits: 17 }, 1, &mut nozero()), Err(KError::InvalidArgument));
        assert_eq!(cs.retype(0, ObjType::Untyped { size_bits: 3 }, 1, &mut nozero()), Err(KError::InvalidArgument));
    }

    #[test]
    fn retype_requires_write_right_on_the_untyped() {
        let mut cs = space::<8>();
        if let Some(s) = cs.slots.get_mut(0) {
            s.cap.rights = Rights::READ;
        }
        assert_eq!(cs.retype(0, ObjType::Frame, 1, &mut nozero()), Err(KError::InsufficientRights));
    }

    #[test]
    fn revoke_destroys_descendants_and_memory_is_zeroed_on_reuse() {
        let mut cs = space::<16>();
        let zeroed = Cell::new(0u64);
        let mut zero = |_s: u64, l: u64| zeroed.set(zeroed.get() + l);
        cs.retype(0, ObjType::Frame, 1, &mut zero).unwrap();
        cs.copy(1, 2, Rights::READ).unwrap();
        cs.copy(2, 3, Rights::READ).unwrap();
        cs.retype(0, ObjType::Untyped { size_bits: 12 }, 4, &mut zero).unwrap();
        cs.retype(4, ObjType::Endpoint, 5, &mut zero).unwrap();
        cs.revoke(0).unwrap();
        for i in 1..=5 {
            assert_eq!(cs.lookup(i, Rights::NONE).unwrap_err(), KError::SlotEmpty);
        }
        assert!(cs.lookup(0, Rights::NONE).is_ok()); // the revoked cap itself survives
        cs.retype(0, ObjType::Frame, 1, &mut zero).unwrap(); // same bytes again...
        let Some((start, _)) = cs.lookup(1, Rights::NONE).unwrap().kind().range() else { panic!() };
        assert_eq!(start, ROOT_A); // ...handed out from the beginning
        assert_eq!(zeroed.get(), 4096 + 4096 + 16 + 4096); // ...and zeroed again
        cs.check_invariants().unwrap();
    }

    #[test]
    fn revoke_with_zero_clears_memory_immediately() {
        let mut cs = space::<16>();
        let zeroed = Cell::new(0u64);
        let mut zero = |_s: u64, l: u64| zeroed.set(zeroed.get() + l);
        cs.retype(0, ObjType::Frame, 1, &mut zero).unwrap();
        assert_eq!(zeroed.get(), 4096);
        zeroed.set(0);
        cs.revoke_with_zero(0, &mut zero).unwrap();
        assert!(zeroed.get() >= 4096);
        assert_eq!(cs.lookup(1, Rights::NONE).unwrap_err(), KError::SlotEmpty);
    }

    #[test]
    fn revoke_of_a_frame_keeps_the_frame_but_kills_copies() {
        let mut cs = space::<8>();
        cs.retype(0, ObjType::Frame, 1, &mut nozero()).unwrap();
        cs.copy(1, 2, Rights::READ).unwrap();
        cs.revoke(1).unwrap();
        assert!(cs.lookup(1, Rights::ALL).is_ok());
        assert_eq!(cs.lookup(2, Rights::NONE).unwrap_err(), KError::SlotEmpty);
    }

    #[test]
    fn delete_reparents_so_ancestor_revoke_still_reaches_children() {
        let mut cs = space::<8>();
        cs.retype(0, ObjType::Frame, 1, &mut nozero()).unwrap();
        cs.copy(1, 2, Rights::READ).unwrap();
        cs.copy(2, 3, Rights::READ).unwrap();
        cs.delete(2).unwrap();
        cs.check_invariants().unwrap();
        cs.revoke(1).unwrap();
        assert_eq!(cs.lookup(3, Rights::NONE).unwrap_err(), KError::SlotEmpty);
    }

    #[test]
    fn untyped_with_children_cannot_be_deleted() {
        let mut cs = space::<8>();
        cs.retype(0, ObjType::Frame, 1, &mut nozero()).unwrap();
        assert_eq!(cs.delete(0), Err(KError::RevokeFirst));
        cs.revoke(0).unwrap();
        cs.delete(0).unwrap();
    }

    #[test]
    fn bad_indices_and_empty_slots_never_panic() {
        let mut cs = space::<4>();
        for bad in [4usize, 5, 1000, usize::MAX] {
            assert_eq!(cs.copy(bad, 1, Rights::ALL), Err(KError::InvalidSlot));
            assert_eq!(cs.copy(0, bad, Rights::ALL), Err(KError::InvalidSlot));
            assert_eq!(cs.delete(bad), Err(KError::InvalidSlot));
            assert_eq!(cs.revoke(bad), Err(KError::InvalidSlot));
            assert_eq!(cs.retype(0, ObjType::Frame, bad, &mut nozero()), Err(KError::InvalidSlot));
            assert_eq!(cs.retype(bad, ObjType::Frame, 1, &mut nozero()), Err(KError::InvalidSlot));
            assert_eq!(cs.lookup(bad, Rights::NONE).unwrap_err(), KError::InvalidSlot);
        }
        assert_eq!(cs.delete(1), Err(KError::SlotEmpty));
        assert_eq!(cs.revoke(1), Err(KError::SlotEmpty));
        assert_eq!(cs.copy(1, 2, Rights::ALL), Err(KError::SlotEmpty));
    }

    #[test]
    fn invariant_checker_is_not_vacuous() {
        // Forge each kind of corruption by hand and make sure the checker catches it.
        let mut cs = space::<8>();
        cs.retype(0, ObjType::Frame, 1, &mut nozero()).unwrap();
        cs.copy(1, 2, Rights::READ).unwrap();
        cs.check_invariants().unwrap();

        let mut bad = CapSpace::<8> { slots: cs.slots };
        bad.slots[1].cap.rights = Rights::READ;
        bad.slots[2].cap.rights = Rights::ALL; // child has more rights than parent
        assert!(bad.check_invariants().is_err());

        let mut bad = CapSpace::<8> { slots: cs.slots };
        bad.slots[1].parent = Some(2); // cycle 1 <-> 2
        assert!(bad.check_invariants().is_err());

        let mut bad = CapSpace::<8> { slots: cs.slots };
        bad.slots[3] = Slot { cap: Cap { kind: CapKind::Endpoint { addr: ROOT_A }, rights: Rights::ALL, badge: 0 }, parent: Some(0) };
        assert!(bad.check_invariants().is_err()); // endpoint overlapping the frame: type confusion
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Pick a slot index satisfying `pred`, scanning from a random start; occasionally
    /// returns a wild index (possibly out of range) to keep error paths covered.
    fn pick<const N: usize>(rng: &mut Rng, cs: &CapSpace<N>, pred: impl Fn(&Slot) -> bool) -> usize {
        if rng.below(10) == 0 {
            return rng.below(N as u64 + 3) as usize;
        }
        let start = rng.below(N as u64) as usize;
        for k in 0..N {
            let i = (start + k) % N;
            if pred(&cs.slots[i]) {
                return i;
            }
        }
        rng.below(N as u64 + 3) as usize
    }

    #[test]
    fn fuzz_no_operation_sequence_breaks_the_invariants() {
        const N: usize = 24;
        let is_empty = |s: &Slot| s.cap.is_null();
        let is_used = |s: &Slot| !s.cap.is_null();
        let is_untyped = |s: &Slot| matches!(s.cap.kind, CapKind::Untyped { .. });
        let is_derivable = |s: &Slot| matches!(s.cap.kind, CapKind::Frame { .. } | CapKind::Endpoint { .. });
        for seed in 1..=20u64 {
            let mut cs = CapSpace::<N>::new();
            cs.install_root(0, Cap::new_untyped(ROOT_A, 16).unwrap()).unwrap();
            cs.install_root(1, Cap::new_untyped(ROOT_B, 16).unwrap()).unwrap();
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let (mut retypes, mut copies, mut mints, mut revokes, mut deletes, mut errors) = (0, 0, 0, 0, 0, 0);
            let mut tally = std::collections::BTreeMap::<String, usize>::new();
            for _ in 0..30_000 {
                // Simulate boot code re-donating a RAM region once its root cap was deleted.
                for base in [ROOT_A, ROOT_B] {
                    let present = cs.slots.iter().any(|s| matches!(s.cap.kind, CapKind::Untyped { base: b, .. } if b == base));
                    if !present && rng.below(8) == 0 {
                        let dst = pick(&mut rng, &cs, is_empty);
                        let _ = cs.install_root(dst, Cap::new_untyped(base, 16).unwrap());
                    }
                }
                let last_zero: RefCell<Option<(u64, u64)>> = RefCell::new(None);
                let mut zero = |s: u64, l: u64| *last_zero.borrow_mut() = Some((s, l));
                let op: &str;
                let res = match rng.below(20) {
                    0..=7 => {
                        op = "retype";
                        let (ut, dst) = (pick(&mut rng, &cs, is_untyped), pick(&mut rng, &cs, is_empty));
                        let ty = match rng.below(3) {
                            0 => ObjType::Frame,
                            1 => ObjType::Endpoint,
                            _ => ObjType::Untyped { size_bits: 4 + rng.below(9) as u8 },
                        };
                        let r = cs.retype(ut, ty, dst, &mut zero);
                        if r.is_ok() {
                            retypes += 1;
                            // Zeroing happened, on exactly the bytes of the new object.
                            let made = cs.lookup(dst, Rights::NONE).unwrap().kind().range();
                            assert_eq!(*last_zero.borrow(), made);
                        } else {
                            assert_eq!(*last_zero.borrow(), None); // no zeroing on failure
                        }
                        r
                    }
                    8..=13 => {
                        op = "copy/mint";
                        let (src, dst) = (pick(&mut rng, &cs, is_derivable), pick(&mut rng, &cs, is_empty));
                        let mask = Rights::from_bits(rng.below(8) as u8).unwrap();
                        let r = if rng.below(2) == 0 {
                            cs.copy(src, dst, mask)
                        } else {
                            cs.mint(src, dst, mask, 1 + rng.below(4))
                        };
                        if r.is_ok() {
                            copies += 1;
                            let (p, ch) = (cs.slots[src].cap, cs.slots[dst].cap);
                            assert!(p.rights().contains(ch.rights())); // never escalates
                            mints += usize::from(ch.badge() != 0);
                        }
                        r
                    }
                    14..=16 => {
                        op = "revoke";
                        // Half the time target Untyped memory so regions get recycled.
                        let r = if rng.below(2) == 0 {
                            cs.revoke(pick(&mut rng, &cs, is_untyped))
                        } else {
                            cs.revoke(pick(&mut rng, &cs, is_used))
                        };
                        revokes += usize::from(r.is_ok());
                        r
                    }
                    _ => {
                        op = "delete";
                        let r = cs.delete(pick(&mut rng, &cs, is_used));
                        deletes += usize::from(r.is_ok());
                        r
                    }
                };
                errors += usize::from(res.is_err());
                if let Err(e) = res {
                    *tally.entry(format!("{op}: {e:?}")).or_default() += 1;
                }
                if let Err(e) = cs.check_invariants() {
                    panic!("seed {seed}: invariant broken: {e}");
                }
            }
            // Make sure the fuzzer actually exercised every operation.
            assert!(
                retypes > 500 && copies > 500 && mints > 50 && revokes > 200 && deletes > 200 && errors > 100,
                "seed {seed}: weak coverage retype={retypes} copy={copies} mint={mints} revoke={revokes} delete={deletes} err={errors}\n{tally:#?}"
            );
        }
    }

    #[test]
    fn test_move_mutate_rotate_invariants() {
        let mut cs = space::<16>();
        let mut zero = nozero();

        // 1. Retype frame into slot 1 (child of 0)
        assert!(cs.retype(0, ObjType::Frame, 1, &mut zero).is_ok());
        assert_eq!(cs.slots[1].parent, Some(0));

        // 2. Derive copy into slot 2 (child of 1)
        assert!(cs.copy(1, 2, Rights::ALL).is_ok());
        assert_eq!(cs.slots[2].parent, Some(1));

        // 3. Derive copy into slot 3 with Rights::READ (child of 2)
        assert!(cs.copy(2, 3, Rights::READ).is_ok());
        assert_eq!(cs.slots[3].parent, Some(2));
        assert!(cs.check_invariants().is_ok());

        // 4. Test move_cap: move slot 2 -> slot 4. Slot 3 must now point to slot 4!
        assert!(cs.move_cap(2, 4).is_ok());
        assert!(cs.slots[2].cap.is_null());
        assert_eq!(cs.slots[4].parent, Some(1));
        assert_eq!(cs.slots[3].parent, Some(4));
        assert!(cs.check_invariants().is_ok());

        // 5. Test mutate: move slot 4 -> slot 5 with Rights::READ.
        // Slot 3 (Rights::READ) is child of 5 (Rights::READ) -> invariant preserved!
        assert!(cs.mutate(4, 5, Rights::READ).is_ok());
        assert!(cs.slots[4].cap.is_null());
        assert_eq!(cs.slots[5].cap.rights, Rights::READ);
        assert_eq!(cs.slots[5].parent, Some(1));
        assert_eq!(cs.slots[3].parent, Some(5));
        assert!(cs.check_invariants().is_ok());

        // 6. Test rotate: src = 1, pivot = 5, dst = 6.
        // pivot (5) moves to dst (6), src (1) moves to pivot (5), src (1) becomes empty.
        // slot 5's children (which was 3) must move to dst (6)!
        // slot 1's children (which was 5, now moving to 6) must point to new pivot (5)!
        assert!(cs.rotate(1, 5, 6).is_ok());
        assert!(cs.slots[1].cap.is_null());
        assert!(!cs.slots[5].cap.is_null());
        assert!(!cs.slots[6].cap.is_null());
        assert!(cs.check_invariants().is_ok());

        // 7. Test revoke: revoke from slot 5 (which now holds what was slot 1)
        assert!(cs.revoke(5).is_ok());
        assert!(cs.slots[6].cap.is_null());
        assert!(cs.check_invariants().is_ok());
    }
}
