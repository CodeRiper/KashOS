//! kcore: the capability and kernel-object-memory core.
//!
//! Design rules enforced here:
//!  * `#![forbid(unsafe_code)]` - the whole security-critical logic is safe Rust.
//!  * No heap, no recursion, every loop bounded by the (static) table size `N`.
//!  * No panics on input-dependent paths (indexing/unwrap/expect/panic are denied by clippy).
//!  * Authority only ever shrinks along a derivation: nothing can be created from nothing
//!    except `CapSpace::install_root`, which only accepts Untyped memory and is meant for boot.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod cap;
mod error;
mod space;

pub use cap::{
    Cap, CapKind, CapRights, CapabilityNode, ObjType, PledgeFlags, ProcessSecurityContext,
    Rights, ENDPOINT_BITS, FRAME_BITS, MAX_UNTYPED_BITS, MIN_UNTYPED_BITS,
};
pub use error::{KError, KResult};
pub use space::CapSpace;

