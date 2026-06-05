//! Backend implementations for Dory primitives
//!
//! This module provides concrete implementations of the abstract traits
//! defined in the primitives module. Currently supports:
//! - arkworks: BN254 pairing curve implementation using Arkworks
//! - bls12_381: BLS12-381 pairing curve (bench-dory feature)
//! - bls12_377: BLS12-377 pairing curve (bench-dory feature)

#[cfg(feature = "arkworks")]
pub mod arkworks;

#[cfg(feature = "arkworks")]
pub use arkworks::*;

#[cfg(feature = "bench-dory")]
pub mod bls12_381;

#[cfg(feature = "bench-dory")]
pub mod bls12_377;
