#![recursion_limit = "32"]
#![allow(dropping_references)]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(generic_const_exprs)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(return_position_impl_trait_in_trait)]
#![allow(unused_imports)]
#![allow(clippy::drop_ref)]

use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;

pub use circuit_definitions::boojum;
pub use circuit_definitions::zk_evm;
pub use circuit_definitions::zkevm_circuits;

pub use circuit_definitions::snark_wrapper;
pub use rescue_poseidon::franklin_crypto;
pub use snark_wrapper::rescue_poseidon;

pub use crate::zk_evm::blake2;
pub use crate::zk_evm::sha2;
pub use crate::zk_evm::sha3;

pub mod data_source;
pub mod entry_point;
pub mod geometry_config;
pub mod proof_compression;
pub mod prover_utils;
pub mod snark_wrapper_test;
pub mod utils;
pub mod witness;

pub use crate::zk_evm::ethereum_types;

use self::utils::*;

pub mod capacity_estimator;
pub mod compute_setups;
pub mod external_calls;
pub mod toolset;
// pub mod circuit_limit_estimator;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

// #[cfg(test)]
pub mod helper;
pub mod proof_wrapper_utils;
pub(crate) mod tests;
