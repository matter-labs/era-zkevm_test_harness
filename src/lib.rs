#![recursion_limit = "32"]
#![allow(dropping_references)]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(generic_const_exprs)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(return_position_impl_trait_in_trait)]
#![feature(allocator_api)]
#![allow(unused_imports)]
#![allow(clippy::drop_ref)]

use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;

use circuit_definitions::boojum;
use circuit_definitions::zk_evm;
use circuit_definitions::zkevm_circuits;

use circuit_definitions::snark_wrapper;
use rescue_poseidon::franklin_crypto;
use snark_wrapper::rescue_poseidon;

use crate::zk_evm::blake2;
use crate::zk_evm::sha2;
use crate::zk_evm::sha3;

//mod data_source;
//mod entry_point;

mod geometry_config;
pub use geometry_config::get_geometry_config;

//pub mod proof_compression;
//pub mod prover_utils;
//pub mod snark_wrapper_test;
//pub mod utils;

mod witness;

pub use toolset::GeometryConfig;
pub use witness::sort_storage_access::sort_storage_access_queries;
pub use witness::utils::events_queue_commitment_fixed;
pub use witness::utils::initial_heap_content_commitment;
pub use witness::utils::initial_heap_content_commitment_fixed;

pub use crate::zk_evm::ethereum_types;
mod utils;

//use self::utils::*;

//pub mod capacity_estimator;
//pub mod compute_setups;
//pub mod external_calls;

mod toolset;
// pub mod circuit_limit_estimator;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

// #[cfg(test)]
//pub mod helper;
//pub mod proof_wrapper_utils;
//pub(crate) mod tests;
