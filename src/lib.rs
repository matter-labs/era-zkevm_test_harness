#![recursion_limit = "32"]
#![allow(dropping_references)]
#![feature(allocator_api)]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(bigint_helper_methods)]
#![allow(clippy::drop_ref)]

use crate::boojum::field::goldilocks::GoldilocksField;

pub use circuit_definitions::boojum;
pub use circuit_definitions::zk_evm;
pub use circuit_definitions::zkevm_circuits;

pub use circuit_definitions::snark_wrapper;
pub use rescue_poseidon::franklin_crypto;
pub use snark_wrapper::rescue_poseidon;

pub use crate::zk_evm::blake2;
pub use crate::zk_evm::sha2;
pub use crate::zk_evm::sha3;

mod geometry_config;
mod utils;
mod witness;

use crate::zk_evm::ethereum_types;

pub mod toolset;

pub use geometry_config::get_geometry_config;
pub use toolset::GeometryConfig;
pub use witness::sort_storage_access::sort_storage_access_queries;

pub use witness::utils::{events_queue_commitment_fixed, initial_heap_content_commitment_fixed};
pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;
