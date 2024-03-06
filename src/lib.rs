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
//#![allow(unused_imports)]
#![allow(clippy::drop_ref)]

use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;

use circuit_definitions::boojum;
use circuit_definitions::zk_evm;
use circuit_definitions::zkevm_circuits;

mod geometry_config;
mod toolset;
mod utils;
mod witness;

pub use geometry_config::get_geometry_config;

pub use toolset::GeometryConfig;
pub use witness::sort_storage_access::sort_storage_access_queries;
pub use witness::utils::events_queue_commitment_fixed;
pub use witness::utils::initial_heap_content_commitment;
pub use witness::utils::initial_heap_content_commitment_fixed;

pub use crate::zk_evm::ethereum_types;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;
