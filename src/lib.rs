#![recursion_limit = "32"]

#![feature(const_eval_limit)]
#![const_eval_limit = "100000000"]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(generic_const_exprs)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(return_position_impl_trait_in_trait)]

#![allow(unused_imports)]
#![allow(clippy::drop_ref)]

use boojum::field::goldilocks::GoldilocksField;
use boojum::implementations::poseidon2::Poseidon2Goldilocks;

pub use zk_evm::blake2;
pub use zk_evm::sha2;
pub use zk_evm::sha3;

pub mod data_source;
pub mod entry_point;
pub mod utils;
pub mod witness;
pub mod geometry_config;
pub mod prover_utils;

pub use zk_evm::ethereum_types;

use self::utils::*;

pub mod external_calls;
pub mod toolset;
pub mod capacity_estimator;
pub mod compute_setups;
// pub mod circuit_limit_estimator;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

pub type ZkSyncDefaultRoundFunction = Poseidon2Goldilocks;

// #[cfg(test)]
pub(crate) mod tests;
