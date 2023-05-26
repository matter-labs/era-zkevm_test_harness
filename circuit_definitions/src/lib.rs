#![recursion_limit = "16"]

#![feature(const_eval_limit)]
#![const_eval_limit = "100000000"]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(generic_const_exprs)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(return_position_impl_trait_in_trait)]

#![allow(clippy::drop_ref)]

pub mod circuit_definitions;
pub mod aux_definitions;
pub mod encodings;

pub use zk_evm::ethereum_types;
use boojum::implementations::poseidon2::Poseidon2Goldilocks;

pub type ZkSyncDefaultRoundFunction = Poseidon2Goldilocks;