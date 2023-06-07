#![allow(clippy::drop_ref)]

#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(generic_const_exprs)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]
#![feature(return_position_impl_trait_in_trait)]


pub mod aux_definitions;
pub mod circuit_definitions;
pub mod encodings;

use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;
pub use zk_evm::ethereum_types;

pub type ZkSyncDefaultRoundFunction = Poseidon2Goldilocks;

pub use zk_evm;
pub use zkevm_circuits;
pub use zkevm_circuits::boojum;
