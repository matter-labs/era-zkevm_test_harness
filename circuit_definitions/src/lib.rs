#![allow(clippy::drop_ref)]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(associated_type_defaults)]

pub type Field = GoldilocksField;
pub type RoundFunction = Poseidon2Goldilocks;

pub const BASE_LAYER_FRI_LDE_FACTOR: usize = 2;
pub const BASE_LAYER_CAP_SIZE: usize = 16;
pub const SECURITY_BITS_TARGET: usize = 100;

pub const RECURSION_LAYER_FRI_LDE_FACTOR: usize = 2;
pub const RECURSION_LAYER_CAP_SIZE: usize = 16;

pub const L1_SECURITY_BITS: usize = 80;

pub const EIP4844_CYCLE_LIMIT: usize = 4096;

pub use snark_wrapper;
use snark_wrapper::boojum::field::goldilocks::GoldilocksField;

use crate::boojum::cs::implementations::prover::ProofConfig;

pub fn base_layer_proof_config() -> ProofConfig {
    ProofConfig {
        fri_lde_factor: BASE_LAYER_FRI_LDE_FACTOR,
        merkle_tree_cap_size: BASE_LAYER_CAP_SIZE,
        fri_folding_schedule: None,
        security_level: SECURITY_BITS_TARGET,
        pow_bits: 0,
    }
}

pub fn recursion_layer_proof_config() -> ProofConfig {
    ProofConfig {
        fri_lde_factor: RECURSION_LAYER_FRI_LDE_FACTOR,
        merkle_tree_cap_size: RECURSION_LAYER_CAP_SIZE,
        fri_folding_schedule: None,
        security_level: SECURITY_BITS_TARGET,
        pow_bits: 0,
    }
}

pub fn eip4844_proof_config() -> ProofConfig {
    ProofConfig {
        fri_lde_factor: BASE_LAYER_FRI_LDE_FACTOR,
        merkle_tree_cap_size: BASE_LAYER_CAP_SIZE,
        fri_folding_schedule: None,
        security_level: SECURITY_BITS_TARGET,
        pow_bits: 0,
    }
}

pub mod encodings;

use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;
pub use zk_evm::ethereum_types;

pub type ZkSyncDefaultRoundFunction = Poseidon2Goldilocks;

pub use zk_evm;
pub use zkevm_circuits;
pub use zkevm_circuits::boojum;
