use super::oracle::*;
use super::*;
use crate::witness::utils::*;

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::queue::CircuitQueueRawWitness;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::boojum::gadgets::traits::round_function::*;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::zkevm_circuits::base_structures::precompile_input_outputs::*;
use crate::zkevm_circuits::base_structures::vm_state::{
    FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH,
};
use crate::zkevm_circuits::fsm_input_output::*;
use crate::zkevm_circuits::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;
use std::collections::VecDeque;

pub mod data_hasher_and_merklizer;
pub mod decommit_code;
pub mod ecrecover;
pub mod events_sort_dedup;
pub mod keccak256_round_function;
pub mod log_demux;
pub mod ram_permutation;
pub mod sha256_round_function;
pub mod sort_decommit_requests;
pub mod storage_application;
pub mod storage_sort_dedup;

// use std::collections::VecDeque;
