use super::*;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::traits::allocatable::*;
use crate::boojum::gadgets::traits::round_function::*;
use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::aux_structures::MemoryIndex;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;
use crate::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use crate::zkevm_circuits::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;
use crate::zkevm_circuits::ecrecover::EcrecoverCircuitInstanceWitness;
use crate::zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::linear_hasher::input::LinearHasherCircuitInstanceWitness;
use crate::zkevm_circuits::log_sorter::input::EventsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::ram_permutation::input::RamPermutationCircuitInstanceWitness;
use crate::zkevm_circuits::scheduler::aux::NUM_CIRCUIT_TYPES_TO_SCHEDULE;
use crate::zkevm_circuits::sha256_round_function::input::Sha256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::storage_application::input::StorageApplicationCircuitInstanceWitness;
use crate::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueSimulator;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;
use circuit_definitions::encodings::memory_query::MemoryQueueState;
use circuit_definitions::encodings::recursion_request::*;
use circuit_definitions::encodings::*;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use derivative::Derivative;
use rayon::slice::ParallelSliceMut;
use std::cmp::Ordering;
use tracing;

#[derive(Derivative)]
#[derivative(Clone, Default(bound = ""))]
pub struct FullBlockArtifacts<F: SmallField> {
    pub is_processed: bool,
    pub memory_queue_simulator: MemoryQueueSimulator<F>,

    // all the RAM (without accumulation into the queue)
    pub vm_memory_queries_accumulated: Vec<(u32, MemoryQuery)>,
    pub vm_memory_queue_states: Vec<(u32, bool, MemoryQueueState<F>)>,
    //
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    // all the RAM queue states
    pub all_memory_queue_states: Vec<MemoryQueueState<F>>,
    // decommittment queue
    pub all_decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
    pub all_decommittment_queue_states: Vec<(u32, DecommittmentQueueState<F>)>,

    // log queue
    pub original_log_queue_simulator: LogQueueSimulator<F>,
    pub original_log_queue_states: Vec<(u32, LogQueueState<F>)>,

    // demuxed log queues
    pub demuxed_rollup_storage_queries: Vec<LogQuery>,
    pub demuxed_event_queries: Vec<LogQuery>,
    pub demuxed_to_l1_queries: Vec<LogQuery>,
    pub demuxed_keccak_precompile_queries: Vec<LogQuery>,
    pub demuxed_sha256_precompile_queries: Vec<LogQuery>,
    pub demuxed_ecrecover_queries: Vec<LogQuery>,

    // deduplicated
    pub deduplicated_rollup_storage_queries: Vec<LogQuery>,
    pub deduplicated_rollup_storage_queue_simulator: LogQueueSimulator<F>,
    pub deduplicated_to_l1_queue_simulator: LogQueueSimulator<F>,

    // keep precompile round functions data
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,

    // processed RAM circuit information
    pub ram_permutation_circuits_data: Vec<RamPermutationCircuitInstanceWitness<F>>,
    // processed code decommitter circuits, as well as sorting circuit
    pub code_decommitter_circuits_data: Vec<CodeDecommitterCircuitInstanceWitness<F>>,
    pub decommittments_deduplicator_circuits_data:
        Vec<CodeDecommittmentsDeduplicatorInstanceWitness<F>>,
    //
    pub log_demuxer_circuit_data: Vec<LogDemuxerCircuitInstanceWitness<F>>,
    // IO related circuits
    pub storage_deduplicator_circuit_data: Vec<StorageDeduplicatorInstanceWitness<F>>,
    pub events_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<F>>,
    pub l1_messages_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<F>>,
    //
    pub keccak256_circuits_data: Vec<Keccak256RoundFunctionCircuitInstanceWitness<F>>,
    //
    pub sha256_circuits_data: Vec<Sha256RoundFunctionCircuitInstanceWitness<F>>,
    //
    pub ecrecover_circuits_data: Vec<EcrecoverCircuitInstanceWitness<F>>,
    //
    pub l1_messages_linear_hash_data: Vec<LinearHasherCircuitInstanceWitness<F>>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct LogQueue<F: SmallField> {
    pub states: Vec<LogQueueState<F>>,
    pub simulator: LogQueueSimulator<F>,
}
