use crate::boojum::field::SmallField;
use crate::zk_evm::aux_structures::{DecommittmentQuery, LogQuery, MemoryQuery};
use crate::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use crate::zkevm_circuits::ecrecover::EcrecoverCircuitInstanceWitness;
use crate::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::linear_hasher::input::LinearHasherCircuitInstanceWitness;
use crate::zkevm_circuits::log_sorter::input::EventsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::sha256_round_function::input::Sha256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;
use circuit_definitions::encodings::memory_query::MemoryQueueState;
use circuit_definitions::encodings::*;
use circuit_definitions::zkevm_circuits::secp256r1_verify::Secp256r1VerifyCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::transient_storage_validity_by_grand_product::input::TransientStorageDeduplicatorInstanceWitness;
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Default)]
pub struct DemuxedQueries {
    pub rollup_storage_queries: Vec<LogQuery>,
    pub porter_storage_queries: Vec<LogQuery>,
    pub event_queries: Vec<LogQuery>,
    pub to_l1_queries: Vec<LogQuery>,
    pub keccak_precompile_queries: Vec<LogQuery>,
    pub sha256_precompile_queries: Vec<LogQuery>,
    pub ecrecover_queries: Vec<LogQuery>,
    pub secp256r1_verify_queries: Vec<LogQuery>,
    pub transient_storage_queries: Vec<LogQuery>,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct MemoryArtifacts<F: SmallField> {
    pub memory_queue_simulator: MemoryQueueSimulator<F>,
    pub vm_memory_query_cycles: Vec<u32>,
    //
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    // all the RAM queue states
    pub all_memory_queue_states: Vec<MemoryQueueState<F>>,
    // decommittment queue
    pub all_prepared_decommittment_queries: Vec<(u32, DecommittmentQuery)>,
    pub all_decommittment_queue_states: Vec<(u32, DecommittmentQueueState<F>)>,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct CircuitArtifacts<F: SmallField> {
    // processed code decommitter circuits, as well as sorting circuit
    pub code_decommitter_circuits_data: Vec<CodeDecommitterCircuitInstanceWitness<F>>,
    pub decommittments_deduplicator_circuits_data:
        Vec<CodeDecommittmentsDeduplicatorInstanceWitness<F>>,
    // IO related circuits
    pub storage_deduplicator_circuit_data: Vec<StorageDeduplicatorInstanceWitness<F>>,
    pub events_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<F>>,
    pub l1_messages_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<F>>,
    pub transient_storage_sorter_circuit_data: Vec<TransientStorageDeduplicatorInstanceWitness<F>>,
    //
    pub keccak256_circuits_data: Vec<Keccak256RoundFunctionCircuitInstanceWitness<F>>,
    //
    pub sha256_circuits_data: Vec<Sha256RoundFunctionCircuitInstanceWitness<F>>,
    //
    pub ecrecover_circuits_data: Vec<EcrecoverCircuitInstanceWitness<F>>,
    //
    pub secp256r1_verify_circuits_data: Vec<Secp256r1VerifyCircuitInstanceWitness<F>>,
    //
    pub l1_messages_linear_hash_data: Vec<LinearHasherCircuitInstanceWitness<F>>,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct LogQueue<F: SmallField> {
    pub states: Vec<LogQueueState<F>>,
    pub simulator: LogQueueSimulator<F>,
}
