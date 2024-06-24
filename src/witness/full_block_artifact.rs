use crate::boojum::field::SmallField;
use crate::ethereum_types::U256;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::LogQuery;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;
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
use crate::zk_evm::zk_evm_abstractions::precompiles::ecadd::ECAddRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecmul::ECMulRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecpairing::ECPairingRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::modexp::ModexpRoundWitness;
use crate::zkevm_circuits::bn254::ec_add::input::EcAddCircuitInstanceWitness;
use crate::zkevm_circuits::bn254::ec_mul::input::EcMulCircuitInstanceWitness;
use crate::zkevm_circuits::bn254::ec_pairing::input::EcPairingCircuitInstanceWitness;
use crate::zkevm_circuits::modexp::input::ModexpCircuitInstanceWitness;

#[derive(Derivative)]
#[derivative(Clone, Default(bound = ""))]
pub struct FullBlockArtifacts<F: SmallField> {
    pub is_processed: bool,
    pub memory_queue_simulator: MemoryQueueSimulator<F>,
    //
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    // all the RAM queue states
    pub all_memory_queue_states: Vec<MemoryQueueState<F>>,
    // decommittment queue
    pub all_prepared_decommittment_queries: Vec<(u32, DecommittmentQuery)>,
    pub all_executed_decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
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
    pub demuxed_ecadd_queries: Vec<LogQuery>,
    pub demuxed_ecmul_queries: Vec<LogQuery>,
    pub demuxed_ecpairing_queries: Vec<LogQuery>,
    pub demuxed_modexp_queries: Vec<LogQuery>,
    pub demuxed_transient_storage_queries: Vec<LogQuery>,
    pub demuxed_secp256r1_verify_queries: Vec<LogQuery>,

    // deduplicated
    pub deduplicated_rollup_storage_queries: Vec<LogQuery>,
    pub deduplicated_rollup_storage_queue_simulator: LogQueueSimulator<F>,
    pub deduplicated_to_l1_queue_simulator: LogQueueSimulator<F>,

    // keep precompile round functions data
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,
    pub secp256r1_verify_witnesses: Vec<(u32, LogQuery, Secp256r1VerifyRoundWitness)>,
    pub ecadd_witnesses: Vec<(u32, LogQuery, ECAddRoundWitness)>,
    pub ecmul_witnesses: Vec<(u32, LogQuery, ECMulRoundWitness)>,
    pub ecpairing_witnesses: Vec<(u32, LogQuery, Vec<ECPairingRoundWitness>)>,
    pub modexp_witnesses: Vec<(u32, LogQuery, ModexpRoundWitness)>,

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
    pub ecadd_circuits_data: Vec<EcAddCircuitInstanceWitness<F>>,
    //
    pub ecmul_circuits_data: Vec<EcMulCircuitInstanceWitness<F>>,
    //
    pub ecpairing_circuits_data: Vec<EcPairingCircuitInstanceWitness<F>>,
    //
    pub modexp_circuits_data: Vec<ModexpCircuitInstanceWitness<F>>,
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
