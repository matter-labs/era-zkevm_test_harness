use super::*;
use crate::boojum::field::SmallField;
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
use crate::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::linear_hasher::input::LinearHasherCircuitInstanceWitness;
use crate::zkevm_circuits::log_sorter::input::EventsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::ram_permutation::input::RamPermutationCircuitInstanceWitness;
use crate::zkevm_circuits::scheduler::aux::NUM_CIRCUIT_TYPES_TO_SCHEDULE;
use crate::zkevm_circuits::sha256_round_function::input::Sha256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::storage_application::input::StorageApplicationCircuitInstanceWitness;
use crate::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueSimulator;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;
use circuit_definitions::encodings::memory_query::MemoryQueueState;
use circuit_definitions::encodings::recursion_request::*;
use circuit_definitions::encodings::*;
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
    pub sorted_memory_queries_accumulated: Vec<MemoryQuery>,
    // all the RAM queue states
    pub all_memory_queue_states: Vec<MemoryQueueState<F>>,
    pub sorted_memory_queue_states: Vec<MemoryQueueState<F>>,
    // decommittment queue
    pub all_decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
    pub sorted_decommittment_queries: Vec<DecommittmentQuery>,
    pub deduplicated_decommittment_queries: Vec<DecommittmentQuery>,
    pub all_decommittment_queue_states: Vec<(u32, DecommittmentQueueState<F>)>,

    pub deduplicated_decommittment_queue_simulator: DecommittmentQueueSimulator<F>,
    pub deduplicated_decommittment_queue_states: Vec<DecommittmentQueueState<F>>,
    pub deduplicated_decommit_requests_with_data: Vec<(DecommittmentQuery, Vec<U256>)>,
    // log queue
    pub original_log_queue: Vec<(u32, LogQuery)>,
    pub original_log_queue_simulator: LogQueueSimulator<F>,
    pub original_log_queue_states: Vec<(u32, LogQueueState<F>)>,

    // demuxed log queues
    pub demuxed_rollup_storage_queries: Vec<LogQuery>,
    pub demuxed_rollup_storage_queue_states: Vec<LogQueueState<F>>,
    pub demuxed_rollup_storage_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_porter_storage_queries: Vec<LogQuery>,
    pub demuxed_porter_storage_queue_states: Vec<LogQueueState<F>>,
    pub demuxed_porter_storage_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_event_queries: Vec<LogQuery>,
    pub demuxed_events_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_event_queue_states: Vec<LogQueueState<F>>,
    pub demuxed_to_l1_queries: Vec<LogQuery>,
    pub demuxed_to_l1_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_to_l1_queue_states: Vec<LogQueueState<F>>,
    pub demuxed_keccak_precompile_queries: Vec<LogQuery>,
    pub demuxed_keccak_precompile_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_keccak_precompile_queue_states: Vec<LogQueueState<F>>,
    pub demuxed_sha256_precompile_queries: Vec<LogQuery>,
    pub demuxed_sha256_precompile_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_sha256_precompile_queue_states: Vec<LogQueueState<F>>,
    pub demuxed_ecrecover_queries: Vec<LogQuery>,
    pub demuxed_ecrecover_queue_simulator: LogQueueSimulator<F>,
    pub demuxed_ecrecover_queue_states: Vec<LogQueueState<F>>,

    // // sorted and deduplicated log-like queues for ones that support reverts
    // // sorted
    // pub _sorted_rollup_storage_queries: Vec<LogQuery>,
    // pub _sorted_rollup_storage_queue_states: Vec<LogQueueState<F>>,
    // pub _sorted_porter_storage_queries: Vec<LogQuery>,
    // pub _sorted_porter_storage_queue_states: Vec<LogQueueState<F>>,
    // pub _sorted_event_queries: Vec<LogQuery>,
    // pub sorted_event_queue_states: Vec<LogQueueState<F>>,
    // pub _sorted_to_l1_queries: Vec<LogQuery>,
    // pub sorted_to_l1_queue_states: Vec<LogQueueState<F>>,

    // deduplicated
    pub deduplicated_rollup_storage_queries: Vec<LogQuery>,
    pub deduplicated_rollup_storage_queue_states: Vec<LogQueueState<F>>,
    pub deduplicated_rollup_storage_queue_simulator: LogQueueSimulator<F>,
    pub deduplicated_porter_storage_queries: Vec<LogQuery>,
    pub deduplicated_porter_storage_queue_states: Vec<LogQueueState<F>>,
    pub deduplicated_event_queries: Vec<LogQuery>,
    pub deduplicated_event_queue_simulator: LogQueueSimulator<F>,
    pub deduplicated_event_queue_states: Vec<LogQueueState<F>>,
    pub deduplicated_to_l1_queries: Vec<LogQuery>,
    pub deduplicated_to_l1_queue_simulator: LogQueueSimulator<F>,
    pub deduplicated_to_l1_queue_states: Vec<LogQueueState<F>>,

    //
    pub special_initial_decommittment_queries: Vec<(DecommittmentQuery, Vec<U256>)>,

    // keep precompile round functions data
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub keccak_256_memory_queries: Vec<MemoryQuery>,
    pub keccak_256_memory_states: Vec<MemoryQueueState<F>>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub sha256_memory_queries: Vec<MemoryQuery>,
    pub sha256_memory_states: Vec<MemoryQueueState<F>>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub ecrecover_memory_queries: Vec<MemoryQuery>,
    pub ecrecover_memory_states: Vec<MemoryQueueState<F>>,

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
    pub rollup_storage_application_circuit_data: Vec<StorageApplicationCircuitInstanceWitness<F>>,
    //
    pub keccak256_circuits_data: Vec<Keccak256RoundFunctionCircuitInstanceWitness<F>>,
    //
    pub sha256_circuits_data: Vec<Sha256RoundFunctionCircuitInstanceWitness<F>>,
    //
    pub ecrecover_circuits_data: Vec<EcrecoverCircuitInstanceWitness<F>>,
    //
    pub l1_messages_linear_hash_data: Vec<LinearHasherCircuitInstanceWitness<F>>,
}

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::witness::tree::*;
use blake2::Blake2s256;

impl<F: SmallField> FullBlockArtifacts<F> {
    pub fn process<
        R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    >(
        &mut self,
        round_function: &R,
        geometry: &GeometryConfig,
        tree: &mut impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
        num_non_deterministic_heap_queries: usize,
    ) {
        // this is parallelizable internally by the factor of 3 in round function implementation later on

        tracing::debug!("Running memory queue simulation");

        for (cycle, query) in self.vm_memory_queries_accumulated.iter() {
            self.all_memory_queries_accumulated.push(*query);

            let (_old_tail, intermediate_info) = self
                .memory_queue_simulator
                .push_and_output_intermediate_data(*query, round_function);

            self.vm_memory_queue_states
                .push((*cycle, false, intermediate_info));
            self.all_memory_queue_states.push(intermediate_info);
        }

        assert!(
            self.memory_queue_simulator.num_items as usize
                == self.vm_memory_queries_accumulated.len()
        );

        // ----------------------------

        {
            assert_eq!(
                self.all_memory_queries_accumulated.len(),
                self.all_memory_queue_states.len()
            );
            assert_eq!(
                self.all_memory_queries_accumulated.len(),
                self.memory_queue_simulator.num_items as usize
            );
        }

        // ----------------------------

        // direct VM related part is done, other subcircuit's functionality is moved to other functions
        // that should properly do sorts and memory writes

        use crate::witness::individual_circuits::sort_decommit_requests::compute_decommitts_sorter_circuit_snapshots;

        tracing::debug!("Running code decommittments sorter simulation");

        let decommittments_deduplicator_witness = compute_decommitts_sorter_circuit_snapshots(
            self,
            round_function,
            geometry.cycles_code_decommitter_sorter as usize,
        );

        self.decommittments_deduplicator_circuits_data = decommittments_deduplicator_witness;

        use crate::witness::individual_circuits::decommit_code::compute_decommitter_circuit_snapshots;

        tracing::debug!("Running code code decommitter simulation");

        let code_decommitter_circuits_data = compute_decommitter_circuit_snapshots(
            self,
            round_function,
            geometry.cycles_per_code_decommitter as usize,
        );

        self.code_decommitter_circuits_data = code_decommitter_circuits_data;

        // demux log queue
        use crate::witness::individual_circuits::log_demux::compute_logs_demux;

        tracing::debug!("Running log demux simulation");

        let log_demuxer_witness = compute_logs_demux(
            self,
            geometry.cycles_per_log_demuxer as usize,
            round_function,
        );

        self.log_demuxer_circuit_data = log_demuxer_witness;

        // keccak precompile

        use crate::witness::individual_circuits::keccak256_round_function::keccak256_decompose_into_per_circuit_witness;

        tracing::debug!("Running keccak simulation");

        let keccak256_circuits_data = keccak256_decompose_into_per_circuit_witness(
            self,
            geometry.cycles_per_keccak256_circuit as usize,
            round_function,
        );
        self.keccak256_circuits_data = keccak256_circuits_data;

        // sha256 precompile

        use crate::witness::individual_circuits::sha256_round_function::sha256_decompose_into_per_circuit_witness;

        tracing::debug!("Running sha256 simulation");

        let sha256_circuits_data = sha256_decompose_into_per_circuit_witness(
            self,
            geometry.cycles_per_sha256_circuit as usize,
            round_function,
        );
        self.sha256_circuits_data = sha256_circuits_data;

        // ecrecover precompile

        use crate::witness::individual_circuits::ecrecover::ecrecover_decompose_into_per_circuit_witness;

        tracing::debug!("Running ecrecover simulation");

        let ecrecover_circuits_data = ecrecover_decompose_into_per_circuit_witness(
            self,
            geometry.cycles_per_ecrecover_circuit as usize,
            round_function,
        );
        self.ecrecover_circuits_data = ecrecover_circuits_data;

        // we are done with a memory and can do the processing and breaking of the logical arguments into individual circits

        use crate::witness::individual_circuits::ram_permutation::compute_ram_circuit_snapshots;

        tracing::debug!("Running RAM permutation simulation");

        let ram_permutation_circuits_data = compute_ram_circuit_snapshots(
            self,
            round_function,
            num_non_deterministic_heap_queries,
            geometry.cycles_per_ram_permutation as usize,
        );

        self.ram_permutation_circuits_data = ram_permutation_circuits_data;

        // now completely parallel process to reconstruct the states, with internally parallelism in each round function

        use crate::witness::individual_circuits::storage_sort_dedup::compute_storage_dedup_and_sort;

        tracing::debug!("Running storage deduplication simulation");

        let storage_deduplicator_circuit_data = compute_storage_dedup_and_sort(
            self,
            geometry.cycles_per_storage_sorter as usize,
            round_function,
        );
        self.storage_deduplicator_circuit_data = storage_deduplicator_circuit_data;

        use crate::witness::individual_circuits::events_sort_dedup::compute_events_dedup_and_sort;

        tracing::debug!("Running events deduplication simulation");

        let events_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &self.demuxed_event_queries,
            &mut self.deduplicated_event_queries,
            &self.demuxed_events_queue_simulator,
            &self.demuxed_event_queue_states,
            &mut self.deduplicated_event_queue_simulator,
            geometry.cycles_per_events_or_l1_messages_sorter as usize,
            round_function,
        );

        self.events_deduplicator_circuit_data = events_deduplicator_circuit_data;

        tracing::debug!("Running L1 messages deduplication simulation");

        let l1_messages_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &self.demuxed_to_l1_queries,
            &mut self.deduplicated_to_l1_queries,
            &self.demuxed_to_l1_queue_simulator,
            &self.demuxed_to_l1_queue_states,
            &mut self.deduplicated_to_l1_queue_simulator,
            geometry.cycles_per_events_or_l1_messages_sorter as usize,
            round_function,
        );

        self.l1_messages_deduplicator_circuit_data = l1_messages_deduplicator_circuit_data;

        // compute flattened hash of all messages

        tracing::debug!("Running L1 messages linear hash simulation");

        assert!(
            self.deduplicated_to_l1_queue_simulator.num_items
                <= geometry.limit_for_l1_messages_pudata_hasher,
            "too many L1 messages to linearly hash by single circuit"
        );

        use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_linear_keccak256;

        let l1_messages_pubdata_hasher_data = compute_linear_keccak256(
            &self.deduplicated_to_l1_queue_simulator,
            geometry.limit_for_l1_messages_pudata_hasher as usize,
            round_function,
        );

        self.l1_messages_linear_hash_data = l1_messages_pubdata_hasher_data;

        // process the storage application

        // and do the actual storage application
        use crate::witness::individual_circuits::storage_application::decompose_into_storage_application_witnesses;

        let rollup_storage_application_circuit_data = decompose_into_storage_application_witnesses(
            self,
            tree,
            round_function,
            geometry.cycles_per_storage_application as usize,
        );

        self.rollup_storage_application_circuit_data = rollup_storage_application_circuit_data;

        self.is_processed = true;
    }
}

use crate::boojum::gadgets::traits::allocatable::*;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone)]
#[serde(bound = "")]
pub struct BlockBasicCircuits<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>
where [(); <zkevm_circuits::base_structures::log_query::LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::memory_query::MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::decommit_query::DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    // main VM circuit. Many of them
    pub main_vm_circuits: Vec<VMMainCircuit<F, VmWitnessOracle<F>, R>>,
    // code decommittments sorters
    pub code_decommittments_sorter_circuits: Vec<CodeDecommittsSorterCircuit<F, R>>,
    // few code decommitters: code hash -> memory
    pub code_decommitter_circuits: Vec<CodeDecommitterCircuit<F, R>>,
    // demux logs to get precompiles for RAM too
    pub log_demux_circuits: Vec<LogDemuxerCircuit<F, R>>,
    // process precompiles
    // keccak
    pub keccak_precompile_circuits: Vec<Keccak256RoundFunctionCircuit<F, R>>,
    // sha256
    pub sha256_precompile_circuits: Vec<Sha256RoundFunctionCircuit<F, R>>,
    // ecrecover
    pub ecrecover_precompile_circuits: Vec<ECRecoverFunctionCircuit<F, R>>,
    // when it's all done we prove the memory validity and finish with it
    pub ram_permutation_circuits: Vec<RAMPermutationCircuit<F, R>>,
    // sort storage changes
    pub storage_sorter_circuits: Vec<StorageSorterCircuit<F, R>>,
    // apply them
    pub storage_application_circuits: Vec<StorageApplicationCircuit<F, R>>,
    // sort and dedup events
    pub events_sorter_circuits: Vec<EventsSorterCircuit<F, R>>,
    // sort and dedup L1 messages
    pub l1_messages_sorter_circuits: Vec<L1MessagesSorterCircuit<F, R>>,
    // hash l1 messages into pubdata
    pub l1_messages_hasher_circuits: Vec<L1MessagesHasherCircuit<F, R>>,
}

impl<
F: SmallField,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> BlockBasicCircuits<F, R>
where [(); <zkevm_circuits::base_structures::log_query::LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::memory_query::MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::base_structures::decommit_query::DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <boojum::gadgets::u256::UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    pub fn into_flattened_set(self) -> Vec<ZkSyncBaseLayerCircuit<F, VmWitnessOracle<F>, R>> {
        let BlockBasicCircuits {
            main_vm_circuits,
            code_decommittments_sorter_circuits,
            code_decommitter_circuits,
            log_demux_circuits,
            keccak_precompile_circuits,
            sha256_precompile_circuits,
            ecrecover_precompile_circuits,
            ram_permutation_circuits,
            storage_sorter_circuits,
            storage_application_circuits,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_hasher_circuits,
        } = self;

        let mut result = vec![];
        result.extend(main_vm_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::MainVM(el)));

        result.extend(code_decommittments_sorter_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(el)));

        result.extend(code_decommitter_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::CodeDecommitter(el)));

        result.extend(log_demux_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::LogDemuxer(el)));

        result.extend(keccak_precompile_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::KeccakRoundFunction(el)));
        result.extend(sha256_precompile_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::Sha256RoundFunction(el)));
        result.extend(ecrecover_precompile_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::ECRecover(el)));

        result.extend(ram_permutation_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::RAMPermutation(el)));

        result.extend(storage_sorter_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::StorageSorter(el)));

        result.extend(storage_application_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::StorageApplication(el)));

        result.extend(events_sorter_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::EventsSorter(el)));

        result.extend(l1_messages_sorter_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::L1MessagesSorter(el)));

        result.extend(l1_messages_hasher_circuits.into_iter().map(|el| ZkSyncBaseLayerCircuit::L1MessagesHasher(el)));

        result
    }
}

use crate::zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone)]
#[serde(bound = "")]
pub struct BlockBasicCircuitsPublicInputs<F: SmallField> {
    // main VM circuit. Many of them
    pub main_vm_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // code decommittments sorter
    pub code_decommittments_sorter_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // few code decommitters: code hash -> memory
    pub code_decommitter_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // demux logs to get precompiles for RAM too
    pub log_demux_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // process precompiles
    // keccak
    pub keccak_precompile_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // sha256
    pub sha256_precompile_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // ecrecover
    pub ecrecover_precompile_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // when it's all done we prove the memory validity and finish with it
    pub ram_permutation_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // sort storage changes
    pub storage_sorter_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // apply them
    pub storage_application_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // sort and dedup events
    pub events_sorter_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // sort and dedup L1 messages
    pub l1_messages_sorter_circuits: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
    // hash l1 messages into pubdata
    pub l1_messages_hasher_circuits_inputs: Vec<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
}

impl<F: SmallField> BlockBasicCircuitsPublicInputs<F> {
    pub fn into_flattened_set(self) -> Vec<ZkSyncBaseLayerCircuitInput<F>> {
        let BlockBasicCircuitsPublicInputs {
            main_vm_circuits,
            code_decommittments_sorter_circuits,
            code_decommitter_circuits,
            log_demux_circuits,
            keccak_precompile_circuits,
            sha256_precompile_circuits,
            ecrecover_precompile_circuits,
            ram_permutation_circuits,
            storage_sorter_circuits,
            storage_application_circuits,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_hasher_circuits_inputs,
        } = self;

        let mut result = vec![];
        result.extend(
            main_vm_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::MainVM(el)),
        );

        result.extend(
            code_decommittments_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::CodeDecommittmentsSorter(el)),
        );

        result.extend(
            code_decommitter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::CodeDecommitter(el)),
        );

        result.extend(
            log_demux_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::LogDemuxer(el)),
        );

        result.extend(
            keccak_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::KeccakRoundFunction(el)),
        );
        result.extend(
            sha256_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::Sha256RoundFunction(el)),
        );
        result.extend(
            ecrecover_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::ECRecover(el)),
        );

        result.extend(
            ram_permutation_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::RAMPermutation(el)),
        );

        result.extend(
            storage_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::StorageSorter(el)),
        );

        result.extend(
            storage_application_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::StorageApplication(el)),
        );

        result.extend(
            events_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::EventsSorter(el)),
        );
        result.extend(
            l1_messages_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::L1MessagesSorter(el)),
        );

        result.extend(
            l1_messages_hasher_circuits_inputs
                .into_iter()
                .map(|el| ZkSyncBaseLayerCircuitInput::L1MessagesHasher(el)),
        );

        result
    }

    pub fn into_recursion_queues<
        R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    >(
        self,
        closed_forms_wits: BlockBasicCircuitsPublicCompactFormsWitnesses<F>,
        round_function: &R,
    ) -> [(
        u64,
        RecursionQueueSimulator<F>,
        Vec<ZkSyncBaseLayerClosedFormInput<F>>,
    ); NUM_CIRCUIT_TYPES_TO_SCHEDULE] {
        let mut simulators =
            vec![(0u64, RecursionQueueSimulator::empty(), vec![]); NUM_CIRCUIT_TYPES_TO_SCHEDULE];
        let flattened_set = self.into_flattened_set();
        let wits_set = closed_forms_wits.into_flattened_set();
        assert_eq!(flattened_set.len(), wits_set.len());

        for (el, inp) in flattened_set.into_iter().zip(wits_set.into_iter()) {
            let circuit_number = el.numeric_circuit_type();
            assert_eq!(circuit_number, inp.numeric_circuit_type());
            let idx = (circuit_number as usize) - 1;
            let (id, dst_queue, dst_for_inputs) = &mut simulators[idx];
            if *id != 0 {
                assert_eq!(*id, circuit_number as u64);
            } else {
                *id = circuit_number as u64;
            }

            let recursive_request = RecursionRequest {
                circuit_type: F::from_u64_unchecked(circuit_number as u64),
                public_input: el.into_inner(),
            };

            let _ = dst_queue.push(recursive_request, round_function);

            dst_for_inputs.push(inp);
        }

        simulators.try_into().expect("length must match")
    }
}

use crate::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone)]
#[serde(bound = "")]
pub struct BlockBasicCircuitsPublicCompactFormsWitnesses<F: SmallField> {
    // main VM circuit. Many of them
    pub main_vm_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // code decommittments sorter
    pub code_decommittments_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // few code decommitters: code hash -> memory
    pub code_decommitter_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // demux logs to get precompiles for RAM too
    pub log_demux_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // process precompiles
    // keccak
    pub keccak_precompile_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // sha256
    pub sha256_precompile_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // ecrecover
    pub ecrecover_precompile_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // when it's all done we prove the memory validity and finish with it
    pub ram_permutation_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // sort storage changes
    pub storage_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // apply them
    pub storage_application_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // sort and dedup events
    pub events_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // sort and dedup L1 messages
    pub l1_messages_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<F>>,
    // hash l1 messages into pubdata
    pub l1_messages_hasher_circuits_compact_forms_witnesses:
        Vec<ClosedFormInputCompactFormWitness<F>>,
}

impl<F: SmallField> BlockBasicCircuitsPublicCompactFormsWitnesses<F> {
    pub fn into_flattened_set(self) -> Vec<ZkSyncBaseLayerClosedFormInput<F>> {
        let BlockBasicCircuitsPublicCompactFormsWitnesses {
            main_vm_circuits,
            code_decommittments_sorter_circuits,
            code_decommitter_circuits,
            log_demux_circuits,
            keccak_precompile_circuits,
            sha256_precompile_circuits,
            ecrecover_precompile_circuits,
            ram_permutation_circuits,
            storage_sorter_circuits,
            storage_application_circuits,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_hasher_circuits_compact_forms_witnesses,
        } = self;

        let mut result = vec![];
        result.extend(
            main_vm_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::MainVM(el)),
        );

        result.extend(
            code_decommittments_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::CodeDecommittmentsSorter(el)),
        );

        result.extend(
            code_decommitter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::CodeDecommitter(el)),
        );

        result.extend(
            log_demux_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::LogDemuxer(el)),
        );

        result.extend(
            keccak_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::KeccakRoundFunction(el)),
        );
        result.extend(
            sha256_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::Sha256RoundFunction(el)),
        );
        result.extend(
            ecrecover_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::ECRecover(el)),
        );

        result.extend(
            ram_permutation_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::RAMPermutation(el)),
        );

        result.extend(
            storage_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::StorageSorter(el)),
        );

        result.extend(
            storage_application_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::StorageApplication(el)),
        );

        result.extend(
            events_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::EventsSorter(el)),
        );
        result.extend(
            l1_messages_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::L1MessagesSorter(el)),
        );

        result.extend(
            l1_messages_hasher_circuits_compact_forms_witnesses
                .into_iter()
                .map(|el| ZkSyncBaseLayerClosedFormInput::L1MessagesHasher(el)),
        );

        result
    }
}
