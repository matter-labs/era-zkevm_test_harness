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

    //
    pub special_initial_decommittment_queries: Vec<(DecommittmentQuery, Vec<U256>)>,

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

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct LogQueue<F: SmallField> {
    pub states: Vec<LogQueueState<F>>,
    pub simulator: LogQueueSimulator<F>,
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

        let mut deduplicated_decommitment_queue_simulator = Default::default();
        let mut deduplicated_decommittment_queue_states = Default::default();
        let mut deduplicated_decommit_requests_with_data = Default::default();

        let decommittments_deduplicator_witness = compute_decommitts_sorter_circuit_snapshots(
            self,
            &mut deduplicated_decommitment_queue_simulator,
            &mut deduplicated_decommittment_queue_states,
            &mut deduplicated_decommit_requests_with_data,
            round_function,
            geometry.cycles_code_decommitter_sorter as usize,
        );

        self.decommittments_deduplicator_circuits_data = decommittments_deduplicator_witness;

        use crate::witness::individual_circuits::decommit_code::compute_decommitter_circuit_snapshots;

        tracing::debug!("Running code code decommitter simulation");

        let code_decommitter_circuits_data = compute_decommitter_circuit_snapshots(
            self,
            &mut deduplicated_decommitment_queue_simulator,
            &mut deduplicated_decommittment_queue_states,
            &mut deduplicated_decommit_requests_with_data,
            round_function,
            geometry.cycles_per_code_decommitter as usize,
        );

        self.code_decommitter_circuits_data = code_decommitter_circuits_data;

        // demux log queue
        use crate::witness::individual_circuits::log_demux::compute_logs_demux;

        tracing::debug!("Running log demux simulation");

        let (
            log_demuxer_witness,
            demuxed_rollup_storage_queue,
            demuxed_event_queue,
            demuxed_to_l1_queue,
            demuxed_keccak_precompile_queue,
            demuxed_sha256_precompile_queue,
            demuxed_ecrecover_queue,
        ) = compute_logs_demux(
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
            demuxed_keccak_precompile_queue,
            geometry.cycles_per_keccak256_circuit as usize,
            round_function,
        );
        self.keccak256_circuits_data = keccak256_circuits_data;

        // sha256 precompile

        use crate::witness::individual_circuits::sha256_round_function::sha256_decompose_into_per_circuit_witness;

        tracing::debug!("Running sha256 simulation");

        let sha256_circuits_data = sha256_decompose_into_per_circuit_witness(
            self,
            demuxed_sha256_precompile_queue,
            geometry.cycles_per_sha256_circuit as usize,
            round_function,
        );
        self.sha256_circuits_data = sha256_circuits_data;

        // ecrecover precompile

        use crate::witness::individual_circuits::ecrecover::ecrecover_decompose_into_per_circuit_witness;

        tracing::debug!("Running ecrecover simulation");

        let ecrecover_circuits_data = ecrecover_decompose_into_per_circuit_witness(
            self,
            demuxed_ecrecover_queue,
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
            demuxed_rollup_storage_queue,
            geometry.cycles_per_storage_sorter as usize,
            round_function,
        );
        self.storage_deduplicator_circuit_data = storage_deduplicator_circuit_data;

        use crate::witness::individual_circuits::events_sort_dedup::compute_events_dedup_and_sort;

        tracing::debug!("Running events deduplication simulation");

        let events_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &self.demuxed_event_queries,
            &demuxed_event_queue,
            &mut Default::default(),
            geometry.cycles_per_events_or_l1_messages_sorter as usize,
            round_function,
        );

        self.events_deduplicator_circuit_data = events_deduplicator_circuit_data;

        tracing::debug!("Running L1 messages deduplication simulation");

        let mut deduplicated_to_l1_queue_simulator = Default::default();
        let l1_messages_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &self.demuxed_to_l1_queries,
            &demuxed_to_l1_queue,
            &mut deduplicated_to_l1_queue_simulator,
            geometry.cycles_per_events_or_l1_messages_sorter as usize,
            round_function,
        );

        self.l1_messages_deduplicator_circuit_data = l1_messages_deduplicator_circuit_data;

        // compute flattened hash of all messages

        tracing::debug!("Running L1 messages linear hash simulation");

        assert!(
            deduplicated_to_l1_queue_simulator.num_items
                <= geometry.limit_for_l1_messages_pudata_hasher,
            "too many L1 messages to linearly hash by single circuit"
        );

        use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_linear_keccak256;

        let l1_messages_pubdata_hasher_data = compute_linear_keccak256(
            &deduplicated_to_l1_queue_simulator,
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
    pub fn into_flat_iterator(self) -> impl Iterator<Item = ZkSyncBaseLayerClosedFormInput<F>> {
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

        main_vm_circuits
            .into_iter()
            .map(|el| ZkSyncBaseLayerClosedFormInput::MainVM(el))
            .chain(
                code_decommittments_sorter_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::CodeDecommittmentsSorter(el)),
            )
            .chain(
                code_decommitter_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::CodeDecommitter(el)),
            )
            .chain(
                log_demux_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::LogDemuxer(el)),
            )
            .chain(
                keccak_precompile_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::KeccakRoundFunction(el)),
            )
            .chain(
                sha256_precompile_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::Sha256RoundFunction(el)),
            )
            .chain(
                ecrecover_precompile_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::ECRecover(el)),
            )
            .chain(
                ram_permutation_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::RAMPermutation(el)),
            )
            .chain(
                storage_sorter_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::StorageSorter(el)),
            )
            .chain(
                storage_application_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::StorageApplication(el)),
            )
            .chain(
                events_sorter_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::EventsSorter(el)),
            )
            .chain(
                l1_messages_sorter_circuits
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::L1MessagesSorter(el)),
            )
            .chain(
                l1_messages_hasher_circuits_compact_forms_witnesses
                    .into_iter()
                    .map(|el| ZkSyncBaseLayerClosedFormInput::L1MessagesHasher(el)),
            )
    }
}
