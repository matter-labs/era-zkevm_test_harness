use super::*;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use crate::encodings::decommittment_request::DecommittmentQueueState;
use crate::encodings::initial_storage_write::CircuitEquivalentReflection;
use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::log_query::LogQueueState;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::encodings::memory_query::MemoryQueueState;
use crate::ethereum_types::U256;
use crate::pairing::Engine;
use crate::toolset::GeometryConfig;
use derivative::Derivative;
use rayon::slice::ParallelSliceMut;
use std::cmp::Ordering;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use sync_vm::glue::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;
use sync_vm::glue::ecrecover_circuit::input::EcrecoverCircuitInstanceWitness;
use sync_vm::glue::keccak256_round_function_circuit::input::Keccak256RoundFunctionInstanceWitness;
use sync_vm::glue::log_sorter::input::EventsDeduplicatorInstanceWitness;
use sync_vm::glue::merkleize_l1_messages::input::MessagesMerklizerInstanceWitness;
use sync_vm::glue::pubdata_hasher::input::PubdataHasherInstanceWitness;
use sync_vm::glue::pubdata_hasher::storage_write_data::InitialStorageWriteData;
use sync_vm::glue::pubdata_hasher::storage_write_data::RepeatedStorageWriteData;
use sync_vm::glue::ram_permutation::RamPermutationCircuitInstanceWitness;
use sync_vm::glue::sha256_round_function_circuit::input::Sha256RoundFunctionCircuitInstanceWitness;
use sync_vm::glue::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use sync_vm::glue::storage_application::input::StorageApplicationCircuitInstanceWitness;
use sync_vm::glue::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use sync_vm::inputs::ClosedFormInputCompactForm;
use sync_vm::scheduler::data_access_functions::StorageLogRecord;
use tracing;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::LogQuery;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;

#[derive(Derivative)]
#[derivative(Clone, Default(bound = ""))]
pub struct FullBlockArtifacts<E: Engine> {
    pub is_processed: bool,
    pub memory_queue_simulator: MemoryQueueSimulator<E>,

    // all the RAM (without accumulation into the queue)
    pub vm_memory_queries_accumulated: Vec<(u32, MemoryQuery)>,
    pub vm_memory_queue_states: Vec<(u32, bool, MemoryQueueState<E>)>,
    //
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    pub sorted_memory_queries_accumulated: Vec<MemoryQuery>,
    // all the RAM queue states
    pub all_memory_queue_states: Vec<MemoryQueueState<E>>,
    pub sorted_memory_queue_states: Vec<MemoryQueueState<E>>,
    // decommittment queue
    pub all_decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
    pub sorted_decommittment_queries: Vec<DecommittmentQuery>,
    pub deduplicated_decommittment_queries: Vec<DecommittmentQuery>,
    pub all_decommittment_queue_states: Vec<(u32, DecommittmentQueueState<E>)>,
    pub sorted_decommittment_queue_states: Vec<DecommittmentQueueState<E>>,
    pub deduplicated_decommittment_queue_states: Vec<DecommittmentQueueState<E>>,
    // log queue
    pub original_log_queue: Vec<(u32, LogQuery)>,
    pub original_log_queue_simulator: LogQueueSimulator<E>,
    pub original_log_queue_states: Vec<(u32, LogQueueState<E>)>,

    // demuxed log queues
    pub demuxed_rollup_storage_queries: Vec<LogQuery>,
    pub demuxed_rollup_storage_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_rollup_storage_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_porter_storage_queries: Vec<LogQuery>,
    pub demuxed_porter_storage_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_porter_storage_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_event_queries: Vec<LogQuery>,
    pub demuxed_events_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_event_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_to_l1_queries: Vec<LogQuery>,
    pub demuxed_to_l1_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_to_l1_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_keccak_precompile_queries: Vec<LogQuery>,
    pub demuxed_keccak_precompile_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_keccak_precompile_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_sha256_precompile_queries: Vec<LogQuery>,
    pub demuxed_sha256_precompile_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_sha256_precompile_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_ecrecover_queries: Vec<LogQuery>,
    pub demuxed_ecrecover_queue_simulator: LogQueueSimulator<E>,
    pub demuxed_ecrecover_queue_states: Vec<LogQueueState<E>>,

    // sorted and deduplicated log-like queues for ones that support reverts
    // sorted
    // pub _sorted_rollup_storage_queries: Vec<LogQuery>,
    // pub _sorted_rollup_storage_queue_states: Vec<LogQueueState<E>>,
    // pub _sorted_porter_storage_queries: Vec<LogQuery>,
    // pub _sorted_porter_storage_queue_states: Vec<LogQueueState<E>>,
    // pub _sorted_event_queries: Vec<LogQuery>,
    // pub sorted_event_queue_states: Vec<LogQueueState<E>>,
    // pub _sorted_to_l1_queries: Vec<LogQuery>,
    // pub sorted_to_l1_queue_states: Vec<LogQueueState<E>>,

    // deduplicated
    pub deduplicated_rollup_storage_queries: Vec<LogQuery>,
    pub deduplicated_rollup_storage_queue_states: Vec<LogQueueState<E>>,
    pub deduplicated_rollup_storage_queue_simulator: LogQueueSimulator<E>,
    pub deduplicated_porter_storage_queries: Vec<LogQuery>,
    pub deduplicated_porter_storage_queue_states: Vec<LogQueueState<E>>,
    pub deduplicated_event_queries: Vec<LogQuery>,
    pub deduplicated_event_queue_simulator: LogQueueSimulator<E>,
    pub deduplicated_event_queue_states: Vec<LogQueueState<E>>,
    pub deduplicated_to_l1_queries: Vec<LogQuery>,
    pub deduplicated_to_l1_queue_simulator: LogQueueSimulator<E>,
    pub deduplicated_to_l1_queue_states: Vec<LogQueueState<E>>,

    //
    pub special_initial_decommittment_queries: Vec<(DecommittmentQuery, Vec<U256>)>,

    // keep precompile round functions data
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub keccak_256_memory_queries: Vec<MemoryQuery>,
    pub keccak_256_memory_states: Vec<MemoryQueueState<E>>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub sha256_memory_queries: Vec<MemoryQuery>,
    pub sha256_memory_states: Vec<MemoryQueueState<E>>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub ecrecover_memory_queries: Vec<MemoryQuery>,
    pub ecrecover_memory_states: Vec<MemoryQueueState<E>>,

    // processed RAM circuit information
    pub ram_permutation_circuits_data: Vec<RamPermutationCircuitInstanceWitness<E>>,
    // processed code decommitter circuits, as well as sorting circuit (1)
    pub code_decommitter_circuits_data: Vec<CodeDecommitterCircuitInstanceWitness<E>>,
    pub decommittments_deduplicator_circuits_data:
        Vec<CodeDecommittmentsDeduplicatorInstanceWitness<E>>,
    //
    pub log_demuxer_circuit_data: Vec<LogDemuxerCircuitInstanceWitness<E>>,
    //
    pub storage_deduplicator_circuit_data: Vec<StorageDeduplicatorInstanceWitness<E>>,
    pub events_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<E>>,
    pub l1_messages_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<E>>,
    //
    pub initial_writes_pubdata_hasher_circuit_data:
        Vec<PubdataHasherInstanceWitness<E, 3, 64, InitialStorageWriteData<E>>>,
    pub repeated_writes_pubdata_hasher_circuit_data:
        Vec<PubdataHasherInstanceWitness<E, 2, 40, RepeatedStorageWriteData<E>>>,
    //
    pub rollup_storage_application_circuit_data: Vec<StorageApplicationCircuitInstanceWitness<E>>,
    //
    pub keccak256_circuits_data: Vec<Keccak256RoundFunctionInstanceWitness<E>>,
    //
    pub sha256_circuits_data: Vec<Sha256RoundFunctionCircuitInstanceWitness<E>>,
    //
    pub ecrecover_circuits_data: Vec<EcrecoverCircuitInstanceWitness<E>>,
    //
    pub l1_messages_linear_hash_data: Vec<
        PubdataHasherInstanceWitness<
            E,
            5,
            88,
            <LogQuery as CircuitEquivalentReflection<E>>::Destination,
        >,
    >,
    pub l1_messages_merklizer_data: Vec<
        MessagesMerklizerInstanceWitness<
            E,
            5,
            88,
            <LogQuery as CircuitEquivalentReflection<E>>::Destination,
        >,
    >,
}

use crate::witness::tree::*;
use blake2::Blake2s256;

impl<E: Engine> FullBlockArtifacts<E> {
    pub fn process<R: CircuitArithmeticRoundFunction<E, 2, 3>>(
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

            let is_pended = query.is_pended;
            self.vm_memory_queue_states
                .push((*cycle, is_pended, intermediate_info));
            self.all_memory_queue_states.push(intermediate_info);
        }

        assert!(
            self.memory_queue_simulator.num_items as usize
                == self.vm_memory_queries_accumulated.len()
        );

        // direct VM related part is done, other subcircuit's functionality is moved to other functions
        // that should properly do sorts and memory writes

        use crate::witness::individual_circuits::decommit_code::compute_decommitter_circuit_snapshots;

        tracing::debug!("Running code decommittments sorter and decommitter simulation");

        let (code_decommitter_circuits_data, decommittments_deduplicator_witness) =
            compute_decommitter_circuit_snapshots(
                self,
                round_function,
                geometry.cycles_per_code_decommitter as usize,
                geometry.cycles_per_code_decommitter_sorter as usize
            );

        self.code_decommitter_circuits_data = code_decommitter_circuits_data;
        self.decommittments_deduplicator_circuits_data = decommittments_deduplicator_witness;

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

        use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_pubdata_hasher_witness;

        let l1_messages_pubdata_hasher_data = compute_pubdata_hasher_witness(
            &self.deduplicated_to_l1_queue_simulator,
            geometry.limit_for_l1_messages_pudata_hasher as usize,
        );

        self.l1_messages_linear_hash_data = vec![l1_messages_pubdata_hasher_data];

        // merklize some messages

        use crate::witness::individual_circuits::data_hasher_and_merklizer::compute_merklizer_witness;

        tracing::debug!("Running L1 messages merklization simulation");

        use crate::witness::postprocessing::L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH;

        assert!(
            self.deduplicated_to_l1_queue_simulator.num_items
                <= geometry.limit_for_l1_messages_merklizer,
            "too many L1 messages to merklize by single circuit"
        );

        let l1_messages_merklizer_data = compute_merklizer_witness(
            &self.deduplicated_to_l1_queue_simulator,
            geometry.limit_for_l1_messages_merklizer as usize,
            L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH,
        );

        self.l1_messages_merklizer_data = vec![l1_messages_merklizer_data];

        // process the storage application

        // we can quickly determine states witness

        use crate::witness::individual_circuits::get_storage_application_pubdata::compute_storage_application_pubdata_queues;

        let (initial, repeated) = compute_storage_application_pubdata_queues(
            self,
            tree,
            round_function,
            geometry.limit_for_initial_writes_pubdata_hasher as usize,
            geometry.limit_for_repeated_writes_pubdata_hasher as usize,
        );

        self.initial_writes_pubdata_hasher_circuit_data = vec![initial];
        self.repeated_writes_pubdata_hasher_circuit_data = vec![repeated];

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

use crate::abstract_zksync_circuit::concrete_circuits::*;
use crate::witness::oracle::VmWitnessOracle;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone)]
#[serde(bound = "")]
pub struct BlockBasicCircuits<E: Engine> {
    // main VM circuit. Many of them
    pub main_vm_circuits: Vec<VMMainCircuit<E, VmWitnessOracle<E>>>,
    // code decommittments sorter is only 1 circuit per block
    pub code_decommittments_sorter_circuits: Vec<CodeDecommittsSorterCircuit<E>>,
    // few code decommitters: code hash -> memory
    pub code_decommitter_circuits: Vec<CodeDecommitterCircuit<E>>,
    // demux logs to get precompiles for RAM too
    pub log_demux_circuits: Vec<LogDemuxerCircuit<E>>,
    // process precompiles
    // keccak
    pub keccak_precompile_circuits: Vec<Keccak256RoundFunctionCircuit<E>>,
    // sha256
    pub sha256_precompile_circuits: Vec<Sha256RoundFunctionCircuit<E>>,
    // ecrecover
    pub ecrecover_precompile_circuits: Vec<ECRecoverFunctionCircuit<E>>,
    // when it's all done we prove the memory validity and finish with it
    pub ram_permutation_circuits: Vec<RAMPermutationCircuit<E>>,
    // sort storage changes
    pub storage_sorter_circuits: Vec<StorageSorterCircuit<E>>,
    // apply them
    pub storage_application_circuits: Vec<StorageApplicationCircuit<E>>,
    // rehash initial writes
    pub initial_writes_hasher_circuit: InitialStorageWritesPubdataHasherCircuit<E>,
    // rehash repeated writes
    pub repeated_writes_hasher_circuit: RepeatedStorageWritesPubdataHasherCircuit<E>,
    // sort and dedup events
    pub events_sorter_circuits: Vec<EventsSorterCircuit<E>>,
    // sort and dedup L1 messages
    pub l1_messages_sorter_circuits: Vec<L1MessagesSorterCircuit<E>>,
    // hash l1 messages into pubdata
    pub l1_messages_pubdata_hasher_circuit: L1MessagesHasherCircuit<E>,
    // merklize L1 message
    pub l1_messages_merklizer_circuit: L1MessagesMerklizerCircuit<E>,
}

impl<E: Engine> BlockBasicCircuits<E> {
    pub fn into_flattened_set(self) -> Vec<ZkSyncCircuit<E, VmWitnessOracle<E>>> {
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
            initial_writes_hasher_circuit,
            repeated_writes_hasher_circuit,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_pubdata_hasher_circuit,
            l1_messages_merklizer_circuit,
        } = self;

        let mut result = vec![];
        result.extend(
            main_vm_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::MainVM(el)),
        );

        result.extend(
            code_decommittments_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::CodeDecommittmentsSorter(el)));

        result.extend(
            code_decommitter_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::CodeDecommitter(el)),
        );

        result.extend(
            log_demux_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::LogDemuxer(el)),
        );

        result.extend(
            keccak_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::KeccakRoundFunction(el)),
        );
        result.extend(
            sha256_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::Sha256RoundFunction(el)),
        );
        result.extend(
            ecrecover_precompile_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::ECRecover(el)),
        );

        result.extend(
            ram_permutation_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::RAMPermutation(el)),
        );

        result.extend(
            storage_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::StorageSorter(el)),
        );

        result.extend(
            storage_application_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::StorageApplication(el)),
        );

        result.push(ZkSyncCircuit::InitialWritesPubdataHasher(
            initial_writes_hasher_circuit,
        ));
        result.push(ZkSyncCircuit::RepeatedWritesPubdataHasher(
            repeated_writes_hasher_circuit,
        ));

        result.extend(
            events_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::EventsSorter(el)),
        );

        result.extend(
            l1_messages_sorter_circuits
                .into_iter()
                .map(|el| ZkSyncCircuit::L1MessagesSorter(el)),
        );

        result.push(ZkSyncCircuit::L1MessagesPubdataHasher(
            l1_messages_pubdata_hasher_circuit,
        ));

        result.push(ZkSyncCircuit::L1MessagesMerklier(
            l1_messages_merklizer_circuit,
        ));

        result
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone)]
#[serde(bound = "")]
pub struct BlockBasicCircuitsPublicInputs<E: Engine> {
    // main VM circuit. Many of them
    pub main_vm_circuits: Vec<E::Fr>,
    // code decommittments sorter
    pub code_decommittments_sorter_circuits: Vec<E::Fr>,
    // few code decommitters: code hash -> memory
    pub code_decommitter_circuits: Vec<E::Fr>,
    // demux logs to get precompiles for RAM too
    pub log_demux_circuits: Vec<E::Fr>,
    // process precompiles
    // keccak
    pub keccak_precompile_circuits: Vec<E::Fr>,
    // sha256
    pub sha256_precompile_circuits: Vec<E::Fr>,
    // ecrecover
    pub ecrecover_precompile_circuits: Vec<E::Fr>,
    // when it's all done we prove the memory validity and finish with it
    pub ram_permutation_circuits: Vec<E::Fr>,
    // sort storage changes
    pub storage_sorter_circuits: Vec<E::Fr>,
    // apply them
    pub storage_application_circuits: Vec<E::Fr>,
    // rehash initial writes
    pub initial_writes_hasher_circuit: E::Fr,
    // rehash repeated writes
    pub repeated_writes_hasher_circuit: E::Fr,
    // sort and dedup events
    pub events_sorter_circuits: Vec<E::Fr>,
    // sort and dedup L1 messages
    pub l1_messages_sorter_circuits: Vec<E::Fr>,
    // hash l1 messages into pubdata
    pub l1_messages_pubdata_hasher_circuit: E::Fr,
    // merklize L1 message
    pub l1_messages_merklizer_circuit: E::Fr,
}

impl<E: Engine> BlockBasicCircuitsPublicInputs<E> {
    pub fn into_flattened_set(self) -> Vec<E::Fr> {
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
            initial_writes_hasher_circuit,
            repeated_writes_hasher_circuit,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_pubdata_hasher_circuit,
            l1_messages_merklizer_circuit,
        } = self;

        use ff::Field;

        let mut result = vec![];
        result.extend(main_vm_circuits);

        result.extend(code_decommittments_sorter_circuits);

        result.extend(code_decommitter_circuits);

        result.extend(log_demux_circuits);

        result.extend(keccak_precompile_circuits);
        result.extend(sha256_precompile_circuits);
        result.extend(ecrecover_precompile_circuits);

        result.extend(ram_permutation_circuits);

        result.extend(storage_sorter_circuits);

        result.extend(storage_application_circuits);

        result.push(initial_writes_hasher_circuit);
        result.push(repeated_writes_hasher_circuit);
        result.extend(events_sorter_circuits);
        result.extend(l1_messages_sorter_circuits);

        result.push(l1_messages_pubdata_hasher_circuit);
        result.push(l1_messages_merklizer_circuit);

        result
    }
}

use sync_vm::inputs::ClosedFormInputCompactFormWitness;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone)]
#[serde(bound = "")]
pub struct BlockBasicCircuitsPublicCompactFormsWitnesses<E: Engine> {
    // main VM circuit. Many of them
    pub main_vm_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // code decommittments sorter
    pub code_decommittments_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // few code decommitters: code hash -> memory
    pub code_decommitter_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // demux logs to get precompiles for RAM too
    pub log_demux_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // process precompiles
    // keccak
    pub keccak_precompile_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // sha256
    pub sha256_precompile_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // ecrecover
    pub ecrecover_precompile_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // when it's all done we prove the memory validity and finish with it
    pub ram_permutation_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // sort storage changes
    pub storage_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // apply them
    pub storage_application_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // rehash initial writes
    pub initial_writes_hasher_circuit: ClosedFormInputCompactFormWitness<E>,
    // rehash repeated writes
    pub repeated_writes_hasher_circuit: ClosedFormInputCompactFormWitness<E>,
    // sort and dedup events
    pub events_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // sort and dedup L1 messages
    pub l1_messages_sorter_circuits: Vec<ClosedFormInputCompactFormWitness<E>>,
    // hash l1 messages into pubdata
    pub l1_messages_pubdata_hasher_circuit: ClosedFormInputCompactFormWitness<E>,
    // merklize L1 message
    pub l1_messages_merklizer_circuit: ClosedFormInputCompactFormWitness<E>,
}

impl<E: Engine> BlockBasicCircuitsPublicCompactFormsWitnesses<E> {
    pub fn into_flattened_set(self) -> Vec<ClosedFormInputCompactFormWitness<E>> {
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
            initial_writes_hasher_circuit,
            repeated_writes_hasher_circuit,
            events_sorter_circuits,
            l1_messages_sorter_circuits,
            l1_messages_pubdata_hasher_circuit,
            l1_messages_merklizer_circuit,
        } = self;

        use sync_vm::traits::CSWitnessable;

        let mut result = vec![];
        result.extend(main_vm_circuits);

        result.extend(code_decommittments_sorter_circuits);

        result.extend(code_decommitter_circuits);

        result.extend(log_demux_circuits);

        result.extend(keccak_precompile_circuits);
        result.extend(sha256_precompile_circuits);
        result.extend(ecrecover_precompile_circuits);

        result.extend(ram_permutation_circuits);

        result.extend(storage_sorter_circuits);

        result.extend(storage_application_circuits);

        result.push(initial_writes_hasher_circuit);
        result.push(repeated_writes_hasher_circuit);
        result.extend(events_sorter_circuits);
        result.extend(l1_messages_sorter_circuits);

        result.push(l1_messages_pubdata_hasher_circuit);
        result.push(l1_messages_merklizer_circuit);

        result
    }
}
