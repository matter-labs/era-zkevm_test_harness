use super::*;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use crate::encodings::decommittment_request::DecommittmentQueueState;
use crate::encodings::log_query::LogQueueState;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::encodings::memory_query::MemoryQueueState;
use crate::ethereum_types::U256;
use crate::pairing::Engine;
use derivative::Derivative;
use rayon::slice::ParallelSliceMut;
use std::cmp::Ordering;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use zk_evm::aux_structures::DecommittmentQuery;
use zk_evm::aux_structures::LogQuery;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use crate::encodings::log_query::LogQueueSimulator;
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use sync_vm::glue::ram_permutation::RamPermutationCircuitInstanceWitness;
use sync_vm::glue::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use sync_vm::glue::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;
use sync_vm::glue::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use sync_vm::glue::log_sorter::input::EventsDeduplicatorInstanceWitness;

#[derive(Derivative)]
#[derivative(Clone, Default(bound = ""))]
pub struct FullBlockArtifacts<E: Engine> {
    pub is_processed: bool,
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
    pub deduplicated_porter_storage_queries: Vec<LogQuery>,
    pub deduplicated_porter_storage_queue_states: Vec<LogQueueState<E>>,
    pub deduplicated_event_queries: Vec<LogQuery>,
    pub deduplicated_event_queue_states: Vec<LogQueueState<E>>,
    pub deduplicated_to_l1_queries: Vec<LogQuery>,
    pub deduplicated_to_l1_queue_states: Vec<LogQueueState<E>>,

    // keep precompile round functions data
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,

    // also separate copy of memory queries that are contributions from individual precompiles
    pub keccak_256_memory_queries: Vec<MemoryQuery>,
    pub keccak_256_memory_states: Vec<MemoryQueueState<E>>,

    // processed RAM circuit information
    pub ram_permutation_circuits_data: Vec<RamPermutationCircuitInstanceWitness<E>>,
    // processed code decommitter circuits, as well as sorting circuit (1)
    pub code_decommitter_circuits_data: Vec<CodeDecommitterCircuitInstanceWitness<E>>,
    //
    pub log_demuxer_circuit_data: Vec<LogDemuxerCircuitInstanceWitness<E>>,
    //
    pub storage_deduplicator_circuit_data: Vec<StorageDeduplicatorInstanceWitness<E>>,
    pub events_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<E>>,
    pub l1_messages_deduplicator_circuit_data: Vec<EventsDeduplicatorInstanceWitness<E>>,
}

impl<E: Engine> FullBlockArtifacts<E> {
    pub fn process<R: CircuitArithmeticRoundFunction<E, 2, 3>>(&mut self, round_function: &R) {
        let mut memory_queue_simulator = MemoryQueueSimulator::<E>::empty();

        // this is parallelizable internally by the factor of 3 in round function implementation later on

        for (cycle, query) in self.vm_memory_queries_accumulated.iter() {
            self.all_memory_queries_accumulated.push(*query);

            let (_old_tail, intermediate_info) =
                memory_queue_simulator.push_and_output_intermediate_data(*query, round_function);

            // dbg!(&intermediate_info.tail);

            let is_pended = query.is_pended;
            self.vm_memory_queue_states
                .push((*cycle, is_pended, intermediate_info));
            self.all_memory_queue_states.push(intermediate_info);
        }

        assert!(
            memory_queue_simulator.num_items as usize == self.vm_memory_queries_accumulated.len()
        );

        // direct VM related part is done, other subcircuit's functionality is moved to other functions
        // that should properly do sorts and memory writes

        use crate::witness::individual_circuits::decommit_code::compute_decommitter_circuit_snapshots;

        let (code_decommitter_circuits_data, _) = compute_decommitter_circuit_snapshots(
            self,
            &mut memory_queue_simulator,
            round_function,
            1 << 1
        );

        self.code_decommitter_circuits_data = code_decommitter_circuits_data;

        // demux log queue
        use crate::witness::individual_circuits::log_demux::compute_logs_demux;

        let log_demuxer_witness = compute_logs_demux(
            self,
            round_function
        );

        self.log_demuxer_circuit_data = vec![log_demuxer_witness];

        // keccak precompile

        for (_cycle, _query, witness) in self.keccak_round_function_witnesses.iter() {
            for el in witness.iter() {
                let Keccak256RoundWitness {
                    new_request: _,
                    reads,
                    writes,
                } = el;

                // we read, then write
                if let Some(reads) = reads.as_ref() {
                    self.all_memory_queries_accumulated.extend_from_slice(reads);
                }

                if let Some(writes) = writes.as_ref() {
                    self.all_memory_queries_accumulated
                        .extend_from_slice(writes);
                }
            }
        }

        // sha256 precompile

        for (_cycle, _query, witness) in self.sha256_round_function_witnesses.iter() {
            for el in witness.iter() {
                let Sha256RoundWitness {
                    new_request: _,
                    reads,
                    writes,
                } = el;

                // we read, then write
                self.all_memory_queries_accumulated.extend_from_slice(reads);

                if let Some(writes) = writes.as_ref() {
                    self.all_memory_queries_accumulated
                        .extend_from_slice(writes);
                }
            }
        }

        // ecrecover precompile

        for (_cycle, _query, witness) in self.ecrecover_witnesses.iter() {
            let ECRecoverRoundWitness {
                new_request: _,
                reads,
                writes,
            } = witness;

            // we read, then write
            self.all_memory_queries_accumulated.extend_from_slice(reads);
            self.all_memory_queries_accumulated
                .extend_from_slice(writes);
        }

        // we are done with a memory and can do the processing and breaking of the logical arguments into individual circits

        use crate::witness::individual_circuits::ram_permutation::compute_ram_circuit_snapshots;

        // let ram_permutation_circuits_data = compute_ram_circuit_snapshots(
        //     self,
        //     memory_queue_simulator,
        //     round_function,
        //     1<<2
        // );

        // self.ram_permutation_circuits_data = ram_permutation_circuits_data;

        // now completely parallel process to reconstruct the states, with internally parallelism in each round function

        use crate::witness::individual_circuits::storage_sort_dedup::compute_storage_dedup_and_sort;

        let storage_deduplicator_circuit_data = compute_storage_dedup_and_sort(
            self,
            round_function
        );
        self.storage_deduplicator_circuit_data = vec![storage_deduplicator_circuit_data];


        use crate::witness::individual_circuits::events_sort_dedup::compute_events_dedup_and_sort;

        let events_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &self.demuxed_event_queries,
            &mut self.deduplicated_event_queries,
            &self.demuxed_events_queue_simulator,
            round_function
        );

        self.events_deduplicator_circuit_data = vec![events_deduplicator_circuit_data];

        let l1_messages_deduplicator_circuit_data = compute_events_dedup_and_sort(
            &self.demuxed_to_l1_queries,
            &mut self.deduplicated_to_l1_queries,
            &self.demuxed_to_l1_queue_simulator,
            round_function
        );

        self.l1_messages_deduplicator_circuit_data = vec![l1_messages_deduplicator_circuit_data];

        self.is_processed = true;
    }
}
