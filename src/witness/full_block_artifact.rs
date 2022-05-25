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
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use sync_vm::glue::ram_permutation::RamPermutationCircuitInstanceWitness;

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
    pub original_log_queue_states: Vec<(u32, LogQueueState<E>)>,
    // demuxed log queues
    pub demuxed_rollup_storage_queries: Vec<LogQuery>,
    pub demuxed_rollup_storage_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_porter_storage_queries: Vec<LogQuery>,
    pub demuxed_porter_storage_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_event_queries: Vec<LogQuery>,
    pub demuxed_event_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_to_l1_queries: Vec<LogQuery>,
    pub demuxed_to_l1_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_keccak_precompile_queries: Vec<LogQuery>,
    pub demuxed_keccak_precompile_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_sha256_precompile_queries: Vec<LogQuery>,
    pub demuxed_sha256_precompile_queue_states: Vec<LogQueueState<E>>,
    pub demuxed_ecrecover_queries: Vec<LogQuery>,
    pub demuxed_ecrecover_queue_states: Vec<LogQueueState<E>>,

    // sorted and deduplicated log-like queues for ones that support reverts
    // sorted
    pub sorted_rollup_storage_queries: Vec<LogQuery>,
    pub sorted_rollup_storage_queue_states: Vec<LogQueueState<E>>,
    pub sorted_porter_storage_queries: Vec<LogQuery>,
    pub sorted_porter_storage_queue_states: Vec<LogQueueState<E>>,
    pub sorted_event_queries: Vec<LogQuery>,
    pub sorted_event_queue_states: Vec<LogQueueState<E>>,
    pub sorted_to_l1_queries: Vec<LogQuery>,
    pub sorted_to_l1_queue_states: Vec<LogQueueState<E>>,

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
}

impl<E: Engine> FullBlockArtifacts<E> {
    pub fn process<R: CircuitArithmeticRoundFunction<E, 2, 3>>(&mut self, round_function: &R) {
        let mut memory_queue_simulator = MemoryQueueSimulator::<E>::empty();
        let mut decommittment_queue_simulator = DecommittmentQueueSimulator::<E>::empty();

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

        // sort decommittment requests

        let mut unsorted_decommittment_requests_with_data = vec![];
        for (cycle, decommittment_request, writes) in self.all_decommittment_queries.iter_mut() {
            let data = std::mem::replace(writes, vec![]);
            unsorted_decommittment_requests_with_data.push((*decommittment_request, data));
        }

        // internally parallelizable by the factor of 3
        for (cycle, decommittment_request, _) in self.all_decommittment_queries.iter() {
            // sponge
            let (old_tail, intermediate_info) = decommittment_queue_simulator
                .push_and_output_intermediate_data(*decommittment_request, round_function);
            self.all_decommittment_queue_states
                .push((*cycle, intermediate_info));
        }

        // sort queries
        let mut sorted_decommittment_requests_with_data = unsorted_decommittment_requests_with_data;
        sorted_decommittment_requests_with_data.par_sort_by(|a, b| 
            // sort by hash first, and then by timestamp
            match a.0.hash.cmp(&b.0.hash) {
                Ordering::Equal => a.0.timestamp.cmp(&b.0.timestamp),
                a @ _ => a,
            }
        );

        for (query, writes) in sorted_decommittment_requests_with_data.into_iter() {
            if query.is_fresh {
                // now feed the queries into it
                let as_queries_it = writes.into_iter().enumerate().map(|(idx, el)| MemoryQuery {
                    timestamp: query.timestamp,
                    location: zk_evm::aux_structures::MemoryLocation {
                        memory_type: zk_evm::abstractions::MemoryType::Code,
                        page: query.memory_page,
                        index: MemoryIndex(idx as u32),
                    },
                    rw_flag: true,
                    value: el,
                    is_pended: false,
                });

                self.all_memory_queries_accumulated.extend(as_queries_it);

                self.deduplicated_decommittment_queries.push(query);
            }

            self.sorted_decommittment_queries.push(query);
        }

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

        let ram_permutation_circuits_data = compute_ram_circuit_snapshots(
            self,
            memory_queue_simulator,
            round_function,
            1<<2
        );

        self.ram_permutation_circuits_data = ram_permutation_circuits_data;

        // now completely parallel process to reconstruct the states, with internally parallelism in each round function

        self.is_processed = true;
    }
}
