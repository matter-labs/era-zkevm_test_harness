// implement witness oracle to actually compute 
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use sync_vm::vm::vm_cycle::memory::MemoryLocation;
use sync_vm::{franklin_crypto::bellman::pairing::Engine, circuit_structures::traits::CircuitArithmeticRoundFunction};
use zk_evm::aux_structures::{MemoryQuery, LogQuery, MemoryPage, MemoryIndex};
use crate::{witness::tracer::WitnessTracer};
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;

pub struct VmWitnessOracle<E: Engine> {
    pub memory_read_witness: Vec<(u32, MemoryQuery)>,
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    pub rollback_queue_head_segments: Vec<(u32, (usize, E::Fr))>,


    pub sorted_rollup_storage_queries: Vec<LogQuery>,
    pub sorted_porter_storage_queries: Vec<LogQuery>,
    pub sorted_event_queries: Vec<LogQuery>,
    pub sorted_to_l1_queries: Vec<LogQuery>,
    pub sorted_keccak_precompile_queries: Vec<LogQuery>,
    pub sorted_sha256_precompile_queries: Vec<LogQuery>,
    pub sorted_ecrecover_queries: Vec<LogQuery>,
}



impl<E: Engine> VmWitnessOracle<E> {
    pub fn from_witness_tracer<R: CircuitArithmeticRoundFunction<E, 2, 3>>(
        tracer: WitnessTracer,
        round_function: &R,
    ) -> Self {
        // TODO: simulate simultaneously the sponges and queue states
        let mut memory_read_witness = vec![];
        let WitnessTracer { 
            memory_queries, 
            precompile_calls, 
            storage_read_queries, 
            decommittment_queries, 
            callstack_actions, 
            keccak_round_function_witnesses, 
            sha256_round_function_witnesses, 
            ecrecover_witnesses, 
            monotonic_frame_counter, 
            log_frames_stack, 
            callstack_helper 
        } = tracer;

        let mut memory_queue_simulator = MemoryQueueSimulator::<E>::empty();
        let mut decommittment_queue_simulator = DecommittmentQueueSimulator::<E>::empty();

        // this one we will later on split and re-arrange into sponge cycles, as well as use for 
        // VmState snapshot reconstruction
        let mut memory_queue_sponge_states = vec![];
        let mut all_memory_queries_flattened = vec![];

        for (cycle, query) in memory_queries.into_iter() {
            if !query.rw_flag {
                memory_read_witness.push(query);
            }

            // simulate cycling sponge
            let is_pending = query.is_pended;
            let states = memory_queue_simulator.push_and_output_intermediate_data(query, round_function);
            assert!(states.len() == 1);
            let s = states[0];
            memory_queue_sponge_states.push((cycle, is_pending, s));

            // and bookkeep for permutation-sort later on
            all_memory_queries_flattened.push(query);
        }

        // process decommittment requests. We only need to simulate state, and collect flattened history for permute-sort-deduplicate

        let mut decommittment_queue_sponge_states = vec![];
        let mut all_decommittment_queries_flattened = vec![];

        // we can also sort-deduplicate immediatelly to materialize all the memoty queries to append 
        let mut sorted_decommittment_requests = std::collections::BTreeMap::new();

        let mut timestamp = 0u32;

        for (cycle, decommittment_request, writes) in decommittment_queries.into_iter() {
            let ts = decommittment_request.timestamp;

            // we sort by hash to ensure uniqueness, so let's check some invariants too!
            if decommittment_request.is_fresh {
                assert!(ts.0 > timestamp);
                timestamp = ts.0;
                let contains = sorted_decommittment_requests.contains_key(&decommittment_request.hash);
                assert!(!contains);

                let page = decommittment_request.memory_page;

                // now feed the queries into it
                let as_queries: Vec<_> = writes.into_iter().enumerate().map(|(idx, el)| {
                    MemoryQuery {
                        timestamp: ts,
                        location: zk_evm::aux_structures::MemoryLocation {
                            memory_type: zk_evm::abstractions::MemoryType::Code,
                            page: page,
                            index: MemoryIndex(idx as u32)
                        },
                        rw_flag: true,
                        value: el,
                        is_pended: false
                    }
                }).collect();

                sorted_decommittment_requests.insert(decommittment_request.hash, as_queries);
            } else {
                let contains = sorted_decommittment_requests.contains_key(&decommittment_request.hash);
                assert!(contains);
            }

            // sponge

            let states = decommittment_queue_simulator.push_and_output_intermediate_data(decommittment_request, round_function);
            assert!(states.len() == 1);
            let s = states[0];
            decommittment_queue_sponge_states.push((cycle, s));

            all_decommittment_queries_flattened.push(decommittment_request);
        }








        todo!()
    }
}