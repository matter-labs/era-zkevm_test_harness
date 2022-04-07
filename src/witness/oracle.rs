// implement witness oracle to actually compute 
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use sync_vm::vm::vm_cycle::memory::MemoryLocation;
use sync_vm::{franklin_crypto::bellman::pairing::Engine, circuit_structures::traits::CircuitArithmeticRoundFunction};
use zk_evm::aux_structures::{MemoryQuery, LogQuery, MemoryPage, MemoryIndex, STORAGE_AUX_BYTE, EVENT_AUX_BYTE, PRECOMPILE_AUX_BYTE, L1_MESSAGE_AUX_BYTE};
use zk_evm::precompiles::KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS;
use zk_evm::testing::event_sink::ApplicationData;
use zk_evm::vm_state::CallStackEntry;
use crate::encodings::log_query::LogQueueSimulator;
use crate::{witness::tracer::WitnessTracer};
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use std::collections::{HashMap, BTreeMap};
use crate::ff::Field;

pub struct VmWitnessOracle<E: Engine> {
    pub memory_read_witness: Vec<(u32, MemoryQuery)>,
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    pub rollback_queue_head_segments: Vec<(u32, E::Fr)>,
    pub rollback_queue_initial_tails_for_new_frames: Vec<(u32, E::Fr)>,
    pub storage_read_queries: Vec<(u32, LogQuery)>,

    pub sorted_rollup_storage_queries: Vec<LogQuery>,
    pub sorted_porter_storage_queries: Vec<LogQuery>,
    pub sorted_event_queries: Vec<LogQuery>,
    pub sorted_to_l1_queries: Vec<LogQuery>,
    pub sorted_keccak_precompile_queries: Vec<LogQuery>,
    pub sorted_sha256_precompile_queries: Vec<LogQuery>,
    pub sorted_ecrecover_queries: Vec<LogQuery>,

    pub callstack_values_for_returns: Vec<(u32, CallStackEntry)>,

    pub initial_tail_for_entry_point: E::Fr,
}

impl<E: Engine> VmWitnessOracle<E> {
    pub fn from_witness_tracer<R: CircuitArithmeticRoundFunction<E, 2, 3>>(
        tracer: WitnessTracer,
        round_function: &R,
    ) -> Self {
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
            log_frames_stack, 
            callstack_helper 
        } = tracer;

        let mut memory_queue_simulator = MemoryQueueSimulator::<E>::empty();
        let mut decommittment_queue_simulator = DecommittmentQueueSimulator::<E>::empty();

        // this one we will later on split and re-arrange into sponge cycles, as well as use for 
        // VmState snapshot reconstruction
        let mut memory_queue_sponge_requests = vec![];
        let mut memory_queue_sponge_states = vec![];
        let mut all_memory_queries_flattened = vec![];

        for (cycle, query) in memory_queries.into_iter() {
            if !query.rw_flag {
                memory_read_witness.push((cycle, query));
            }

            // simulate cycling sponge
            let is_pending = query.is_pended;
            let ((old_tail, new_tail), states) = memory_queue_simulator.push_and_output_intermediate_data(query, round_function);
            assert!(states.len() == 1);
            let s = states[0];
            memory_queue_sponge_requests.push((cycle, is_pending, s));

            memory_queue_sponge_states.push((cycle, new_tail));

            // and bookkeep for permutation-sort later on
            all_memory_queries_flattened.push(query);
        }

        // process decommittment requests. We only need to simulate state, and collect flattened history for permute-sort-deduplicate

        let mut decommittment_queue_sponge_requests = vec![];
        let mut decommittment_queue_sponge_states = vec![];
        let mut all_decommittment_queries_flattened = vec![];

        // we can also sort-deduplicate immediatelly to materialize all the memoty queries to append 
        let mut sorted_decommittment_requests = BTreeMap::new();

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
            let ((old_tail, new_tail), states) = decommittment_queue_simulator.push_and_output_intermediate_data(decommittment_request, round_function);
            assert!(states.len() == 1);
            let s = states[0];
            decommittment_queue_sponge_requests.push((cycle, s));
            decommittment_queue_sponge_states.push((cycle, new_tail));

            all_decommittment_queries_flattened.push(decommittment_request);
        }

        // now more complex things

        // segmentation of the log queue
        // - split into independent queues
        // - compute initial tail segments (with head == tail) for every new call frame
        // - also compute head segments for every write-like actions

        let mut log_queue_simulator = LogQueueSimulator::<E>::empty();
        let mut log_frames_stack = log_frames_stack;
        assert!(log_frames_stack.len() == 1); // we must have exited the root
        let ApplicationData {
            forward,
            rollbacks
        } = log_frames_stack.drain(0..1).next().unwrap();
        drop(log_frames_stack);

        let num_forwards = forward.len();

        let mut sorted_rollup_storage_queries = vec![];
        let mut sorted_porter_storage_queries = vec![];
        let mut sorted_event_queries = vec![];
        let mut sorted_to_l1_queries = vec![];
        let mut sorted_keccak_precompile_queries = vec![];
        let mut sorted_sha256_precompile_queries = vec![];
        let mut sorted_ecrecover_queries = vec![];

        let mut chain_of_states = vec![];

        // we want to have some hashmap that will indicate
        // that on some specific VM cycle we either read or write

        // from cycle into first two sponges (common), then tail-tail pair and 3rd sponge for forward, then head-head pair and 3rd sponge for rollback
        let mut frames_data: HashMap<u32, (
            Option<[([E::Fr; 3], [E::Fr; 3]); 2]>, 
            Option<((E::Fr, E::Fr), ([E::Fr; 3], [E::Fr; 3]))>, 
            Option<((E::Fr, E::Fr), ([E::Fr; 3], [E::Fr; 3]))>
        )> = HashMap::new();

        let mut cycle_pointers = HashMap::<u32, (usize, usize)>::new();
        let mut frame_pointers = HashMap::<usize, (usize, usize)>::new();

        let mut frames_sequence = vec![];

        for (((parent_frame_index, this_frame_index), (cycle, query)), was_applied) in forward.into_iter().zip(std::iter::repeat(true))
                        .chain(rollbacks.into_iter().zip(std::iter::repeat(false))) {
            let ((old_tail, new_tail), states) = log_queue_simulator.push_and_output_intermediate_data(
                query, 
                round_function
            );

            let pointer = chain_of_states.len();
            // we just log all chains of old tail -> new tail, and will interpret them later
            chain_of_states.push((cycle, this_frame_index, (old_tail, new_tail)));

            assert!(states.len() == 3);
            if query.rollback {
                let entry = frames_data.get_mut(&cycle).expect("rollbacks always happen after forward case");
                let common_sponges_pair = entry.0.expect("rollbacks always happen after forward case");
                assert_eq!(&common_sponges_pair[0], &states[0]);
                assert_eq!(&common_sponges_pair[1], &states[1]);
                let head_head_pair = (old_tail, new_tail);
                let third_sponge = states.last().unwrap().clone();

                entry.2 = Some((head_head_pair, third_sponge));

                if let Some(entry) = frame_pointers.get_mut(&this_frame_index) {
                    if entry.1 > pointer {
                        // nothing
                    } else {
                        entry.1 = pointer;
                    }
                } else {
                    unreachable!()
                }

                cycle_pointers.get_mut(&cycle).expect("rollbacks always happen after forward case").1 = pointer;
            } else {
                let entry = frames_data.entry(cycle).or_default();
                let common_sponges: [([E::Fr; 3], [E::Fr; 3]); 2] = states[0..2].try_into().unwrap();
                let tail_tail_pair = (old_tail, new_tail);
                let third_sponge = states.last().unwrap().clone();

                entry.0 = Some(common_sponges);
                entry.1 = Some((tail_tail_pair, third_sponge));

                cycle_pointers.entry(cycle).or_default().0 = pointer;

                if let Some(entry) = frame_pointers.get_mut(&this_frame_index) {
                    if entry.0 < pointer {
                        // nothing
                    } else {
                        entry.0 = pointer;
                    }
                } else {
                    frame_pointers.insert(this_frame_index, (pointer, usize::MAX));
                }
            }

            if was_applied {
                frames_sequence.push((this_frame_index, cycle));
            }

            // and sort
            if was_applied {
                match query.aux_byte {
                    STORAGE_AUX_BYTE => {
                        // sort rollup and porter
                        match query.shard_id {
                            0 => {
                                sorted_rollup_storage_queries.push(query);
                            },
                            1 => {
                                sorted_porter_storage_queries.push(query);
                            },
                            _ => unreachable!()
                        }
                    },
                    L1_MESSAGE_AUX_BYTE => {
                        sorted_to_l1_queries.push(query);
                    },
                    EVENT_AUX_BYTE => {
                        sorted_event_queries.push(query);
                    },
                    PRECOMPILE_AUX_BYTE => {
                        assert!(!query.rollback);
                        use zk_evm::precompiles::*;
                        match query.address {
                            a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                                sorted_keccak_precompile_queries.push(query);
                            },
                            a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                                sorted_sha256_precompile_queries.push(query);
                            },
                            a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                                sorted_ecrecover_queries.push(query);
                            },
                            _ => unreachable!(),
                        }
                    },
                    _ => unreachable!()
                }
            }
        }

        let mut rollback_queue_head_segments = vec![];
        let mut rollback_queue_initial_tails_for_new_frames = vec![];

        let mut current_frame = 0;

        let initial_tail_for_entry_point = chain_of_states.last().map(|el| el.2.1).unwrap_or(E::Fr::zero());

        // only keep necessary information by walking over the frames sequence
        for (frame, cycle_idx) in frames_sequence.into_iter() {
            if frame != current_frame {
                // we start a new frame, or return
                if frame > current_frame {
                    // near/far call
                    let mut entry = frame_pointers.get_mut(&frame).expect("must be present in frame pointers");
                    if entry.1 != usize::MAX {
                        // there will be rollbackable operations
                        let (cycle, frame, (_, tail)) = chain_of_states[entry.1];
                        assert!(cycle_idx == cycle);
                        if frame != current_frame {
                            unreachable!(); // self-consitency checks
                        } 
                        rollback_queue_initial_tails_for_new_frames.push((cycle, tail));
                        entry.1 -= 1;
                    }
                } else {
                    // this is a return, and we do not care
                }

                current_frame = frame;
            } else {
                // same frame, so it's some rollbackable operation
                let mut entry = frame_pointers.get_mut(&frame).expect("must be present in frame pointers");
                if entry.1 != usize::MAX {
                    // there will be rollbackable operations
                    let (cycle, frame, (head, _)) = chain_of_states[entry.1];
                    assert!(cycle_idx == cycle);
                    if frame != current_frame {
                        unreachable!(); // self-consitency checks
                    } 
                    rollback_queue_head_segments.push((cycle, head));
                    entry.1 -= 1;
                }
            }
        }

        VmWitnessOracle::<E> {
            memory_read_witness,
            all_memory_queries_accumulated: vec![], // TODO
            rollback_queue_head_segments,
            rollback_queue_initial_tails_for_new_frames,
            storage_read_queries,
            sorted_rollup_storage_queries,
            sorted_porter_storage_queries,
            sorted_event_queries,
            sorted_to_l1_queries,
            sorted_keccak_precompile_queries,
            sorted_sha256_precompile_queries,
            sorted_ecrecover_queries,
            callstack_values_for_returns: vec![], // TODO
            initial_tail_for_entry_point,
        }
    }
}