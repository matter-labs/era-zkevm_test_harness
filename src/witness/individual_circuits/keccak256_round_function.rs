use super::*;
use crate::biguint_from_u256;
use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use derivative::Derivative;
use num_bigint::BigUint;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::glue::keccak256_round_function_circuit::input::Keccak256RoundFunctionInstanceWitness;
use sync_vm::glue::keccak256_round_function_circuit::input::*;
use sync_vm::glue::keccak256_round_function_circuit::*;
use sync_vm::precompiles::*;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;
use zk_evm::precompiles::keccak256::BUFFER_SIZE;

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keccak256PrecompileState {
    GetRequestFromQueue,
    RunRoundFunction,
    Finished,
}

// we want to simulate splitting of data into many separate instances of the same circuit.
// So we basically need to reconstruct the FSM state on input/output, and passthrough data.
// In practice the only difficulty is buffer state, everything else is provided by out-of-circuit VM

pub fn keccak256_decompose_into_per_circuit_witness<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>,
>(
    artifacts: &mut FullBlockArtifacts<E>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> Vec<Keccak256RoundFunctionInstanceWitness<E>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    // split into aux witness, don't mix with the memory
    use zk_evm::precompiles::keccak256::Keccak256RoundWitness;

    for (_cycle, _query, witness) in artifacts.keccak_round_function_witnesses.iter() {
        for el in witness.iter() {
            let Keccak256RoundWitness {
                new_request: _,
                reads,
                writes,
            } = el;

            // we read, then write
            if let Some(reads) = reads.as_ref() {
                artifacts.keccak_256_memory_queries.extend_from_slice(reads);
            }

            if let Some(writes) = writes.as_ref() {
                artifacts
                    .keccak_256_memory_queries
                    .extend_from_slice(writes);
            }
        }
    }

    let mut result = vec![];

    let keccak_precompile_calls =
        std::mem::replace(&mut artifacts.demuxed_keccak_precompile_queries, vec![]);
    let keccak_precompile_calls_queue_states = std::mem::replace(
        &mut artifacts.demuxed_keccak_precompile_queue_states,
        vec![],
    );
    let simulator_witness: Vec<_> = artifacts
        .demuxed_keccak_precompile_queue_simulator
        .witness
        .clone()
        .into();
    let round_function_witness =
        std::mem::replace(&mut artifacts.keccak_round_function_witnesses, vec![]);

    let memory_queries = std::mem::replace(&mut artifacts.keccak_256_memory_queries, vec![]);

    // check basic consistency
    assert_eq!(
        keccak_precompile_calls.len(),
        keccak_precompile_calls_queue_states.len()
    );
    assert_eq!(keccak_precompile_calls.len(), round_function_witness.len());

    if keccak_precompile_calls.len() == 0 {
        // we can not skip the circuit (at least for now), so we have to create a dummy on
        let log_queue_input_state =
            take_queue_state_from_simulator(&artifacts.demuxed_keccak_precompile_queue_simulator);
        let memory_queue_input_state =
            take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);
        let current_memory_queue_state = memory_queue_input_state.clone();

        let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
        observable_input_data.initial_memory_state = memory_queue_input_state.clone();
        observable_input_data.initial_log_queue_state = log_queue_input_state.clone();

        let mut observable_output_data = PrecompileFunctionOutputData::placeholder_witness();
        observable_output_data.final_memory_state = current_memory_queue_state.clone();

        let mut hidden_fsm_input_state = KeccakPrecompileState::<E>::placeholder_witness();
        hidden_fsm_input_state.read_precompile_call = true;

        let mut hidden_fsm_output_state = KeccakPrecompileState::<E>::placeholder_witness();
        hidden_fsm_output_state.completed = true;

        // internal state is a bit more tricky, it'll be a round over empty input
        use zk_evm::precompiles::keccak256::Keccak256;
        let mut internal_state_over_empty_buffer = Keccak256::default();
        use zk_evm::precompiles::keccak256::KECCAK_RATE_IN_U64_WORDS;
        let empty_block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];
        use zk_evm::precompiles::keccak256::Digest;
        internal_state_over_empty_buffer.update(&empty_block);
        let empty_state_inner = zk_evm::precompiles::keccak256::transmute_state(
            internal_state_over_empty_buffer.clone(),
        );
        let mut keccak_internal_state_over_empty_buffer = vec![];
        for i in 0..5 {
            for j in 0..5 {
                let el = empty_state_inner[i + 5 * j]; // circuit and non-circuit impls have different order
                keccak_internal_state_over_empty_buffer.push(el);
            }
        }

        let keccak_internal_state: [E::Fr; 25] = keccak_internal_state_over_empty_buffer
            .into_iter()
            .map(|el| u64_to_fe::<E::Fr>(el))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        hidden_fsm_output_state.keccak_internal_state = keccak_internal_state;

        let witness = Keccak256RoundFunctionInstanceWitness::<E> {
            closed_form_input: Keccak256RoundFunctionInputOutputWitness::<E> {
                start_flag: true,
                completion_flag: true,
                observable_input: observable_input_data,
                observable_output: observable_output_data,
                hidden_fsm_input: Keccak256RoundFunctionFSMWitness::<E> {
                    precompile_state: hidden_fsm_input_state,
                    log_queue_state: log_queue_input_state.clone(),

                    memory_queue_state: memory_queue_input_state.clone(),
                    _marker: std::marker::PhantomData,
                },
                hidden_fsm_output: Keccak256RoundFunctionFSMWitness::<E> {
                    precompile_state: hidden_fsm_output_state,
                    log_queue_state: take_queue_state_from_simulator(
                        &artifacts.demuxed_keccak_precompile_queue_simulator,
                    ),
                    memory_queue_state: current_memory_queue_state.clone(),
                    _marker: std::marker::PhantomData,
                },
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            requests_queue_witness: FixedWidthEncodingGenericQueueWitness {
                wit: VecDeque::new(),
            },
            memory_reads_witness: vec![],
        };
        result.push(witness);

        return result;
    }

    let mut round_counter = 0;
    let num_requests = keccak_precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&artifacts.demuxed_keccak_precompile_queue_simulator);
    use sync_vm::traits::CSWitnessable;

    use sync_vm::precompiles::keccak256::KeccakPrecompileState;

    let mut hidden_fsm_input_state = KeccakPrecompileState::<E>::placeholder_witness();
    hidden_fsm_input_state.read_precompile_call = true;

    let mut memory_queries_it = memory_queries.into_iter();

    let mut memory_read_witnesses = vec![];

    let mut precompile_state = Keccak256PrecompileState::GetRequestFromQueue;

    let mut request_ranges = vec![];
    let mut starting_request_idx = 0;

    let mut memory_queue_input_state =
        take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);
    let mut current_memory_queue_state = memory_queue_input_state.clone();

    for (request_idx, ((request, _queue_transition_state), per_request_work)) in
        keccak_precompile_calls
            .into_iter()
            .zip(keccak_precompile_calls_queue_states.into_iter())
            .zip(round_function_witness.into_iter())
            .enumerate()
    {
        // request level. Each request can be broken into few rounds

        let _ = artifacts
            .demuxed_keccak_precompile_queue_simulator
            .pop_and_output_intermediate_data(round_function);

        use zk_evm::precompiles::keccak256::Keccak256;
        let mut internal_state = Keccak256::default();

        let mut memory_reads_per_request = vec![];

        assert_eq!(
            precompile_state,
            Keccak256PrecompileState::GetRequestFromQueue
        );

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        // those are refreshed every cycle
        let mut input_buffer = zk_evm::precompiles::keccak256::Buffer::new();
        use zk_evm::precompiles::keccak256::NEW_WORDS_PER_CYCLE;
        let mut words_buffer = [0u64; NEW_WORDS_PER_CYCLE];

        use zk_evm::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let num_rounds = precompile_request.precompile_interpreted_data as usize;
        assert_eq!(num_rounds, round_witness.len());

        let mut num_rounds_left = num_rounds;

        let is_last_request = request_idx == num_requests - 1;

        precompile_state = Keccak256PrecompileState::RunRoundFunction;

        for (round_idx, round) in round_witness.into_iter().enumerate() {
            // we proceed the request as long as we can
            if round_idx == 0 {
                assert!(round.new_request.is_some());
            }

            // simulate absorb
            if input_buffer.can_read_into() {
                use zk_evm::precompiles::keccak256::NUM_WORDS_PER_QUERY;
                assert!(round.reads.is_some());
                let reads = round.reads.unwrap();
                for (query_index, read) in reads.into_iter().enumerate() {
                    let data = read.value;
                    let mut bytes32_buffer = [0u8; 32];
                    data.to_big_endian(&mut bytes32_buffer[..]);
                    for (i, chunk) in bytes32_buffer.chunks(8).enumerate() {
                        let as_u64 = u64::from_le_bytes(chunk.try_into().unwrap());
                        words_buffer[query_index * NUM_WORDS_PER_QUERY + i] = as_u64;
                    }

                    let read_query = memory_queries_it.next().unwrap();
                    assert_eq!(read, read_query);
                    memory_reads_per_request.push(biguint_from_u256(read_query.value));

                    artifacts.all_memory_queries_accumulated.push(read);
                    let (_, intermediate_info) = artifacts
                        .memory_queue_simulator
                        .push_and_output_intermediate_data(read, round_function);
                    artifacts.all_memory_queue_states.push(intermediate_info);
                    current_memory_queue_state = take_sponge_like_queue_state_from_simulator(
                        &artifacts.memory_queue_simulator,
                    );

                    precompile_request.input_memory_offset += 1;
                }

                input_buffer.append(&words_buffer);
            }

            let words = input_buffer.consume_rate();
            use zk_evm::precompiles::keccak256::KECCAK_RATE_IN_U64_WORDS;
            let mut block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];

            for (i, word) in words.into_iter().enumerate() {
                block[(i * 8)..(i * 8 + 8)].copy_from_slice(&word.to_le_bytes());
            }
            use zk_evm::precompiles::keccak256::Digest;
            internal_state.update(&block);

            num_rounds_left -= 1;

            let is_last_round = round_idx == num_rounds - 1;

            if is_last_round {
                assert_eq!(num_rounds_left, 0);
                assert!(round.writes.is_some());
                let [write] = round.writes.unwrap();
                let write_query = memory_queries_it.next().unwrap();
                assert_eq!(write, write_query);

                artifacts.all_memory_queries_accumulated.push(write);
                let (_, intermediate_info) = artifacts
                    .memory_queue_simulator
                    .push_and_output_intermediate_data(write, round_function);
                artifacts.all_memory_queue_states.push(intermediate_info);
                current_memory_queue_state =
                    take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);

                if is_last_request {
                    precompile_state = Keccak256PrecompileState::Finished;
                } else {
                    precompile_state = Keccak256PrecompileState::GetRequestFromQueue;
                }
            }

            round_counter += 1;

            if round_counter == num_rounds_per_circuit || (is_last_request && is_last_round) {
                let early_termination = round_counter != num_rounds_per_circuit;
                round_counter = 0;

                let finished = is_last_request && is_last_round;
                if finished {
                    assert!(memory_queries_it.next().is_none());
                }

                let state_inner =
                    zk_evm::precompiles::keccak256::transmute_state(internal_state.clone());
                let mut u64_words_buffer_markers = [false; BUFFER_SIZE];
                for i in 0..input_buffer.filled {
                    u64_words_buffer_markers[i] = true;
                }

                let mut keccak_internal_state = vec![];
                for i in 0..5 {
                    for j in 0..5 {
                        let el = state_inner[i + 5 * j]; // circuit and non-circuit impls have different order
                        keccak_internal_state.push(el);
                    }
                }

                let mut keccak_internal_state: [E::Fr; 25] = keccak_internal_state
                    .into_iter()
                    .map(|el| u64_to_fe::<E::Fr>(el))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                if early_termination {
                    assert_eq!(precompile_state, Keccak256PrecompileState::Finished);
                    // we finished all the requests, but didn't reset the state as circuit would do

                    // Even though any work of the circuit after requests are done is NOT observable
                    // and doesn't affect the correctness, we have a strict check that simulated input + output
                    // matches to what output circuit produced by itself based on the common input only
                    for el in u64_words_buffer_markers.iter_mut() {
                        *el = false;
                    }
                    for el in input_buffer.words.iter_mut() {
                        *el = 0u64;
                    }
                    // internal state is a bit more tricky, it'll be a round over empty input
                    let mut internal_state_over_empty_buffer = Keccak256::default();
                    let empty_block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];
                    use zk_evm::precompiles::keccak256::Digest;
                    internal_state_over_empty_buffer.update(&empty_block);
                    let empty_state_inner = zk_evm::precompiles::keccak256::transmute_state(
                        internal_state_over_empty_buffer.clone(),
                    );
                    let mut keccak_internal_state_over_empty_buffer = vec![];
                    for i in 0..5 {
                        for j in 0..5 {
                            let el = empty_state_inner[i + 5 * j]; // circuit and non-circuit impls have different order
                            keccak_internal_state_over_empty_buffer.push(el);
                        }
                    }

                    keccak_internal_state = keccak_internal_state_over_empty_buffer
                        .into_iter()
                        .map(|el| u64_to_fe::<E::Fr>(el))
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap();
                }

                let input_is_empty = is_last_request;
                let nothing_left = is_last_round && input_is_empty;

                assert_eq!(nothing_left, finished);

                let completed = precompile_state == Keccak256PrecompileState::Finished;
                let read_unaligned_words_for_round =
                    precompile_state == Keccak256PrecompileState::RunRoundFunction;
                let read_precompile_call =
                    precompile_state == Keccak256PrecompileState::GetRequestFromQueue;

                use sync_vm::precompiles::keccak256::*;

                let hidden_fsm_output_state = KeccakPrecompileStateWitness::<E> {
                    completed,
                    read_unaligned_words_for_round,
                    keccak_internal_state,
                    read_precompile_call,
                    timestamp_to_use_for_read: request.timestamp.0,
                    timestamp_to_use_for_write: request.timestamp.0 + 1,
                    u64_words_buffer: input_buffer.words,
                    u64_words_buffer_markers,
                    call_params: KeccakPrecompileCallParamsWitness::<E> {
                        input_page: precompile_request.memory_page_to_read,
                        input_offset: precompile_request.input_memory_offset,
                        output_page: precompile_request.memory_page_to_write,
                        output_offset: precompile_request.output_memory_offset,
                        num_rounds: num_rounds_left as u16,
                        _marker: std::marker::PhantomData,
                    },

                    _marker: std::marker::PhantomData,
                };

                use crate::encodings::log_query::log_query_into_storage_record_witness;

                let range = starting_request_idx..(request_idx + 1);
                let wit: VecDeque<_> = (&simulator_witness[range])
                    .iter()
                    .map(|el| {
                        let mapped = log_query_into_storage_record_witness::<E>(&el.2);

                        (el.0, mapped, el.1)
                    })
                    .collect();

                let current_reads = std::mem::replace(&mut memory_reads_per_request, vec![]);
                let mut current_witness = std::mem::replace(&mut memory_read_witnesses, vec![]);
                current_witness.push(current_reads);

                let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
                if result.len() == 0 {
                    observable_input_data.initial_log_queue_state = log_queue_input_state.clone();
                    observable_input_data.initial_memory_state = memory_queue_input_state.clone();
                }

                let mut observable_output_data =
                    PrecompileFunctionOutputData::placeholder_witness();
                if finished {
                    observable_output_data.final_memory_state = current_memory_queue_state.clone();
                }

                let witness = Keccak256RoundFunctionInstanceWitness::<E> {
                    closed_form_input: Keccak256RoundFunctionInputOutputWitness::<E> {
                        start_flag: result.len() == 0,
                        completion_flag: finished,
                        observable_input: observable_input_data,
                        observable_output: observable_output_data,
                        hidden_fsm_input: Keccak256RoundFunctionFSMWitness::<E> {
                            precompile_state: hidden_fsm_input_state,
                            log_queue_state: log_queue_input_state.clone(),

                            memory_queue_state: memory_queue_input_state.clone(),
                            _marker: std::marker::PhantomData,
                        },
                        hidden_fsm_output: Keccak256RoundFunctionFSMWitness::<E> {
                            precompile_state: hidden_fsm_output_state.clone(),
                            log_queue_state: take_queue_state_from_simulator(
                                &artifacts.demuxed_keccak_precompile_queue_simulator,
                            ),
                            memory_queue_state: current_memory_queue_state.clone(),
                            _marker: std::marker::PhantomData,
                        },
                        _marker_e: (),
                        _marker: std::marker::PhantomData,
                    },
                    requests_queue_witness: FixedWidthEncodingGenericQueueWitness { wit: wit },
                    memory_reads_witness: current_witness,
                };

                // make non-inclusize
                request_ranges.push(starting_request_idx..(request_idx + 1));
                starting_request_idx = request_idx + 1;

                result.push(witness);

                log_queue_input_state = take_queue_state_from_simulator(
                    &artifacts.demuxed_keccak_precompile_queue_simulator,
                );
                hidden_fsm_input_state = hidden_fsm_output_state;
                memory_queue_input_state = current_memory_queue_state.clone();
            }
        }

        if !memory_reads_per_request.is_empty() {
            // we may have drained it already if it was the end of the circuit
            memory_read_witnesses.push(memory_reads_per_request);
        }
    }

    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    result
}

// #[cfg(test)]
// mod test {
//     use super::*;

//     use sync_vm::scheduler::queues::StorageLogQueue;
//     use sync_vm::{
//         franklin_crypto::{
//             bellman::{SynthesisError},
//             plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns,
//         },
//         precompiles::keccak256::{
//             keccak256_precompile_inner, KeccakPrecompileState,
//         },
//         scheduler::queues::{FixedWidthEncodingGenericQueueState, FullSpongeLikeQueueState},
//         testing::create_test_artifacts_with_optimized_gate,
//         traits::{CSAllocatable, CSWitnessable},
//     };
//     type E = sync_vm::testing::Bn256;

//     use sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueriesQueue;

//     #[test]
//     fn test_witness_coincides() -> Result<(), SynthesisError> {
//         let (mut dummy_cs, committer, _) = create_test_artifacts_with_optimized_gate();
//         let cs = &mut dummy_cs;
//         inscribe_default_range_table_for_bit_width_over_first_three_columns(cs, 16)?;

//         let limit = 16;

//         let witness: Keccak256RoundFunctionCircuitWitness<E> = { todo!() };

//         let Keccak256RoundFunctionCircuitWitness {
//             is_finished,
//             passthrough_data,
//             hidden_fsm_input,
//             hidden_fsm_output,
//             memory_reads_witness,
//         } = witness;

//         let initial_state = KeccakPrecompileState::alloc_from_witness(cs, Some(hidden_fsm_input))?;
//         let Keccak256RoundFunctionPassthroughStructureWitness {
//             memory_queue_input_state,
//             memory_queue_output_state,
//             log_queue_input_state,
//             log_queue_output_state,
//             ..
//         } = passthrough_data;

//         let initial_memory_state =
//             FullSpongeLikeQueueState::alloc_from_witness(cs, Some(memory_queue_input_state))?;
//         let mut memory_queue = MemoryQueriesQueue::from_state(cs, initial_memory_state)?;

//         let initial_requests_queue_state = FixedWidthEncodingGenericQueueState::alloc_from_witness(
//             cs,
//             Some(log_queue_input_state),
//         )?;
//         let mut requests_queue = StorageLogQueue::from_state(cs, initial_requests_queue_state)?;

//         let final_state = keccak256_precompile_inner(
//             cs,
//             &mut memory_queue,
//             &mut requests_queue,
//             Some(memory_reads_witness),
//             initial_state,
//             &committer,
//             limit,
//         )?;

//         let final_memory_queue_state = memory_queue.into_state().create_witness().unwrap();
//         assert_eq!(
//             final_memory_queue_state.head,
//             memory_queue_output_state.head
//         );
//         assert_eq!(
//             final_memory_queue_state.tail,
//             memory_queue_output_state.tail
//         );
//         assert_eq!(
//             final_memory_queue_state.length,
//             memory_queue_output_state.length
//         );

//         let final_requests_queue_state = requests_queue.into_state().create_witness().unwrap();
//         assert_eq!(
//             final_requests_queue_state.head_state,
//             log_queue_output_state.head_state
//         );
//         assert_eq!(
//             final_requests_queue_state.tail_state,
//             log_queue_output_state.tail_state
//         );
//         assert_eq!(
//             final_requests_queue_state.num_items,
//             log_queue_output_state.num_items
//         );

//         let final_state = final_state.create_witness().unwrap();
//         assert_eq!(
//             final_state.keccak_internal_state,
//             hidden_fsm_output.keccak_internal_state
//         );

//         Ok(())
//     }
// }
