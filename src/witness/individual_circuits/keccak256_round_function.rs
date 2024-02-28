use super::*;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::keccak256_round_function::{
    input::*, Keccak256PrecompileCallParamsWitness,
};
use circuit_definitions::encodings::*;
use derivative::*;

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
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> Vec<Keccak256RoundFunctionCircuitInstanceWitness<F>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    // split into aux witness, don't mix with the memory
    use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;

    for (_cycle, _query, witness) in artifacts.keccak_round_function_witnesses.iter() {
        for el in witness.iter() {
            let Keccak256RoundWitness {
                new_request: _,
                reads,
                writes,
            } = el;

            // we read, then write
            reads.iter().for_each(|read| {
                if let Some(read) = read {
                    artifacts.keccak_256_memory_queries.push(*read);
                }
            });

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
        observable_input_data.initial_memory_queue_state = memory_queue_input_state.clone();
        observable_input_data.initial_log_queue_state = log_queue_input_state.clone();

        let mut observable_output_data = PrecompileFunctionOutputData::placeholder_witness();
        observable_output_data.final_memory_state = current_memory_queue_state.clone();

        let mut hidden_fsm_input_state = Keccak256RoundFunctionFSM::<F>::placeholder_witness();
        hidden_fsm_input_state.read_precompile_call = true;

        let mut hidden_fsm_output_state = Keccak256RoundFunctionFSM::<F>::placeholder_witness();
        hidden_fsm_output_state.completed = true;

        // internal state is a bit more tricky, it'll be a round over empty input
        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256;
        let mut internal_state_over_empty_buffer = Keccak256::default();
        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::KECCAK_RATE_IN_U64_WORDS;
        let empty_block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];
        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Digest;
        internal_state_over_empty_buffer.update(&empty_block);
        let empty_state_inner =
            zk_evm::zk_evm_abstractions::precompiles::keccak256::transmute_state(
                internal_state_over_empty_buffer.clone(),
            );

        let keccak_internal_state = encode_kecca256_inner_state(empty_state_inner);
        hidden_fsm_output_state.keccak_internal_state = keccak_internal_state;

        let witness = Keccak256RoundFunctionCircuitInstanceWitness::<F> {
            closed_form_input: Keccak256RoundFunctionCircuitInputOutputWitness::<F> {
                start_flag: true,
                completion_flag: true,
                observable_input: observable_input_data,
                observable_output: observable_output_data,
                hidden_fsm_input: Keccak256RoundFunctionFSMInputOutputWitness::<F> {
                    internal_fsm: hidden_fsm_input_state,
                    log_queue_state: log_queue_input_state.clone(),
                    memory_queue_state: memory_queue_input_state.clone(),
                },
                hidden_fsm_output: Keccak256RoundFunctionFSMInputOutputWitness::<F> {
                    internal_fsm: hidden_fsm_output_state,
                    log_queue_state: take_queue_state_from_simulator(
                        &artifacts.demuxed_keccak_precompile_queue_simulator,
                    ),
                    memory_queue_state: current_memory_queue_state.clone(),
                },
            },
            requests_queue_witness: CircuitQueueRawWitness::<
                F,
                LogQuery<F>,
                4,
                LOG_QUERY_PACKED_WIDTH,
            > {
                elements: VecDeque::new(),
            },
            memory_reads_witness: VecDeque::new(),
        };
        result.push(witness);

        return result;
    }

    let mut round_counter = 0;
    let num_requests = keccak_precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&artifacts.demuxed_keccak_precompile_queue_simulator);

    let mut hidden_fsm_input_state = Keccak256RoundFunctionFSM::<F>::placeholder_witness();
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

        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256;
        let mut internal_state = Keccak256::default();

        let mut memory_reads_per_request = vec![];

        assert_eq!(
            precompile_state,
            Keccak256PrecompileState::GetRequestFromQueue
        );

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        // those are refreshed every cycle
        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::KECCAK_PRECOMPILE_BUFFER_SIZE;
        let mut input_buffer = zk_evm::zk_evm_abstractions::precompiles::keccak256::ByteBuffer {
            bytes: [0u8; KECCAK_PRECOMPILE_BUFFER_SIZE],
            filled: 0,
        };
        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::MEMORY_READS_PER_CYCLE;
        use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::NUM_WORDS_PER_QUERY;
        let mut words_buffer = [0u8; NUM_WORDS_PER_QUERY * MEMORY_READS_PER_CYCLE * 8];

        use crate::zk_evm::zk_evm_abstractions::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let num_rounds = precompile_request.precompile_interpreted_data as usize;
        assert_eq!(num_rounds, round_witness.len());

        let mut num_rounds_left = num_rounds;

        let is_last_request = request_idx == num_requests - 1;

        precompile_state = Keccak256PrecompileState::RunRoundFunction;

        let needs_full_padding_round =
            precompile_request.input_memory_length as usize % KECCAK_PRECOMPILE_BUFFER_SIZE == 0;

        for (round_idx, round) in round_witness.into_iter().enumerate() {
            // we proceed the request as long as we can
            if round_idx == 0 {
                assert!(round.new_request.is_some());
            }

            // simulate absorb
            if input_buffer.can_fill_bytes(NUM_WORDS_PER_QUERY * MEMORY_READS_PER_CYCLE * 8) {
                use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::NUM_WORDS_PER_QUERY;
                for (query_index, read) in round.reads.into_iter().enumerate() {
                    if read.is_none() {
                        continue;
                    }
                    let read = read.unwrap();
                    let data = read.value;
                    data.to_big_endian(&mut words_buffer[..]);

                    let read_query = memory_queries_it.next().unwrap();
                    assert_eq!(read, read_query);
                    memory_reads_per_request.push(read_query.value);

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

                input_buffer.fill_with_bytes(&words_buffer, 0, 32);
            }

            let words: Vec<u64> = input_buffer
                .consume::<KECCAK_PRECOMPILE_BUFFER_SIZE>()
                .chunks(8)
                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                .collect();
            use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::KECCAK_RATE_IN_U64_WORDS;
            let mut block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];

            for (i, word) in words.into_iter().enumerate() {
                block[(i * 8)..(i * 8 + 8)].copy_from_slice(&word.to_le_bytes());
            }
            use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Digest;
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
                    zk_evm::zk_evm_abstractions::precompiles::keccak256::transmute_state(
                        internal_state.clone(),
                    );
                let mut u64_words_buffer_markers =
                    [false; zkevm_circuits::keccak256_round_function::BUFFER_SIZE_IN_U64_WORDS];
                for i in 0..input_buffer.filled {
                    u64_words_buffer_markers[i] = true;
                }

                let mut keccak_internal_state = encode_kecca256_inner_state(state_inner);

                if early_termination {
                    assert_eq!(precompile_state, Keccak256PrecompileState::Finished);
                    // we finished all the requests, but didn't reset the state as circuit would do

                    // Even though any work of the circuit after requests are done is NOT observable
                    // and doesn't affect the correctness, we have a strict check that simulated input + output
                    // matches to what output circuit produced by itself based on the common input only
                    for el in u64_words_buffer_markers.iter_mut() {
                        *el = false;
                    }
                    for el in input_buffer.bytes.iter_mut() {
                        *el = 0u8;
                    }
                    // internal state is a bit more tricky, it'll be a round over empty input
                    let mut internal_state_over_empty_buffer = Keccak256::default();
                    let empty_block = [0u8; KECCAK_RATE_IN_U64_WORDS * 8];
                    use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Digest;
                    internal_state_over_empty_buffer.update(&empty_block);
                    let empty_state_inner =
                        zk_evm::zk_evm_abstractions::precompiles::keccak256::transmute_state(
                            internal_state_over_empty_buffer.clone(),
                        );

                    keccak_internal_state = encode_kecca256_inner_state(empty_state_inner);
                }

                let input_is_empty = is_last_request;
                let nothing_left = is_last_round && input_is_empty;

                assert_eq!(nothing_left, finished);

                let completed = precompile_state == Keccak256PrecompileState::Finished;
                let read_unaligned_words_for_round =
                    precompile_state == Keccak256PrecompileState::RunRoundFunction;
                let read_precompile_call =
                    precompile_state == Keccak256PrecompileState::GetRequestFromQueue;

                let padding_round = read_unaligned_words_for_round
                    && precompile_request.input_memory_length == 0
                    && needs_full_padding_round;

                let hidden_fsm_output_state = Keccak256RoundFunctionFSMWitness::<F> {
                    completed,
                    read_unaligned_words_for_round,
                    padding_round,
                    keccak_internal_state,
                    read_precompile_call,
                    timestamp_to_use_for_read: request.timestamp.0,
                    timestamp_to_use_for_write: request.timestamp.0 + 1,
                    precompile_call_params: Keccak256PrecompileCallParamsWitness::<F> {
                        input_page: precompile_request.memory_page_to_read,
                        input_memory_byte_offset: precompile_request.input_memory_offset,
                        input_memory_byte_length: precompile_request.input_memory_length,
                        output_page: precompile_request.memory_page_to_write,
                        output_word_offset: precompile_request.output_memory_offset,
                        needs_full_padding_round,
                    },
                    buffer: zkevm_circuits::keccak256_round_function::buffer::ByteBufferWitness {
                        bytes: input_buffer.bytes,
                        filled: input_buffer.filled as u8,
                    },
                };

                let range = starting_request_idx..(request_idx + 1);
                let wit: VecDeque<_> = (&simulator_witness[range])
                    .iter()
                    .map(|el| {
                        let mapped = log_query_into_circuit_log_query_witness(&el.2);

                        (mapped, el.1)
                    })
                    .collect();

                let current_reads = std::mem::replace(&mut memory_reads_per_request, vec![]);
                let mut current_witness = std::mem::replace(&mut memory_read_witnesses, vec![]);
                current_witness.push(current_reads);

                let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
                if result.len() == 0 {
                    observable_input_data.initial_log_queue_state = log_queue_input_state.clone();
                    observable_input_data.initial_memory_queue_state =
                        memory_queue_input_state.clone();
                }

                let mut observable_output_data =
                    PrecompileFunctionOutputData::placeholder_witness();
                if finished {
                    observable_output_data.final_memory_state = current_memory_queue_state.clone();
                }

                let witness = Keccak256RoundFunctionCircuitInstanceWitness::<F> {
                    closed_form_input: Keccak256RoundFunctionCircuitInputOutputWitness::<F> {
                        start_flag: result.len() == 0,
                        completion_flag: finished,
                        observable_input: observable_input_data,
                        observable_output: observable_output_data,
                        hidden_fsm_input: Keccak256RoundFunctionFSMInputOutputWitness::<F> {
                            internal_fsm: hidden_fsm_input_state,
                            log_queue_state: log_queue_input_state.clone(),
                            memory_queue_state: memory_queue_input_state.clone(),
                        },
                        hidden_fsm_output: Keccak256RoundFunctionFSMInputOutputWitness::<F> {
                            internal_fsm: hidden_fsm_output_state.clone(),
                            log_queue_state: take_queue_state_from_simulator(
                                &artifacts.demuxed_keccak_precompile_queue_simulator,
                            ),
                            memory_queue_state: current_memory_queue_state.clone(),
                        },
                    },
                    requests_queue_witness: CircuitQueueRawWitness::<
                        F,
                        LogQuery<F>,
                        4,
                        LOG_QUERY_PACKED_WIDTH,
                    > {
                        elements: wit,
                    },
                    memory_reads_witness: current_witness.into_iter().flatten().collect(),
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

pub(crate) fn encode_kecca256_inner_state(state: [u64; 25]) -> [[[u8; 8]; 5]; 5] {
    // we need to transpose
    let mut result = [[[0u8; 8]; 5]; 5];
    for (idx, src) in state.iter().enumerate() {
        let i = idx % 5;
        let j = idx / 5;
        let dst = &mut result[i][j];
        *dst = src.to_le_bytes();
    }

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
//         let mut memory_queue = MemoryQueriesQueuFom_state(cs, initial_memory_state)?;

//         let initial_requests_queue_state = FixedWidthEncodingGenericQueueState::alloc_from_witness(
//             cs,
//             Some(log_queue_input_state),
//         )?;
//         let mut requests_queue = StorageLogQueuFom_state(cs, initial_requests_queue_state)?;

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
