use super::*;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::zk_evm::zkevm_opcode_defs::ethereum_types::U256;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::sha256_round_function::input::*;
use crate::zkevm_circuits::sha256_round_function::*;
use circuit_definitions::encodings::*;
use derivative::*;

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha256PrecompileState {
    GetRequestFromQueue,
    RunRoundFunction,
    Finished,
}

// we want to simulate splitting of data into many separate instances of the same circuit.
// So we basically need to reconstruct the FSM state on input/output, and passthrough data.
// In practice the only difficulty is buffer state, everything else is provided by out-of-circuit VM

pub fn sha256_decompose_into_per_circuit_witness<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> Vec<Sha256RoundFunctionCircuitInstanceWitness<F>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    // split into aux witness, don't mix with the memory
    use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;

    for (_cycle, _query, witness) in artifacts.sha256_round_function_witnesses.iter() {
        for el in witness.iter() {
            let Sha256RoundWitness {
                new_request: _,
                reads,
                writes,
            } = el;

            // we read, then write
            artifacts.sha256_memory_queries.extend_from_slice(reads);

            if let Some(writes) = writes.as_ref() {
                artifacts.sha256_memory_queries.extend_from_slice(writes);
            }
        }
    }

    let mut result = vec![];

    let precompile_calls =
        std::mem::replace(&mut artifacts.demuxed_sha256_precompile_queries, vec![]);
    let precompile_calls_queue_states = std::mem::replace(
        &mut artifacts.demuxed_sha256_precompile_queue_states,
        vec![],
    );
    let simulator_witness: Vec<_> = artifacts
        .demuxed_sha256_precompile_queue_simulator
        .witness
        .clone()
        .into();
    let round_function_witness =
        std::mem::replace(&mut artifacts.sha256_round_function_witnesses, vec![]);

    let memory_queries = std::mem::replace(&mut artifacts.sha256_memory_queries, vec![]);

    // check basic consistency
    assert!(precompile_calls.len() == precompile_calls_queue_states.len());
    assert!(precompile_calls.len() == round_function_witness.len());

    if precompile_calls.len() == 0 {
        // we can not skip the circuit (at least for now), so we have to create a dummy on
        let log_queue_input_state =
            take_queue_state_from_simulator(&artifacts.demuxed_sha256_precompile_queue_simulator);
        let memory_queue_input_state =
            take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);
        let current_memory_queue_state = memory_queue_input_state.clone();

        let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
        observable_input_data.initial_memory_queue_state = memory_queue_input_state.clone();
        observable_input_data.initial_log_queue_state = log_queue_input_state.clone();

        let mut observable_output_data = PrecompileFunctionOutputData::placeholder_witness();
        observable_output_data.final_memory_state = current_memory_queue_state.clone();

        let mut hidden_fsm_input_state = Sha256RoundFunctionFSM::<F>::placeholder_witness();
        hidden_fsm_input_state.read_precompile_call = true;

        let mut hidden_fsm_output_state = Sha256RoundFunctionFSM::<F>::placeholder_witness();
        hidden_fsm_output_state.completed = true;

        use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256;
        // internal state is a bit more tricky, it'll be a round over empty input
        let mut internal_state_over_empty_buffer = Sha256::default();
        let empty_block = [0u8; 64];
        use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Digest;
        internal_state_over_empty_buffer.update(&empty_block);
        let sha256_internal_state_over_empty_buffer =
            zk_evm::zk_evm_abstractions::precompiles::sha256::transmute_state(
                internal_state_over_empty_buffer.clone(),
            );

        let circuit_hash_internal_state = sha256_internal_state_over_empty_buffer;

        hidden_fsm_output_state.sha256_inner_state = circuit_hash_internal_state;

        let witness = Sha256RoundFunctionCircuitInstanceWitness::<F> {
            closed_form_input: Sha256RoundFunctionCircuitInputOutputWitness::<F> {
                start_flag: true,
                completion_flag: true,
                observable_input: observable_input_data,
                observable_output: observable_output_data,
                hidden_fsm_input: Sha256RoundFunctionFSMInputOutputWitness::<F> {
                    internal_fsm: hidden_fsm_input_state,
                    log_queue_state: log_queue_input_state.clone(),
                    memory_queue_state: memory_queue_input_state,
                },
                hidden_fsm_output: Sha256RoundFunctionFSMInputOutputWitness::<F> {
                    internal_fsm: hidden_fsm_output_state,
                    log_queue_state: take_queue_state_from_simulator(
                        &artifacts.demuxed_sha256_precompile_queue_simulator,
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
    let num_requests = precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&artifacts.demuxed_sha256_precompile_queue_simulator);
    let mut hidden_fsm_input_state = Sha256RoundFunctionFSM::<F>::placeholder_witness();
    hidden_fsm_input_state.read_precompile_call = true;

    let mut memory_queries_it = memory_queries.into_iter();

    let mut memory_read_witnesses = vec![];

    let mut precompile_state = Sha256PrecompileState::GetRequestFromQueue;

    let mut request_ranges = vec![];
    let mut starting_request_idx = 0;

    let mut memory_queue_input_state =
        take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);
    let mut current_memory_queue_state = memory_queue_input_state.clone();

    for (request_idx, ((request, _queue_transition_state), per_request_work)) in precompile_calls
        .into_iter()
        .zip(precompile_calls_queue_states.into_iter())
        .zip(round_function_witness.into_iter())
        .enumerate()
    {
        let _ = artifacts
            .demuxed_sha256_precompile_queue_simulator
            .pop_and_output_intermediate_data(round_function);

        use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256;
        let mut internal_state = Sha256::default();

        let mut memory_reads_per_request: Vec<U256> = vec![];

        assert_eq!(precompile_state, Sha256PrecompileState::GetRequestFromQueue);

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        use crate::zk_evm::zk_evm_abstractions::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let num_rounds = precompile_request.precompile_interpreted_data as usize;
        assert_eq!(num_rounds, round_witness.len());

        let mut num_rounds_left = num_rounds;

        let is_last_request = request_idx == num_requests - 1;

        precompile_state = Sha256PrecompileState::RunRoundFunction;

        for (round_idx, round) in round_witness.into_iter().enumerate() {
            if round_idx == 0 {
                assert!(round.new_request.is_some());
            }

            let mut block = [0u8; 64];

            // we have two reads
            for (dst, read) in block.array_chunks_mut::<32>().zip(round.reads.into_iter()) {
                let data = read.value;
                data.to_big_endian(dst);
                let read_query = memory_queries_it.next().unwrap();
                assert_eq!(read, read_query);
                memory_reads_per_request.push(read_query.value);

                artifacts.all_memory_queries_accumulated.push(read);
                let (_, intermediate_info) = artifacts
                    .memory_queue_simulator
                    .push_and_output_intermediate_data(read, round_function);
                artifacts.all_memory_queue_states.push(intermediate_info);
                current_memory_queue_state =
                    take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);

                precompile_request.input_memory_offset += 1;
            }
            use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Digest;
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
                    precompile_state = Sha256PrecompileState::Finished;
                } else {
                    precompile_state = Sha256PrecompileState::GetRequestFromQueue;
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

                let state_inner = zk_evm::zk_evm_abstractions::precompiles::sha256::transmute_state(
                    internal_state.clone(),
                );

                let mut circuit_hash_internal_state = state_inner;

                let input_is_empty = is_last_request;
                let nothing_left = is_last_round && input_is_empty;

                assert_eq!(nothing_left, finished);

                if early_termination {
                    assert_eq!(precompile_state, Sha256PrecompileState::Finished);
                    // we finished all the requests, but didn't reset the state as circuit would do

                    // Even though any work of the circuit after requests are done is NOT observable
                    // and doesn't affect the correctness, we have a strict check that simulated input + output
                    // matches to what output circuit produced by itself based on the common input only

                    // internal state is a bit more tricky, it'll be a round over empty input
                    let mut internal_state_over_empty_buffer = Sha256::default();
                    let empty_block = [0u8; 64];
                    use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Digest;
                    internal_state_over_empty_buffer.update(&empty_block);
                    let sha256_internal_state_over_empty_buffer =
                        zk_evm::zk_evm_abstractions::precompiles::sha256::transmute_state(
                            internal_state_over_empty_buffer.clone(),
                        );

                    circuit_hash_internal_state = sha256_internal_state_over_empty_buffer;
                }

                let completed = precompile_state == Sha256PrecompileState::Finished;
                let read_words_for_round =
                    precompile_state == Sha256PrecompileState::RunRoundFunction;
                let read_precompile_call =
                    precompile_state == Sha256PrecompileState::GetRequestFromQueue;

                let hidden_fsm_output_state = Sha256RoundFunctionFSMWitness::<F> {
                    completed,
                    read_words_for_round,
                    sha256_inner_state: circuit_hash_internal_state,
                    read_precompile_call,
                    timestamp_to_use_for_read: request.timestamp.0,
                    timestamp_to_use_for_write: request.timestamp.0 + 1,
                    precompile_call_params: Sha256PrecompileCallParamsWitness::<F> {
                        input_page: precompile_request.memory_page_to_read,
                        input_offset: precompile_request.input_memory_offset,
                        output_page: precompile_request.memory_page_to_write,
                        output_offset: precompile_request.output_memory_offset,
                        num_rounds: num_rounds_left as u32,
                    },
                };

                let range = starting_request_idx..(request_idx + 1);
                let wit: VecDeque<_> = (&simulator_witness[range])
                    .iter()
                    .map(|el| (log_query_into_circuit_log_query_witness(&el.2), el.1))
                    .collect();

                let current_reads = std::mem::replace(&mut memory_reads_per_request, vec![]);
                let mut current_witness = std::mem::replace(&mut memory_read_witnesses, vec![]);
                current_witness.push(current_reads);

                let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
                if result.len() == 0 {
                    observable_input_data.initial_memory_queue_state =
                        memory_queue_input_state.clone();
                    observable_input_data.initial_log_queue_state = log_queue_input_state.clone();
                }

                let mut observable_output_data =
                    PrecompileFunctionOutputData::placeholder_witness();
                if finished {
                    observable_output_data.final_memory_state = current_memory_queue_state.clone();
                }

                let witness = Sha256RoundFunctionCircuitInstanceWitness::<F> {
                    closed_form_input: Sha256RoundFunctionCircuitInputOutputWitness::<F> {
                        start_flag: result.len() == 0,
                        completion_flag: finished,
                        observable_input: observable_input_data,
                        observable_output: observable_output_data,
                        hidden_fsm_input: Sha256RoundFunctionFSMInputOutputWitness::<F> {
                            internal_fsm: hidden_fsm_input_state,
                            log_queue_state: log_queue_input_state.clone(),
                            memory_queue_state: memory_queue_input_state,
                        },
                        hidden_fsm_output: Sha256RoundFunctionFSMInputOutputWitness::<F> {
                            internal_fsm: hidden_fsm_output_state.clone(),
                            log_queue_state: take_queue_state_from_simulator(
                                &artifacts.demuxed_sha256_precompile_queue_simulator,
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
                    &artifacts.demuxed_sha256_precompile_queue_simulator,
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
