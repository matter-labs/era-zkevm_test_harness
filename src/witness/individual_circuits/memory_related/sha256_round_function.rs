use super::*;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::witness::artifacts::{DemuxedLogQueries, LogQueueStates};
use crate::witness::aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator;
use crate::witness::aux_data_structs::MemoryQueuePerCircuitSimulator;
use crate::zk_evm::aux_structures::LogQuery as LogQuery_;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;
use crate::zk_evm::zkevm_opcode_defs::ethereum_types::U256;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::sha256_round_function::input::*;
use crate::zkevm_circuits::sha256_round_function::*;
use circuit_definitions::encodings::memory_query::MemoryQueueSimulator;
use circuit_definitions::encodings::memory_query::MemoryQueueState;
use circuit_definitions::encodings::*;
use derivative::*;

pub(crate) fn sha256_memory_queries(
    sha256_round_function_witnesses: &Vec<(u32, LogQuery_, Vec<Sha256RoundWitness>)>,
) -> Vec<MemoryQuery> {
    let amount_of_queries =
        sha256_round_function_witnesses
            .iter()
            .fold(0, |mut inner, (_, _, witness)| {
                for el in witness.iter() {
                    inner += el.reads.len();

                    if let Some(writes) = el.writes.as_ref() {
                        inner += writes.len()
                    }
                }
                inner
            });

    let mut sha256_memory_queries = Vec::with_capacity(amount_of_queries);

    for (_cycle, _query, witness) in sha256_round_function_witnesses.iter() {
        for el in witness.iter() {
            let Sha256RoundWitness {
                new_request: _,
                reads,
                writes,
            } = el;

            // we read, then write
            sha256_memory_queries.extend_from_slice(reads);

            if let Some(writes) = writes.as_ref() {
                sha256_memory_queries.extend_from_slice(writes);
            }
        }
    }

    sha256_memory_queries
}

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

pub(crate) fn sha256_decompose_into_per_circuit_witness<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    amount_of_memory_queries_before: usize,
    sha256_memory_queries: Vec<MemoryQuery>,
    sha256_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    sha256_memory_states: Vec<MemoryQueueState<F>>,
    sha256_round_function_witnesses: Vec<(u32, LogQuery_, Vec<Sha256RoundWitness>)>,
    sha256_precompile_queries: Vec<LogQuery_>,
    mut demuxed_sha256_precompile_queue: LogQueueStates<F>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> (Vec<Sha256RoundFunctionCircuitInstanceWitness<F>>, usize) {
    assert_eq!(sha256_memory_queries.len(), sha256_memory_states.len());

    let memory_simulator_before = &sha256_simulator_snapshots[0];
    assert_eq!(
        amount_of_memory_queries_before,
        memory_simulator_before.num_items as usize
    );

    let mut result = vec![];

    let precompile_calls = sha256_precompile_queries;
    let simulator_witness: Vec<_> = demuxed_sha256_precompile_queue
        .simulator
        .witness
        .clone()
        .into();
    let round_function_witness = sha256_round_function_witnesses;

    // check basic consistency
    assert!(precompile_calls.len() == demuxed_sha256_precompile_queue.states_accumulator.len());
    drop(demuxed_sha256_precompile_queue.states_accumulator);
    assert!(precompile_calls.len() == round_function_witness.len());

    if precompile_calls.len() == 0 {
        return (vec![], amount_of_memory_queries_before);
    }

    let mut round_counter = 0;
    let num_requests = precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&demuxed_sha256_precompile_queue.simulator);
    let mut hidden_fsm_input_state = Sha256RoundFunctionFSM::<F>::placeholder_witness();
    hidden_fsm_input_state.read_precompile_call = true;

    let amount_sha256_memory_queries = sha256_memory_queries.len();
    let mut memory_queries_it = sha256_memory_queries.into_iter();

    let mut memory_read_witnesses = vec![];

    let mut precompile_state = Sha256PrecompileState::GetRequestFromQueue;

    let mut request_ranges = vec![];
    let mut starting_request_idx = 0;

    let mut memory_queue_input_state = memory_simulator_before.take_sponge_like_queue_state();
    let mut current_memory_queue_state = memory_queue_input_state.clone();

    let mut memory_queue_states_it = sha256_memory_states.iter();

    for (request_idx, (request, per_request_work)) in precompile_calls
        .into_iter()
        .zip(round_function_witness.into_iter())
        .enumerate()
    {
        let _ = demuxed_sha256_precompile_queue
            .simulator
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

                current_memory_queue_state =
                    transform_sponge_like_queue_state(*memory_queue_states_it.next().unwrap());

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

                current_memory_queue_state =
                    transform_sponge_like_queue_state(*memory_queue_states_it.next().unwrap());

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

                let current_reads = std::mem::take(&mut memory_reads_per_request);
                let mut current_witness = std::mem::take(&mut memory_read_witnesses);
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
                                &demuxed_sha256_precompile_queue.simulator,
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

                log_queue_input_state =
                    take_queue_state_from_simulator(&demuxed_sha256_precompile_queue.simulator);
                hidden_fsm_input_state = hidden_fsm_output_state;
                memory_queue_input_state = current_memory_queue_state.clone();
            }
        }

        if !memory_reads_per_request.is_empty() {
            // we may have drained it already if it was the end of the circuit
            memory_read_witnesses.push(memory_reads_per_request);
        }
    }

    let memory_simulator_after = &sha256_simulator_snapshots[1];
    let amount_of_memory_queries_after =
        amount_of_memory_queries_before + amount_sha256_memory_queries;

    assert_eq!(
        amount_of_memory_queries_after,
        memory_simulator_after.num_items as usize
    );

    (result, amount_of_memory_queries_after)
}
