use super::*;
use crate::witness::full_block_artifact::LogQueue;
use crate::zk_evm::zkevm_opcode_defs::ethereum_types::U256;
use crate::zkevm_circuits::base_structures::log_query::*;
use crate::zkevm_circuits::secp256r1_verify::*;
use circuit_definitions::encodings::*;

// we want to simulate splitting of data into many separate instances of the same circuit.
// So we basically need to reconstruct the FSM state on input/output, and passthrough data.
// In practice the only difficulty is buffer state, everything else is provided by out-of-circuit VM

pub fn secp256r1_verify_decompose_into_per_circuit_witness<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    mut demuxed_secp256r1_verify_queue: LogQueue<F>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> Vec<Secp256r1VerifyCircuitInstanceWitness<F>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    // split into aux witness, don't mix with the memory

    use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
    let mut memory_queries = vec![];

    for (_cycle, _query, witness) in artifacts.secp256r1_verify_witnesses.iter() {
        let Secp256r1VerifyRoundWitness {
            new_request: _,
            reads,
            writes,
        } = witness;

        // we read, then write
        memory_queries.extend_from_slice(reads);

        memory_queries.extend_from_slice(writes);
    }

    let mut result = vec![];

    let precompile_calls = std::mem::replace(&mut artifacts.demuxed_secp256r1_verify_queries, vec![]);
    let precompile_calls_queue_states =
        std::mem::replace(&mut demuxed_secp256r1_verify_queue.states, vec![]);
    let simulator_witness: Vec<_> = demuxed_secp256r1_verify_queue.simulator.witness.clone().into();
    let round_function_witness = std::mem::replace(&mut artifacts.secp256r1_verify_witnesses, vec![]);

    // check basic consistency
    assert!(precompile_calls.len() == precompile_calls_queue_states.len());
    assert!(precompile_calls.len() == round_function_witness.len());

    if precompile_calls.len() == 0 {
        return vec![];
    }

    let mut round_counter = 0;
    let num_requests = precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&demuxed_secp256r1_verify_queue.simulator);
    let mut memory_queries_it = memory_queries.into_iter();

    let mut memory_read_witnesses = vec![];
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
        let _ = demuxed_secp256r1_verify_queue
            .simulator
            .pop_and_output_intermediate_data(round_function);
        let initial_memory_len = artifacts.memory_queue_simulator.num_items;

        let mut memory_reads_per_request = vec![];

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        use crate::zk_evm::zk_evm_abstractions::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let is_last_request = request_idx == num_requests - 1;

        // we have reads
        for (_query_index, read) in round_witness.reads.into_iter().enumerate() {
            let read_query = memory_queries_it.next().unwrap();
            assert!(read == read_query);
            assert!(read_query.rw_flag == false);
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

        // and writes
        for (_query_index, write) in round_witness.writes.into_iter().enumerate() {
            let write_query = memory_queries_it.next().unwrap();
            assert!(write == write_query);
            assert!(write_query.rw_flag == true);

            artifacts.all_memory_queries_accumulated.push(write);
            let (_, intermediate_info) = artifacts
                .memory_queue_simulator
                .push_and_output_intermediate_data(write, round_function);
            artifacts.all_memory_queue_states.push(intermediate_info);
            current_memory_queue_state =
                take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);

            precompile_request.output_memory_offset += 1;
        }

        assert_eq!(
            artifacts.memory_queue_simulator.num_items - initial_memory_len,
            7
        );
        round_counter += 1;

        if round_counter == num_rounds_per_circuit || is_last_request {
            round_counter = 0;

            let finished = is_last_request;
            if finished {
                assert!(memory_queries_it.next().is_none());
            }

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
                observable_input_data.initial_memory_queue_state = memory_queue_input_state.clone();
                observable_input_data.initial_log_queue_state = log_queue_input_state.clone();
            }

            let mut observable_output_data = PrecompileFunctionOutputData::placeholder_witness();
            if finished {
                observable_output_data.final_memory_state = current_memory_queue_state.clone();
            }

            let witness = Secp256r1VerifyCircuitInstanceWitness::<F> {
                closed_form_input: Secp256r1VerifyCircuitInputOutputWitness::<F> {
                    start_flag: result.len() == 0,
                    completion_flag: finished,
                    observable_input: observable_input_data,
                    observable_output: observable_output_data,
                    hidden_fsm_input: Secp256r1VerifyCircuitFSMInputOutputWitness::<F> {
                        log_queue_state: log_queue_input_state.clone(),
                        memory_queue_state: memory_queue_input_state,
                    },
                    hidden_fsm_output: Secp256r1VerifyCircuitFSMInputOutputWitness::<F> {
                        log_queue_state: take_queue_state_from_simulator(
                            &demuxed_secp256r1_verify_queue.simulator,
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
                memory_reads_witness: current_witness
                    .into_iter()
                    .map(|el| el.try_into().expect("length must match"))
                    .collect(),
            };

            // make non-inclusize
            starting_request_idx = request_idx + 1;

            result.push(witness);

            log_queue_input_state =
                take_queue_state_from_simulator(&demuxed_secp256r1_verify_queue.simulator);
            memory_queue_input_state = current_memory_queue_state.clone();
        }

        if !memory_reads_per_request.is_empty() {
            // we may have drained it already if it was the end of the circuit
            memory_read_witnesses.push(memory_reads_per_request);
        }
    }

    result
}
