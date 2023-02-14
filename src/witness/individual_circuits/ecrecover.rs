use super::*;
use crate::biguint_from_u256;
use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use derivative::Derivative;
use num_bigint::BigUint;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::glue::ecrecover_circuit::input::*;
use sync_vm::precompiles::*;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;

// we want to simulate splitting of data into many separate instances of the same circuit.
// So we basically need to reconstruct the FSM state on input/output, and passthrough data.
// In practice the only difficulty is buffer state, everything else is provided by out-of-circuit VM

pub fn ecrecover_decompose_into_per_circuit_witness<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>,
>(
    artifacts: &mut FullBlockArtifacts<E>,
    num_rounds_per_circuit: usize,
    round_function: &R,
) -> Vec<EcrecoverCircuitInstanceWitness<E>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    // split into aux witness, don't mix with the memory

    use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
    for (_cycle, _query, witness) in artifacts.ecrecover_witnesses.iter() {
        let ECRecoverRoundWitness {
            new_request: _,
            reads,
            writes,
        } = witness;

        // we read, then write
        artifacts.ecrecover_memory_queries.extend_from_slice(reads);

        artifacts.ecrecover_memory_queries.extend_from_slice(writes);
    }

    let mut result = vec![];

    let precompile_calls = std::mem::replace(&mut artifacts.demuxed_ecrecover_queries, vec![]);
    let precompile_calls_queue_states =
        std::mem::replace(&mut artifacts.demuxed_ecrecover_queue_states, vec![]);
    let simulator_witness: Vec<_> = artifacts
        .demuxed_ecrecover_queue_simulator
        .witness
        .clone()
        .into();
    let round_function_witness = std::mem::replace(&mut artifacts.ecrecover_witnesses, vec![]);

    let memory_queries = std::mem::replace(&mut artifacts.ecrecover_memory_queries, vec![]);

    // check basic consistency
    assert!(precompile_calls.len() == precompile_calls_queue_states.len());
    assert!(precompile_calls.len() == round_function_witness.len());

    if precompile_calls.len() == 0 {
        // we can not skip the circuit (at least for now), so we have to create a dummy on
        let log_queue_input_state =
            take_queue_state_from_simulator(&artifacts.demuxed_ecrecover_queue_simulator);
        let memory_queue_input_state =
            take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);
        let current_memory_queue_state = memory_queue_input_state.clone();

        let mut observable_input_data = PrecompileFunctionInputData::placeholder_witness();
        observable_input_data.initial_memory_state = memory_queue_input_state.clone();
        observable_input_data.initial_log_queue_state = log_queue_input_state.clone();

        let mut observable_output_data = PrecompileFunctionOutputData::placeholder_witness();
        observable_output_data.final_memory_state = current_memory_queue_state.clone();

        let witness = EcrecoverCircuitInstanceWitness::<E> {
            closed_form_input: EcrecoverCircuitInputOutputWitness::<E> {
                start_flag: true,
                completion_flag: true,
                observable_input: observable_input_data,
                observable_output: observable_output_data,
                hidden_fsm_input: EcrecoverCircuitFSMInputOutputWitness::<E> {
                    log_queue_state: log_queue_input_state.clone(),
                    memory_queue_state: memory_queue_input_state,
                    _marker: std::marker::PhantomData,
                },
                hidden_fsm_output: EcrecoverCircuitFSMInputOutputWitness::<E> {
                    log_queue_state: take_queue_state_from_simulator(
                        &artifacts.demuxed_sha256_precompile_queue_simulator,
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
    let num_requests = precompile_calls.len();

    // convension
    let mut log_queue_input_state =
        take_queue_state_from_simulator(&artifacts.demuxed_ecrecover_queue_simulator);
    use sync_vm::traits::CSWitnessable;

    let mut memory_queries_it = memory_queries.into_iter();

    let mut memory_read_witnesses = vec![];

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
            .demuxed_ecrecover_queue_simulator
            .pop_and_output_intermediate_data(round_function);
        let initial_memory_len = artifacts.memory_queue_simulator.num_items;

        let mut memory_reads_per_request = vec![];

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        use zk_evm::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let is_last_request = request_idx == num_requests - 1;

        // we have 4 reads
        for (_query_index, read) in round_witness.reads.into_iter().enumerate() {
            let read_query = memory_queries_it.next().unwrap();
            assert!(read == read_query);
            assert!(read_query.rw_flag == false);
            memory_reads_per_request.push(biguint_from_u256(read_query.value));

            artifacts.all_memory_queries_accumulated.push(read);
            let (_, intermediate_info) = artifacts
                .memory_queue_simulator
                .push_and_output_intermediate_data(read, round_function);
            artifacts.all_memory_queue_states.push(intermediate_info);
            current_memory_queue_state =
                take_sponge_like_queue_state_from_simulator(&artifacts.memory_queue_simulator);

            precompile_request.input_memory_offset += 1;
        }

        // and 2 writes
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
            6
        );
        round_counter += 1;

        if round_counter == num_rounds_per_circuit || is_last_request {
            round_counter = 0;

            let finished = is_last_request;
            if finished {
                assert!(memory_queries_it.next().is_none());
            }

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
                observable_input_data.initial_memory_state = memory_queue_input_state.clone();
                observable_input_data.initial_log_queue_state = log_queue_input_state.clone();
            }

            let mut observable_output_data = PrecompileFunctionOutputData::placeholder_witness();
            if finished {
                observable_output_data.final_memory_state = current_memory_queue_state.clone();
            }

            let witness = EcrecoverCircuitInstanceWitness::<E> {
                closed_form_input: EcrecoverCircuitInputOutputWitness::<E> {
                    start_flag: result.len() == 0,
                    completion_flag: finished,
                    observable_input: observable_input_data,
                    observable_output: observable_output_data,
                    hidden_fsm_input: EcrecoverCircuitFSMInputOutputWitness::<E> {
                        log_queue_state: log_queue_input_state.clone(),
                        memory_queue_state: memory_queue_input_state,
                        _marker: std::marker::PhantomData,
                    },
                    hidden_fsm_output: EcrecoverCircuitFSMInputOutputWitness::<E> {
                        log_queue_state: take_queue_state_from_simulator(
                            &artifacts.demuxed_ecrecover_queue_simulator,
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

            // dbg!(&witness);

            result.push(witness);

            log_queue_input_state =
                take_queue_state_from_simulator(&artifacts.demuxed_ecrecover_queue_simulator);
            memory_queue_input_state = current_memory_queue_state.clone();
        }

        if !memory_reads_per_request.is_empty() {
            // we may have drained it already if it was the end of the circuit
            memory_read_witnesses.push(memory_reads_per_request);
        }
    }

    result
}
