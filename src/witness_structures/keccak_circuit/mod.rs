use super::*;
use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use derivative::Derivative;
use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::glue::keccak256_round_function_circuit::*;
use zk_evm::precompiles::keccak256::BUFFER_SIZE;

pub type Keccak256CircuitFSMData<E> = Keccak256RoundFunctionFSMWitness<E>;
pub type Keccak256CircuitPassthroughData<E> = Keccak256RoundFunctionPassthroughStructureWitness<E>;

use crate::witness::full_block_artifact::FullBlockArtifacts;

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct Keccak256RoundFunctionCircuitWitness<E: Engine> {
    pub is_finished: bool,
    pub passthrough_data: Keccak256CircuitPassthroughData<E>,
    pub fsm_input: Keccak256CircuitFSMData<E>,
    pub fsm_output: Keccak256CircuitFSMData<E>,
}

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

pub fn decompose_into_per_circuit_witness<E: Engine>(
    artifacts: &mut FullBlockArtifacts<E>,
    num_rounds_per_circuit: usize,
) -> Vec<Keccak256RoundFunctionCircuitWitness<E>> {
    assert!(artifacts.is_processed);

    let mut result = vec![];

    let keccak_precompile_calls =
        std::mem::replace(&mut artifacts.demuxed_keccak_precompile_queries, vec![]);
    let keccak_precompile_calls_queue_states = std::mem::replace(
        &mut artifacts.demuxed_keccak_precompile_queue_states,
        vec![],
    );
    let round_function_witness =
        std::mem::replace(&mut artifacts.keccak_round_function_witnesses, vec![]);

    let memory_queries = std::mem::replace(&mut artifacts.keccak_256_memory_queries, vec![]);
    let memory_queue_states = std::mem::replace(&mut artifacts.keccak_256_memory_states, vec![]);

    // check basic consistency
    assert!(keccak_precompile_calls.len() == keccak_precompile_calls_queue_states.len());
    assert!(keccak_precompile_calls.len() == round_function_witness.len());

    if keccak_precompile_calls.len() == 0 {
        return result;
    }

    let mut input_buffer = zk_evm::precompiles::keccak256::Buffer::new();
    use zk_evm::precompiles::keccak256::NEW_WORDS_PER_CYCLE;
    let mut words_buffer = [0u64; NEW_WORDS_PER_CYCLE];

    let mut round_counter = 0;
    let num_requests = keccak_precompile_calls.len();

    // let global_queue_tail = *keccak_precompile_calls_queue_states.last().unwrap();
    // let mut queue_length = keccak_precompile_calls_queue_states.len();

    use zk_evm::precompiles::keccak256::Keccak256;
    let mut internal_state = Keccak256::default();

    // convension
    let mut log_queue_input_state = *keccak_precompile_calls_queue_states.first().unwrap();
    let mut memory_queue_input_state = *memory_queue_states.first().unwrap();
    let mut current_memory_queue_state = memory_queue_input_state;
    use sync_vm::traits::CSWitnessable;
    let mut fsm_input_state = Keccak256RoundFunctionFSM::<E>::empty()
        .create_witness()
        .unwrap();
    fsm_input_state.read_precompile_call = true;

    let mut memory_queries_it = memory_queries.into_iter();
    let mut memory_queue_states_it = memory_queue_states.into_iter();

    let mut memory_read_witnesses = vec![];

    let mut precompile_state = Keccak256PrecompileState::GetRequestFromQueue;

    for (request_idx, ((request, queue_transition_state), per_request_work)) in
        keccak_precompile_calls
            .into_iter()
            .zip(keccak_precompile_calls_queue_states.into_iter())
            .zip(round_function_witness.into_iter())
            .enumerate()
    {
        assert_eq!(
            precompile_state,
            Keccak256PrecompileState::GetRequestFromQueue
        );

        let (_cycle, _req, round_witness) = per_request_work;
        assert_eq!(request, _req);

        use zk_evm::precompiles::precompile_abi_in_log;
        let mut precompile_request = precompile_abi_in_log(request);
        let num_rounds = precompile_request.precompile_interpreted_data as usize;
        assert_eq!(num_rounds, round_witness.len());

        let mut num_rounds_left = num_rounds;

        let is_last_request = request_idx == num_requests - 1;

        precompile_state = Keccak256PrecompileState::RunRoundFunction;

        for (round_idx, round) in round_witness.into_iter().enumerate() {
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
                    assert!(data == read_query.value);
                    memory_read_witnesses.push(read_query.value);
                    current_memory_queue_state = memory_queue_states_it.next().unwrap();

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
                let _ = memory_queries_it.next().unwrap();
                current_memory_queue_state = memory_queue_states_it.next().unwrap();

                if is_last_request {
                    precompile_state = Keccak256PrecompileState::Finished;
                } else {
                    precompile_state = Keccak256PrecompileState::GetRequestFromQueue;
                }
            }

            round_counter += 1;

            if round_counter == num_rounds_per_circuit || (is_last_request && is_last_round) {
                round_counter = 0;

                let finished = is_last_request && is_last_round;
                if finished {
                    assert!(memory_queries_it.next().is_none());
                    assert!(memory_queue_states_it.next().is_none());
                }

                let state_inner =
                    zk_evm::precompiles::keccak256::transmute_state(internal_state.clone());
                let mut u64_words_buffer_markers = [false; BUFFER_SIZE];
                for i in 0..input_buffer.filled {
                    u64_words_buffer_markers[i] = true;
                }

                let keccak_internal_state: [E::Fr; 25] = state_inner
                    .into_iter()
                    .map(|el| u64_to_fe::<E::Fr>(el))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                let input_is_empty = is_last_request;
                let nothing_left = is_last_round && input_is_empty;
                // let process_next = is_last_round && !input_is_empty;

                assert_eq!(nothing_left, finished);

                // let read_precompile_call = process_next;
                // let completed = nothing_left;
                // let read_unaligned_words_for_round = !(read_precompile_call || completed);

                let completed = precompile_state == Keccak256PrecompileState::Finished;
                let read_unaligned_words_for_round =
                    precompile_state == Keccak256PrecompileState::RunRoundFunction;
                let read_precompile_call =
                    precompile_state == Keccak256PrecompileState::GetRequestFromQueue;

                use sync_vm::precompiles::keccak256::KeccakPrecompileCallParamsWitness;

                let fsm_output_state = Keccak256RoundFunctionFSMWitness::<E> {
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
                        output_offset: precompile_request.input_memory_offset,
                        num_rounds: num_rounds_left as u16,
                        _marker: std::marker::PhantomData,
                    },

                    _marker: std::marker::PhantomData,
                };

                let witness = Keccak256RoundFunctionCircuitWitness::<E> {
                    is_finished: finished,
                    passthrough_data: Keccak256CircuitPassthroughData::<E> {
                        log_queue_input_state: transform_queue_state(log_queue_input_state),
                        log_queue_output_state: transform_queue_state(queue_transition_state),
                        memory_queue_input_state: transform_sponge_like_queue_state(
                            memory_queue_input_state,
                        ),
                        memory_queue_output_state: transform_sponge_like_queue_state(
                            current_memory_queue_state,
                        ),
                        _marker: std::marker::PhantomData,
                    },

                    fsm_input: fsm_input_state,
                    fsm_output: fsm_output_state.clone(),
                };

                result.push(witness);

                log_queue_input_state = queue_transition_state;
                fsm_input_state = fsm_output_state;
                memory_queue_input_state = current_memory_queue_state;
            }
        }
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;

    use sync_vm::scheduler::queues::StorageLogQueue;
    use sync_vm::{
        franklin_crypto::{
            bellman::{compact_bn256::Bn256, SynthesisError},
            plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns,
        },
        precompiles::keccak256::{
            keccak256_precompile_inner, KeccakPrecompileState, KeccakPrecompileStateWitness,
        },
        scheduler::queues::{FixedWidthEncodingGenericQueueState, FullSpongeLikeQueueState},
        testing::create_test_artifacts_with_optimized_gate,
        traits::{CSAllocatable, CSWitnessable},
    };
    type E = sync_vm::testing::Bn256;

    use sync_vm::glue::code_unpacker_sha256::memory_query_updated::MemoryQueriesQueue;

    #[test]
    fn test_witness_coincides() -> Result<(), SynthesisError> {
        let (mut dummy_cs, committer, _) = create_test_artifacts_with_optimized_gate();
        let cs = &mut dummy_cs;
        inscribe_default_range_table_for_bit_width_over_first_three_columns(cs, 16)?;

        let limit = 16;

        let witness: Keccak256RoundFunctionCircuitWitness<E> = { todo!() };

        let Keccak256RoundFunctionCircuitWitness {
            is_finished,
            passthrough_data,
            fsm_input,
            fsm_output,
        } = witness;

        let initial_state = KeccakPrecompileState::alloc_from_witness(cs, Some(fsm_input))?;
        let Keccak256RoundFunctionPassthroughStructureWitness {
            memory_queue_input_state,
            memory_queue_output_state,
            log_queue_input_state,
            log_queue_output_state,
            ..
        } = passthrough_data;

        let initial_memory_state =
            FullSpongeLikeQueueState::alloc_from_witness(cs, Some(memory_queue_input_state))?;
        let mut memory_queue = MemoryQueriesQueue::from_state(cs, initial_memory_state)?;

        let initial_requests_queue_state = FixedWidthEncodingGenericQueueState::alloc_from_witness(
            cs,
            Some(log_queue_input_state),
        )?;
        let mut requests_queue = StorageLogQueue::from_state(cs, initial_requests_queue_state)?;

        let final_state = keccak256_precompile_inner(
            cs,
            &mut memory_queue,
            &mut requests_queue,
            None,
            initial_state,
            &committer,
            limit,
        )?;

        let final_memory_queue_state = memory_queue.into_state().create_witness().unwrap();
        assert_eq!(
            final_memory_queue_state.head,
            memory_queue_output_state.head
        );
        assert_eq!(
            final_memory_queue_state.tail,
            memory_queue_output_state.tail
        );
        assert_eq!(
            final_memory_queue_state.length,
            memory_queue_output_state.length
        );

        let final_requests_queue_state = requests_queue.into_state().create_witness().unwrap();
        assert_eq!(
            final_requests_queue_state.head_state,
            log_queue_output_state.head_state
        );
        assert_eq!(
            final_requests_queue_state.tail_state,
            log_queue_output_state.tail_state
        );
        assert_eq!(
            final_requests_queue_state.num_items,
            log_queue_output_state.num_items
        );

        let final_state = final_state.create_witness().unwrap();
        assert_eq!(
            final_state.keccak_internal_state,
            fsm_output.keccak_internal_state
        );

        Ok(())
    }
}
