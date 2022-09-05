use sync_vm::franklin_crypto::plonk::circuit::utils::u128_to_fe;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::code_unpacker_sha256::input::*;
use sync_vm::glue::optimizable_queue::FixedWidthEncodingGenericQueueWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::scheduler::queues::DecommitQueryWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::aux_structures::*;

use crate::encodings::log_query::LogQueueSimulator;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::utils::biguint_from_u256;
use crate::witness_structures::transform_sponge_like_queue_state;
use std::cmp::Ordering;
use crate::bellman::Engine;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use crate::ff::Field;
use crate::encodings::decommittment_request::DecommittmentQueueSimulator;
use zk_evm::aux_structures::MemoryIndex;
use zk_evm::aux_structures::MemoryQuery;
use sync_vm::glue::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;
use crate::encodings::log_query::log_query_into_storage_record_witness;

/// Take a storage log, output logs separately for events, l1 messages, storage, etc
pub fn compute_logs_demux<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(
    artifacts: &mut FullBlockArtifacts<E>,
    round_function: &R,
) -> LogDemuxerCircuitInstanceWitness<E> {
    for x in artifacts.demuxed_rollup_storage_queries {
        println!(x);
    }

    // parallelizable 
    
    // have to manually unroll, otherwise borrow checker will complain

    let mut all_queues = [
        &mut artifacts.demuxed_rollup_storage_queue_simulator,
        &mut artifacts.demuxed_events_queue_simulator,
        &mut artifacts.demuxed_to_l1_queue_simulator,
        &mut artifacts.demuxed_keccak_precompile_queue_simulator,
        &mut artifacts.demuxed_sha256_precompile_queue_simulator,
        &mut artifacts.demuxed_ecrecover_queue_simulator,
    ];

    let all_inputs = [
        &artifacts.demuxed_rollup_storage_queries,
        &artifacts.demuxed_event_queries,
        &artifacts.demuxed_to_l1_queries,
        &artifacts.demuxed_keccak_precompile_queries,
        &artifacts.demuxed_sha256_precompile_queries,
        &artifacts.demuxed_ecrecover_queries,
    ];

    let mut all_intermediate_states = [
        &mut artifacts.demuxed_rollup_storage_queue_states,
        &mut artifacts.demuxed_event_queue_states,
        &mut artifacts.demuxed_to_l1_queue_states,
        &mut artifacts.demuxed_keccak_precompile_queue_states,
        &mut artifacts.demuxed_sha256_precompile_queue_states,
        &mut artifacts.demuxed_ecrecover_queue_states,
    ];

    for ((simulator, input), states) in all_queues.iter_mut().zip(all_inputs.into_iter()).zip(all_intermediate_states.iter_mut()) {
        for el in input.iter().copied() {
            let (_old_tail, intermediate_info) = simulator.push_and_output_intermediate_data(
                el,
                round_function
            );

            states.push(intermediate_info);
        }
    }

    // in general we have everything ready, just form the witness
    use sync_vm::glue::demux_log_queue::input::*;
    use sync_vm::traits::CSWitnessable;
    use crate::witness_structures::take_queue_state_from_simulator;

    let mut input_passthrough_data = LogDemuxerInputData::placeholder_witness();
    // we only need the state of the original input
    input_passthrough_data.initial_log_queue_state = take_queue_state_from_simulator(&artifacts.original_log_queue_simulator);

    let mut output_passthrough_data = LogDemuxerOutputData::placeholder_witness();

    output_passthrough_data.storage_access_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_rollup_storage_queue_simulator);
    output_passthrough_data.events_access_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_events_queue_simulator);
    output_passthrough_data.l1messages_access_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_to_l1_queue_simulator);
    output_passthrough_data.keccak256_access_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_keccak_precompile_queue_simulator);
    output_passthrough_data.sha256_access_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_sha256_precompile_queue_simulator);
    output_passthrough_data.ecrecover_access_queue_state = take_queue_state_from_simulator(&artifacts.demuxed_ecrecover_queue_simulator);

    // dbg!(&output_passthrough_data);

    let input_witness: Vec<_> = artifacts.original_log_queue_simulator.witness.iter().map(|(encoding, old_tail, element)| {
        let as_storage_log = log_query_into_storage_record_witness(element);

        (*encoding, as_storage_log, *old_tail)
    }).collect();
    
    let witness = LogDemuxerCircuitInstanceWitness {
        closed_form_input: ClosedFormInputWitness { 
            start_flag: true, 
            completion_flag: true, 
            observable_input: input_passthrough_data, 
            observable_output: output_passthrough_data, 
            hidden_fsm_input: (), 
            hidden_fsm_output: (), 
            _marker_e: (), 
            _marker: std::marker::PhantomData 
        },
        initial_queue_witness: FixedWidthEncodingGenericQueueWitness {wit: input_witness}
    };

    witness
}