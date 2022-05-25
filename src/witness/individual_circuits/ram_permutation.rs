use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::memory_queries_validity::ram_permutation_inout::{RamPermutationFSMInputOutputWitness, RamPermutationPassthroughDataWitness};
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::utils::u64_to_fe;

use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::witness_structures::transform_sponge_like_queue_state;
use std::cmp::Ordering;
use crate::bellman::Engine;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use crate::ff::Field;
use sync_vm::glue::ram_permutation::RamPermutationCircuitInstanceWitness;

use super::*;

pub fn compute_ram_circuit_snapshots<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(
    artifacts: &mut FullBlockArtifacts<E>,
    mut memory_queue_simulator: MemoryQueueSimulator<E>,
    round_function: &R,
    per_circuit_capacity: usize
) -> Vec<RamPermutationCircuitInstanceWitness<E>> {
    assert!(artifacts.all_memory_queries_accumulated.len() > 0, "VM should have made some memory requests");

    // sort by memory location, and then by timestamp
    artifacts.sorted_memory_queries_accumulated = artifacts.all_memory_queries_accumulated.clone();
    artifacts.sorted_memory_queries_accumulated.par_sort_by(|a, b| {
        match a.location.cmp(&b.location) {
            Ordering::Equal => a.timestamp.cmp(&b.timestamp),
            a @ _ => a,
        }
    });

    // those two thins are parallelizable, and can be internally parallelized too

    // now we can finish reconstruction of each sorted and unsorted memory queries

    // Transform the rest of queries into states
    for query in artifacts
        .all_memory_queries_accumulated
        .iter()
        .skip(artifacts.vm_memory_queries_accumulated.len())
    {
        let (_old_tail, intermediate_info) =
            memory_queue_simulator.push_and_output_intermediate_data(*query, round_function);
        artifacts.all_memory_queue_states.push(intermediate_info);
    }

    // reconstruct sorted one in full
    let mut sorted_memory_queries_simulator = MemoryQueueSimulator::<E>::empty();
    for query in artifacts.sorted_memory_queries_accumulated.iter() {
        let (_old_tail, intermediate_info) =
            sorted_memory_queries_simulator.push_and_output_intermediate_data(*query, round_function);

        artifacts.sorted_memory_queue_states.push(intermediate_info);
    }

    // now we should chunk it by circuits but briefly simulating their logic

    let mut challenges = vec![];

    let mut fs_input = vec![];
    fs_input.extend_from_slice(&memory_queue_simulator.tail);
    fs_input.push(u64_to_fe(memory_queue_simulator.num_items as u64));
    fs_input.extend_from_slice(&sorted_memory_queries_simulator.tail);
    fs_input.push(u64_to_fe(sorted_memory_queries_simulator.num_items as u64));

    let sequence_of_states = round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&fs_input);
    let final_state = sequence_of_states.last().unwrap().1;
    let base_fs_challenge = R::simulate_state_into_commitment(final_state);

    let mut current = base_fs_challenge;
    challenges.push(current);
    current.mul_assign(&base_fs_challenge);
    challenges.push(current);
    current.mul_assign(&base_fs_challenge);
    challenges.push(current);

    // since encodings of the elements provide all the information necessary to perform soring argument,
    // we use them naively

    let lhs_contributions: Vec<_> = memory_queue_simulator.witness.iter().map(|el| el.0).collect();
    let rhs_contributions: Vec<_> = sorted_memory_queries_simulator.witness.iter().map(|el| el.0).collect();

    let mut lhs_grand_product_chain: Vec<E::Fr> = vec![E::Fr::zero(); lhs_contributions.len()];
    let mut rhs_grand_product_chain: Vec<E::Fr> = vec![E::Fr::zero(); rhs_contributions.len()];

    const CHUNK_SIZE: usize = 1 << 18;

    let challenges: [E::Fr; 3] = challenges.try_into().unwrap();

    lhs_grand_product_chain.par_chunks_mut(CHUNK_SIZE).zip(lhs_contributions.par_chunks(CHUNK_SIZE)).for_each(
        |(dst, src)| {
            let mut grand_product = E::Fr::one();
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = challenges[2];

                let mut tmp = src[0];
                tmp.mul_assign(&challenges[0]);
                acc.add_assign(&tmp);

                let mut tmp = src[1];
                tmp.mul_assign(&challenges[1]);
                acc.add_assign(&tmp);

                grand_product.mul_assign(&acc);
    
                *dst = grand_product;
            }
        }
    );

    rhs_grand_product_chain.par_chunks_mut(CHUNK_SIZE).zip(rhs_contributions.par_chunks(CHUNK_SIZE)).for_each(
        |(dst, src)| {
            let mut grand_product = E::Fr::one();
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = challenges[2];

                let mut tmp = src[0];
                tmp.mul_assign(&challenges[0]);
                acc.add_assign(&tmp);

                let mut tmp = src[1];
                tmp.mul_assign(&challenges[1]);
                acc.add_assign(&tmp);

                grand_product.mul_assign(&acc);
    
                *dst = grand_product;
            }
        }
    );

    // elementwise products are done, now must fold

    let lhs_intermediates: Vec<E::Fr> = lhs_grand_product_chain.par_chunks(CHUNK_SIZE).map(
        |slice: &[E::Fr]| {
            *slice.last().unwrap()
        }
    ).collect();

    let rhs_intermediates: Vec<E::Fr> = rhs_grand_product_chain.par_chunks(CHUNK_SIZE).map(
        |slice: &[E::Fr]| {
            *slice.last().unwrap()
        }
    ).collect();

    lhs_grand_product_chain.par_chunks_mut(CHUNK_SIZE).skip(1).zip(lhs_intermediates.par_chunks(1)).for_each(
        |(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        }
    );

    rhs_grand_product_chain.par_chunks_mut(CHUNK_SIZE).skip(1).zip(rhs_intermediates.par_chunks(1)).for_each(
        |(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        }
    );

    // dbg!(&lhs_grand_product_chain);
    // dbg!(&rhs_grand_product_chain);

    // dbg!(lhs_grand_product_chain.last().unwrap());

    // sanity check
    assert_eq!(lhs_grand_product_chain.last().unwrap(), rhs_grand_product_chain.last().unwrap());

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    assert_eq!(lhs_grand_product_chain.len(), artifacts.all_memory_queries_accumulated.len());
    assert_eq!(lhs_grand_product_chain.len(), artifacts.sorted_memory_queries_accumulated.len());
    assert_eq!(lhs_grand_product_chain.len(), memory_queue_simulator.witness.len());
    assert_eq!(lhs_grand_product_chain.len(), sorted_memory_queries_simulator.witness.len());

    // we also want to have chunks of witness for each of all the intermediate states

    let it = artifacts.all_memory_queue_states.chunks(per_circuit_capacity)
            .zip(artifacts.sorted_memory_queue_states.chunks(per_circuit_capacity))
            .zip(lhs_grand_product_chain.chunks(per_circuit_capacity))
            .zip(rhs_grand_product_chain.chunks(per_circuit_capacity))
            .zip(memory_queue_simulator.witness.chunks(per_circuit_capacity))
            .zip(sorted_memory_queries_simulator.witness.chunks(per_circuit_capacity));

    // now trivial transformation into desired data structures,
    // and we are all good

    let num_circuits = it.len();
    let mut results = vec![];

    let mut current_lhs_product = E::Fr::zero();
    let mut current_rhs_product = E::Fr::zero();
    let mut previous_sorting_key = E::Fr::zero();
    let mut previous_comparison_key = E::Fr::zero();
    let mut previous_value_pair = [E::Fr::zero(); 2];

    let unsorted_global_final_state = artifacts.all_memory_queue_states.last().unwrap().clone();
    let sorted_global_final_state = artifacts.sorted_memory_queue_states.last().unwrap().clone();

    let total_queue_length = artifacts.all_memory_queue_states.len() as u32;

    for (idx, (((((unsorted_sponge_states, sorted_sponge_states), lhs_grand_product), rhs_grand_product), unsorted_states), sorted_states)) in it.enumerate() {
        // we need witnesses to pop elements from the front of the queue
        use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;
        use crate::witness_structures::ram_circuit::transform_raw_memory_query_witness;

        let unsorted_witness = FixedWidthEncodingSpongeLikeQueueWitness::<E, RawMemoryQuery<E>, 2, 3> {
            wit: unsorted_states.iter().map(|el| {
                let witness = transform_raw_memory_query_witness(&el.2);
                (el.0, witness, el.1)
            }).collect()
        };

        let sorted_witness = FixedWidthEncodingSpongeLikeQueueWitness::<E, RawMemoryQuery<E>, 2, 3> {
            wit: sorted_states.iter().map(|el| {
                let witness = transform_raw_memory_query_witness(&el.2);
                (el.0, witness, el.1)
            }).collect()
        };

        // now we need to have final grand product value that will also become an input for the next circuit

        let if_first = idx == 0;
        let is_last = idx == num_circuits - 1;

        let last_unsorted_state = unsorted_sponge_states.last().unwrap().clone();
        let last_sorted_state = sorted_sponge_states.last().unwrap().clone();

        let accumulated_lhs = *lhs_grand_product.last().unwrap();
        let accumulated_rhs = *rhs_grand_product.last().unwrap();

        let last_sorted_query = sorted_states.last().unwrap().2;
        use crate::encodings::memory_query::*;
        let sorting_key = sorting_key::<E>(&last_sorted_query);
        let comparison_key = comparison_key::<E>(&last_sorted_query);

        let raw_query_witness = transform_raw_memory_query_witness::<E>(&last_sorted_query);
        let value_low = raw_query_witness.value;
        let value_high = u64_to_fe(raw_query_witness.value_residual);

        use sync_vm::traits::CSWitnessable;
        use sync_vm::scheduler::queues::FullSpongeLikeQueueState;

        let placeholder_witness = FullSpongeLikeQueueState::placeholder_witness();

        let (current_unsorted_queue_state, current_sorted_queue_state) = results.last().map(|el: &RamPermutationCircuitInstanceWitness<E>| {
            let tmp = &el.closed_form_input.fsm_output;

            (tmp.current_unsorted_queue_state.clone(), tmp.current_sorted_queue_state.clone())
        }).unwrap_or(
            (placeholder_witness.clone(), placeholder_witness)
        );

        // we use current final state as the intermediate head
        let mut final_unsorted_state = transform_sponge_like_queue_state(last_unsorted_state);
        final_unsorted_state.head = final_unsorted_state.tail;
        final_unsorted_state.tail = unsorted_global_final_state.tail;
        final_unsorted_state.length = unsorted_global_final_state.num_items - final_unsorted_state.length;
        let mut final_sorted_state = transform_sponge_like_queue_state(last_sorted_state);
        final_sorted_state.head = final_sorted_state.tail;
        final_sorted_state.tail = sorted_global_final_state.tail;
        final_sorted_state.length = sorted_global_final_state.num_items - final_sorted_state.length;

        let mut instance_witness = RamPermutationCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                _marker_e: (),
                start_flag: if_first,
                completion_flag: is_last,
                passthrough_input_data: RamPermutationPassthroughDataWitness {
                    unsorted_queue_initial_state: transform_sponge_like_queue_state(unsorted_global_final_state),
                    sorted_queue_initial_state: transform_sponge_like_queue_state(sorted_global_final_state),
                    non_deterministic_bootloader_memory_snapshot_length: 0,
                    _marker: std::marker::PhantomData,
                },
                passthrough_output_data: RamPermutationPassthroughDataWitness {
                    unsorted_queue_initial_state: transform_sponge_like_queue_state(unsorted_global_final_state),
                    sorted_queue_initial_state: transform_sponge_like_queue_state(sorted_global_final_state),
                    non_deterministic_bootloader_memory_snapshot_length: 0,
                    _marker: std::marker::PhantomData,
                },
                fsm_input: RamPermutationFSMInputOutputWitness {
                    lhs_accumulator: current_lhs_product,
                    rhs_accumulator: current_rhs_product,
                    current_unsorted_queue_state,
                    current_sorted_queue_state,
                    previous_sorting_key: previous_sorting_key,
                    previous_full_key: previous_comparison_key,
                    previous_values_pair: previous_value_pair,
                    _marker: std::marker::PhantomData,
                },
                fsm_output: RamPermutationFSMInputOutputWitness {
                    lhs_accumulator: accumulated_lhs,
                    rhs_accumulator: accumulated_rhs,
                    current_unsorted_queue_state: final_unsorted_state,
                    current_sorted_queue_state: final_sorted_state,
                    previous_sorting_key: sorting_key,
                    previous_full_key: comparison_key,
                    previous_values_pair: [value_low, value_high],
                    _marker: std::marker::PhantomData,
                },
                _marker: std::marker::PhantomData,
            },
            unsorted_queue_witness: unsorted_witness,
            sorted_queue_witness: sorted_witness,
        };

        // // adjust queue lengths. States indicate a number of elements in the queue, but when we pop we should actually
        // // use a value that says how many elements left in the queue
        // instance_witness.closed_form_input.fsm_input.current_unsorted_queue_state.length = total_queue_length - instance_witness.closed_form_input.fsm_input.current_unsorted_queue_state.length;
        // instance_witness.closed_form_input.fsm_input.current_sorted_queue_state.length = total_queue_length - instance_witness.closed_form_input.fsm_input.current_sorted_queue_state.length;

        // instance_witness.closed_form_input.fsm_output.current_unsorted_queue_state.length = total_queue_length - instance_witness.closed_form_input.fsm_output.current_unsorted_queue_state.length;
        // instance_witness.closed_form_input.fsm_output.current_unsorted_queue_state.length = total_queue_length - instance_witness.closed_form_input.fsm_output.current_unsorted_queue_state.length;

        current_lhs_product = accumulated_lhs;
        current_rhs_product = accumulated_rhs;

        previous_sorting_key = sorting_key;
        previous_comparison_key = comparison_key;
        previous_value_pair = [value_low, value_high];

        results.push(instance_witness);
    }

    results
}