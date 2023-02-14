use super::*;
use crate::bellman::Engine;
use crate::encodings::memory_query::MemoryQueueSimulator;
use crate::ff::Field;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use std::cmp::Ordering;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::code_unpacker_sha256::memory_query_updated::RawMemoryQuery;
use sync_vm::glue::memory_queries_validity::ram_permutation_inout::*;
use sync_vm::glue::ram_permutation::RamPermutationCircuitInstanceWitness;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::utils::u64_to_fe;
use zk_evm::abstractions::MemoryType;

use zk_evm::zkevm_opcode_defs::BOOTLOADER_HEAP_PAGE;

pub const RAM_PERMUTATION_CHUNK_SIZE: usize = 1 << 18;
// pub const RAM_PERMUTATION_CHUNK_SIZE: usize = 1 << 10;

pub fn compute_ram_circuit_snapshots<E: Engine, R: CircuitArithmeticRoundFunction<E, 2, 3>>(
    artifacts: &mut FullBlockArtifacts<E>,
    round_function: &R,
    num_non_deterministic_heap_queries: usize,
    per_circuit_capacity: usize,
) -> Vec<RamPermutationCircuitInstanceWitness<E>> {
    assert!(
        artifacts.all_memory_queries_accumulated.len() > 0,
        "VM should have made some memory requests"
    );

    // sort by memory location, and then by timestamp
    artifacts.sorted_memory_queries_accumulated = artifacts.all_memory_queries_accumulated.clone();
    artifacts
        .sorted_memory_queries_accumulated
        .par_sort_by(|a, b| match a.location.cmp(&b.location) {
            Ordering::Equal => a.timestamp.cmp(&b.timestamp),
            a @ _ => a,
        });

    // those two thins are parallelizable, and can be internally parallelized too

    // now we can finish reconstruction of each sorted and unsorted memory queries

    // reconstruct sorted one in full
    let mut sorted_memory_queries_simulator = MemoryQueueSimulator::<E>::empty();
    for query in artifacts.sorted_memory_queries_accumulated.iter() {
        let (_old_tail, intermediate_info) = sorted_memory_queries_simulator
            .push_and_output_intermediate_data(*query, round_function);

        artifacts.sorted_memory_queue_states.push(intermediate_info);
    }

    assert_eq!(
        sorted_memory_queries_simulator.num_items,
        artifacts.memory_queue_simulator.num_items
    );

    // now we should chunk it by circuits but briefly simulating their logic

    let mut challenges = vec![];

    let mut fs_input = vec![];
    fs_input.extend_from_slice(&artifacts.memory_queue_simulator.tail);
    fs_input.push(u64_to_fe(artifacts.memory_queue_simulator.num_items as u64));
    fs_input.extend_from_slice(&sorted_memory_queries_simulator.tail);
    fs_input.push(u64_to_fe(sorted_memory_queries_simulator.num_items as u64));

    let sequence_of_states =
        round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&fs_input);
    let final_state = sequence_of_states.last().unwrap().1;

    // manually unroll to get irreducible over every challenge
    challenges.push(final_state[0]);
    challenges.push(final_state[1]);
    let final_state = round_function.simulate_round_function(final_state);
    challenges.push(final_state[0]);

    // since encodings of the elements provide all the information necessary to perform soring argument,
    // we use them naively

    assert_eq!(
        artifacts.memory_queue_simulator.num_items,
        sorted_memory_queries_simulator.num_items
    );
    assert_eq!(
        artifacts.memory_queue_simulator.num_items as usize,
        artifacts.all_memory_queries_accumulated.len()
    );

    let lhs_contributions: Vec<_> = artifacts
        .memory_queue_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();
    let rhs_contributions: Vec<_> = sorted_memory_queries_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    let (lhs_grand_product_chain, rhs_grand_product_chain) =
        compute_grand_product_chains::<E, 2, 3>(&lhs_contributions, &rhs_contributions, challenges);

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    assert_eq!(
        lhs_grand_product_chain.len(),
        artifacts.all_memory_queries_accumulated.len()
    );
    assert_eq!(
        lhs_grand_product_chain.len(),
        artifacts.sorted_memory_queries_accumulated.len()
    );
    assert_eq!(
        lhs_grand_product_chain.len(),
        artifacts.memory_queue_simulator.witness.len()
    );
    assert_eq!(
        lhs_grand_product_chain.len(),
        sorted_memory_queries_simulator.witness.len()
    );

    // we also want to have chunks of witness for each of all the intermediate states

    assert!(artifacts
        .memory_queue_simulator
        .witness
        .as_slices()
        .1
        .is_empty());
    assert!(sorted_memory_queries_simulator
        .witness
        .as_slices()
        .1
        .is_empty());

    let it = artifacts
        .all_memory_queue_states
        .chunks(per_circuit_capacity)
        .zip(
            artifacts
                .sorted_memory_queue_states
                .chunks(per_circuit_capacity),
        )
        .zip(lhs_grand_product_chain.chunks(per_circuit_capacity))
        .zip(rhs_grand_product_chain.chunks(per_circuit_capacity))
        .zip(
            artifacts
                .memory_queue_simulator
                .witness
                .as_slices()
                .0
                .chunks(per_circuit_capacity),
        )
        .zip(
            sorted_memory_queries_simulator
                .witness
                .as_slices()
                .0
                .chunks(per_circuit_capacity),
        );

    // now trivial transformation into desired data structures,
    // and we are all good

    let num_circuits = it.len();
    let mut results = vec![];

    let mut current_lhs_product = E::Fr::zero();
    let mut current_rhs_product = E::Fr::zero();
    let mut previous_sorting_key = E::Fr::zero();
    let mut previous_comparison_key = E::Fr::zero();
    let mut previous_value_pair = [E::Fr::zero(); 2];
    let mut previous_is_ptr = false;

    let unsorted_global_final_state = artifacts.all_memory_queue_states.last().unwrap().clone();
    let sorted_global_final_state = artifacts.sorted_memory_queue_states.last().unwrap().clone();

    assert_eq!(
        unsorted_global_final_state.num_items,
        sorted_global_final_state.num_items
    );

    let mut current_number_of_nondet_writes = 0u32;

    for (
        idx,
        (
            (
                (
                    ((unsorted_sponge_states, sorted_sponge_states), lhs_grand_product),
                    rhs_grand_product,
                ),
                unsorted_states,
            ),
            sorted_states,
        ),
    ) in it.enumerate()
    {
        // we need witnesses to pop elements from the front of the queue
        use sync_vm::scheduler::queues::FixedWidthEncodingSpongeLikeQueueWitness;

        let unsorted_witness =
            FixedWidthEncodingSpongeLikeQueueWitness::<E, RawMemoryQuery<E>, 2, 3> {
                wit: unsorted_states
                    .iter()
                    .map(|el| {
                        let witness = transform_raw_memory_query_witness(&el.2);
                        (el.0, witness, el.1)
                    })
                    .collect(),
            };

        let sorted_witness = FixedWidthEncodingSpongeLikeQueueWitness::<E, RawMemoryQuery<E>, 2, 3> {
            wit: sorted_states
                .iter()
                .map(|el| {
                    let witness = transform_raw_memory_query_witness(&el.2);
                    (el.0, witness, el.1)
                })
                .collect(),
        };

        // now we need to have final grand product value that will also become an input for the next circuit

        let if_first = idx == 0;
        let is_last = idx == num_circuits - 1;

        let num_nondet_writes_in_chunk = sorted_states
            .iter()
            .filter(|el| {
                let query = &el.2;
                query.rw_flag == true
                    && query.timestamp.0 == 0
                    && query.location.page.0 == BOOTLOADER_HEAP_PAGE
            })
            .count();

        let new_num_nondet_writes =
            current_number_of_nondet_writes + (num_nondet_writes_in_chunk as u32);

        let last_unsorted_state = unsorted_sponge_states.last().unwrap().clone();
        let last_sorted_state = sorted_sponge_states.last().unwrap().clone();

        let accumulated_lhs = *lhs_grand_product.last().unwrap();
        let accumulated_rhs = *rhs_grand_product.last().unwrap();

        let last_sorted_query = sorted_states.last().unwrap().2;
        use crate::encodings::memory_query::*;
        let sorting_key = sorting_key::<E>(&last_sorted_query);
        let comparison_key = comparison_key::<E>(&last_sorted_query);
        let is_ptr = last_sorted_query.value_is_pointer;

        let raw_query_witness = transform_raw_memory_query_witness::<E>(&last_sorted_query);
        let value_low = raw_query_witness.value;
        let value_high = u64_to_fe(raw_query_witness.value_residual);

        use sync_vm::scheduler::queues::FullSpongeLikeQueueState;
        use sync_vm::traits::CSWitnessable;

        let placeholder_witness = FullSpongeLikeQueueState::placeholder_witness();

        let (current_unsorted_queue_state, current_sorted_queue_state) = results
            .last()
            .map(|el: &RamPermutationCircuitInstanceWitness<E>| {
                let tmp = &el.closed_form_input.hidden_fsm_output;

                (
                    tmp.current_unsorted_queue_state.clone(),
                    tmp.current_sorted_queue_state.clone(),
                )
            })
            .unwrap_or((placeholder_witness.clone(), placeholder_witness));

        assert_eq!(
            current_unsorted_queue_state.length,
            current_sorted_queue_state.length
        );

        // we use current final state as the intermediate head
        let mut final_unsorted_state = transform_sponge_like_queue_state(last_unsorted_state);
        final_unsorted_state.head = final_unsorted_state.tail;
        final_unsorted_state.tail = unsorted_global_final_state.tail;
        final_unsorted_state.length =
            unsorted_global_final_state.num_items - final_unsorted_state.length;

        let mut final_sorted_state = transform_sponge_like_queue_state(last_sorted_state);
        final_sorted_state.head = final_sorted_state.tail;
        final_sorted_state.tail = sorted_global_final_state.tail;
        final_sorted_state.length = sorted_global_final_state.num_items - final_sorted_state.length;

        assert_eq!(final_unsorted_state.length, final_sorted_state.length);

        let mut instance_witness = RamPermutationCircuitInstanceWitness {
            closed_form_input: ClosedFormInputWitness {
                _marker_e: (),
                start_flag: if_first,
                completion_flag: is_last,
                observable_input: RamPermutationInputDataWitness {
                    unsorted_queue_initial_state: transform_sponge_like_queue_state(
                        unsorted_global_final_state,
                    ),
                    sorted_queue_initial_state: transform_sponge_like_queue_state(
                        sorted_global_final_state,
                    ),
                    non_deterministic_bootloader_memory_snapshot_length:
                        num_non_deterministic_heap_queries as u32,
                    _marker: std::marker::PhantomData,
                },
                observable_output: (),
                hidden_fsm_input: RamPermutationFSMInputOutputWitness {
                    lhs_accumulator: current_lhs_product,
                    rhs_accumulator: current_rhs_product,
                    current_unsorted_queue_state,
                    current_sorted_queue_state,
                    previous_sorting_key: previous_sorting_key,
                    previous_full_key: previous_comparison_key,
                    previous_values_pair: previous_value_pair,
                    previous_is_ptr: previous_is_ptr,
                    num_nondeterministic_writes: current_number_of_nondet_writes,
                    _marker: std::marker::PhantomData,
                },
                hidden_fsm_output: RamPermutationFSMInputOutputWitness {
                    lhs_accumulator: accumulated_lhs,
                    rhs_accumulator: accumulated_rhs,
                    current_unsorted_queue_state: final_unsorted_state,
                    current_sorted_queue_state: final_sorted_state,
                    previous_sorting_key: sorting_key,
                    previous_full_key: comparison_key,
                    previous_values_pair: [value_low, value_high],
                    previous_is_ptr: is_ptr,
                    num_nondeterministic_writes: new_num_nondet_writes,
                    _marker: std::marker::PhantomData,
                },
                _marker: std::marker::PhantomData,
            },
            unsorted_queue_witness: unsorted_witness,
            sorted_queue_witness: sorted_witness,
        };

        if sorted_states.len() % per_circuit_capacity != 0 {
            // RAM circuit does padding, so all previous values must be reset
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_sorting_key = E::Fr::zero();
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_full_key = E::Fr::zero();
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_values_pair = [E::Fr::zero(); 2];
            instance_witness
                .closed_form_input
                .hidden_fsm_output
                .previous_is_ptr = false;
        }

        current_lhs_product = accumulated_lhs;
        current_rhs_product = accumulated_rhs;

        previous_sorting_key = sorting_key;
        previous_comparison_key = comparison_key;
        previous_value_pair = [value_low, value_high];
        previous_is_ptr = is_ptr;

        current_number_of_nondet_writes = new_num_nondet_writes;

        results.push(instance_witness);
    }

    results
}

pub(crate) fn compute_grand_product_chains<E: Engine, const N: usize, const M: usize>(
    lhs_contributions: &Vec<[E::Fr; N]>,
    rhs_contributions: &Vec<[E::Fr; N]>,
    challenges: Vec<E::Fr>,
) -> (Vec<E::Fr>, Vec<E::Fr>) {
    assert_eq!(N + 1, M);
    let mut lhs_grand_product_chain: Vec<E::Fr> = vec![E::Fr::zero(); lhs_contributions.len()];
    let mut rhs_grand_product_chain: Vec<E::Fr> = vec![E::Fr::zero(); rhs_contributions.len()];

    let challenges: [E::Fr; M] = challenges.try_into().unwrap();

    lhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .zip(lhs_contributions.par_chunks(RAM_PERMUTATION_CHUNK_SIZE))
        .for_each(|(dst, src)| {
            let mut grand_product = E::Fr::one();
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = challenges[M - 1];

                debug_assert_eq!(challenges[..(M - 1)].len(), src.len());

                for (a, b) in src.iter().zip(challenges[..(M - 1)].iter()) {
                    let mut tmp = *a;
                    tmp.mul_assign(b);
                    acc.add_assign(&tmp);
                }

                grand_product.mul_assign(&acc);

                *dst = grand_product;
            }
        });

    rhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .zip(rhs_contributions.par_chunks(RAM_PERMUTATION_CHUNK_SIZE))
        .for_each(|(dst, src)| {
            let mut grand_product = E::Fr::one();
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = challenges[M - 1];

                debug_assert_eq!(challenges[..(M - 1)].len(), src.len());

                for (a, b) in src.iter().zip(challenges[..(M - 1)].iter()) {
                    let mut tmp = *a;
                    tmp.mul_assign(b);
                    acc.add_assign(&tmp);
                }

                grand_product.mul_assign(&acc);

                *dst = grand_product;
            }
        });

    // elementwise products are done, now must fold

    let mut lhs_intermediates: Vec<E::Fr> = lhs_grand_product_chain
        .par_chunks(RAM_PERMUTATION_CHUNK_SIZE)
        .map(|slice: &[E::Fr]| *slice.last().unwrap())
        .collect();

    let mut rhs_intermediates: Vec<E::Fr> = rhs_grand_product_chain
        .par_chunks(RAM_PERMUTATION_CHUNK_SIZE)
        .map(|slice: &[E::Fr]| *slice.last().unwrap())
        .collect();

    assert_eq!(
        lhs_intermediates.len(),
        lhs_grand_product_chain
            .chunks(RAM_PERMUTATION_CHUNK_SIZE)
            .len()
    );
    assert_eq!(
        rhs_intermediates.len(),
        rhs_grand_product_chain
            .chunks(RAM_PERMUTATION_CHUNK_SIZE)
            .len()
    );

    // accumulate intermediate products
    // we should multiply element [1] by element [0],
    // element [2] by [0] * [1],
    // etc
    let mut acc_lhs = E::Fr::one();
    for el in lhs_intermediates.iter_mut() {
        let tmp = *el;
        el.mul_assign(&acc_lhs);
        acc_lhs.mul_assign(&tmp);
    }

    let mut acc_rhs = E::Fr::one();
    for el in rhs_intermediates.iter_mut() {
        let tmp = *el;
        el.mul_assign(&acc_rhs);
        acc_rhs.mul_assign(&tmp);
    }

    match (lhs_intermediates.last(), rhs_intermediates.last()) {
        (Some(lhs), Some(rhs)) => {
            assert_eq!(lhs, rhs);
        }
        (None, None) => {}
        _ => unreachable!(),
    }

    lhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .skip(1)
        .zip(lhs_intermediates.par_chunks(1))
        .for_each(|(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        });

    rhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .skip(1)
        .zip(rhs_intermediates.par_chunks(1))
        .for_each(|(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        });

    // sanity check
    match (
        lhs_grand_product_chain.last(),
        rhs_grand_product_chain.last(),
    ) {
        (Some(lhs), Some(rhs)) => {
            assert_eq!(lhs, rhs);
        }
        (None, None) => {}
        _ => unreachable!(),
    }

    (lhs_grand_product_chain, rhs_grand_product_chain)
}

#[test]
fn test_parallelized_grand_product() {
    // this is only proof of permutation, without extra login on what the permutation should be

    use crate::ethereum_types::U256;
    use sync_vm::franklin_crypto::bellman::pairing::ff::ScalarEngine;
    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    use sync_vm::testing::Bn256;
    use sync_vm::traits::GenericHasher;
    use zk_evm::aux_structures::*;

    type E = Bn256;

    let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    // create dummy queries

    let mut all_queries = vec![];

    let write = MemoryQuery {
        timestamp: Timestamp(0),
        location: MemoryLocation {
            page: MemoryPage(0),
            index: MemoryIndex(0),
            memory_type: MemoryType::Heap,
        },
        rw_flag: true,
        value: U256::from(123u64),
        is_pended: false,
        value_is_pointer: false,
    };

    all_queries.push(write);

    for i in (1u32..(1u32 << 12)).rev() {
        let read = MemoryQuery {
            timestamp: Timestamp(i),
            location: MemoryLocation {
                page: MemoryPage(0),
                index: MemoryIndex(0),
                memory_type: MemoryType::Heap,
            },
            rw_flag: false,
            value: U256::from(123u64),
            is_pended: false,
            value_is_pointer: false,
        };

        all_queries.push(read);
    }

    // sort by memory location, and then by timestamp
    let mut sorted_memory_queries_accumulated = all_queries.clone();
    sorted_memory_queries_accumulated.par_sort_by(|a, b| match a.location.cmp(&b.location) {
        Ordering::Equal => a.timestamp.cmp(&b.timestamp),
        a @ _ => a,
    });

    println!("Sorted");

    // those two thins are parallelizable, and can be internally parallelized too

    // now we can finish reconstruction of each sorted and unsorted memory queries

    let mut unsorted_memory_queue_states = vec![];
    let mut sorted_memory_queue_states = vec![];

    let mut unsorted_memory_queries_simulator = MemoryQueueSimulator::<E>::empty();
    for query in all_queries.iter() {
        let (_old_tail, intermediate_info) = unsorted_memory_queries_simulator
            .push_and_output_intermediate_data(*query, &round_function);

        unsorted_memory_queue_states.push(intermediate_info);
    }

    println!("Original committed");

    // reconstruct sorted one in full
    let mut sorted_memory_queries_simulator = MemoryQueueSimulator::<E>::empty();
    for query in sorted_memory_queries_accumulated.iter() {
        let (_old_tail, intermediate_info) = sorted_memory_queries_simulator
            .push_and_output_intermediate_data(*query, &round_function);

        sorted_memory_queue_states.push(intermediate_info);
    }

    println!("Sorted committed");

    // dbg!(&sorted_memory_queries_simulator.num_items);

    assert_eq!(
        sorted_memory_queries_simulator.num_items,
        unsorted_memory_queries_simulator.num_items
    );

    // now we should chunk it by circuits but briefly simulating their logic

    let mut challenges = vec![];

    let mut fs_input = vec![];
    fs_input.extend_from_slice(&unsorted_memory_queries_simulator.tail);
    fs_input.push(u64_to_fe(
        unsorted_memory_queries_simulator.num_items as u64,
    ));
    fs_input.extend_from_slice(&sorted_memory_queries_simulator.tail);
    fs_input.push(u64_to_fe(sorted_memory_queries_simulator.num_items as u64));

    let sequence_of_states =
        round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&fs_input);
    let final_state = sequence_of_states.last().unwrap().1;
    use sync_vm::rescue_poseidon::RescueParams;
    let base_fs_challenge: <E as ScalarEngine>::Fr =
        GenericHasher::<Bn256, RescueParams<Bn256, 2, 3>, 2, 3>::simulate_state_into_commitment(
            final_state,
        );

    let mut current = base_fs_challenge;
    challenges.push(current);
    current.mul_assign(&base_fs_challenge);
    challenges.push(current);
    current.mul_assign(&base_fs_challenge);
    challenges.push(current);

    // since encodings of the elements provide all the information necessary to perform soring argument,
    // we use them naively

    let lhs_contributions: Vec<_> = unsorted_memory_queries_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();
    let rhs_contributions: Vec<_> = sorted_memory_queries_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    assert_eq!(lhs_contributions.len(), rhs_contributions.len());

    let mut lhs_grand_product_chain: Vec<_> =
        vec![<E as ScalarEngine>::Fr::zero(); lhs_contributions.len()];
    let mut rhs_grand_product_chain: Vec<_> =
        vec![<E as ScalarEngine>::Fr::zero(); rhs_contributions.len()];

    let challenges: [<E as ScalarEngine>::Fr; 3] = challenges.try_into().unwrap();

    lhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .zip(lhs_contributions.par_chunks(RAM_PERMUTATION_CHUNK_SIZE))
        .for_each(|(dst, src)| {
            assert_eq!(dst.len(), src.len());
            let mut grand_product = <E as ScalarEngine>::Fr::one();
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
        });

    rhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .zip(rhs_contributions.par_chunks(RAM_PERMUTATION_CHUNK_SIZE))
        .for_each(|(dst, src)| {
            assert_eq!(dst.len(), src.len());
            let mut grand_product = <E as ScalarEngine>::Fr::one();
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
        });

    let mut grand_product = <E as ScalarEngine>::Fr::one();
    let mut naive_lhs = vec![];
    for src in lhs_contributions.iter() {
        let mut acc = challenges[2];

        let mut tmp = src[0];
        tmp.mul_assign(&challenges[0]);
        acc.add_assign(&tmp);

        let mut tmp = src[1];
        tmp.mul_assign(&challenges[1]);
        acc.add_assign(&tmp);

        grand_product.mul_assign(&acc);

        naive_lhs.push(grand_product);
    }

    assert_eq!(naive_lhs.len(), lhs_grand_product_chain.len());

    // elementwise products are done, now must fold

    let mut lhs_intermediates: Vec<<E as ScalarEngine>::Fr> = lhs_grand_product_chain
        .par_chunks(RAM_PERMUTATION_CHUNK_SIZE)
        .map(|slice: &[<E as ScalarEngine>::Fr]| *slice.last().unwrap())
        .collect();

    let mut rhs_intermediates: Vec<<E as ScalarEngine>::Fr> = rhs_grand_product_chain
        .par_chunks(RAM_PERMUTATION_CHUNK_SIZE)
        .map(|slice: &[<E as ScalarEngine>::Fr]| *slice.last().unwrap())
        .collect();

    assert_eq!(
        lhs_intermediates.len(),
        lhs_grand_product_chain
            .chunks(RAM_PERMUTATION_CHUNK_SIZE)
            .len()
    );
    assert_eq!(
        rhs_intermediates.len(),
        rhs_grand_product_chain
            .chunks(RAM_PERMUTATION_CHUNK_SIZE)
            .len()
    );

    // accumulate intermediate products
    // we should multiply element [1] by element [0],
    // element [2] by [0] * [1],
    // etc
    let mut acc_lhs = <E as ScalarEngine>::Fr::one();
    for el in lhs_intermediates.iter_mut() {
        let tmp = *el;
        el.mul_assign(&acc_lhs);
        acc_lhs.mul_assign(&tmp);
    }

    let mut acc_rhs = <E as ScalarEngine>::Fr::one();
    for el in rhs_intermediates.iter_mut() {
        let tmp = *el;
        el.mul_assign(&acc_rhs);
        acc_rhs.mul_assign(&tmp);
    }

    assert_eq!(
        lhs_intermediates.last().unwrap(),
        rhs_intermediates.last().unwrap()
    );

    // here we skip 1 because we do not have anything to pre-accumuate
    lhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .skip(1)
        .zip(lhs_intermediates.par_chunks(1))
        .for_each(|(dst, src)| {
            assert_eq!(src.len(), 1);
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        });

    for (idx, (a, b)) in naive_lhs
        .iter()
        .zip(lhs_grand_product_chain.iter())
        .enumerate()
    {
        assert_eq!(a, b, "failed at index {}: a = {}, b = {}", idx, a, b);
    }

    rhs_grand_product_chain
        .par_chunks_mut(RAM_PERMUTATION_CHUNK_SIZE)
        .skip(1)
        .zip(rhs_intermediates.par_chunks(1))
        .for_each(|(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        });

    // sanity check
    assert_eq!(
        lhs_grand_product_chain.last().unwrap(),
        rhs_grand_product_chain.last().unwrap()
    );
}
