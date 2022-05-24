use sync_vm::utils::u64_to_fe;

use crate::encodings::memory_query::MemoryQueueSimulator;
use std::cmp::Ordering;
use crate::bellman::Engine;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use rayon::prelude::*;
use crate::ff::Field;
use crate::witness_structures::ram_circuit::RamPermutationCircuitInstanceWitness;

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
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = E::Fr::zero();
                let mut tmp = src[0];
                tmp.mul_assign(&challenges[0]);
                acc.add_assign(&tmp);
                let mut tmp = src[1];
                tmp.mul_assign(&challenges[1]);
                acc.add_assign(&tmp);
    
                acc.add_assign(&challenges[2]);
    
                *dst = acc;
            }
        }
    );

    rhs_grand_product_chain.par_chunks_mut(CHUNK_SIZE).zip(rhs_contributions.par_chunks(CHUNK_SIZE)).for_each(
        |(dst, src)| {
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = E::Fr::zero();
                let mut tmp = src[0];
                tmp.mul_assign(&challenges[0]);
                acc.add_assign(&tmp);
                let mut tmp = src[1];
                tmp.mul_assign(&challenges[1]);
                acc.add_assign(&tmp);
    
                acc.add_assign(&challenges[2]);
    
                *dst = acc;
            }
        }
    );

    // elementwise products are done, now must fold

    let lhs_intermediates: Vec<E::Fr> = lhs_grand_product_chain.par_chunks(CHUNK_SIZE).map(
        |slice: &[E::Fr]| {
            let mut grand_product: E::Fr = E::Fr::one();
            for el in slice.iter() {
                grand_product.mul_assign(el);
            }

            grand_product
        }
    ).collect();

    let rhs_intermediates: Vec<E::Fr> = rhs_grand_product_chain.par_chunks(CHUNK_SIZE).map(
        |slice: &[E::Fr]| {
            let mut grand_product: E::Fr = E::Fr::one();
            for el in slice.iter() {
                grand_product.mul_assign(el);
            }

            grand_product
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

    // sanity check
    assert_eq!(lhs_grand_product_chain.last().unwrap(), rhs_grand_product_chain.last().unwrap());

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    assert_eq!(lhs_grand_product_chain.len(), artifacts.all_memory_queries_accumulated.len());
    assert_eq!(lhs_grand_product_chain.len(), artifacts.sorted_memory_queries_accumulated.len());
    assert_eq!(lhs_grand_product_chain.len(), memory_queue_simulator.witness.len());
    assert_eq!(lhs_grand_product_chain.len(), sorted_memory_queries_simulator.witness.len());

    // we also want to have chunks of witness for each of all the intermediate states

    let mut it = artifacts.all_memory_queries_accumulated.chunks(per_circuit_capacity)
            .zip(artifacts.sorted_memory_queries_accumulated.chunks(per_circuit_capacity))
            .zip(lhs_grand_product_chain.chunks(per_circuit_capacity))
            .zip(rhs_grand_product_chain.chunks(per_circuit_capacity))
            .zip(memory_queue_simulator.witness.chunks(per_circuit_capacity))
            .zip(sorted_memory_queries_simulator.witness.chunks(per_circuit_capacity));

    // now trivial transformation into desired data structures,
    // and we are all good


    // // quick and dirty grand product calculation
    // let lhs_fold = lhs_contributions.into_par_iter().fold(
    //     || E::Fr::one(),
    //     |mut a, b| {
    //         let mut acc = E::Fr::zero();
    //         let mut tmp = b[0];
    //         tmp.mul_assign(&challenges[0]);
    //         acc.add_assign(&tmp);
    //         let mut tmp = b[1];
    //         tmp.mul_assign(&challenges[1]);
    //         acc.add_assign(&tmp);

    //         acc.add_assign(&challenges[2]);

    //         a.mul_assign(&acc);

    //         a
    //     }
    // );

    // for el in lhs_fold.into_iter() {
    //     dbg!(&el);
    // }

    // previous_sk: Num<E>,
    // previous_full_key: Num<E>,
    // last_element_values: [Num<E>; 2],

    // we have to
    todo!()
}