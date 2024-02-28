use super::*;
use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::boojum::gadgets::u256::decompose_u256_as_u32x8;
use crate::ethereum_types::U256;
use crate::witness::utils::produce_fs_challenges;
use crate::zk_evm::aux_structures::MemoryIndex;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zkevm_circuits::base_structures::decommit_query::DecommitQuery;
use crate::zkevm_circuits::base_structures::decommit_query::DecommitQueryWitness;
use crate::zkevm_circuits::base_structures::decommit_query::DECOMMIT_QUERY_PACKED_WIDTH;
use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::zkevm_circuits::sort_decommittment_requests::input::*;
use crate::zkevm_circuits::DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS;
use circuit_definitions::encodings::decommittment_request::*;
use circuit_definitions::encodings::CircuitEquivalentReflection;
use rayon::prelude::*;
use std::cmp::Ordering;

pub fn compute_decommitts_sorter_circuit_snapshots<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    artifacts: &mut FullBlockArtifacts<F>,
    round_function: &R,
    deduplicator_circuit_capacity: usize,
) -> Vec<CodeDecommittmentsDeduplicatorInstanceWitness<F>> {
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.all_memory_queue_states.len()
    );
    assert_eq!(
        artifacts.all_memory_queries_accumulated.len(),
        artifacts.memory_queue_simulator.num_items as usize
    );

    assert!(
        artifacts.all_decommittment_queries.len() > 0,
        "VM should have made some code decommits"
    );

    // we produce witness for two circuits at once

    let mut unsorted_decommittment_queue_simulator = DecommittmentQueueSimulator::<F>::empty();
    let mut sorted_decommittment_queue_simulator = DecommittmentQueueSimulator::<F>::empty();

    // sort decommittment requests

    let mut sorted_decommittment_queue_states = vec![];

    let mut unsorted_decommittment_requests_with_data = vec![];
    for (_cycle, decommittment_request, writes) in artifacts.all_decommittment_queries.iter_mut() {
        let data = std::mem::replace(writes, vec![]);
        unsorted_decommittment_requests_with_data.push((*decommittment_request, data));
    }

    let num_circuits = (artifacts.all_decommittment_queries.len() + deduplicator_circuit_capacity
        - 1)
        / deduplicator_circuit_capacity;

    // internally parallelizable by the factor of 3
    for (cycle, decommittment_request, _) in artifacts.all_decommittment_queries.iter() {
        // sponge
        let (_old_tail, intermediate_info) = unsorted_decommittment_queue_simulator
            .push_and_output_intermediate_data(*decommittment_request, round_function);

        artifacts
            .all_decommittment_queue_states
            .push((*cycle, intermediate_info));
    }

    // sort queries
    let mut sorted_decommittment_requests_with_data = unsorted_decommittment_requests_with_data;
    sorted_decommittment_requests_with_data.par_sort_by(|a, b|
        // sort by hash first, and then by timestamp
        match a.0.hash.cmp(&b.0.hash) {
            Ordering::Equal => a.0.timestamp.cmp(&b.0.timestamp),
            a @ _ => a,
        });

    // let mut deduplicated_decommit_requests_with_data = vec![];

    let mut counter = 0;
    let mut deduplicated_intermediate_states = vec![];
    let mut previous_packed_keys = vec![];
    let mut previous_records = vec![];
    let mut first_encountered_timestamps = vec![];
    let mut first_encountered_timestamp = 0;
    let mut previous_deduplicated_decommittment_queue_simulator_state =
        take_sponge_like_queue_state_from_simulator(
            &artifacts.deduplicated_decommittment_queue_simulator,
        );

    let num_items = sorted_decommittment_requests_with_data.len();

    // self-check that we had a proper oracle
    use crate::zk_evm::aux_structures::{MemoryPage, Timestamp};
    let mut tmp: Option<(U256, MemoryPage, Timestamp)> = None;
    for (query, _) in sorted_decommittment_requests_with_data.iter() {
        if let Some((hash, page, timestamp)) = tmp.as_mut() {
            if *hash == query.hash {
                assert_eq!(*page, query.memory_page);
                assert!(query.timestamp.0 > (*timestamp).0);
            } else {
                assert!(query.hash >= *hash);
                *hash = query.hash;
                *page = query.memory_page;
                *timestamp = query.timestamp;
            }
        } else {
            tmp = Some((query.hash, query.memory_page, query.timestamp));
        }
    }

    for (idx, (query, writes)) in sorted_decommittment_requests_with_data
        .into_iter()
        .enumerate()
    {
        let last = idx == num_items - 1;
        if query.is_fresh {
            assert!(writes.len() > 0);

            first_encountered_timestamp = query.timestamp.0;

            // and sorted request
            artifacts.deduplicated_decommittment_queries.push(query);

            previous_deduplicated_decommittment_queue_simulator_state =
                take_sponge_like_queue_state_from_simulator(
                    &artifacts.deduplicated_decommittment_queue_simulator,
                );
            let (_old_tail, intermediate_info) = artifacts
                .deduplicated_decommittment_queue_simulator
                .push_and_output_intermediate_data(query, round_function);

            artifacts
                .deduplicated_decommittment_queue_states
                .push(intermediate_info);
            artifacts
                .deduplicated_decommit_requests_with_data
                .push((query, writes));
        }

        let (_old_tail, intermediate_info) = sorted_decommittment_queue_simulator
            .push_and_output_intermediate_data(query, round_function);

        sorted_decommittment_queue_states.push(intermediate_info);

        artifacts.sorted_decommittment_queries.push(query);

        counter += 1;

        if counter == deduplicator_circuit_capacity {
            counter = 0;

            if last {
                deduplicated_intermediate_states.push(take_sponge_like_queue_state_from_simulator(
                    &artifacts.deduplicated_decommittment_queue_simulator,
                ));
            } else {
                deduplicated_intermediate_states
                    .push(previous_deduplicated_decommittment_queue_simulator_state.clone());
            }

            let record = sorted_decommittment_queue_simulator
                .witness
                .pop_back()
                .unwrap();
            previous_packed_keys.push(concatenate_key(record.2.hash, record.2.timestamp.0));

            previous_records.push(record.2.reflect());
            first_encountered_timestamps.push(first_encountered_timestamp);

            sorted_decommittment_queue_simulator
                .witness
                .push_back(record);
        }
    }
    if counter > 0 {
        deduplicated_intermediate_states.push(take_sponge_like_queue_state_from_simulator(
            &artifacts.deduplicated_decommittment_queue_simulator,
        ));

        previous_packed_keys.push([0u32; PACKED_KEY_LENGTH]);
        previous_records.push(DecommitQuery::<F>::placeholder_witness());
        first_encountered_timestamps.push(0);
    }

    assert_eq!(
        artifacts.all_memory_queue_states.len(),
        artifacts.all_memory_queries_accumulated.len()
    );

    // create witnesses

    let mut decommittments_deduplicator_witness: Vec<
        CodeDecommittmentsDeduplicatorInstanceWitness<F>,
    > = vec![];

    let mut input_passthrough_data =
        CodeDecommittmentsDeduplicatorInputData::<F>::placeholder_witness();
    input_passthrough_data.initial_queue_state =
        take_sponge_like_queue_state_from_simulator(&unsorted_decommittment_queue_simulator);
    input_passthrough_data.sorted_queue_initial_state =
        take_sponge_like_queue_state_from_simulator(&sorted_decommittment_queue_simulator);

    let mut output_passthrough_data =
        CodeDecommittmentsDeduplicatorOutputData::<F>::placeholder_witness();
    output_passthrough_data.final_queue_state = take_sponge_like_queue_state_from_simulator(
        &artifacts.deduplicated_decommittment_queue_simulator,
    );

    // now we should chunk it by circuits but briefly simulating their logic

    let challenges = produce_fs_challenges::<F, R, 12, { DECOMMIT_QUERY_PACKED_WIDTH + 1 }, 2>(
        take_sponge_like_queue_state_from_simulator(&unsorted_decommittment_queue_simulator).tail,
        take_sponge_like_queue_state_from_simulator(&sorted_decommittment_queue_simulator).tail,
        round_function,
    );

    let lhs_contributions: Vec<_> = unsorted_decommittment_queue_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();
    let rhs_contributions: Vec<_> = sorted_decommittment_queue_simulator
        .witness
        .iter()
        .map(|el| el.0)
        .collect();

    let mut lhs_grand_product_chains = vec![];
    let mut rhs_grand_product_chains = vec![];

    for idx in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
        let (lhs_grand_product_chain, rhs_grand_product_chain) =
            compute_grand_product_chains::<
                F,
                DECOMMIT_QUERY_PACKED_WIDTH,
                { DECOMMIT_QUERY_PACKED_WIDTH + 1 },
            >(&lhs_contributions, &rhs_contributions, &challenges[idx]);
        assert_eq!(
            lhs_grand_product_chain.len(),
            unsorted_decommittment_queue_simulator.witness.len()
        );
        assert_eq!(
            lhs_grand_product_chain.len(),
            sorted_decommittment_queue_simulator.witness.len()
        );

        lhs_grand_product_chains.push(lhs_grand_product_chain);
        rhs_grand_product_chains.push(rhs_grand_product_chain);
    }

    // now we need to split them into individual circuits
    // splitting is not extra hard here, we walk over iterator over everything and save states on checkpoints

    let num_items = unsorted_decommittment_queue_simulator.num_items;

    let mut input_products = [F::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut input_products_snapshots = vec![];
    let mut input_witness = vec![];
    let mut input_witness_chunk = VecDeque::new();
    let mut unsorted_intermediate_states = vec![];
    for i in 0..num_items {
        let (encoding, old_tail, element) = unsorted_decommittment_queue_simulator
            .witness
            .front()
            .unwrap();

        let wit = DecommitQueryWitness {
            code_hash: element.hash,
            page: element.memory_page.0,
            is_first: element.is_fresh,
            timestamp: element.timestamp.0,
        };

        input_witness_chunk.push_back((*encoding, wit, *old_tail));

        unsorted_decommittment_queue_simulator.pop_and_output_intermediate_data(round_function);
        if input_witness_chunk.len() == deduplicator_circuit_capacity {
            let completed_chunk = std::mem::replace(&mut input_witness_chunk, VecDeque::new());
            for j in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
                input_products[j] = lhs_grand_product_chains[j][i as usize];
            }
            input_witness.push(completed_chunk);
            input_products_snapshots.push(input_products);
            unsorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(
                &unsorted_decommittment_queue_simulator,
            ));
        }
    }
    if input_witness_chunk.len() > 0 {
        input_witness.push(input_witness_chunk);
        for j in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
            input_products[j] = *lhs_grand_product_chains[j].last().unwrap();
        }
        input_products_snapshots.push(input_products);
        unsorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(
            &unsorted_decommittment_queue_simulator,
        ));
    }

    assert_eq!(num_items, sorted_decommittment_queue_simulator.num_items);
    let mut sorted_products = [F::ONE; DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS];
    let mut sorted_products_snapshots = vec![];
    let mut sorted_witness = vec![];
    let mut sorted_witness_chunk = VecDeque::new();
    let mut sorted_intermediate_states = vec![];
    for i in 0..num_items {
        let (encoding, old_tail, element) = sorted_decommittment_queue_simulator
            .witness
            .front()
            .unwrap();
        let wit = DecommitQueryWitness {
            code_hash: element.hash,
            page: element.memory_page.0,
            is_first: element.is_fresh,
            timestamp: element.timestamp.0,
        };

        sorted_witness_chunk.push_back((*encoding, wit, *old_tail));

        sorted_decommittment_queue_simulator.pop_and_output_intermediate_data(round_function);
        if sorted_witness_chunk.len() == deduplicator_circuit_capacity {
            let completed_chunk = std::mem::replace(&mut sorted_witness_chunk, VecDeque::new());
            sorted_witness.push(completed_chunk);
            for j in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
                sorted_products[j] = rhs_grand_product_chains[j][i as usize];
            }
            sorted_products_snapshots.push(sorted_products);
            sorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(
                &sorted_decommittment_queue_simulator,
            ));
        }
    }
    if sorted_witness_chunk.len() > 0 {
        sorted_witness.push(sorted_witness_chunk);
        for j in 0..DEFAULT_NUM_PERMUTATION_ARGUMENT_REPETITIONS {
            sorted_products[j] = *rhs_grand_product_chains[j].last().unwrap();
        }
        sorted_products_snapshots.push(sorted_products);
        sorted_intermediate_states.push(take_sponge_like_queue_state_from_simulator(
            &sorted_decommittment_queue_simulator,
        ));
    }

    for i in 0..num_circuits {
        let mut current_witness = CodeDecommittmentsDeduplicatorInstanceWitness {
            closed_form_input: CodeDecommittmentsDeduplicatorInputOutputWitness {
                start_flag: i == 0,
                completion_flag: i == num_circuits - 1,
                observable_input: input_passthrough_data.clone(),
                observable_output: CodeDecommittmentsDeduplicatorOutputData::placeholder_witness(),
                hidden_fsm_input: CodeDecommittmentsDeduplicatorFSMInputOutput::placeholder_witness(
                ),
                hidden_fsm_output:
                    CodeDecommittmentsDeduplicatorFSMInputOutput::placeholder_witness(),
            },
            initial_queue_witness: FullStateCircuitQueueRawWitness::<
                F,
                DecommitQuery<F>,
                FULL_SPONGE_QUEUE_STATE_WIDTH,
                DECOMMIT_QUERY_PACKED_WIDTH,
            > {
                elements: VecDeque::new(),
            },
            sorted_queue_witness: FullStateCircuitQueueRawWitness::<
                F,
                DecommitQuery<F>,
                FULL_SPONGE_QUEUE_STATE_WIDTH,
                DECOMMIT_QUERY_PACKED_WIDTH,
            > {
                elements: VecDeque::new(),
            },
        };

        if i == num_circuits - 1 {
            // set passthrough output
            current_witness.closed_form_input.observable_output = output_passthrough_data.clone();
        }
        let unsorted_circuit_witness = input_witness[i]
            .iter()
            .map(|el| (el.1.clone(), el.2))
            .collect();
        let sorted_circuit_witness = sorted_witness[i]
            .iter()
            .map(|el| (el.1.clone(), el.2))
            .collect();
        current_witness.initial_queue_witness = FullStateCircuitQueueRawWitness::<
            F,
            DecommitQuery<F>,
            FULL_SPONGE_QUEUE_STATE_WIDTH,
            DECOMMIT_QUERY_PACKED_WIDTH,
        > {
            elements: unsorted_circuit_witness,
        };
        current_witness.sorted_queue_witness = FullStateCircuitQueueRawWitness::<
            F,
            DecommitQuery<F>,
            FULL_SPONGE_QUEUE_STATE_WIDTH,
            DECOMMIT_QUERY_PACKED_WIDTH,
        > {
            elements: sorted_circuit_witness,
        };

        if let Some(previous_witness) = decommittments_deduplicator_witness.last() {
            current_witness.closed_form_input.hidden_fsm_input =
                previous_witness.closed_form_input.hidden_fsm_output.clone();
        }

        current_witness.closed_form_input.hidden_fsm_output =
            CodeDecommittmentsDeduplicatorFSMInputOutputWitness {
                initial_queue_state: unsorted_intermediate_states[i].clone(),
                sorted_queue_state: sorted_intermediate_states[i].clone(),
                final_queue_state: deduplicated_intermediate_states[i].clone(),

                lhs_accumulator: input_products_snapshots[i],
                rhs_accumulator: sorted_products_snapshots[i],

                previous_packed_key: previous_packed_keys[i],
                previous_record: previous_records[i].clone(),
                first_encountered_timestamp: first_encountered_timestamps[i],
            };

        decommittments_deduplicator_witness.push(current_witness);
    }

    decommittments_deduplicator_witness
}

fn concatenate_key(hash: U256, timestamp: u32) -> [u32; PACKED_KEY_LENGTH] {
    let hash_as_u32_le = decompose_u256_as_u32x8(hash);
    [
        timestamp,
        hash_as_u32_le[0],
        hash_as_u32_le[1],
        hash_as_u32_le[2],
        hash_as_u32_le[3],
        hash_as_u32_le[4],
        hash_as_u32_le[5],
        hash_as_u32_le[6],
        hash_as_u32_le[7],
    ]
}
