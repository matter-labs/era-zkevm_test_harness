use crate::boojum::{
    cs::traits::cs::ConstraintSystem,
    field::{goldilocks::GoldilocksExt2, U64Representable},
    gadgets::{
        queue::QueueTailStateWitness, recursion::allocated_vk::AllocatedVerificationKey,
        traits::allocatable::CSAllocatable,
    },
};

use super::*;
use crate::boojum::gadgets::num::Num;
use crate::boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::witness::utils::take_sponge_like_queue_state_from_simulator;
use crate::zkevm_circuits::recursion::{
    leaf_layer::input::*,
    node_layer::{input::RecursionNodeInputWitness, NodeLayerRecursionConfig},
    VK_COMMITMENT_LENGTH,
};
use crate::zkevm_circuits::scheduler::LEAF_LAYER_PARAMETERS_COMMITMENT_LENGTH;
use circuit_definitions::{base_layer_proof_config, recursion_layer_proof_config};
use circuit_definitions::{
    zkevm_circuits::scheduler::aux::NUM_CIRCUIT_TYPES_TO_SCHEDULE, ZkSyncDefaultRoundFunction,
};
use std::collections::VecDeque;

type F = GoldilocksField;
type EXT = GoldilocksExt2;
type H = CircuitGoldilocksPoseidon2Sponge;

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::RecursiveTreeHasher;
use crate::boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use crate::boojum::gadgets::traits::round_function::BuildableCircuitRoundFunction;
use crate::boojum::gadgets::traits::witnessable::WitnessHookable;
use crate::zkevm_circuits::fsm_input_output::commit_variable_length_encodable_item;
use crate::zkevm_circuits::recursion::leaf_layer::LeafLayerRecursionConfig;
use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::{
    node_layer::ZkSyncNodeLayerRecursiveCircuit, *,
};
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::encodings::CircuitEquivalentReflection;

pub(crate) fn compute_encodable_item_from_witness<
    T: CSAllocatable<F> + CircuitVarLengthEncodable<F>,
    const N: usize,
    CS: ConstraintSystem<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
>(
    wit: T::Witness,
    cs: &mut CS,
    round_function: &R,
) -> [F; N] {
    // allocate in full

    let element = T::allocate(cs, wit);

    let commitment = commit_variable_length_encodable_item(cs, &element, round_function);
    let commitment = commitment.witness_hook(&*cs)().unwrap();

    commitment
}

pub fn create_leaf_witnesses(
    subset: (
        u64,
        RecursionQueueSimulator<F>,
        Vec<ZkSyncBaseLayerClosedFormInput<F>>,
    ),
    proofs: Vec<ZkSyncBaseLayerProof>,
    vk: ZkSyncBaseLayerVerificationKey,
    leaf_params: (u8, RecursionLeafParametersWitness<F>),
) -> (
    Vec<(
        u64,
        RecursionQueueSimulator<F>, // chunk
        ZkSyncRecursiveLayerCircuit, // proof for that chunk
                                    // RecursionLeafInputWitness<F>, // input for the circuit over this chunk
    )>,
    Vec<ZkSyncBaseLayerClosedFormInput<F>>,
) {
    let round_function = ZkSyncDefaultRoundFunction::default();

    let (circuit_type, queue, closed_form_inputs) = subset;
    assert_eq!(queue.num_items as usize, proofs.len());
    assert_eq!(circuit_type, vk.numeric_circuit_type() as u64);

    let (t, params) = leaf_params;
    assert_eq!(t, circuit_type as u8);

    let queue_splits = queue.split_by(RECURSION_ARITY, &round_function);
    let mut proofs_iter = proofs.into_iter();

    let mut results = Vec::with_capacity(queue_splits.len());

    for el in queue_splits.iter().cloned() {
        let mut proof_witnesses = VecDeque::new();
        for _ in 0..el.num_items {
            let t = proofs_iter.next().expect("proof");
            proof_witnesses.push_back(t.into_inner());
        }
        let leaf_input = RecursionLeafInputWitness::<F> {
            params: params.clone(),
            queue_state: take_sponge_like_queue_state_from_simulator(&el),
        };

        let elements: VecDeque<_> = el
            .witness
            .iter()
            .map(|(_, old_tail, element)| (element.reflect(), *old_tail))
            .collect();

        let witness = RecursionLeafInstanceWitness::<F, H, EXT> {
            input: leaf_input,
            vk_witness: vk.clone().into_inner(),
            queue_witness: FullStateCircuitQueueRawWitness { elements: elements },
            proof_witnesses: proof_witnesses,
        };

        let config = LeafLayerRecursionConfig::<
            F,
            <H as RecursiveTreeHasher<F, Num<F>>>::NonCircuitSimulator,
            EXT,
        > {
            proof_config: recursion_layer_proof_config(),
            vk_fixed_parameters: vk.clone().into_inner().fixed_parameters,
            capacity: RECURSION_ARITY,
            _marker: std::marker::PhantomData,
        };

        let base_layer_circuit_type =
            BaseLayerCircuitType::from_numeric_value(vk.numeric_circuit_type());
        let circuit = ZkSyncLeafLayerRecursiveCircuit {
            witness,
            config,
            transcript_params: (),
            base_layer_circuit_type: base_layer_circuit_type,
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncRecursiveLayerCircuit::leaf_circuit_from_base_type(
            BaseLayerCircuitType::from_numeric_value(vk.numeric_circuit_type()),
            circuit,
        );

        results.push((
            circuit_type,
            el,
            circuit,
            // leaf_input,
        ));
    }

    (results, closed_form_inputs)
}

pub fn compute_leaf_params(
    circuit_type: u8,
    base_layer_vk: ZkSyncBaseLayerVerificationKey,
    leaf_layer_vk: ZkSyncRecursionLayerVerificationKey,
) -> RecursionLeafParametersWitness<F> {
    use circuit_definitions::ZkSyncDefaultRoundFunction;
    let round_function = ZkSyncDefaultRoundFunction::default();

    use crate::witness::utils::*;

    assert_eq!(circuit_type, base_layer_vk.numeric_circuit_type());
    assert_eq!(
        base_circuit_type_into_recursive_leaf_circuit_type(
            BaseLayerCircuitType::from_numeric_value(circuit_type)
        ) as u8,
        leaf_layer_vk.numeric_circuit_type()
    );

    let mut cs_for_witness_generation =
        create_cs_for_witness_generation::<F, ZkSyncDefaultRoundFunction>(
            TRACE_LEN_LOG_2_FOR_CALCULATION,
            MAX_VARS_LOG_2_FOR_CALCULATION,
        );

    let base_vk_commitment: [_; VK_COMMITMENT_LENGTH] = compute_encodable_item_from_witness::<
        AllocatedVerificationKey<F, H>,
        VK_COMMITMENT_LENGTH,
        _,
        _,
    >(
        base_layer_vk.into_inner(),
        &mut cs_for_witness_generation,
        &round_function,
    );

    let leaf_vk_commitment: [_; VK_COMMITMENT_LENGTH] = compute_encodable_item_from_witness::<
        AllocatedVerificationKey<F, H>,
        VK_COMMITMENT_LENGTH,
        _,
        _,
    >(
        leaf_layer_vk.into_inner(),
        &mut cs_for_witness_generation,
        &round_function,
    );

    let params = RecursionLeafParametersWitness::<F> {
        circuit_type: F::from_u64_unchecked(circuit_type as u64),
        basic_circuit_vk_commitment: base_vk_commitment,
        leaf_layer_vk_commitment: leaf_vk_commitment,
    };

    params
}

pub fn compute_leaf_vks_and_params_commitment(
    leaf_params: [RecursionLeafParametersWitness<F>; NUM_CIRCUIT_TYPES_TO_SCHEDULE],
) -> [F; LEAF_LAYER_PARAMETERS_COMMITMENT_LENGTH] {
    use circuit_definitions::ZkSyncDefaultRoundFunction;

    let round_function = ZkSyncDefaultRoundFunction::default();
    use crate::witness::utils::*;
    let mut cs_for_witness_generation =
        create_cs_for_witness_generation::<F, ZkSyncDefaultRoundFunction>(
            TRACE_LEN_LOG_2_FOR_CALCULATION,
            MAX_VARS_LOG_2_FOR_CALCULATION,
        );

    let params_commitment: [_; LEAF_LAYER_PARAMETERS_COMMITMENT_LENGTH] =
        compute_encodable_item_from_witness::<
            [RecursionLeafParameters<F>; NUM_CIRCUIT_TYPES_TO_SCHEDULE],
            LEAF_LAYER_PARAMETERS_COMMITMENT_LENGTH,
            _,
            _,
        >(leaf_params, &mut cs_for_witness_generation, &round_function);

    params_commitment
}

pub fn compute_node_vk_commitment(
    node_vk: ZkSyncRecursionLayerVerificationKey,
) -> [F; VK_COMMITMENT_LENGTH] {
    use circuit_definitions::ZkSyncDefaultRoundFunction;

    let round_function = ZkSyncDefaultRoundFunction::default();
    use crate::witness::utils::*;
    let mut cs_for_witness_generation =
        create_cs_for_witness_generation::<F, ZkSyncDefaultRoundFunction>(
            TRACE_LEN_LOG_2_FOR_CALCULATION,
            MAX_VARS_LOG_2_FOR_CALCULATION,
        );

    let vk_commitment: [_; VK_COMMITMENT_LENGTH] = compute_encodable_item_from_witness::<
        AllocatedVerificationKey<F, H>,
        VK_COMMITMENT_LENGTH,
        _,
        _,
    >(
        node_vk.into_inner(),
        &mut cs_for_witness_generation,
        &round_function,
    );

    vk_commitment
}

pub fn create_node_witnesses(
    chunks: Vec<(
        u64,
        RecursionQueueSimulator<F>,  // chunk
        ZkSyncRecursiveLayerCircuit, // proof for that chunk
    )>,
    proofs: Vec<ZkSyncRecursionLayerProof>,
    vk: ZkSyncRecursionLayerVerificationKey,
    node_vk_commitment: [F; VK_COMMITMENT_LENGTH],
    leaf_layer_params: &Vec<(u8, RecursionLeafParametersWitness<F>)>,
) -> Vec<(
    u64,
    RecursionQueueSimulator<F>,  // chunk
    ZkSyncRecursiveLayerCircuit, // proof for that chunk
)> {
    use crate::boojum::gadgets::queue::QueueState;
    use crate::zkevm_circuits::recursion::NUM_BASE_LAYER_CIRCUITS;

    assert_eq!(leaf_layer_params.len(), NUM_BASE_LAYER_CIRCUITS);

    assert_eq!(chunks.len(), proofs.len());

    assert!(chunks.len() > 0);
    let circuit_type = chunks[0].0 as u8;
    let mut proofs_iter = proofs.into_iter();

    let leaf_layer_params = leaf_layer_params
        .iter()
        .map(|el| {
            assert_eq!(el.0 as u64, el.1.circuit_type.as_u64_reduced());

            el.1.clone()
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let partial_inputs = RecursionNodeInputWitness {
        branch_circuit_type: F::from_u64_unchecked(circuit_type as u64),
        leaf_layer_parameters: leaf_layer_params,
        node_layer_vk_commitment: node_vk_commitment,
        queue_state: QueueState::placeholder_witness(),
    };

    let config = NodeLayerRecursionConfig::<
        F,
        <H as RecursiveTreeHasher<F, Num<F>>>::NonCircuitSimulator,
        EXT,
    > {
        proof_config: recursion_layer_proof_config(),
        vk_fixed_parameters: vk.clone().into_inner().fixed_parameters,
        leaf_layer_capacity: RECURSION_ARITY,
        node_layer_capacity: RECURSION_ARITY,
        _marker: std::marker::PhantomData,
    };

    let mut results = vec![];

    for chunk in chunks.chunks(RECURSION_ARITY) {
        assert!(chunk.len() > 0);
        // if chunk exists it's elements are non-trivial
        for (_, c, _) in chunk.iter() {
            assert!(c.num_items > 0);
        }
        let num_chunks = chunk.len();
        // we can immediatelly collect proofs
        let proofs: Vec<_> = (&mut proofs_iter)
            .take(num_chunks)
            .map(|el| el.into_inner())
            .collect();
        assert_eq!(proofs.len(), num_chunks); // so we indeed taken exactly enough

        // now even though we would have a chunk of len N, we should only create N-1 split points at the end

        let mut split_points = Vec::with_capacity(RECURSION_ARITY);
        let mut it = chunk.into_iter();

        // Take the first chunk (guaranteed to exist)
        let (circuit_type, queue, _) = (&mut it).next().unwrap();
        let circuit_type = *circuit_type;
        let mut queue = queue.clone();
        split_points.push(QueueTailStateWitness {
            tail: queue.tail,
            length: queue.num_items,
        });

        // merge all of them, and record split points
        for (_, c, _) in it {
            // Split point is a tail of the subqueue
            split_points.push(QueueTailStateWitness {
                tail: c.tail,
                length: c.num_items,
            });

            queue = RecursionQueueSimulator::<F>::merge(queue, c.clone());
        }

        // check that for every subqueue we have a proof
        assert_eq!(split_points.len(), proofs.len());

        // self-check that we have a matching length
        let total_queue_len = queue.num_items;
        let mut acc = 0;
        for el in split_points.iter() {
            acc += el.length;
        }
        assert_eq!(acc, total_queue_len);

        // for N chunks we need N-1 split points, so either truncate, or pad
        assert!(split_points.len() <= RECURSION_ARITY);

        if split_points.len() == RECURSION_ARITY {
            let _ = split_points.pop().unwrap();
        } else {
            // pad it
            let padding = QueueTailStateWitness {
                tail: queue.tail,
                length: 0,
            };
            split_points.resize(RECURSION_ARITY - 1, padding);
        }

        assert_eq!(split_points.len() + 1, RECURSION_ARITY);

        let mut input = partial_inputs.clone();
        input.queue_state = take_sponge_like_queue_state_from_simulator(&queue);

        use crate::zkevm_circuits::recursion::node_layer::input::RecursionNodeInstanceWitness;

        let witness = RecursionNodeInstanceWitness {
            input,
            vk_witness: vk.clone().into_inner(),
            split_points: split_points.into(),
            proof_witnesses: proofs.into(),
        };

        let circuit = ZkSyncNodeLayerRecursiveCircuit {
            witness: witness,
            config: config.clone(),
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let circuit = ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(circuit);

        results.push((circuit_type, queue, circuit));
    }

    assert!(proofs_iter.next().is_none());

    results
}
