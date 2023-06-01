use boojum::{field::{goldilocks::GoldilocksExt2, U64Representable}, gadgets::{traits::allocatable::CSAllocatable, recursion::allocated_vk::AllocatedVerificationKey, queue::QueueTailStateWitness}, cs::traits::cs::ConstraintSystem};

use crate::witness::utils::take_sponge_like_queue_state_from_simulator;
use super::*;
use boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use zkevm_circuits::recursion::{leaf_layer::input::*, VK_COMMITMENT_LENGTH, node_layer::{input::RecursionNodeInputWitness, NodeLayerRecursionConfig}};
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use std::collections::VecDeque;
use boojum::gadgets::num::Num;

type F = GoldilocksField;
type EXT = GoldilocksExt2;
type H = CircuitGoldilocksPoseidon2Sponge;

use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::traits::round_function::BuildableCircuitRoundFunction;
use zkevm_circuits::fsm_input_output::commit_variable_length_encodable_item;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use zkevm_circuits::recursion::leaf_layer::LeafLayerRecursionConfig;
use crate::external_calls::base_layer_proof_config;
use boojum::gadgets::recursion::recursive_tree_hasher::RecursiveTreeHasher;
use circuit_definitions::circuit_definitions::recursion_layer::{*, node_layer::ZkSyncNodeLayerRecursiveCircuit};
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::circuit_definitions::recursion_layer::leaf_layer::*;
use circuit_definitions::encodings::CircuitEquivalentReflection;

pub(crate) fn compute_encodable_item_from_witness<
T: CSAllocatable<F> + CircuitVarLengthEncodable<F>, 
const N: usize, 
CS: ConstraintSystem<F>,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
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
    subset: (u64, RecursionQueueSimulator<F>, Vec<ZkSyncBaseLayerClosedFormInput<F>>),
    proofs: Vec<ZkSyncBaseLayerProof>,
    padding_proof: ZkSyncBaseLayerProof,
    vk: ZkSyncBaseLayerVerificationKey,
    leaf_params: (u8, RecursionLeafParametersWitness<F>),
) -> (Vec<(
    u64,
    RecursionQueueSimulator<F>, // chunk
    ZkSyncRecursiveLayerCircuit, // proof for that chunk
    // RecursionLeafInputWitness<F>, // input for the circuit over this chunk
)>,
    Vec<ZkSyncBaseLayerClosedFormInput<F>>
) {
    let round_function = ZkSyncDefaultRoundFunction::default();

    let (circuit_type, queue, closed_form_inputs) = subset;
    assert_eq!(queue.num_items as usize, proofs.len());
    assert_eq!(circuit_type, padding_proof.numeric_circuit_type() as u64);
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

        let elements: VecDeque<_> = el.witness.iter().map(|(_, old_tail, element)| {
            (element.reflect(), *old_tail)
        }).collect();

        let witness = RecursionLeafInstanceWitness::<F, H, EXT> {
            input: leaf_input,
            vk_witness: vk.clone().into_inner(),
            queue_witness: FullStateCircuitQueueRawWitness { elements: elements },
            proof_witnesses: proof_witnesses,
        };

        let config = LeafLayerRecursionConfig::<F, <H as RecursiveTreeHasher<F, Num<F>>>::NonCircuitSimulator, EXT> {
            proof_config: base_layer_proof_config(),
            vk_fixed_parameters: vk.clone().into_inner().fixed_parameters,
            capacity: RECURSION_ARITY,
            padding_proof: padding_proof.clone().into_inner(),
        };

        let base_layer_circuit_type = BaseLayerCircuitType::from_numeric_value(vk.numeric_circuit_type());
        let circuit = ZkSyncLeafLayerRecursiveCircuit {
            witness,
            config,
            transcript_params: (),
            base_layer_circuit_type: base_layer_circuit_type,
            _marker: std::marker::PhantomData,
        };

        let circuit = match vk.numeric_circuit_type() {
            i if i == BaseLayerCircuitType::VM as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForMainVM(circuit)
            },
            i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForCodeDecommittmentsSorter(circuit)
            },
            i if i == BaseLayerCircuitType::Decommiter as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForCodeDecommitter(circuit)
            },
            i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForLogDemuxer(circuit)
            },
            i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForKeccakRoundFunction(circuit)
            },
            i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForSha256RoundFunction(circuit)
            },
            i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForECRecover(circuit)
            },
            i if i == BaseLayerCircuitType::RamValidation as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForRAMPermutation(circuit)
            },
            i if i == BaseLayerCircuitType::StorageFilter as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForStorageSorter(circuit)
            },
            i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForStorageApplication(circuit)
            },
            i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForEventsSorter(circuit)
            },
            i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
                ZkSyncRecursiveLayerCircuit::LeafLayerCircuitForL1MessagesSorter(circuit)
            },
            // i if i == BaseLayerCircuitType::VM as u8 => {
            //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_verifier_builder()
            // },
            // i if i == BaseLayerCircuitType::VM as u8 => {
            //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_verifier_builder()
            // },
            _ => {
                panic!("unknown circuit type = {}", circuit_type);
            }
        };

        results.push(
            (
                circuit_type,
                el,
                circuit,
                // leaf_input,
            )
        );
    }

    (results, closed_form_inputs)
}

pub fn compute_leaf_params(
    circuit_type: u8,
    base_layer_vk: ZkSyncBaseLayerVerificationKey,
    leaf_layer_vk: ZkSyncRecursionLayerVerificationKey,
) -> RecursionLeafParametersWitness<F> {
    let round_function = ZkSyncDefaultRoundFunction::default();
    use crate::witness::utils::create_cs_for_witness_generation;
    use crate::witness::utils::*;

    assert_eq!(circuit_type, base_layer_vk.numeric_circuit_type());
    assert_eq!(base_circuit_type_into_recursive_leaf_circuit_type(BaseLayerCircuitType::from_numeric_value(circuit_type)) as u8, leaf_layer_vk.numeric_circuit_type());

    let mut cs_for_witness_generation = create_cs_for_witness_generation::<F, ZkSyncDefaultRoundFunction>(
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

pub fn compute_node_vk_commitment(
    node_vk: ZkSyncRecursionLayerVerificationKey,
) -> [F; VK_COMMITMENT_LENGTH] {
    let round_function = ZkSyncDefaultRoundFunction::default();
    use crate::witness::utils::create_cs_for_witness_generation;
    use crate::witness::utils::*;
    let mut cs_for_witness_generation = create_cs_for_witness_generation::<F, ZkSyncDefaultRoundFunction>(
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

pub fn base_circuit_type_into_recursive_leaf_circuit_type(
    value: BaseLayerCircuitType
) -> ZkSyncRecursionLayerStorageType {
    match value {
        BaseLayerCircuitType::None => {panic!("None is not a proper type")},
        BaseLayerCircuitType::VM => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForMainVM,
        BaseLayerCircuitType::DecommitmentsFilter => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommittmentsSorter,
        BaseLayerCircuitType::Decommiter => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForCodeDecommitter,
        BaseLayerCircuitType::LogDemultiplexer => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForLogDemuxer,
        BaseLayerCircuitType::KeccakPrecompile => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForKeccakRoundFunction,
        BaseLayerCircuitType::Sha256Precompile => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForSha256RoundFunction,
        BaseLayerCircuitType::EcrecoverPrecompile => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForECRecover,
        BaseLayerCircuitType::RamValidation => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForRAMPermutation,
        BaseLayerCircuitType::StorageFilter => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageSorter,
        BaseLayerCircuitType::StorageApplicator => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForStorageApplication,
        BaseLayerCircuitType::EventsRevertsFilter => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForEventsSorter,
        BaseLayerCircuitType::L1MessagesRevertsFilter => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesSorter,
        BaseLayerCircuitType::L1MessagesHasher => ZkSyncRecursionLayerStorageType::LeafLayerCircuitForL1MessagesHasher,
    }
}

pub fn create_node_witnesses(
    chunks: Vec<(
        u64,
        RecursionQueueSimulator<F>, // chunk
        ZkSyncRecursiveLayerCircuit, // proof for that chunk
    )>,
    proofs: Vec<ZkSyncRecursionLayerProof>,
    padding_proof: ZkSyncRecursionLayerProof,
    vk: ZkSyncRecursionLayerVerificationKey,
    node_vk_commitment: [F; VK_COMMITMENT_LENGTH],
    leaf_layer_params: &Vec<(u8, RecursionLeafParametersWitness<F>)>,
) -> Vec<(
    u64,
    RecursionQueueSimulator<F>, // chunk
    ZkSyncRecursiveLayerCircuit, // proof for that chunk
)> {
    use zkevm_circuits::recursion::NUM_BASE_LAYER_CIRCUITS;
    use boojum::gadgets::queue::QueueState;

    assert_eq!(leaf_layer_params.len(), NUM_BASE_LAYER_CIRCUITS);

    assert_eq!(chunks.len(), proofs.len());

    assert!(chunks.len() > 0);
    let circuit_type = chunks[0].0 as u8;
    assert_eq!(base_circuit_type_into_recursive_leaf_circuit_type(BaseLayerCircuitType::from_numeric_value(circuit_type)) as u8, vk.numeric_circuit_type());
    let mut proofs_iter = proofs.into_iter();

    let leaf_layer_params = leaf_layer_params.iter().map(|el| {
        assert_eq!(el.0 as u64, el.1.circuit_type.as_u64_reduced());

        el.1.clone()
    }).collect::<Vec<_>>().try_into().unwrap();

    let partial_inputs = RecursionNodeInputWitness {
        branch_circuit_type: F::from_u64_unchecked(circuit_type as u64),
        leaf_layer_parameters: leaf_layer_params,
        node_layer_vk_commitment: node_vk_commitment,
        queue_state: QueueState::placeholder_witness(),
    };

    let config = NodeLayerRecursionConfig::<F, <H as RecursiveTreeHasher<F, Num<F>>>::NonCircuitSimulator, EXT> {
        proof_config: base_layer_proof_config(),
        vk_fixed_parameters: vk.clone().into_inner().fixed_parameters,
        leaf_layer_capacity: RECURSION_ARITY,
        node_layer_capacity: RECURSION_ARITY,
        padding_proof: padding_proof.clone().into_inner(),
    };

    let mut results = vec![];

    for chunk in chunks.chunks(RECURSION_ARITY) {
        let mut it = chunk.into_iter();
        let mut proofs = vec![];
        let (circuit_type, queue, _) = (&mut it).next().unwrap();

        let circuit_type = *circuit_type;
        let mut queue = queue.clone();

        let mut split_points = vec![];
        split_points.push(
            QueueTailStateWitness {
                tail: queue.tail,
                length: queue.num_items,
            }
        );

        proofs.push(proofs_iter.next().unwrap().into_inner());
        for (_, c, _) in it {
            split_points.push(
                QueueTailStateWitness {
                    tail: c.tail,
                    length: c.num_items,
                }
            );
            queue = RecursionQueueSimulator::<F>::merge(queue, c.clone());
            proofs.push(proofs_iter.next().unwrap().into_inner());
        }
        if split_points.len() + 1 < RECURSION_ARITY {
            let padding = QueueTailStateWitness {
                tail: queue.tail,
                length: 0,
            };
            split_points.resize(RECURSION_ARITY - 1, padding);
        }

        let mut input = partial_inputs.clone();
        input.queue_state = take_sponge_like_queue_state_from_simulator(&queue);

        use zkevm_circuits::recursion::node_layer::input::RecursionNodeInstanceWitness;

        let witness = RecursionNodeInstanceWitness{
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

        results.push(
            (
                circuit_type,
                queue,
                circuit
            )
        );
    }

    results
}