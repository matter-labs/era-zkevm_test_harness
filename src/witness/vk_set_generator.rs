use super::oracle::VmWitnessOracle;
use super::recursive_aggregation::*;
use super::*;
use crate::abstract_zksync_circuit::concrete_circuits::*;
use crate::bellman::plonk::better_better_cs::proof::Proof;
use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
use crate::toolset::GeometryConfig;
use sync_vm::recursion::recursion_tree::NUM_LIMBS;
use sync_vm::testing::Bn256;
use sync_vm::testing::Fr;

// create circuits WITHOUT witness, but with all the parameters
// to generate verification keys. It needs geometry and some valid proofs for padding
pub fn circuits_for_vk_generation(
    geometry: GeometryConfig,
    splitting_factor_for_leafs: usize,
    splitting_factor_for_nodes: usize,
    scheduler_upper_bound: u32,
    padding_aggregations: Vec<(
        [Fr; NUM_LIMBS],
        [Fr; NUM_LIMBS],
        [Fr; NUM_LIMBS],
        [Fr; NUM_LIMBS],
    )>,
) -> Vec<ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>> {
    // scheduler
    let mut result = vec![];

    use sync_vm::circuit_structures::utils::bn254_rescue_params;
    use sync_vm::recursion::aggregation::VkInRns;
    use sync_vm::recursion::get_base_placeholder_point_for_accumulators;
    use sync_vm::recursion::get_prefered_committer;
    use sync_vm::recursion::get_prefered_rns_params;
    use sync_vm::recursion::recursion_tree::AggregationParameters;
    use sync_vm::recursion::transcript::GenericTranscriptGadget;

    let rns_params = get_prefered_rns_params();
    let round_function = get_prefered_committer();
    let sponge_params = bn254_rescue_params();

    let aggregation_params =
        AggregationParameters::<_, GenericTranscriptGadget<_, _, 2, 3>, _, 2, 3> {
            base_placeholder_point: get_base_placeholder_point_for_accumulators(),
            hash_params: sponge_params.clone(),
            transcript_params: sponge_params.clone(),
        };

    let (padding_vk, padding_proofs) = get_paddings();

    let transcript_params = (&sponge_params, &rns_params);

    use sync_vm::recursion::RescueTranscriptForRecursion;

    for proof in padding_proofs.iter() {
        let is_valid = crate::bellman::plonk::better_better_cs::verifier::verify::<
            Bn256,
            _,
            RescueTranscriptForRecursion<'_>,
        >(&padding_vk, proof, Some(transcript_params))
        .expect("must try to verify a proof");
        assert!(is_valid, "padding proof and VK must be valid");
    }

    let padding_vk_encoding: [_; sync_vm::recursion::node_aggregation::VK_ENCODING_LENGTH] = {
        // add
        let vk_in_rns = VkInRns {
            vk: Some(padding_vk.clone()),
            rns_params: &rns_params,
        };
        use sync_vm::traits::ArithmeticEncodable;
        let encoding = vk_in_rns.encode().unwrap();

        encoding.try_into().unwrap()
    };

    let circuit = SchedulerCircuit::new(
        None,
        (
            scheduler_upper_bound,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_encoding.to_vec(),
            padding_proofs[0].clone(),
            None,
        ),
        round_function.clone(),
        None,
    );

    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::Scheduler(circuit);
    result.push(circuit);

    let (padding_proofs, padding_public_inputs) =
        get_filled_paddings(splitting_factor_for_nodes, &padding_proofs);

    use sync_vm::glue::optimizable_queue::simulate_variable_length_hash;
    let padding_vk_committment =
        simulate_variable_length_hash(&padding_vk_encoding, &round_function);

    // node aggregation
    let circuit = NodeAggregationCircuit::new(
        None,
        (
            splitting_factor_for_nodes,
            splitting_factor_for_leafs,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_committment,
            padding_vk_encoding.to_vec(),
            padding_public_inputs.clone(),
            padding_proofs.clone(),
            padding_aggregations.clone(),
            None,
        ),
        round_function.clone(),
        None,
    );

    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::NodeAggregation(circuit);
    result.push(circuit);

    let (padding_proofs, padding_public_inputs) =
        get_filled_paddings(splitting_factor_for_leafs, &padding_proofs);

    // leaf aggregation
    let circuit = LeafAggregationCircuit::new(
        None,
        (
            splitting_factor_for_leafs,
            rns_params.clone(),
            aggregation_params.clone(),
            padding_vk_committment,
            padding_vk_encoding.to_vec(),
            padding_public_inputs.clone(),
            padding_proofs.clone(),
            None,
        ),
        round_function.clone(),
        None,
    );

    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::LeafAggregation(circuit);
    result.push(circuit);

    // VM
    let circuit = VMMainCircuit::new(
        None,
        geometry.cycles_per_vm_snapshot as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::MainVM(circuit);
    result.push(circuit);

    // decommits sorter
    let circuit = CodeDecommittsSorterCircuit::new(
        None,
        geometry.cycles_per_code_decommitter_sorter as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::CodeDecommittmentsSorter(circuit);
    result.push(circuit);

    // code decommitter
    let circuit = CodeDecommitterCircuit::new(
        None,
        geometry.cycles_per_code_decommitter as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::CodeDecommitter(circuit);
    result.push(circuit);

    // log demuxer
    let circuit = LogDemuxerCircuit::new(
        None,
        geometry.cycles_per_log_demuxer as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::LogDemuxer(circuit);
    result.push(circuit);

    // keccak
    let circuit = Keccak256RoundFunctionCircuit::new(
        None,
        geometry.cycles_per_keccak256_circuit as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::KeccakRoundFunction(circuit);
    result.push(circuit);

    // sha256
    let circuit = Sha256RoundFunctionCircuit::new(
        None,
        geometry.cycles_per_sha256_circuit as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::Sha256RoundFunction(circuit);
    result.push(circuit);

    // ecrecover
    let circuit = ECRecoverFunctionCircuit::new(
        None,
        geometry.cycles_per_ecrecover_circuit as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::ECRecover(circuit);
    result.push(circuit);

    // ram permutation
    let circuit = RAMPermutationCircuit::new(
        None,
        geometry.cycles_per_ram_permutation as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::RAMPermutation(circuit);
    result.push(circuit);

    // storage sorter
    let circuit = StorageSorterCircuit::new(
        None,
        geometry.cycles_per_storage_sorter as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::StorageSorter(circuit);
    result.push(circuit);

    use crate::witness::postprocessing::USE_BLAKE2S_EXTRA_TABLES;
    // storage application
    let circuit = StorageApplicationCircuit::new(
        None,
        (
            geometry.cycles_per_storage_application as usize,
            USE_BLAKE2S_EXTRA_TABLES,
        ),
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::StorageApplication(circuit);
    result.push(circuit);

    // initial writes rehasher
    let circuit = InitialStorageWritesPubdataHasherCircuit::new(
        None,
        geometry.limit_for_initial_writes_pubdata_hasher as usize,
        round_function.clone(),
        None,
    );
    let circuit =
        ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::InitialWritesPubdataHasher(circuit);
    result.push(circuit);

    // repeated writes rehasher
    let circuit = RepeatedStorageWritesPubdataHasherCircuit::new(
        None,
        geometry.limit_for_repeated_writes_pubdata_hasher as usize,
        round_function.clone(),
        None,
    );
    let circuit =
        ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::RepeatedWritesPubdataHasher(circuit);
    result.push(circuit);

    // events sorter
    let circuit = EventsSorterCircuit::new(
        None,
        geometry.cycles_per_events_or_l1_messages_sorter as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::EventsSorter(circuit);
    result.push(circuit);

    // l1 messages sorter
    let circuit = L1MessagesSorterCircuit::new(
        None,
        geometry.cycles_per_events_or_l1_messages_sorter as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::L1MessagesSorter(circuit);
    result.push(circuit);

    // l1 messages hasher
    let circuit = L1MessagesHasherCircuit::new(
        None,
        geometry.limit_for_l1_messages_pudata_hasher as usize,
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::L1MessagesPubdataHasher(circuit);
    result.push(circuit);

    use crate::witness::postprocessing::L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH;
    // l1 merklizer
    let circuit = L1MessagesMerklizerCircuit::new(
        None,
        (
            geometry.limit_for_l1_messages_merklizer as usize,
            L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH,
        ),
        round_function.clone(),
        None,
    );
    let circuit = ZkSyncCircuit::<Bn256, VmWitnessOracle<Bn256>>::L1MessagesMerklier(circuit);
    result.push(circuit);

    // check ordering
    let mut idx = -1;
    for el in result.iter() {
        let i = el.numeric_circuit_type();
        assert!(i as isize > idx, "previous idx is {}, but got {}", idx, i);
        idx = i as isize;
    }

    result
}
