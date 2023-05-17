use std::ops::Add;

use crate::witness::tree::BinaryHasher;
use boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use boojum::cs::implementations::setup::FinalizationHintsForProver;
use boojum::field::goldilocks::GoldilocksExt2;
use num_bigint::BigUint;
use zk_evm::{address_to_u256, ethereum_types::*};
use boojum::config::*;

pub fn u64_as_u32_le(value: u64) -> [u32; 2] {
    [
        value as u32,
        (value >> 32) as u32,
    ]
}

pub fn u128_as_u32_le(value: u128) -> [u32; 4] {
    [
        value as u32,
        (value >> 32) as u32,
        (value >> 64) as u32,
        (value >> 96) as u32,
    ]
}

pub fn calldata_to_aligned_data(calldata: &Vec<u8>) -> Vec<U256> {
    if calldata.len() == 0 {
        return vec![];
    }
    let mut capacity = calldata.len() / 32;
    if calldata.len() % 32 != 0 {
        capacity += 1;
    }
    let mut result = Vec::with_capacity(capacity);
    let mut it = calldata.chunks_exact(32);
    for el in &mut it {
        let el = U256::from_big_endian(el);
        result.push(el);
    }
    let remainder = it.remainder();
    if remainder.len() != 0 {
        let mut buffer = [0u8; 32];
        buffer[0..remainder.len()].copy_from_slice(remainder);
        let el = U256::from_big_endian(&buffer);
        result.push(el);
    }

    result
}

pub fn bytes_to_u32_le<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u32; M] {
    assert!(M > 0);
    assert!(M * 4 == N);

    let mut result = [0u32; M];

    for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        result[idx] = word;
    }

    result
}

pub fn bytes_to_u128_le<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u128; M] {
    assert!(M > 0);
    assert!(M * 16 == N);

    let mut result = [0u128; M];

    for (idx, chunk) in bytes.chunks_exact(16).enumerate() {
        let word = u128::from_le_bytes(chunk.try_into().unwrap());
        result[idx] = word;
    }

    result
}

use crate::encodings::BytesSerializable;

pub fn binary_merklize_set<
    'a, 
    const N: usize, 
    T: BytesSerializable<N> + 'a, 
    H: BinaryHasher<32>,
    I: Iterator<Item = &'a T> + ExactSizeIterator
>(
    input: I,
    tree_size: usize,
) -> [u8; 32] {
    let input_len = input.len();
    assert!(tree_size >= input_len);
    assert!(tree_size.is_power_of_two());
    let mut leaf_hashes =  Vec::with_capacity(tree_size);

    for el in input {
        let encoding = el.serialize();
        let leaf_hash = H::leaf_hash(&encoding);
        leaf_hashes.push(leaf_hash);
    }

    let trivial_leaf_hash = H::leaf_hash(&[0u8; N]);
    leaf_hashes.resize(tree_size, trivial_leaf_hash);
    
    let mut previous_layer_hashes = leaf_hashes;
    let mut node_hashes = vec![];

    let num_layers = tree_size.trailing_zeros();

    for level in 0..num_layers {
        for pair in previous_layer_hashes.chunks(2) {
            let new_node_hash = H::node_hash(level as usize, &pair[0], &pair[1]);
            node_hashes.push(new_node_hash);
        }

        let p = std::mem::replace(&mut node_hashes, vec![]);
        previous_layer_hashes = p;   
    }

    assert_eq!(previous_layer_hashes.len(), 1);
    let root = previous_layer_hashes[0];

    root
}

use crate::GoldilocksField;
use crate::witness::oracle::VmWitnessOracle;
use crate::abstract_zksync_circuit::concrete_circuits::ZkSyncBaseLayerCircuit;
use crate::ZkSyncDefaultRoundFunction;
use boojum::worker::Worker;
use std::alloc::Global;
use boojum::cs::implementations::polynomial_storage::*;
use boojum::cs::implementations::verifier::*;
use boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use boojum::cs::oracle::merkle_tree::*;
use boojum::cs::implementations::hints::*;

pub const BASE_LAYER_FRI_LDE_FACTOR: usize = 2;
pub const BASE_LAYER_CAP_SIZE: usize = 32;

type F = GoldilocksField;
type P = boojum::field::goldilocks::MixedGL;
type H = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;

pub fn create_base_layer_setup_data(
    circuit: ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, ZkSyncDefaultRoundFunction>,
    worker: &Worker,
    fri_lde_factor: usize,
    merkle_tree_cap_size: usize,
) -> (
    SetupBaseStorage<F, P, Global, Global>,
    SetupStorage<F, P, Global, Global>, 
    VerificationKey<F, H>, 
    MerkleTreeWithCap<F, H>,
    DenseVariablesCopyHint,
    DenseWitnessCopyHint,
    FinalizationHintsForProver,
){
    use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use boojum::config::DevCSConfig;
    use boojum::cs::cs_builder::new_builder;
    use boojum::cs::traits::circuit::Circuit;

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
        geometry, 
        num_vars.unwrap(), 
        max_trace_len.unwrap(),
    );
    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let (mut cs, finalization_hint) = match circuit {
        ZkSyncBaseLayerCircuit::MainVM(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::ECRecover(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
        ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            let (_, finalization_hint) = cs.pad_and_shrink();
            (cs.into_assembly(), finalization_hint)
        },
    };

    let (            
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints
    ) = cs.get_full_setup(
        worker,
        fri_lde_factor,
        merkle_tree_cap_size,
    );

    (
        setup_base,
        setup,
        vk,
        setup_tree,
        vars_hint,
        witness_hints,
        finalization_hint
    )
}

use boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::proof::Proof;

type TR = GoldilocksPoisedon2Transcript;
type EXT = GoldilocksExt2;

use boojum::cs::implementations::pow::PoWRunner;

pub fn prove_base_layer_circuit<
    POW: PoWRunner
>
(
    circuit: ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, ZkSyncDefaultRoundFunction>,
    worker: &Worker,
    proof_config: ProofConfig,
    setup_base: &SetupBaseStorage<F, P>, 
    setup: &SetupStorage<F, P>, 
    setup_tree: &MerkleTreeWithCap<F, H, Global, Global>, 
    vk: &VerificationKey<F, H>,
    vars_hint: &DenseVariablesCopyHint,
    wits_hint: &DenseWitnessCopyHint,
    finalization_hint: &FinalizationHintsForProver,
) -> Proof<F, H, EXT> {
    use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use boojum::cs::cs_builder::new_builder;
    use boojum::cs::traits::circuit::Circuit;

    let geometry = circuit.geometry();
    let (max_trace_len, num_vars) = circuit.size_hint();

    let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, ProvingCSConfig>::new(
        geometry, 
        num_vars.unwrap(), 
        max_trace_len.unwrap(),
    );
    let builder = new_builder::<_, GoldilocksField>(builder_impl);

    let mut cs = match circuit {
        ZkSyncBaseLayerCircuit::MainVM(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::ECRecover(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
        ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
            let builder = inner.configure_builder(builder);
            let mut cs = builder.build(());
            inner.add_tables(&mut cs);
            inner.synthesize_into_cs(&mut cs);
            cs.pad_and_shrink_using_hint(finalization_hint);
            cs.into_assembly()
        },
    };

    cs.prove_from_precomputations::<EXT, TR, H, POW>(
        proof_config,
        setup_base,
        setup,
        setup_tree,
        vk,
        vars_hint,
        wits_hint,
        (),
        worker,
    )

}

pub fn verify_base_layer_proof<
    POW: PoWRunner
>
(
    circuit: &ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, ZkSyncDefaultRoundFunction>,
    proof: &Proof<F, H, EXT>,
    vk: &VerificationKey<F, H>,
) -> bool {
    use boojum::cs::implementations::convenience::verify_circuit;

    match circuit {
        ZkSyncBaseLayerCircuit::MainVM(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::ECRecover(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
        ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
            verify_circuit::<F, _, EXT, TR, H, POW>(
                inner,
                proof,
                vk,
                ()
            )
        },
    }
}