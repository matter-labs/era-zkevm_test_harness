use super::*;
use circuit_definitions::circuit_definitions::aux_layer::compression::*;
use crate::zkevm_circuits::recursion::compression::CompressionRecursionConfig;
use circuit_definitions::circuit_definitions::recursion_layer::verifier_builder::*;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

#[cfg(test)]
mod test {
    use circuit_definitions::boojum::cs::implementations::pow::NoPow;
    use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
    use circuit_definitions::{circuit_definitions::recursion_layer::ZkSyncRecursionLayerStorageType, base_layer_proof_config};

    use super::*;
    use crate::data_source::{LocalFileDataSource, BlockDataSource, SetupDataSource};
    use crate::boojum::worker::Worker;
    use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use crate::boojum::config::DevCSConfig;
    use crate::boojum::cs::cs_builder::new_builder;

    #[test]
    fn compress_1() {
        let mut source = LocalFileDataSource;
        let proof = source.get_scheduler_proof().unwrap();
        let vk = source.get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8).unwrap();

        let verifier_builder = dyn_verifier_builder_for_recursive_circuit_type(ZkSyncRecursionLayerStorageType::SchedulerCircuit);
        let verifier = verifier_builder.create_verifier();
        let is_valid = verifier.verify::<
            H,
            TR,
            NoPow,
        >((), &vk.clone().into_inner(), &proof.clone().into_inner());
        assert!(is_valid);

        // make a compression circuit
        let circuit = CompressionMode1Circuit {
            witness: Some(proof.clone().into_inner()),
            config: CompressionRecursionConfig {
                proof_config: base_layer_proof_config(),
                verification_key: vk.into_inner(),
                padding_proof: proof.into_inner(),
            },
            transcript_params: (),
            _marker: std::marker::PhantomData,
        };

        let worker = Worker::new();

        let geometry = circuit.geometry();
        let (max_trace_len, num_vars) = circuit.size_hint();
    
        let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, DevCSConfig>::new(
            geometry,
            num_vars.unwrap(),
            max_trace_len.unwrap(),
        );
        let builder = new_builder::<_, GoldilocksField>(builder_impl);
        let builder = circuit.configure_builder_proxy(builder);
        let mut cs_owned = builder.build(());
        circuit.synthesize_into_cs(&mut cs_owned);

        let assembly = cs_owned.into_assembly();

        dbg!(assembly.print_gate_stats());
    
    }
}