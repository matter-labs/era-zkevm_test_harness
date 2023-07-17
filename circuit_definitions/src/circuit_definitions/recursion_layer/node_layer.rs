use crate::boojum::cs::implementations::pow::NoPow;
use derivative::*;
use zkevm_circuits::boojum::cs::gates::PublicInputGate;

use super::circuit_def::*;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::cs::implementations::transcript::Transcript;
use crate::boojum::gadgets::recursion::circuit_pow::*;
use crate::circuit_definitions::base_layer::TARGET_CIRCUIT_TRACE_LENGTH;
use zkevm_circuits::base_structures::recursion_query::RecursionQuery;
use zkevm_circuits::recursion::node_layer::input::*;
use zkevm_circuits::recursion::node_layer::*;

use super::*;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""))]
#[serde(bound = "")]
// #[serde(bound = "RecursionNodeInstanceWitness<F, H, EXT>: serde::Serialize + serde::de::DeserializeOwned,
//     NodeLayerRecursionConfig<F, H::NonCircuitSimulator, EXT>: serde::Serialize + serde::de::DeserializeOwned,
//     TR::TransciptParameters: serde::Serialize + serde::de::DeserializeOwned")]
pub struct NodeLayerRecursiveCircuit<POW: RecursivePoWRunner<F>> {
    pub witness: RecursionNodeInstanceWitness<F, RH, EXT>,
    pub config: NodeLayerRecursionConfig<F, H, EXT>,
    pub transcript_params: <TR as Transcript<F>>::TransciptParameters,
    pub _marker: std::marker::PhantomData<(R, POW)>,
}

impl<POW: RecursivePoWRunner<F>> crate::boojum::cs::traits::circuit::CircuitBuilder<F>
    for NodeLayerRecursiveCircuit<POW>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <RecursionQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    fn geometry() -> CSGeometry {
        geometry_for_recursion_step()
    }

    fn lookup_parameters() -> LookupParameters {
        lookup_parameters_recursion_step()
    }

    fn configure_builder<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        configure_builder_recursion_step(builder)
    }
}

impl<POW: RecursivePoWRunner<F>> NodeLayerRecursiveCircuit<POW>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <RecursionQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    pub fn description() -> String {
        "Node layer circuit".to_string()
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        (
            Some(TARGET_CIRCUIT_TRACE_LENGTH),
            Some((1 << 26) + (1 << 25)),
        )
    }

    pub fn configure_builder_proxy<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        &self,
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        <Self as crate::boojum::cs::traits::circuit::CircuitBuilder<F>>::configure_builder(builder)
    }

    pub fn add_tables<CS: ConstraintSystem<F>>(&self, _cs: &mut CS) {}

    pub fn synthesize_into_cs<CS: ConstraintSystem<F> + 'static>(
        self,
        cs: &mut CS,
        round_function: &R,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        let Self {
            witness,
            config,
            transcript_params,
            ..
        } = self;

        let verifier_builder =
            LeafLayerCircuitBuilder::<POW>::dyn_recursive_verifier_builder::<EXT, CS>();

        // reserve enough fixed locations for public inputs
        for _ in 0..INPUT_OUTPUT_COMMITMENT_LENGTH {
            PublicInputGate::reserve_public_input_location(cs);
        }

        let input_commitments = node_layer_recursion_entry_point::<F, CS, R, RH, EXT, TR, CTR, POW>(
            cs,
            witness,
            round_function,
            config,
            verifier_builder,
            transcript_params,
        );

        // use reserved_locations
        for el in input_commitments.iter() {
            PublicInputGate::use_reserved_public_input_location(cs, el.get_variable())
        }

        input_commitments
    }
}

pub type ZkSyncNodeLayerRecursiveCircuit = NodeLayerRecursiveCircuit<
    // GoldilocksField,
    // GoldilocksExt2,
    // ZkSyncDefaultRoundFunction,
    // CircuitGoldilocksPoseidon2Sponge,
    // GoldilocksPoisedon2Transcript,
    // CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, ZkSyncDefaultRoundFunction>,
    NoPow,
>;

use crate::boojum::cs::traits::circuit::CircuitBuilderProxy;

pub type NodeLayerCircuitBuilder<POW> = CircuitBuilderProxy<F, NodeLayerRecursiveCircuit<POW>>;
pub type ConcreteNodeLayerCircuitBuilder = NodeLayerCircuitBuilder<NoPow>;
