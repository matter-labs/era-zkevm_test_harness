use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;

use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::cs::implementations::transcript::Transcript;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::gadgets::recursion::circuit_pow::*;
use crate::boojum::gadgets::recursion::recursive_transcript::*;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;

use crate::circuit_definitions::implementations::pow::PoWRunner;
use crate::circuit_definitions::implementations::proof::Proof;

use crate::circuit_definitions::traits::circuit::ErasedBuilderForRecursiveVerifier;

use crate::zkevm_circuits::recursion::compression::*;
use derivative::*;
use zkevm_circuits::boojum::cs::implementations::prover::ProofConfig;
use zkevm_circuits::boojum::cs::oracle::TreeHasher;

use super::compression_modes::*;

use super::*;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

// trait to enumerate different compression modes
pub trait ProofCompressionFunction {
    type PreviousLayerPoW: RecursivePoWRunner<F>;

    type ThisLayerPoW: PoWRunner;
    type ThisLayerHasher: TreeHasher<
        F,
        Output = <Self::ThisLayerTranscript as Transcript<F>>::CompatibleCap,
    >;
    type ThisLayerTranscript: Transcript<F>;

    fn this_layer_transcript_parameters(
    ) -> <Self::ThisLayerTranscript as Transcript<F>>::TransciptParameters;

    fn description_for_compression_step() -> String;

    fn size_hint_for_compression_step() -> (usize, usize);

    fn geometry_for_compression_step() -> CSGeometry;

    fn lookup_parameters_for_compression_step() -> LookupParameters;

    fn configure_builder_for_compression_step<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder>;

    fn previous_step_builder_for_compression<CS: ConstraintSystem<F> + 'static>(
    ) -> Box<dyn ErasedBuilderForRecursiveVerifier<GoldilocksField, EXT, CS>>;

    fn proof_config_for_compression_step() -> ProofConfig;
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""))]
#[serde(bound = "")]
pub struct CompressionLayerCircuit<CF: ProofCompressionFunction> {
    pub witness: Option<Proof<F, H, EXT>>,
    pub config: CompressionRecursionConfig<F, H, EXT>,
    pub transcript_params: <TR as Transcript<F>>::TransciptParameters,
    pub _marker: std::marker::PhantomData<CF>,
}

impl<CF: ProofCompressionFunction> crate::boojum::cs::traits::circuit::CircuitBuilder<F>
    for CompressionLayerCircuit<CF>
{
    fn geometry() -> CSGeometry {
        CF::geometry_for_compression_step()
    }

    fn lookup_parameters() -> LookupParameters {
        CF::lookup_parameters_for_compression_step()
    }

    fn configure_builder<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        CF::configure_builder_for_compression_step(builder)
    }
}

impl<CF: ProofCompressionFunction> CompressionLayerCircuit<CF> {
    pub fn description() -> String {
        CF::description_for_compression_step()
    }

    pub fn geometry(&self) -> CSGeometry {
        CF::geometry_for_compression_step()
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        let (trace_len, max_variables) = CF::size_hint_for_compression_step();
        (Some(trace_len), Some(max_variables))
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

    pub fn synthesize_into_cs<CS: ConstraintSystem<F> + 'static>(self, cs: &mut CS) {
        let Self {
            witness,
            config,
            transcript_params,
            ..
        } = self;

        let verifier_builder = CF::previous_step_builder_for_compression::<CS>();
        let compression_witness = CompressionCircuitInstanceWitness {
            proof_witness: witness,
        };

        proof_compression_function::<F, CS, RH, EXT, TR, CTR, CF::PreviousLayerPoW>(
            cs,
            compression_witness,
            config,
            verifier_builder,
            transcript_params,
        )
    }
}

pub type CompressionMode1Circuit = CompressionLayerCircuit<CompressionMode1>;
pub type CompressionMode2Circuit = CompressionLayerCircuit<CompressionMode2>;
pub type CompressionMode3Circuit = CompressionLayerCircuit<CompressionMode3>;
pub type CompressionMode4Circuit = CompressionLayerCircuit<CompressionMode4>;
pub type CompressionMode5Circuit = CompressionLayerCircuit<CompressionMode5>;

pub type CompressionMode1ForWrapperCircuit = CompressionLayerCircuit<CompressionMode1ForWrapper>;
pub type CompressionMode2ForWrapperCircuit = CompressionLayerCircuit<CompressionMode2ForWrapper>;
pub type CompressionMode3ForWrapperCircuit = CompressionLayerCircuit<CompressionMode3ForWrapper>;
pub type CompressionMode4ForWrapperCircuit = CompressionLayerCircuit<CompressionMode4ForWrapper>;
pub type CompressionMode5ForWrapperCircuit = CompressionLayerCircuit<CompressionMode5ForWrapper>;

use crate::circuit_definitions::traits::circuit::CircuitBuilderProxy;

pub type CompressionMode1CircuitBuilder = CircuitBuilderProxy<F, CompressionMode1Circuit>;
pub type CompressionMode2CircuitBuilder = CircuitBuilderProxy<F, CompressionMode2Circuit>;
pub type CompressionMode3CircuitBuilder = CircuitBuilderProxy<F, CompressionMode3Circuit>;
pub type CompressionMode4CircuitBuilder = CircuitBuilderProxy<F, CompressionMode4Circuit>;
pub type CompressionMode5CircuitBuilder = CircuitBuilderProxy<F, CompressionMode5Circuit>;

pub type CompressionMode1ForWrapperCircuitBuilder =
    CircuitBuilderProxy<F, CompressionMode1ForWrapperCircuit>;
pub type CompressionMode2ForWrapperCircuitBuilder =
    CircuitBuilderProxy<F, CompressionMode2ForWrapperCircuit>;
pub type CompressionMode3ForWrapperCircuitBuilder =
    CircuitBuilderProxy<F, CompressionMode3ForWrapperCircuit>;
pub type CompressionMode4ForWrapperCircuitBuilder =
    CircuitBuilderProxy<F, CompressionMode4ForWrapperCircuit>;
pub type CompressionMode5ForWrapperCircuitBuilder =
    CircuitBuilderProxy<F, CompressionMode5ForWrapperCircuit>;
