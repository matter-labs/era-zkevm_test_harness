use crate::boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::cs::implementations::pow::NoPow;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::cs::implementations::transcript::Transcript;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::gadgets::recursion::circuit_pow::*;
use crate::boojum::gadgets::recursion::recursive_transcript::*;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::circuit_definitions::gates::*;
use crate::circuit_definitions::implementations::pow::PoWRunner;
use crate::circuit_definitions::implementations::proof::Proof;
use crate::circuit_definitions::recursion_layer::scheduler::SchedulerCircuitBuilder;
use crate::circuit_definitions::traits::circuit::ErasedBuilderForRecursiveVerifier;
use crate::circuit_definitions::traits::gate::GatePlacementStrategy;
use crate::zkevm_circuits::recursion::compression::*;
use derivative::*;
use zkevm_circuits::boojum::cs::implementations::prover::ProofConfig;
use zkevm_circuits::boojum::cs::oracle::TreeHasher;

use super::*;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

// trait to enumerate different compression modes
pub trait ProofCompressionFunction {
    type PreviousLayerPoW: RecursivePoWRunner<F>;

    type ThisLayerPoW: PoWRunner;
    type ThisLayerHasher: TreeHasher<F>;
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

// no lookup, just enough copiable width, moderate LDE factor, still special boolean column,
// and Poseidon2 gate
pub struct CompressionMode1;

impl ProofCompressionFunction for CompressionMode1 {
    // no PoW from the previous step
    type PreviousLayerPoW = NoPow;

    // no PoW on this step too
    type ThisLayerPoW = NoPow;
    type ThisLayerHasher = H;
    type ThisLayerTranscript = TR;

    fn this_layer_transcript_parameters(
    ) -> <Self::ThisLayerTranscript as Transcript<F>>::TransciptParameters {
        ();
    }

    fn description_for_compression_step() -> String {
        "Compression mode 1: no lookup, just enough copiable width, moderate LDE factor, still special boolean column, and Poseidon2 gate"
        .to_string()
    }

    fn size_hint_for_compression_step() -> (usize, usize) {
        (1 << 16, 1 << 20)
    }

    fn geometry_for_compression_step() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 24,
            num_witness_columns: 96,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters_for_compression_step() -> LookupParameters {
        LookupParameters::NoLookup
    }

    fn configure_builder_for_compression_step<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = ConstantsAllocatorGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = BooleanConstraintGate::configure_builder(
            builder,
            GatePlacementStrategy::UseSpecializedColumns {
                num_repetitions: 1,
                share_constants: false,
            },
        );
        let builder =
            R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<32>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ParallelSelectionGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = PublicInputGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<_, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }

    fn proof_config_for_compression_step() -> ProofConfig {
        ProofConfig {
            fri_lde_factor: 8,
            merkle_tree_cap_size: 64,
            fri_folding_schedule: None,
            security_level: crate::SECURITY_BITS_TARGET,
            pow_bits: 0,
        }
    }

    fn previous_step_builder_for_compression<CS: ConstraintSystem<F> + 'static>(
    ) -> Box<dyn ErasedBuilderForRecursiveVerifier<GoldilocksField, EXT, CS>> {
        SchedulerCircuitBuilder::<Self::PreviousLayerPoW>::dyn_recursive_verifier_builder::<EXT, CS>(
        )
    }
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

pub type CompressionMode1CircuitBuilder = CompressionLayerCircuit<CompressionMode1>;
// pub type CompressionMode2CircuitBuilder = CompressionLayerCircuit<ProofCompressionFunction>;
// pub type CompressionMode3CircuitBuilder = CompressionLayerCircuit<ProofCompressionFunction>;

impl<CF: ProofCompressionFunction> CompressionLayerCircuit<CF> {
    pub fn description() -> String {
        CF::description_for_compression_step()
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
