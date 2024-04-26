use derivative::*;

use self::aux_layer::fri_proof_verification::proof_config_for_fri_proofs_precompile;
use self::aux_layer::fri_proof_verification::transcript_params_for_fri_proofs_precompile;
use self::aux_layer::fri_proof_verification::verification_key_geometry_for_fri_proofs_precompile;
use self::aux_layer::fri_proof_verification::verifier_builder_for_fri_proofs_precompile;

use super::*;
use crate::boojum::cs::traits::circuit::CircuitBuilder;
use crate::boojum::gadgets::recursion::recursive_transcript::CircuitAlgebraicSpongeBasedTranscript;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::circuit_definitions::aux_layer::fri_proof_verification::FRIProofVerificationPrecompilePoW;
use crate::circuit_definitions::implementations::transcript::GoldilocksPoisedon2Transcript;

type F = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct FRIProofVerificationFunctionInstanceSynthesisFunction {
    _marker: std::marker::PhantomData<(F, R)>,
}

use crate::zkevm_circuits::fri_proof_verification_precompile::fri_proof_verification_function_entry_point;
use crate::zkevm_circuits::fri_proof_verification_precompile::input::*;
use crate::zkevm_circuits::fri_proof_verification_precompile::FRIProofVerificationPrecompileConfig;

impl CircuitBuilder<F> for FRIProofVerificationFunctionInstanceSynthesisFunction
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    fn geometry() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 140,
            num_witness_columns: 0,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 1,
            num_repetitions: 2,
            share_table_id: true,
        }
    }

    fn configure_builder<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = builder.allow_lookup(<Self as CircuitBuilder<F>>::lookup_parameters());

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
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<F, 4>::configure_builder(
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
        let builder = UIntXAddGate::<32>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );

        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }
}

impl ZkSyncUniformSynthesisFunction<F> for FRIProofVerificationFunctionInstanceSynthesisFunction
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    type Witness = FRIProofVerificationCircuitInstanceWitness<F, H, EXT>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "FRI proof verification precompile function".to_string()
    }

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(TARGET_CIRCUIT_TRACE_LENGTH), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        let table = create_range_check_16_bits_table();
        cs.add_lookup_table::<RangeCheck16BitsTable, 1>(table);
    }

    fn synthesize_into_cs_inner<CS: ConstraintSystem<F> + 'static>(
        cs: &mut CS,
        witness: Self::Witness,
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        let proof_config = FRIProofVerificationPrecompileConfig::<F, H, EXT> {
            proof_config: proof_config_for_fri_proofs_precompile(),
            vk_fixed_parameters: verification_key_geometry_for_fri_proofs_precompile(),
            _marker: std::marker::PhantomData,
        };
        fri_proof_verification_function_entry_point::<
            F,
            CS,
            R,
            RH,
            EXT,
            TR,
            CTR,
            FRIProofVerificationPrecompilePoW,
        >(
            cs,
            witness,
            proof_config,
            verifier_builder_for_fri_proofs_precompile(),
            transcript_params_for_fri_proofs_precompile(),
            round_function,
            config,
        )
    }
}
