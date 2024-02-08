use derivative::*;

use super::*;
use crate::boojum::cs::traits::circuit::CircuitBuilder;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct Secp256r1VerifyFunctionInstanceSynthesisFunction<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
> {
    _marker: std::marker::PhantomData<(F, R)>,
}

use zkevm_circuits::secp256r1_verify::input::*;
use zkevm_circuits::secp256r1_verify::secp256r1_verify_function_entry_point;

impl<
        F: SmallField,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > CircuitBuilder<F> for Secp256r1VerifyFunctionInstanceSynthesisFunction<F, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    fn geometry() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 100,
            num_witness_columns: 0,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 1,
            num_repetitions: 24,
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
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<F, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        // let owned_cs = ReductionGate::<F, 4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 8, share_constants: true });
        let builder = BooleanConstraintGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<32>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<16>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            false,
        );
        let builder = DotProductGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        // let owned_cs = DotProductGate::<4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: true });
        let builder = NopGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );

        builder
    }
}

impl<
        F: SmallField,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > ZkSyncUniformSynthesisFunction<F> for Secp256r1VerifyFunctionInstanceSynthesisFunction<F, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    type Witness = Secp256r1VerifyCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "Secp256r1 verify".to_string()
    }

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(TARGET_CIRCUIT_TRACE_LENGTH), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        let table = create_range_check_table::<F, 8>();
        cs.add_lookup_table::<RangeCheckTable<8>, 1>(table);

        let table = create_range_check_16_bits_table::<F>();
        cs.add_lookup_table::<RangeCheck16BitsTable, 1>(table);
    }

    fn synthesize_into_cs_inner<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: Self::Witness,
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        secp256r1_verify_function_entry_point(cs, witness, round_function, config)
    }
}
