use derivative::*;

use super::*;
use crate::boojum::cs::traits::circuit::CircuitBuilder;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct Sha256RoundFunctionInstanceSynthesisFunction<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
> {
    _marker: std::marker::PhantomData<(F, R)>,
}

use zkevm_circuits::sha256_round_function::input::*;
use zkevm_circuits::sha256_round_function::sha256_round_function_entry_point;

impl<
        F: SmallField,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > CircuitBuilder<F> for Sha256RoundFunctionInstanceSynthesisFunction<F, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    fn geometry() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 116,
            num_witness_columns: 0,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 4,
            num_repetitions: 9,
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

impl<
        F: SmallField,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > ZkSyncUniformSynthesisFunction<F> for Sha256RoundFunctionInstanceSynthesisFunction<F, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    type Witness = Sha256RoundFunctionCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "SHA256 round function".to_string()
    }

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(TARGET_CIRCUIT_TRACE_LENGTH), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        let table = create_tri_xor_table();
        cs.add_lookup_table::<TriXor4Table, 4>(table);

        let table = create_ch4_table();
        cs.add_lookup_table::<Ch4Table, 4>(table);

        let table = create_maj4_table();
        cs.add_lookup_table::<Maj4Table, 4>(table);

        let table = create_4bit_chunk_split_table::<F, 1>();
        cs.add_lookup_table::<Split4BitChunkTable<1>, 4>(table);

        let table = create_4bit_chunk_split_table::<F, 2>();
        cs.add_lookup_table::<Split4BitChunkTable<2>, 4>(table);
    }

    fn synthesize_into_cs_inner<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: Self::Witness,
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        sha256_round_function_entry_point(cs, witness, round_function, config)
    }
}
