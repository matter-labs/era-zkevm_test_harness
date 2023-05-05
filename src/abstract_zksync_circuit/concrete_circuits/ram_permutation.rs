use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct RAMPermutationInstanceSynthesisFunction<
F: SmallField, 
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> {
_marker: std::marker::PhantomData<(F, R)>
}

use zkevm_circuits::ram_permutation::input::*;
use zkevm_circuits::ram_permutation::ram_permutation_entry_point;

impl<
F: SmallField, 
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncUniformSynthesisFunction<F> for RAMPermutationInstanceSynthesisFunction<F, R> 
where [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:
{
    type Witness = RamPermutationCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "RAM permutation".to_string()
    }

    fn geometry() -> CSGeometry {
        CSGeometry { 
            num_columns_under_copy_permutation: 140, 
            num_witness_columns: 0, 
            num_constant_columns: 4, 
            max_allowed_constraint_degree: 8,
        }
    }
    
    fn size_hint() -> (Option<usize>, Option<usize>) {
        (
            Some(TARGET_CIRCUIT_TRACE_LENGTH),
            Some(1 << 26)
        )
    }

    fn configure_builder<T: CsBuilderImpl<F, T>, GC: GateConfigurationHolder<F>, TB: StaticToolboxHolder>(
        builder: CsBuilder<T, F, GC, TB>
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = builder.allow_lookup(
            boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant { width: 1, num_repetitions: 8, share_table_id: true }
        );

        let builder = ConstantsAllocatorGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = BooleanConstraintGate::configure_builder(builder, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: false });
        let builder = R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns, false);
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<32>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ParallelSelectionGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = PublicInputGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ReductionGate::<_, 4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        let table = create_range_check_table::<F, 8>();
        cs.add_lookup_table::<RangeCheckTable<8>, 1>(table);
    }

    fn synthesize_into_cs_inner<
        CS: ConstraintSystem<F>,
    >(
        cs: &mut CS, 
        witness: Self::Witness, 
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        ram_permutation_entry_point(cs, witness, round_function, config)
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(ram_permutation_entry_point)
    }
}