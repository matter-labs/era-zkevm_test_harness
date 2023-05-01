
use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct CodeDecommittmentsSorterSynthesisFunction<
F: SmallField, 
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> {
_marker: std::marker::PhantomData<(F, R)>
}

use zkevm_circuits::sort_decommittment_requests::input::*;
use zkevm_circuits::sort_decommittment_requests::sort_and_deduplicate_code_decommittments_entry_point;

impl<
F: SmallField, 
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncUniformSynthesisFunction<F> for CodeDecommittmentsSorterSynthesisFunction<F, R> 
where [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:
{
    type Witness = CodeDecommittmentsDeduplicatorInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "Decommittment requests sorter".to_string()
    }

    fn geometry() -> CSGeometry {
        CSGeometry { 
            num_columns_under_copy_permutation: 60, 
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
            boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant { width: 3, num_repetitions: 2, share_table_id: true }
        );

        let builder = ConstantsAllocatorGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = BooleanConstraintGate::configure_builder(builder, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: false });
        let builder = U8x4FMAGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = DotProductGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns, false);
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<32>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<16>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<8>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ParallelSelectionGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = PublicInputGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ReductionGate::<_, 4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(sort_and_deduplicate_code_decommittments_entry_point)
    }
}