use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct ECRecoverFunctionInstanceSynthesisFunction<
    F: SmallField, 
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> {
    _marker: std::marker::PhantomData<(F, R)>
}

use zkevm_circuits::ecrecover::input::*;
use zkevm_circuits::ecrecover::ecrecover_function_entry_point;

impl<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncUniformSynthesisFunction<F> for ECRecoverFunctionInstanceSynthesisFunction<F, R> 
    where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]: 
{
    type Witness = EcrecoverCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "ECRecover".to_string()
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
            LookupParameters::UseSpecializedColumnsWithTableIdAsConstant { 
                width: 3, 
                num_repetitions: 8, 
                share_table_id: true 
            }
        );
        let builder = R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ConstantsAllocatorGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ReductionGate::<F, 4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let owned_cs = ReductionGate::<F, 4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 8, share_constants: true });
        let builder = BooleanConstraintGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<32>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<16>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns, false);
        let builder = DotProductGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let owned_cs = DotProductGate::<4>::configure_for_cs(owned_cs, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: true });
        let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        
    }

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(ecrecover_function_entry_point)
    }
}