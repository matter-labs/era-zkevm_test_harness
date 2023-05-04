
use derivative::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct CodeDecommitterInstanceSynthesisFunction<
F: SmallField, 
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> {
_marker: std::marker::PhantomData<(F, R)>
}

use zkevm_circuits::code_unpacker_sha256::input::*;
use zkevm_circuits::code_unpacker_sha256::unpack_code_into_memory_entry_point;

impl<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncUniformSynthesisFunction<F> for CodeDecommitterInstanceSynthesisFunction<F, R> 
where [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:
{
    type Witness = CodeDecommitterCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "Code decommitter".to_string()
    }

    fn geometry() -> CSGeometry {
        CSGeometry { 
            num_columns_under_copy_permutation: 120, 
            num_witness_columns: 0, 
            num_constant_columns: 8, 
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
                width: 4, 
                num_repetitions: 8, 
                share_table_id: true 
            }
        );
        let builder = ConstantsAllocatorGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = BooleanConstraintGate::configure_builder(builder, GatePlacementStrategy::UseSpecializedColumns { num_repetitions: 1, share_constants: false });
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ReductionGate::<F, 4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ParallelSelectionGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = PublicInputGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = UIntXAddGate::<32>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns, false);

        let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);


        // let builder = U8x4FMAGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = DotProductGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        // let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        // let builder = UIntXAddGate::<16>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = UIntXAddGate::<8>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = ParallelSelectionGate::<4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = PublicInputGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = ReductionGate::<_, 4>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
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

    fn get_synthesis_function_dyn<
        'a,
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a> {
        Box::new(unpack_code_into_memory_entry_point)
    }
}