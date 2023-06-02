use derivative::*;

use super::*;
use crate::boojum::cs::traits::circuit::CircuitBuilder;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
#[serde(bound = "")]
pub struct VmMainInstanceSynthesisFunction<
    F: SmallField,
    W: WitnessOracle<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
> {
    _marker: std::marker::PhantomData<(F, W, R)>,
}

use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmCircuitWitness;
use zkevm_circuits::main_vm::main_vm_entry_point;

impl<
        F: SmallField,
        W: WitnessOracle<F>,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > CircuitBuilder<F> for VmMainInstanceSynthesisFunction<F, W, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    fn geometry() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 26 * 5, // 26 is a width of u32 FMA gate
            num_witness_columns: 0,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions: 8,
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
        let builder = U8x4FMAGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder =
            R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        // let builder = SimpleNonlinearityGate::<F, 7>::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = DotProductGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
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
        let builder = UIntXAddGate::<16>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = UIntXAddGate::<8>::configure_builder(
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
}

impl<
        F: SmallField,
        W: WitnessOracle<F>,
        R: BuildableCircuitRoundFunction<F, 8, 12, 4>
            + AlgebraicRoundFunction<F, 8, 12, 4>
            + serde::Serialize
            + serde::de::DeserializeOwned,
    > ZkSyncUniformSynthesisFunction<F> for VmMainInstanceSynthesisFunction<F, W, R>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    type Witness = VmCircuitWitness<F, W>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "VM main circuit".to_string()
    }

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(TARGET_CIRCUIT_TRACE_LENGTH), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        let table = create_binop_table();
        cs.add_lookup_table::<BinopTable, 3>(table);

        let subpc_to_mask_table = create_subpc_bitmask_table::<F>();
        cs.add_lookup_table::<VMSubPCToBitmaskTable, 3>(subpc_to_mask_table);

        let opcode_decoding_table = create_opcodes_decoding_and_pricing_table::<F>();
        cs.add_lookup_table::<VMOpcodeDecodingTable, 3>(opcode_decoding_table);

        let conditions_resolution_table = create_conditionals_resolution_table::<F>();
        cs.add_lookup_table::<VMConditionalResolutionTable, 3>(conditions_resolution_table);

        let integer_to_bitmask_table = create_integer_to_bitmask_table::<F>(
            15u32.next_power_of_two().trailing_zeros() as usize,
            REG_IDX_TO_BITMASK_TABLE_NAME,
        );
        cs.add_lookup_table::<RegisterIndexToBitmaskTable, 3>(integer_to_bitmask_table);

        let shifts_table = create_shift_to_num_converter_table::<F>();
        cs.add_lookup_table::<BitshiftTable, 3>(shifts_table);

        let uma_unaligned_access_table =
            create_integer_set_ith_bit_table::<F>(5, UMA_SHIFT_TO_BITMASK_TABLE_NAME);
        cs.add_lookup_table::<UMAShiftToBitmaskTable, 3>(uma_unaligned_access_table);

        let uma_ptr_read_cleanup_table = create_uma_ptr_read_bitmask_table::<F>();
        cs.add_lookup_table::<UMAPtrReadCleanupTable, 3>(uma_ptr_read_cleanup_table);
    }

    fn synthesize_into_cs_inner<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: Self::Witness,
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        main_vm_entry_point(cs, witness, round_function, config)
    }
}
