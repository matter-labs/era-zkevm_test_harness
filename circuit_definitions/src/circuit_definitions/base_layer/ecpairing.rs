use circuit_encodings::zkevm_circuits::bn254::{
    ec_pairing::{ecpairing_function_entry_point, input::EcPairingCircuitInstanceWitness},
    fixed_base_mul_table::{create_fixed_base_mul_table, FixedBaseMulTable},
};
use derivative::*;

use super::*;
use crate::boojum::cs::traits::circuit::CircuitBuilder;

type F = GoldilocksField;
type R = Poseidon2Goldilocks;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct ECPairingFunctionInstanceSynthesisFunction {
    _marker: std::marker::PhantomData<(F, R)>,
}

impl CircuitBuilder<F> for ECPairingFunctionInstanceSynthesisFunction
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    fn geometry() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 200,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
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
        // TODO: Maybe some gates are not actually needed since it was copy-pasting from the previous secp256k1 ecmul implementation.
        let builder = builder.allow_lookup(<Self as CircuitBuilder<F>>::lookup_parameters());

        let builder = U8x4FMAGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
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
        let builder = UIntXAddGate::<8>::configure_builder(
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
        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }
}

impl ZkSyncUniformSynthesisFunction<F> for ECPairingFunctionInstanceSynthesisFunction
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    type Witness = EcPairingCircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "Elliptic Curve Pairing".to_string()
    }

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(TARGET_CIRCUIT_TRACE_LENGTH), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        // let table = create_range_check_table::<F, 8>();
        // cs.add_lookup_table::<RangeCheckTable<8>, 1>(table);

        // let table = create_range_check_16_bits_table::<F>();
        // cs.add_lookup_table::<RangeCheck16BitsTable, 1>(table);

        let table = create_xor8_table();
        cs.add_lookup_table::<Xor8Table, 3>(table);

        let table = create_and8_table();
        cs.add_lookup_table::<And8Table, 3>(table);

        seq_macro::seq!(C in 0..32 {
            let table = create_fixed_base_mul_table::<F, 0, C>();
            cs.add_lookup_table::<FixedBaseMulTable<0, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 1, C>();
            cs.add_lookup_table::<FixedBaseMulTable<1, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 2, C>();
            cs.add_lookup_table::<FixedBaseMulTable<2, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 3, C>();
            cs.add_lookup_table::<FixedBaseMulTable<3, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 4, C>();
            cs.add_lookup_table::<FixedBaseMulTable<4, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 5, C>();
            cs.add_lookup_table::<FixedBaseMulTable<5, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 6, C>();
            cs.add_lookup_table::<FixedBaseMulTable<6, C>, 3>(table);
            let table = create_fixed_base_mul_table::<F, 7, C>();
            cs.add_lookup_table::<FixedBaseMulTable<7, C>, 3>(table);
        });

        let table = create_byte_split_table::<F, 1>();
        cs.add_lookup_table::<ByteSplitTable<1>, 3>(table);
        let table = create_byte_split_table::<F, 2>();
        cs.add_lookup_table::<ByteSplitTable<2>, 3>(table);
        let table = create_byte_split_table::<F, 3>();
        cs.add_lookup_table::<ByteSplitTable<3>, 3>(table);
        let table = create_byte_split_table::<F, 4>();
        cs.add_lookup_table::<ByteSplitTable<4>, 3>(table);
    }

    fn synthesize_into_cs_inner<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: Self::Witness,
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        ecpairing_function_entry_point(cs, witness, round_function, config)
    }
}
