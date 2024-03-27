use crate::boojum::config::CSConfig;
use crate::boojum::config::ProvingCSConfig;
use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;
use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;
use crate::boojum::dag::CircuitResolver;
use crate::boojum::field::traits::field_like::PrimeFieldLikeVectorized;
use derivative::*;

use super::*;
use crate::boojum::cs::traits::circuit::CircuitBuilder;
use crate::boojum::gadgets::tables::create_and8_table;
use crate::boojum::gadgets::tables::create_byte_split_table;
use crate::boojum::gadgets::tables::create_xor8_table;
use crate::boojum::gadgets::tables::And8Table;
use crate::boojum::gadgets::tables::ByteSplitTable;
use crate::boojum::gadgets::tables::Xor8Table;
use crate::circuit_definitions::base_layer::TARGET_CIRCUIT_TRACE_LENGTH;
use crate::circuit_definitions::traits::gate::GatePlacementStrategy;

type F = GoldilocksField;
type R = Poseidon2Goldilocks;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct EIP4844InstanceSynthesisFunction {
    _marker: std::marker::PhantomData<(F, R)>,
}

use zkevm_circuits::eip_4844::eip_4844_entry_point;
use zkevm_circuits::eip_4844::input::*;

impl CircuitBuilder<F> for EIP4844InstanceSynthesisFunction
where
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    fn geometry() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 60,
            num_witness_columns: 0,
            num_constant_columns: 8,
            max_allowed_constraint_degree: 4,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::UseSpecializedColumnsWithTableIdAsConstant {
            width: 3,
            num_repetitions: 20,
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
        let builder = PublicInputGate::configure_builder(
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
        let builder = DotProductGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }
}

impl ZkSyncUniformSynthesisFunction<F> for EIP4844InstanceSynthesisFunction
where
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    type Witness = EIP4844CircuitInstanceWitness<F>;
    type Config = usize;
    type RoundFunction = R;

    fn description() -> String {
        "EIP4844".to_string()
    }

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(TARGET_CIRCUIT_TRACE_LENGTH), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS) {
        let table = create_xor8_table();
        cs.add_lookup_table::<Xor8Table, 3>(table);

        let table = create_and8_table();
        cs.add_lookup_table::<And8Table, 3>(table);

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
        eip_4844_entry_point(cs, witness, round_function, config)
    }
}

pub fn synthesis<P, CR>(
    circuit: EIP4844Circuit,
    hint: &FinalizationHintsForProver,
) -> CSReferenceAssembly<F, P, ProvingCSConfig>
where
    P: PrimeFieldLikeVectorized<Base = F>,
    CR: CircuitResolver<
        F,
        zkevm_circuits::boojum::config::Resolver<
            zkevm_circuits::boojum::config::DontPerformRuntimeAsserts,
        >,
    >,
    usize: Into<<CR as CircuitResolver<F, <ProvingCSConfig as CSConfig>::ResolverConfig>>::Arg>,

    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
{
    let geometry = circuit.geometry_proxy();
    let (max_trace_len, num_vars) = circuit.size_hint();
    let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig, CR>::new(
        geometry,
        max_trace_len.unwrap(),
    );
    let cs_builder = new_builder::<_, F>(builder_impl);
    let builder = circuit.configure_builder_proxy(cs_builder);
    let mut cs = builder.build(num_vars.unwrap());
    circuit.add_tables_proxy(&mut cs);
    circuit.clone().synthesize_proxy(&mut cs);
    cs.pad_and_shrink_using_hint(hint);
    cs.into_assembly()
}
