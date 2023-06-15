use crate::boojum::cs::cs_builder::*;
use crate::boojum::cs::*;
use crate::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};
use crate::boojum::gadgets::traits::round_function::BuildableCircuitRoundFunction;
use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;

type F = GoldilocksField;
type R = Poseidon2Goldilocks;
type EXT = GoldilocksExt2;

use crate::boojum::cs::gates::*;
use crate::boojum::cs::traits::gate::GatePlacementStrategy;

pub fn geometry_for_recursion_step() -> CSGeometry {
    CSGeometry {
        num_columns_under_copy_permutation: 140,
        num_witness_columns: 0,
        num_constant_columns: 4,
        max_allowed_constraint_degree: 8,
    }
}

pub fn lookup_parameters_recursion_step() -> LookupParameters {
    LookupParameters::NoLookup
}

pub fn configure_builder_recursion_step<
    T: CsBuilderImpl<F, T>,
    GC: GateConfigurationHolder<F>,
    TB: StaticToolboxHolder,
>(
    builder: CsBuilder<T, F, GC, TB>,
) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
    // let builder = builder.allow_lookup(<Self as CircuitBuilder::<F>>::lookup_parameters());

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
    let builder = R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = ZeroCheckGate::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
        false,
    );
    let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = FmaGateInExtensionWithoutConstant::<F, EXT>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder = UIntXAddGate::<32>::configure_builder(
        builder,
        GatePlacementStrategy::UseGeneralPurposeColumns,
    );
    let builder =
        SelectionGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
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
