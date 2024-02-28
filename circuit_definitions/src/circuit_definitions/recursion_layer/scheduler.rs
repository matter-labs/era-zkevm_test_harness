use crate::boojum::cs::implementations::pow::NoPow;
use derivative::*;

use crate::boojum::cs::gates::*;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::cs::implementations::transcript::Transcript;
use crate::boojum::cs::traits::gate::GatePlacementStrategy;
use crate::boojum::gadgets::recursion::circuit_pow::*;
use crate::boojum::gadgets::tables::*;
use crate::circuit_definitions::base_layer::TARGET_CIRCUIT_TRACE_LENGTH;
use zkevm_circuits::base_structures::recursion_query::RecursionQuery;
use zkevm_circuits::scheduler::input::SchedulerCircuitInstanceWitness;
use zkevm_circuits::scheduler::*;

use super::*;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""))]
#[serde(bound = "")]
// #[serde(bound = "RecursionNodeInstanceWitness<F, H, EXT>: serde::Serialize + serde::de::DeserializeOwned,
//     NodeLayerRecursionConfig<F, H::NonCircuitSimulator, EXT>: serde::Serialize + serde::de::DeserializeOwned,
//     TR::TransciptParameters: serde::Serialize + serde::de::DeserializeOwned")]
pub struct SchedulerCircuit<POW: RecursivePoWRunner<F>> {
    pub witness: SchedulerCircuitInstanceWitness<F, RH, EXT>,
    pub config: SchedulerConfig<F, H, EXT>,
    pub transcript_params: <TR as Transcript<F>>::TransciptParameters,
    pub _marker: std::marker::PhantomData<(R, POW)>,
}

impl<POW: RecursivePoWRunner<F>> crate::boojum::cs::traits::circuit::CircuitBuilder<F>
    for SchedulerCircuit<POW>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <RecursionQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
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
            num_repetitions: 4,
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
        let builder = builder.allow_lookup(
            <Self as crate::boojum::cs::traits::circuit::CircuitBuilder<F>>::lookup_parameters(),
        );

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
        let builder =
            R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
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

impl<POW: RecursivePoWRunner<F>> SchedulerCircuit<POW>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <RecursionQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    pub fn description() -> String {
        "Scheduler circuit".to_string()
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        (
            Some(TARGET_CIRCUIT_TRACE_LENGTH),
            Some((1 << 26) + (1 << 25)),
        )
    }

    pub fn configure_builder_proxy<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        &self,
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        <Self as crate::boojum::cs::traits::circuit::CircuitBuilder<F>>::configure_builder(builder)
    }

    pub fn add_tables<CS: ConstraintSystem<F>>(&self, cs: &mut CS) {
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

    pub fn synthesize_into_cs<CS: ConstraintSystem<F> + 'static>(
        self,
        cs: &mut CS,
        round_function: &R,
    ) {
        let Self {
            witness,
            config,
            transcript_params,
            ..
        } = self;

        let verifier_builder =
            NodeLayerCircuitBuilder::<POW>::dyn_recursive_verifier_builder::<EXT, CS>();
        scheduler_function::<F, CS, R, RH, EXT, TR, CTR, POW>(
            cs,
            witness,
            round_function,
            config,
            verifier_builder,
            transcript_params,
        )
    }
}

pub type ZkSyncSchedulerCircuit = SchedulerCircuit<
    // GoldilocksField,
    // GoldilocksExt2,
    // ZkSyncDefaultRoundFunction,
    // CircuitGoldilocksPoseidon2Sponge,
    // GoldilocksPoisedon2Transcript,
    // CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, ZkSyncDefaultRoundFunction>,
    NoPow,
>;

use crate::boojum::cs::traits::circuit::CircuitBuilderProxy;

pub type SchedulerCircuitBuilder<POW> = CircuitBuilderProxy<F, SchedulerCircuit<POW>>;
pub type ConcreteSchedulerCircuitBuilder = SchedulerCircuitBuilder<NoPow>;
