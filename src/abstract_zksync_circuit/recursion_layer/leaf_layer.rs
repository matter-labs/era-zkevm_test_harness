use boojum::algebraic_props::round_function;
use boojum::cs::implementations::pow::NoPow;
use derivative::*;
use crate::ZkSyncDefaultRoundFunction;
use crate::abstract_zksync_circuit::concrete_circuits::TARGET_CIRCUIT_TRACE_LENGTH;
use boojum::gadgets::recursion::recursive_tree_hasher::*;
use boojum::gadgets::recursion::recursive_transcript::*;
use boojum::gadgets::recursion::circuit_pow::*;
use boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use boojum::cs::oracle::TreeHasher;
use zkevm_circuits::base_structures::recursion_query::RecursionQuery;

use zkevm_circuits::recursion::leaf_layer::input::*;
use zkevm_circuits::recursion::leaf_layer::*;

use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""))]
#[serde(bound = "RecursionLeafInstanceWitness<F, H, EXT>: serde::Serialize + serde::de::DeserializeOwned,
    LeafLayerRecursionConfig<F, H::NonCircuitSimulator, EXT>: serde::Serialize + serde::de::DeserializeOwned,
    TR::TransciptParameters: serde::Serialize + serde::de::DeserializeOwned")]
pub struct LeafLayerRecursiveCircuit<
F: SmallField,
EXT: FieldExtension<2, BaseField = F>,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
H: RecursiveTreeHasher<F, Num<F>>,
TR: RecursiveTranscript<F, CompatibleCap = <H::NonCircuitSimulator as TreeHasher<F>>::Output, CircuitReflection = CTR>,
CTR: CircuitTranscript<F, CircuitCompatibleCap = <H as CircuitTreeHasher<F, Num<F>>>::CircuitOutput, TransciptParameters = TR::TransciptParameters>,
POW: RecursivePoWRunner<F>,
> {
   pub witness: RecursionLeafInstanceWitness<F, H, EXT>,
   pub config: LeafLayerRecursionConfig<F, H::NonCircuitSimulator, EXT>,
   pub transcript_params: TR::TransciptParameters,
   pub base_layer_circuit_type: BaseLayerCircuitType,
   pub _marker: std::marker::PhantomData<(R, POW)>
}

impl<
F: SmallField,
EXT: FieldExtension<2, BaseField = F>,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
H: RecursiveTreeHasher<F, Num<F>>,
TR: RecursiveTranscript<F, CompatibleCap = <H::NonCircuitSimulator as TreeHasher<F>>::Output, CircuitReflection = CTR>,
CTR: CircuitTranscript<F, CircuitCompatibleCap = <H as CircuitTreeHasher<F, Num<F>>>::CircuitOutput, TransciptParameters = TR::TransciptParameters>,
POW: RecursivePoWRunner<F>,
> LeafLayerRecursiveCircuit<F, EXT, R, H, TR, CTR, POW> 
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
    pub fn description(&self) -> String {
        format!("Leaf layer circuit for circuit id {}", self.base_layer_circuit_type as u8)
    }

    pub fn geometry(&self) -> CSGeometry {
        <LeafLayerCircuitBuilder<F, R> as CircuitBuilder<F>>::geometry()
    }

    pub fn lookup_parameters(&self) -> LookupParameters {
        <LeafLayerCircuitBuilder<F, R> as CircuitBuilder<F>>::lookup_parameters()
    }
    
    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        (
            Some(TARGET_CIRCUIT_TRACE_LENGTH),
            Some((1 << 26) + (1 << 25))
        )
    }

    pub fn configure_builder<T: CsBuilderImpl<F, T>, GC: GateConfigurationHolder<F>, TB: StaticToolboxHolder>(
        &self,
        builder: CsBuilder<T, F, GC, TB>
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        LeafLayerCircuitBuilder::<F, R>::configure_builder(builder)
    }

    pub fn add_tables<CS: ConstraintSystem<F>>(&self, _cs: &mut CS) {
    }

    pub fn synthesize_into_cs<
        CS: ConstraintSystem<F> + 'static,
    >(
        self,
        cs: &mut CS,
        round_function: &R,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] {
        let Self {
            witness, 
            config,
            transcript_params,
            ..
        } = self;

        todo!();

        // use crate::abstract_zksync_circuit::verifier_builder::dyn_recursive_verifier_builder_for_circuit_type;
        // let verifier_builder = dyn_recursive_verifier_builder_for_circuit_type::<F, EXT, CS, R>(self.base_layer_circuit_type as u8);
        // leaf_layer_recursion_entry_point::<F, CS, R, H, EXT, TR, CTR, POW>(
        //     cs, 
        //     witness, 
        //     round_function, 
        //     config, 
        //     verifier_builder, 
        //     transcript_params
        // )
    }

    pub fn get_builder(&self) -> LeafLayerCircuitBuilder<F, R> {
        LeafLayerCircuitBuilder {
            _marker: std::marker::PhantomData
        }
    }
}

pub type ZkSyncLeafLayerRecursiveCircuit = LeafLayerRecursiveCircuit<
    GoldilocksField,
    GoldilocksExt2,
    ZkSyncDefaultRoundFunction,
    CircuitGoldilocksPoseidon2Sponge,
    GoldilocksPoisedon2Transcript,
    CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, ZkSyncDefaultRoundFunction>,
    NoPow,
>;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default)]
pub struct LeafLayerCircuitBuilder<
F: SmallField,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> {
    _marker: std::marker::PhantomData<(F, R)>
}

impl<
F: SmallField,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> CircuitBuilder<F> for LeafLayerCircuitBuilder<F, R> {
    fn geometry() -> CSGeometry {
        CSGeometry { 
            num_columns_under_copy_permutation: 140, 
            num_witness_columns: 0, 
            num_constant_columns: 4, 
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters() -> LookupParameters {
        LookupParameters::NoLookup
    }
    
    fn configure_builder<T: CsBuilderImpl<F, T>, GC: GateConfigurationHolder<F>, TB: StaticToolboxHolder>(
        builder: CsBuilder<T, F, GC, TB>
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = builder.allow_lookup(<Self as CircuitBuilder::<F>>::lookup_parameters());

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
}

impl<
F: SmallField,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> LeafLayerCircuitBuilder<F, R> {
    pub fn dyn_verifier_builder<EXT: FieldExtension<2, BaseField = F>>() -> Box<dyn ErasedBuilderForVerifier<F, EXT>> {
        Box::new(Self::default())
    }

    pub fn dyn_recursive_verifier_builder<EXT: FieldExtension<2, BaseField = F>, CS: ConstraintSystem<F> + 'static>() -> Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>> {
        Box::new(Self::default())
    }

    pub fn into_dyn_verifier_builder<EXT: FieldExtension<2, BaseField = F>>(&self) -> Box<dyn ErasedBuilderForVerifier<F, EXT>> {
        Box::new(Self::default())
    }

    pub fn into_dyn_recursive_verifier_builder<EXT: FieldExtension<2, BaseField = F>, CS: ConstraintSystem<F> + 'static>(&self) -> Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>> {
        Box::new(Self::default())
    }
}