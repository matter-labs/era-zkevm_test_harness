use super::*;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug, Default(bound = ""))]
#[serde(bound = "")]
pub struct ZkSyncUniformCircuitVerifierBuilder<
    F: SmallField,
    S: ZkSyncUniformSynthesisFunction<F>,
> {
    _marker: std::marker::PhantomData<(F, S)>
}

impl<
    F: SmallField,
    S: ZkSyncUniformSynthesisFunction<F>,
> CircuitBuilder<F> for ZkSyncUniformCircuitVerifierBuilder<F, S> 
{
    fn geometry() -> CSGeometry {
        S::geometry()
    }
    fn lookup_parameters() -> LookupParameters {
        S::lookup_parameters()
    }
    fn configure_builder<T: CsBuilderImpl<F, T>, GC: GateConfigurationHolder<F>, TB: StaticToolboxHolder>(
        builder: CsBuilder<T, F, GC, TB>
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        S::configure_builder(builder)
    }
}

impl<
    F: SmallField,
    S: ZkSyncUniformSynthesisFunction<F>,
>ZkSyncUniformCircuitVerifierBuilder<F, S> {
    pub fn into_dyn_verifier_builder<EXT: FieldExtension<2, BaseField = F>>(self) -> Box<dyn ErasedBuilderForVerifier<F, EXT>> {
        Box::new(self) as Box<dyn CircuitBuilder<F>> as Box<dyn ErasedBuilderForVerifier<F, EXT>>
    }

    pub fn into_dyn_recursive_verifier_builder<EXT: FieldExtension<2, BaseField = F>, CS: ConstraintSystem<F> + 'static>(self) -> Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>> {
        Box::new(self) as Box<dyn CircuitBuilder<F>> as Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>>
    }
}

impl<F: SmallField, S: ZkSyncUniformSynthesisFunction<F>> ZkSyncUniformCircuitInstance<F, S>  
{
    pub fn verifier_builder() -> ZkSyncUniformCircuitVerifierBuilder<F, S> {
        ZkSyncUniformCircuitVerifierBuilder {
            _marker: std::marker::PhantomData
        }
    }

    pub fn into_verifier_builder(&self) -> ZkSyncUniformCircuitVerifierBuilder<F, S> {
        ZkSyncUniformCircuitVerifierBuilder {
            _marker: std::marker::PhantomData
        }
    }
}

pub type VMMainCircuitVerifierBuilder<F, W, R> = ZkSyncUniformCircuitVerifierBuilder<F, VmMainInstanceSynthesisFunction<F, W, R>>; 
pub type CodeDecommittsSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, LogDemuxInstanceSynthesisFunction<F, R>>;
pub type Keccak256RoundFunctionVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, Keccak256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type Sha256RoundFunctionVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, Sha256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type ECRecoverFunctionVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, ECRecoverFunctionInstanceSynthesisFunction<F, R>>;
pub type RAMPermutationVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, RAMPermutationInstanceSynthesisFunction<F, R>>;
pub type StorageSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, StorageSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type StorageApplicationVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, StorageApplicationInstanceSynthesisFunction<F, R>>;
pub type EventsSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesSorterVerifierBuilder<F, R> = ZkSyncUniformCircuitVerifierBuilder<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;


pub fn dyn_verifier_builder_for_circuit_type<
F: SmallField, 
EXT: FieldExtension<2, BaseField = F>,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>(circuit_type: u8) -> Box<dyn boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>> 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

    match circuit_type {
        i if i == BaseLayerCircuitType::VM as u8 => {
            VMMainCircuitVerifierBuilder::<F, VmWitnessOracle<F>, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::<F, R>::default().into_dyn_verifier_builder()
        },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_verifier_builder()
        // },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_verifier_builder()
        // },
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}

pub fn dyn_recursive_verifier_builder_for_circuit_type<
F: SmallField, 
EXT: FieldExtension<2, BaseField = F>,
CS: ConstraintSystem<F> + 'static,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>(circuit_type: u8) -> Box<dyn boojum::cs::traits::circuit::ErasedBuilderForRecursiveVerifier<F, EXT, CS>> 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

    match circuit_type {
        i if i == BaseLayerCircuitType::VM as u8 => {
            VMMainCircuitVerifierBuilder::<F, VmWitnessOracle<F>, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::<F, R>::default().into_dyn_recursive_verifier_builder()
        },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_recursive_verifier_builder()
        // },
        // i if i == BaseLayerCircuitType::VM as u8 => {
        //     ZkSyncUniformCircuitVerifierBuilder::<F, VMMainCircuitVerifierBuilder<F, VmWitnessOracle<F>, R>>::default().into_dyn_recursive_verifier_builder()
        // },
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}

impl<
    F: SmallField, 
    W: WitnessOracle<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
> ZkSyncBaseLayerCircuit<F, W, R>  
    where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    pub fn into_dyn_verifier_builder<EXT: FieldExtension<2, BaseField = F>>(&self) -> Box<dyn ErasedBuilderForVerifier<F, EXT>> {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::ECRecover(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {inner.into_verifier_builder().into_dyn_verifier_builder::<EXT>()},
        }
    }

    pub fn into_dyn_recursive_verifier_builder<EXT: FieldExtension<2, BaseField = F>, CS: ConstraintSystem<F> + 'static>(&self) -> Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>> {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::ECRecover(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {inner.into_verifier_builder().into_dyn_recursive_verifier_builder::<EXT, CS>()},
        }
    }
}