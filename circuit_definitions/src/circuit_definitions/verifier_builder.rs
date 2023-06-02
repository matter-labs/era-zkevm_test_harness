use super::*;

use crate::aux_definitions::witness_oracle::VmWitnessOracle;

use crate::boojum::cs::traits::circuit::CircuitBuilderProxy;
use crate::circuit_definitions::base_layer::*;

pub type VMMainCircuitVerifierBuilder<F, W, R> =
    CircuitBuilderProxy<F, VmMainInstanceSynthesisFunction<F, W, R>>;
pub type CodeDecommittsSorterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, LogDemuxInstanceSynthesisFunction<F, R>>;
pub type Keccak256RoundFunctionVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, Keccak256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type Sha256RoundFunctionVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, Sha256RoundFunctionInstanceSynthesisFunction<F, R>>;
pub type ECRecoverFunctionVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, ECRecoverFunctionInstanceSynthesisFunction<F, R>>;
pub type RAMPermutationVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, RAMPermutationInstanceSynthesisFunction<F, R>>;
pub type StorageSorterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, StorageSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type StorageApplicationVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, StorageApplicationInstanceSynthesisFunction<F, R>>;
pub type EventsSorterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesSorterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<F, R>>;
pub type L1MessagesHaherVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, LinearHasherInstanceSynthesisFunction<F, R>>;

pub fn dyn_verifier_builder_for_circuit_type<
    F: SmallField,
    EXT: FieldExtension<2, BaseField = F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
>(
    circuit_type: u8,
) -> Box<dyn crate::boojum::cs::traits::circuit::ErasedBuilderForVerifier<F, EXT>>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
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
            VMMainCircuitVerifierBuilder::<F, VmWitnessOracle<F>, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesHasher as u8 => {
            L1MessagesHaherVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}

pub fn dyn_recursive_verifier_builder_for_circuit_type<
    F: SmallField,
    EXT: FieldExtension<2, BaseField = F>,
    CS: ConstraintSystem<F> + 'static,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned,
>(
    circuit_type: u8,
) -> Box<dyn crate::boojum::cs::traits::circuit::ErasedBuilderForRecursiveVerifier<F, EXT, CS>>
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
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
            VMMainCircuitVerifierBuilder::<F, VmWitnessOracle<F>, R>::dyn_recursive_verifier_builder(
            )
        }
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesHasher as u8 => {
            L1MessagesHaherVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}
