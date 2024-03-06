use snark_wrapper::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};

use super::*;

use crate::boojum::cs::traits::circuit::CircuitBuilderProxy;
use crate::circuit_definitions::base_layer::*;

use crate::circuit_definitions::eip4844::EIP4844InstanceSynthesisFunction;

pub type EIP4844VerifierBuilder = CircuitBuilderProxy<F, EIP4844InstanceSynthesisFunction>;

pub type VMMainCircuitVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, VmMainInstanceSynthesisFunction>;
pub type CodeDecommittsSorterVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, CodeDecommittmentsSorterSynthesisFunction>;
pub type CodeDecommitterVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, CodeDecommitterInstanceSynthesisFunction>;
pub type LogDemuxerVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, LogDemuxInstanceSynthesisFunction>;
pub type Keccak256RoundFunctionVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, Keccak256RoundFunctionInstanceSynthesisFunction>;
pub type Sha256RoundFunctionVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, Sha256RoundFunctionInstanceSynthesisFunction>;
pub type ECRecoverFunctionVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, ECRecoverFunctionInstanceSynthesisFunction>;
pub type RAMPermutationVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, RAMPermutationInstanceSynthesisFunction>;
pub type StorageSorterVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, StorageSortAndDedupInstanceSynthesisFunction>;
pub type StorageApplicationVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, StorageApplicationInstanceSynthesisFunction>;
pub type EventsSorterVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction>;
pub type L1MessagesSorterVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction>;
pub type L1MessagesHaherVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, LinearHasherInstanceSynthesisFunction>;

type F = GoldilocksField;
type EXT = GoldilocksExt2;
type R = Poseidon2Goldilocks;

pub fn dyn_verifier_builder_for_circuit_type(
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
            VMMainCircuitVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesHasher as u8 => {
            L1MessagesHaherVerifierBuilder::dyn_verifier_builder()
        }
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}

pub fn dyn_recursive_verifier_builder_for_circuit_type<
    CS: ConstraintSystem<GoldilocksField> + 'static,
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
            VMMainCircuitVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
            CodeDecommittsSorterVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::KeccakPrecompile as u8 => {
            Keccak256RoundFunctionVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Sha256Precompile as u8 => {
            Sha256RoundFunctionVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EcrecoverPrecompile as u8 => {
            ECRecoverFunctionVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::RamValidation as u8 => {
            RAMPermutationVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageFilter as u8 => {
            StorageSorterVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::StorageApplicator as u8 => {
            StorageApplicationVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::EventsRevertsFilter as u8 => {
            EventsSorterVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
            L1MessagesSorterVerifierBuilder::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::L1MessagesHasher as u8 => {
            L1MessagesHaherVerifierBuilder::dyn_recursive_verifier_builder()
        }
        _ => {
            panic!("unknown circuit type = {}", circuit_type);
        }
    }
}
