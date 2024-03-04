use snark_wrapper::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};

use super::*;

use crate::aux_definitions::witness_oracle::VmWitnessOracle;

use crate::boojum::cs::traits::circuit::CircuitBuilderProxy;
use crate::circuit_definitions::base_layer::*;

use crate::circuit_definitions::eip4844::EIP4844InstanceSynthesisFunction;

pub type EIP4844VerifierBuilder<F, R> =
    CircuitBuilderProxy<F, EIP4844InstanceSynthesisFunction<F, R>>;

pub type VMMainCircuitVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, VmMainInstanceSynthesisFunction>;
pub type CodeDecommittsSorterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, CodeDecommittmentsSorterSynthesisFunction<F, R>>;
pub type CodeDecommitterVerifierBuilder<F, R> =
    CircuitBuilderProxy<F, CodeDecommitterInstanceSynthesisFunction<F, R>>;
pub type LogDemuxerVerifierBuilder =
    CircuitBuilderProxy<GoldilocksField, LogDemuxInstanceSynthesisFunction>;
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
            CodeDecommittsSorterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::dyn_verifier_builder()
        }
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::dyn_verifier_builder()
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
            CodeDecommittsSorterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::Decommiter as u8 => {
            CodeDecommitterVerifierBuilder::<F, R>::dyn_recursive_verifier_builder()
        }
        i if i == BaseLayerCircuitType::LogDemultiplexer as u8 => {
            LogDemuxerVerifierBuilder::dyn_recursive_verifier_builder()
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
