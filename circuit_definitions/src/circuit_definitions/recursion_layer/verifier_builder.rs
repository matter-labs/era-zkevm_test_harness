use super::*;

type F = GoldilocksField;
type EXT = GoldilocksExt2;

pub fn dyn_verifier_builder_for_recursive_circuit_type(
    circuit_type: ZkSyncRecursionLayerStorageType,
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
    match circuit_type {
        ZkSyncRecursionLayerStorageType::SchedulerCircuit => {
            ConcreteSchedulerCircuitBuilder::dyn_verifier_builder::<EXT>()
        }
        ZkSyncRecursionLayerStorageType::NodeLayerCircuit => {
            ConcreteNodeLayerCircuitBuilder::dyn_verifier_builder::<EXT>()
        }
        _ => ConcreteLeafLayerCircuitBuilder::dyn_verifier_builder::<EXT>(),
    }
}

pub fn dyn_recursive_verifier_builder_for_recursive_circuit_type<
    CS: ConstraintSystem<F> + 'static,
>(
    circuit_type: ZkSyncRecursionLayerStorageType,
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
    match circuit_type {
        ZkSyncRecursionLayerStorageType::SchedulerCircuit => {
            ConcreteSchedulerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
        }
        ZkSyncRecursionLayerStorageType::NodeLayerCircuit => {
            ConcreteNodeLayerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
        }
        _ => ConcreteLeafLayerCircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>(),
    }
}
