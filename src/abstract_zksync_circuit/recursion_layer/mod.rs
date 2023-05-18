use super::*;
use crate::witness::oracle::VmWitnessOracle;
use boojum::cs::implementations::proof::Proof;
use boojum::field::FieldExtension;
use boojum::field::goldilocks::{GoldilocksField, GoldilocksExt2};
use zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use crate::Poseidon2Goldilocks;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use zkevm_circuits::tables::*;
use boojum::gadgets::tables::*;
use boojum::cs::gates::*;
use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;

pub mod leaf_layer;
pub mod node_layer;

use self::leaf_layer::*;
use self::node_layer::*;

pub const RECURSION_ARITY: usize = 16;

pub const BASE_LAYER_CIRCUIT_VM: u8 = BaseLayerCircuitType::VM as u8;
pub const BASE_LAYER_CIRCUIT_DECOMMITS_SORTER: u8 =  BaseLayerCircuitType::DecommitmentsFilter as u8;
pub const BASE_LAYER_CIRCUIT_DECOMMITER: u8 =  BaseLayerCircuitType::Decommiter as u8;
pub const BASE_LAYER_CIRCUIT_LOG_DEMUXER: u8 =  BaseLayerCircuitType::LogDemultiplexer as u8;
pub const BASE_LAYER_CIRCUIT_KECCAK256: u8 =  BaseLayerCircuitType::KeccakPrecompile as u8;
pub const BASE_LAYER_CIRCUIT_SHA256: u8 =  BaseLayerCircuitType::Sha256Precompile as u8;
pub const BASE_LAYER_CIRCUIT_ECRECOVER: u8 =  BaseLayerCircuitType::EcrecoverPrecompile as u8;
pub const BASE_LAYER_CIRCUIT_RAM_PERMUTATION: u8 =  BaseLayerCircuitType::RamValidation as u8;
pub const BASE_LAYER_CIRCUIT_STORAGE_SORTER: u8 =  BaseLayerCircuitType::StorageFilter as u8;
pub const BASE_LAYER_CIRCUIT_STORAGE_APPLICATION: u8 =  BaseLayerCircuitType::StorageApplicator as u8;
pub const BASE_LAYER_CIRCUIT_EVENTS_SORTER: u8 =  BaseLayerCircuitType::EventsRevertsFilter as u8;
pub const BASE_LAYER_CIRCUIT_L1_MESSAGES_SORTER: u8 =  BaseLayerCircuitType::L1MessagesRevertsFilter as u8;

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncRecursiveLayerCircuit {
    SchedulerCircuit,
    NodeLayerCircuit(ZkSyncNodeLayerRecursiveCircuit),
    LeafLayerCircuitForMainVM(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_VM>),
    LeafLayerCircuitForCodeDecommittmentsSorter(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_DECOMMITS_SORTER>),
    LeafLayerCircuitForCodeDecommitter(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_DECOMMITER>),
    LeafLayerCircuitForLogDemuxer(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_LOG_DEMUXER>),
    LeafLayerCircuitForKeccakRoundFunction(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_KECCAK256>),
    LeafLayerCircuitForSha256RoundFunction(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_SHA256>),
    LeafLayerCircuitForECRecover(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_ECRECOVER>),
    LeafLayerCircuitForRAMPermutation(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_RAM_PERMUTATION>),
    LeafLayerCircuitForStorageSorter(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_STORAGE_SORTER>),
    LeafLayerCircuitForStorageApplication(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_STORAGE_APPLICATION>),
    LeafLayerCircuitForEventsSorter(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_EVENTS_SORTER>),
    LeafLayerCircuitForL1MessagesSorter(ZkSyncLeafLayerRecursiveCircuit<BASE_LAYER_CIRCUIT_L1_MESSAGES_SORTER>),
}