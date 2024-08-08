use crate::blake2::Blake2s256;
use crate::ethereum_types::{Address, U256};
use crate::run_vms::{run_vms, RunVMsResult, RunVmError};
pub use crate::run_vms::SCHEDULER_TIMESTAMP;
use crate::snark_wrapper::boojum::field::goldilocks::GoldilocksExt2;
use crate::snark_wrapper::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::toolset::GeometryConfig;
use crate::witness::oracle::WitnessGenerationArtifact;
use crate::witness::tree::BinarySparseStorageTree;
use crate::witness::tree::ZkSyncStorageLeaf;
use crate::zk_evm::abstractions::Storage;
use crate::zk_evm::GenericNoopTracer;
use crate::zkevm_circuits::scheduler::block_header::BlockAuxilaryOutputWitness;
use crate::zkevm_circuits::scheduler::{
    block_header::MAX_4844_BLOBS_PER_BLOCK, input::SchedulerCircuitInstanceWitness,
};
use circuit_definitions::boojum::field::Field;
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
use circuit_definitions::snark_wrapper::franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data;
use circuit_definitions::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;
use circuit_definitions::Field as MainField;

/// Executes a given set of instructions, and returns things necessary to do the proving:
/// - all circuits as a callback
/// - circuit recursion queues and associated inputs as a callback
/// - partial witness for the scheduler circuit (later we have to add proof witnesses for the nodes)
/// - witness with AUX data (with information that might be useful during verification to generate the public input)
///
/// This function will setup the environment and will run out-of-circuit and then in-circuit.
/// GenericNoopTracer will be used as out-of-circuit tracer
pub fn run<S: Storage, CB: FnMut(WitnessGenerationArtifact)>(
    caller: Address,                 // for real block must be zero
    entry_point_address: Address,    // for real block must be the bootloader
    entry_point_code: Vec<[u8; 32]>, // for read block must be a bootloader code
    initial_heap_content: Vec<u8>,   // bootloader starts with non-deterministic heap
    zk_porter_is_available: bool,
    default_aa_code_hash: U256,
    evm_simulator_code_hash: U256,
    used_bytecodes: std::collections::HashMap<U256, Vec<[u8; 32]>>, // auxilary information to avoid passing a full set of all used codes
    ram_verification_queries: Vec<(u32, U256)>, // we may need to check that after the bootloader's memory is filled
    cycle_limit: usize,
    geometry: GeometryConfig,
    storage: S,
    tree: impl BinarySparseStorageTree<256, 32, 32, 8, 32, Blake2s256, ZkSyncStorageLeaf>,
    trusted_setup_path: &str,
    eip_4844_repack_inputs: [Option<Vec<u8>>; MAX_4844_BLOBS_PER_BLOCK],
    artifacts_callback: CB,
) -> (
    SchedulerCircuitInstanceWitness<MainField, CircuitGoldilocksPoseidon2Sponge, GoldilocksExt2>,
    BlockAuxilaryOutputWitness<MainField>,
) {
    let mut out_of_circuit_tracer = GenericNoopTracer::<_>::new();
    match run_vms(
        caller,
        entry_point_address,
        entry_point_code,
        initial_heap_content,
        zk_porter_is_available,
        default_aa_code_hash,
        evm_simulator_code_hash,
        used_bytecodes,
        ram_verification_queries,
        cycle_limit,
        geometry,
        storage,
        tree,
        trusted_setup_path,
        eip_4844_repack_inputs,
        artifacts_callback,
        &mut out_of_circuit_tracer,
    ) {
        Ok((scheduler_circuit_witness, aux_data)) => (scheduler_circuit_witness, aux_data),
        Err(err) => {
            let error_text = match err {
                RunVmError::InvalidInput(msg) => {
                    format!("Invalid input error: {msg}")
                }
                RunVmError::OutOfCircuitExecutionError(msg) => {
                    format!("Out-of-circuit execution error: {msg}")
                }
            };
            panic!("{error_text}");
        }
    }
}
