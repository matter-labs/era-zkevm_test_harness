use zkevm_circuits::base_structures::precompile_input_outputs::PrecompileFunctionInputDataWitness;
use zkevm_circuits::base_structures::precompile_input_outputs::PrecompileFunctionOutputDataWitness;
use zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterInputDataWitness;
use zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterOutputDataWitness;
use zkevm_circuits::demux_log_queue::input::LogDemuxerInputDataWitness;
use zkevm_circuits::demux_log_queue::input::LogDemuxerOutputDataWitness;
use zkevm_circuits::eip_4844::input::EIP4844OutputDataWitness;
use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmInputDataWitness;
use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmOutputDataWitness;
use zkevm_circuits::linear_hasher::input::LinearHasherInputDataWitness;
use zkevm_circuits::linear_hasher::input::LinearHasherOutputDataWitness;
use zkevm_circuits::log_sorter::input::EventsDeduplicatorInputDataWitness;
use zkevm_circuits::log_sorter::input::EventsDeduplicatorOutputDataWitness;
use zkevm_circuits::ram_permutation::input::RamPermutationInputDataWitness;
use zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInputDataWitness;
use zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorOutputDataWitness;
use zkevm_circuits::storage_application::input::StorageApplicationInputDataWitness;
use zkevm_circuits::storage_application::input::StorageApplicationOutputDataWitness;
use zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInputDataWitness;
use zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorOutputDataWitness;

use crate::witness::postprocessing::CSAllocatable;
use crate::witness::postprocessing::CircuitVarLengthEncodable;
use crate::witness::postprocessing::SmallField;
use crate::witness::postprocessing::WitnessHookable;
use crate::witness::postprocessing::*;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
pub struct ObservableWitness<F: SmallField, T: ClosedFormInputField<F>> {
    pub observable_input: <T::IN as CSAllocatable<F>>::Witness,
    pub observable_output: <T::OUT as CSAllocatable<F>>::Witness
}

pub type VmObservableWitness<F: SmallField> = ObservableWitness<F, VmCircuitWitness<F, VmWitnessOracle<F>>>;
pub type LinearHasherObservableWitness<F: SmallField> = ObservableWitness<F, LinearHasherCircuitInstanceWitness<F>>;
pub type CodeDecommittmentsDeduplicatorObservableWitness<F: SmallField> = ObservableWitness<F, CodeDecommittmentsDeduplicatorInstanceWitness<F>>;
pub type CodeDecommitterObservableWitness<F: SmallField> = ObservableWitness<F, CodeDecommitterCircuitInstanceWitness<F>>;
pub type LogDemuxerObservableWitness<F: SmallField> = ObservableWitness<F, LogDemuxerCircuitInstanceWitness<F>>;
pub type Keccak256RoundFunctionObservableWitness<F: SmallField> = ObservableWitness<F, Keccak256RoundFunctionCircuitInstanceWitness<F>>;

pub type Sha256RoundFunctionObservableWitness<F: SmallField> = ObservableWitness<F, Sha256RoundFunctionCircuitInstanceWitness<F>>;
pub type EcrecoverObservableWitness<F: SmallField> = ObservableWitness<F, EcrecoverCircuitInstanceWitness<F>>;
pub type Secp256r1VerifyObservableWitness<F: SmallField> = ObservableWitness<F, Secp256r1VerifyCircuitInstanceWitness<F>>;
pub type RamPermutationObservableWitness<F: SmallField> = ObservableWitness<F, RamPermutationCircuitInstanceWitness<F>>;

pub type StorageDeduplicatorObservableWitness<F: SmallField> = ObservableWitness<F, StorageDeduplicatorInstanceWitness<F>>;
pub type StorageApplicationObservableWitness<F: SmallField> = ObservableWitness<F, StorageApplicationCircuitInstanceWitness<F>>;

pub type TransientStorageDeduplicatorObservableWitness<F: SmallField> = ObservableWitness<F, TransientStorageDeduplicatorInstanceWitness<F>>;
pub type EventsDeduplicatorObservableWitness<F: SmallField> = ObservableWitness<F, EventsDeduplicatorInstanceWitness<F>>;