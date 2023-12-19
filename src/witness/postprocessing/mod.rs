use super::*;

use crate::boojum::algebraic_props::round_function;
use crate::boojum::config::ProvingCSConfig;
use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
use crate::witness::full_block_artifact::BlockBasicCircuitsPublicCompactFormsWitnesses;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use crate::witness::oracle::VmInstanceWitness;
use crate::witness::utils::*;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::boojum::cs::gates::lookup_marker::LookupFormalGate;
use circuit_definitions::boojum::cs::gates::{
    BooleanConstraintGate, ConstantToVariableMappingToolMarker, ConstantsAllocatorGate,
    FmaGateInBaseFieldWithoutConstant, FmaGateInBaseWithoutConstantParams, ReductionGate,
    ReductionGateParams, SelectionGate,
};
use circuit_definitions::boojum::cs::implementations::reference_cs::CSReferenceImplementation;
use circuit_definitions::boojum::cs::traits::circuit::Circuit;
use circuit_definitions::boojum::cs::traits::cs::ConstraintSystem;
use circuit_definitions::boojum::cs::{GateTypeEntry, Tool, Variable};
use circuit_definitions::boojum::field::U64Representable;
use circuit_definitions::boojum::gadgets::queue;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use circuit_definitions::boojum::gadgets::traits::witnessable::WitnessHookable;
use circuit_definitions::boojum::pairing::Engine;
use circuit_definitions::circuit_definitions::{
    base_layer::*, ZkSyncUniformCircuitInstance, ZkSyncUniformSynthesisFunction,
};
use circuit_definitions::encodings::recursion_request::{
    RecursionQueueSimulator, RecursionRequest,
};
use circuit_definitions::zkevm_circuits::base_structures::precompile_input_outputs::PrecompileFunctionInputData;
use circuit_definitions::zkevm_circuits::base_structures::precompile_input_outputs::PrecompileFunctionOutputData;
use circuit_definitions::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterFSMInputOutput;
use circuit_definitions::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterInputData;
use circuit_definitions::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterOutputData;
use circuit_definitions::zkevm_circuits::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::demux_log_queue::input::LogDemuxerFSMInputOutput;
use circuit_definitions::zkevm_circuits::demux_log_queue::input::LogDemuxerInputData;
use circuit_definitions::zkevm_circuits::demux_log_queue::input::LogDemuxerOutputData;
use circuit_definitions::zkevm_circuits::ecrecover::EcrecoverCircuitFSMInputOutput;
use circuit_definitions::zkevm_circuits::ecrecover::EcrecoverCircuitInputOutput;
use circuit_definitions::zkevm_circuits::ecrecover::EcrecoverCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::fsm_input_output::circuit_inputs::main_vm;
use circuit_definitions::zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use circuit_definitions::zkevm_circuits::fsm_input_output::{
    ClosedFormInputCompactFormWitness, ClosedFormInputWitness,
};
use circuit_definitions::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionFSMInputOutput;
use circuit_definitions::zkevm_circuits::linear_hasher::input::{
    LinearHasherCircuitInstanceWitness, LinearHasherInputData, LinearHasherInputDataWitness,
    LinearHasherOutputData,
};
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorFSMInputOutput;
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorInputData;
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorInstanceWitness;
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorOutputData;
use circuit_definitions::zkevm_circuits::ram_permutation::input::RamPermutationCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::ram_permutation::input::RamPermutationFSMInputOutput;
use circuit_definitions::zkevm_circuits::ram_permutation::input::RamPermutationInputData;
use circuit_definitions::zkevm_circuits::sha256_round_function::input::Sha256RoundFunctionCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::sha256_round_function::input::Sha256RoundFunctionFSMInputOutput;
use circuit_definitions::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorFSMInputOutput;
use circuit_definitions::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInputData;
use circuit_definitions::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use circuit_definitions::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorOutputData;
use circuit_definitions::zkevm_circuits::storage_application::input::StorageApplicationCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::storage_application::input::StorageApplicationFSMInputOutput;
use circuit_definitions::zkevm_circuits::storage_application::input::StorageApplicationInputData;
use circuit_definitions::zkevm_circuits::storage_application::input::StorageApplicationOutputData;
use circuit_definitions::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorFSMInputOutput;
use circuit_definitions::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInputData;
use circuit_definitions::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use circuit_definitions::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorOutputData;
use circuit_definitions::{Field, RoundFunction};
use crossbeam::atomic::AtomicCell;
use derivative::Derivative;
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;

pub const L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH: bool = false;

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::traits::allocatable::CSAllocatableExt;
use crate::boojum::gadgets::traits::round_function::*;

pub fn create_leaf_level_circuits_and_scheduler_witness<
    CB: FnMut(
        ZkSyncBaseLayerCircuit<
            GoldilocksField,
            VmWitnessOracle<GoldilocksField>,
            Poseidon2Goldilocks,
        >,
    ),
    QSCB: FnMut(RecursionQueueSimulator<GoldilocksField>),
>(
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
    vm_instances_witness: Vec<VmInstanceWitness<GoldilocksField, VmWitnessOracle<GoldilocksField>>>,
    artifacts: FullBlockArtifacts<GoldilocksField>,
    geometry: GeometryConfig,
    round_function: &Poseidon2Goldilocks,
    mut circuit_callback: CB,
    mut queue_simulator_callback: QSCB,
) -> (
    BlockFirstAndLastBasicCircuits,
    BlockBasicCircuitsPublicCompactFormsWitnesses<GoldilocksField>,
) {
    assert!(artifacts.is_processed);

    let FullBlockArtifacts {
        ram_permutation_circuits_data,
        code_decommitter_circuits_data,
        decommittments_deduplicator_circuits_data,
        log_demuxer_circuit_data,
        storage_deduplicator_circuit_data,
        events_deduplicator_circuit_data,
        l1_messages_deduplicator_circuit_data,
        rollup_storage_application_circuit_data,
        keccak256_circuits_data,
        sha256_circuits_data,
        ecrecover_circuits_data,
        l1_messages_linear_hash_data,
        ..
    } = artifacts;

    let round_function = Arc::new(round_function.clone());

    use crate::zkevm_circuits::base_structures::vm_state::GlobalContextWitness;

    let in_circuit_global_context = GlobalContextWitness {
        zkporter_is_available,
        default_aa_code_hash,
    };

    use crate::witness::utils::create_cs_for_witness_generation;
    use crate::witness::utils::simulate_public_input_value_from_witness;

    let mut cs_for_witness_generation =
        create_cs_for_witness_generation::<GoldilocksField, Poseidon2Goldilocks>(
            TRACE_LEN_LOG_2_FOR_CALCULATION,
            MAX_VARS_LOG_2_FOR_CALCULATION,
        );

    let mut cycles_used: usize = 0;

    // VM

    let mut main_vm_circuits = FirstAndLastCircuit::default();
    let mut main_vm_circuits_compact_forms_witnesses = vec![];
    let mut queue_simulator = RecursionQueueSimulator::empty();
    let num_instances = vm_instances_witness.len();
    let mut observable_input = None;
    for (instance_idx, vm_instance) in vm_instances_witness.into_iter().enumerate() {
        use crate::witness::utils::vm_instance_witness_to_circuit_formal_input;
        let is_first = instance_idx == 0;
        let is_last = instance_idx == num_instances - 1;
        let mut circuit_input = vm_instance_witness_to_circuit_formal_input(
            vm_instance,
            is_first,
            is_last,
            in_circuit_global_context.clone(),
        );

        if observable_input.is_none() {
            assert!(is_first);
            observable_input = Some(circuit_input.closed_form_input.observable_input.clone());
        } else {
            circuit_input.closed_form_input.observable_input =
                observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            &mut cs_for_witness_generation,
            circuit_input.closed_form_input.clone(),
            &*round_function,
        );

        cycles_used += 1;
        if cycles_used == CYCLES_PER_SCRATCH_SPACE {
            cs_for_witness_generation =
                create_cs_for_witness_generation::<GoldilocksField, Poseidon2Goldilocks>(
                    TRACE_LEN_LOG_2_FOR_CALCULATION,
                    MAX_VARS_LOG_2_FOR_CALCULATION,
                );
            cycles_used = 0;
        }

        let instance = VMMainCircuit {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(geometry.cycles_per_vm_snapshot as usize),
            round_function: round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        if is_first {
            main_vm_circuits.first = Some(instance.clone());
        }
        if is_last {
            main_vm_circuits.last = Some(instance.clone());
        }

        let instance = instance.into();
        circuit_callback(instance);

        let recursive_request = RecursionRequest {
            circuit_type: GoldilocksField::from_u64_unchecked(
                instance.numeric_circuit_type() as u64
            ),
            public_input: proof_system_input,
        };
        let _ = queue_simulator.push(recursive_request, &*round_function);

        main_vm_circuits_compact_forms_witnesses.push(compact_form_witness);
    }
    queue_simulator_callback(queue_simulator);

    // Code decommitter sorter

    let mut maker = CircuitMaker::new(
        geometry.cycles_code_decommitter_sorter,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in decommittments_deduplicator_circuits_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        code_decommittments_sorter_circuits,
        queue_simulator,
        code_decommittments_sorter_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // Actual decommitter

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_code_decommitter,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in code_decommitter_circuits_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        code_decommitter_circuits,
        queue_simulator,
        code_decommitter_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // log demux

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_log_demuxer,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in log_demuxer_circuit_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (log_demux_circuits, queue_simulator, log_demux_circuits_compact_forms_witnesses) =
        maker.into_results();
    queue_simulator_callback(queue_simulator);

    // keccak precompiles

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_keccak256_circuit,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in keccak256_circuits_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        keccak_precompile_circuits,
        queue_simulator,
        keccak_precompile_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // sha256 precompiles

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_sha256_circuit,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in sha256_circuits_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        sha256_precompile_circuits,
        queue_simulator,
        sha256_precompile_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // ecrecover precompiles

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_ecrecover_circuit,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in ecrecover_circuits_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        ecrecover_precompile_circuits,
        queue_simulator,
        ecrecover_precompile_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // RAM permutation

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_ram_permutation,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in ram_permutation_circuits_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        ram_permutation_circuits,
        queue_simulator,
        ram_permutation_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // storage sorter

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_storage_sorter,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in storage_deduplicator_circuit_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (storage_sorter_circuits, queue_simulator, storage_sorter_circuit_compact_form_witnesses) =
        maker.into_results();
    queue_simulator_callback(queue_simulator);

    // storage application

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_storage_application,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in rollup_storage_application_circuit_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        storage_application_circuits,
        queue_simulator,
        storage_application_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // events sorter

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_events_or_l1_messages_sorter,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in events_deduplicator_circuit_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (events_sorter_circuits, queue_simulator, events_sorter_circuits_compact_forms_witnesses) =
        maker.into_results();
    queue_simulator_callback(queue_simulator);

    // l1 messages sorter

    let mut maker = CircuitMaker::new(
        geometry.cycles_per_events_or_l1_messages_sorter,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in l1_messages_deduplicator_circuit_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        l1_messages_sorter_circuits,
        queue_simulator,
        l1_messages_sorter_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // l1 messages pubdata hasher

    let mut maker = CircuitMaker::new(
        geometry.limit_for_l1_messages_pudata_hasher,
        round_function,
        &mut cs_for_witness_generation,
        &mut cycles_used,
    );

    for circuit_input in l1_messages_linear_hash_data.into_iter() {
        circuit_callback(maker.process(circuit_input));
    }

    let (
        l1_messages_hasher_circuits,
        queue_simulator,
        l1_messages_hasher_circuits_compact_forms_witnesses,
    ) = maker.into_results();
    queue_simulator_callback(queue_simulator);

    // done!

    let basic_circuits = BlockFirstAndLastBasicCircuits {
        main_vm_circuits,
        code_decommittments_sorter_circuits,
        code_decommitter_circuits,
        log_demux_circuits,
        keccak_precompile_circuits,
        sha256_precompile_circuits,
        ecrecover_precompile_circuits,
        ram_permutation_circuits,
        storage_sorter_circuits,
        storage_application_circuits,
        events_sorter_circuits,
        l1_messages_sorter_circuits,
        l1_messages_hasher_circuits,
    };

    let basic_circuits_public_inputs = BlockBasicCircuitsPublicCompactFormsWitnesses {
        main_vm_circuits: main_vm_circuits_compact_forms_witnesses,
        code_decommittments_sorter_circuits:
            code_decommittments_sorter_circuits_compact_forms_witnesses,
        code_decommitter_circuits: code_decommitter_circuits_compact_forms_witnesses,
        log_demux_circuits: log_demux_circuits_compact_forms_witnesses,
        keccak_precompile_circuits: keccak_precompile_circuits_compact_forms_witnesses,
        sha256_precompile_circuits: sha256_precompile_circuits_compact_forms_witnesses,
        ecrecover_precompile_circuits: ecrecover_precompile_circuits_compact_forms_witnesses,
        ram_permutation_circuits: ram_permutation_circuits_compact_forms_witnesses,
        storage_sorter_circuits: storage_sorter_circuit_compact_form_witnesses,
        storage_application_circuits: storage_application_circuits_compact_forms_witnesses,
        events_sorter_circuits: events_sorter_circuits_compact_forms_witnesses,
        l1_messages_sorter_circuits: l1_messages_sorter_circuits_compact_forms_witnesses,
        l1_messages_hasher_circuits_compact_forms_witnesses,
    };

    (basic_circuits, basic_circuits_public_inputs)
}

struct BlockFirstAndLastBasicCircuits {
    pub main_vm_circuits: FirstAndLastCircuit<
        VmMainInstanceSynthesisFunction<Field, VmWitnessOracle<Field>, RoundFunction>,
    >,
    pub code_decommittments_sorter_circuits:
        FirstAndLastCircuit<CodeDecommittmentsSorterSynthesisFunction<Field, RoundFunction>>,
    pub code_decommitter_circuits:
        FirstAndLastCircuit<CodeDecommitterInstanceSynthesisFunction<Field, RoundFunction>>,
    pub log_demux_circuits:
        FirstAndLastCircuit<LogDemuxInstanceSynthesisFunction<Field, RoundFunction>>,
    pub keccak_precompile_circuits:
        FirstAndLastCircuit<Keccak256RoundFunctionInstanceSynthesisFunction<Field, RoundFunction>>,
    pub sha256_precompile_circuits:
        FirstAndLastCircuit<Sha256RoundFunctionInstanceSynthesisFunction<Field, RoundFunction>>,
    pub ecrecover_precompile_circuits:
        FirstAndLastCircuit<ECRecoverFunctionInstanceSynthesisFunction<Field, RoundFunction>>,
    pub ram_permutation_circuits:
        FirstAndLastCircuit<RAMPermutationInstanceSynthesisFunction<Field, RoundFunction>>,
    pub storage_sorter_circuits:
        FirstAndLastCircuit<StorageSortAndDedupInstanceSynthesisFunction<Field, RoundFunction>>,
    pub storage_application_circuits:
        FirstAndLastCircuit<StorageApplicationInstanceSynthesisFunction<Field, RoundFunction>>,
    pub events_sorter_circuits: FirstAndLastCircuit<
        EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<Field, RoundFunction>,
    >,
    pub l1_messages_sorter_circuits: FirstAndLastCircuit<
        EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction<Field, RoundFunction>,
    >,
    pub l1_messages_hasher_circuits:
        FirstAndLastCircuit<LinearHasherInstanceSynthesisFunction<Field, RoundFunction>>,
}

struct FirstAndLastCircuit<S>
where
    S: ZkSyncUniformSynthesisFunction<Field>,
{
    pub first: Option<ZkSyncUniformCircuitInstance<GoldilocksField, S>>,
    pub last: Option<ZkSyncUniformCircuitInstance<GoldilocksField, S>>,
}

impl<S: ZkSyncUniformSynthesisFunction<Field>> Default for FirstAndLastCircuit<S> {
    fn default() -> Self {
        Self {
            first: None,
            last: None,
        }
    }
}

/// Implemented for structs that have a field called `closed_form_input`.
/// They are defined as if they were completely unrelated in era-zkevm_circuits.
trait ClosedFormInputField<F: SmallField> {
    type T: Clone
        + std::fmt::Debug
        + CSAllocatable<F>
        + CircuitVarLengthEncodable<F>
        + WitnessHookable<F>;

    type IN: Clone
        + std::fmt::Debug
        + CSAllocatable<F>
        + CircuitVarLengthEncodable<F>
        + WitnessHookable<F>;

    type OUT: Clone
        + std::fmt::Debug
        + CSAllocatable<F>
        + CircuitVarLengthEncodable<F>
        + WitnessHookable<F>;

    fn closed_form_input(&mut self) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT>
    where
        <Self::T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
        <Self::IN as CSAllocatable<F>>::Witness:
            serde::Serialize + serde::de::DeserializeOwned + Eq,
        <Self::OUT as CSAllocatable<F>>::Witness:
            serde::Serialize + serde::de::DeserializeOwned + Eq;
}

impl<F: SmallField> ClosedFormInputField<F> for LinearHasherCircuitInstanceWitness<F> {
    type T = ();
    type IN = LinearHasherInputData<F>;
    type OUT = LinearHasherOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for CodeDecommittmentsDeduplicatorInstanceWitness<F> {
    type T = CodeDecommittmentsDeduplicatorFSMInputOutput<F>;
    type IN = CodeDecommittmentsDeduplicatorInputData<F>;
    type OUT = CodeDecommittmentsDeduplicatorOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for CodeDecommitterCircuitInstanceWitness<F> {
    type T = CodeDecommitterFSMInputOutput<F>;
    type IN = CodeDecommitterInputData<F>;
    type OUT = CodeDecommitterOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for LogDemuxerCircuitInstanceWitness<F> {
    type T = LogDemuxerFSMInputOutput<F>;
    type IN = LogDemuxerInputData<F>;
    type OUT = LogDemuxerOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for Keccak256RoundFunctionCircuitInstanceWitness<F> {
    type T = Keccak256RoundFunctionFSMInputOutput<F>;
    type IN = PrecompileFunctionInputData<F>;
    type OUT = PrecompileFunctionOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for Sha256RoundFunctionCircuitInstanceWitness<F> {
    type T = Sha256RoundFunctionFSMInputOutput<F>;
    type IN = PrecompileFunctionInputData<F>;
    type OUT = PrecompileFunctionOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for EcrecoverCircuitInstanceWitness<F> {
    type T = EcrecoverCircuitFSMInputOutput<F>;
    type IN = PrecompileFunctionInputData<F>;
    type OUT = PrecompileFunctionOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for RamPermutationCircuitInstanceWitness<F> {
    type T = RamPermutationFSMInputOutput<F>;
    type IN = RamPermutationInputData<F>;
    type OUT = ();

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for StorageDeduplicatorInstanceWitness<F> {
    type T = StorageDeduplicatorFSMInputOutput<F>;
    type IN = StorageDeduplicatorInputData<F>;
    type OUT = StorageDeduplicatorOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for StorageApplicationCircuitInstanceWitness<F> {
    type T = StorageApplicationFSMInputOutput<F>;
    type IN = StorageApplicationInputData<F>;
    type OUT = StorageApplicationOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for EventsDeduplicatorInstanceWitness<F> {
    type T = EventsDeduplicatorFSMInputOutput<F>;
    type IN = EventsDeduplicatorInputData<F>;
    type OUT = EventsDeduplicatorOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

struct CircuitMaker<'a, T, S>
where
    T: ClosedFormInputField<GoldilocksField>,
    S: ZkSyncUniformSynthesisFunction<
        GoldilocksField,
        Config = usize,
        Witness = T,
        RoundFunction = Poseidon2Goldilocks,
    >,
{
    geometry: u32,
    round_function: Arc<Poseidon2Goldilocks>,
    observable_input: Option<<T::IN as CSAllocatable<GoldilocksField>>::Witness>,
    cs_for_witness_generation: &'a mut ConstraintSystemImpl<GoldilocksField, Poseidon2Goldilocks>,
    cycles_used: &'a mut usize,
    queue_simulator: RecursionQueueSimulator<GoldilocksField>,
    compact_form_witnesses: Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    extremes: FirstAndLastCircuit<S>,
}

impl<T, S> CircuitMaker<'_, T, S>
where
    T: ClosedFormInputField<GoldilocksField>,
    <T::T as CSAllocatable<GoldilocksField>>::Witness:
        serde::Serialize + serde::de::DeserializeOwned + Eq,
    <T::IN as CSAllocatable<GoldilocksField>>::Witness:
        serde::Serialize + serde::de::DeserializeOwned + Eq,
    <T::OUT as CSAllocatable<GoldilocksField>>::Witness:
        serde::Serialize + serde::de::DeserializeOwned + Eq,
    S: ZkSyncUniformSynthesisFunction<
        GoldilocksField,
        Config = usize,
        Witness = T,
        RoundFunction = Poseidon2Goldilocks,
    >,
    ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, Poseidon2Goldilocks>:
        From<ZkSyncUniformCircuitInstance<GoldilocksField, S>>,
{
    fn new(
        geometry: u32,
        round_function: Arc<Poseidon2Goldilocks>,
        cs_for_witness_generation: &mut ConstraintSystemImpl<GoldilocksField, Poseidon2Goldilocks>,
        cycles_used: &mut usize,
    ) -> Self {
        Self {
            geometry,
            round_function,
            observable_input: None,
            cs_for_witness_generation,
            cycles_used,
            queue_simulator: RecursionQueueSimulator::empty(),
            compact_form_witnesses: vec![],
            extremes: FirstAndLastCircuit::default(),
        }
    }

    fn process(
        &mut self,
        circuit_input: T,
    ) -> ZkSyncBaseLayerCircuit<
        GoldilocksField,
        VmWitnessOracle<GoldilocksField>,
        Poseidon2Goldilocks,
    > {
        if self.observable_input.is_none() {
            self.observable_input =
                Some(circuit_input.closed_form_input().observable_input.clone());
        } else {
            circuit_input.closed_form_input().observable_input =
                self.observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) = simulate_public_input_value_from_witness(
            self.cs_for_witness_generation,
            circuit_input.closed_form_input().clone(),
            &*self.round_function,
        );

        *self.cycles_used += 1;
        if *self.cycles_used == CYCLES_PER_SCRATCH_SPACE {
            *self.cs_for_witness_generation =
                create_cs_for_witness_generation::<GoldilocksField, Poseidon2Goldilocks>(
                    TRACE_LEN_LOG_2_FOR_CALCULATION,
                    MAX_VARS_LOG_2_FOR_CALCULATION,
                );
            *self.cycles_used = 0;
        }

        self.compact_form_witnesses.push(compact_form_witness);

        let circuit = ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(self.geometry as usize),
            round_function: self.round_function.clone(),
            expected_public_input: Some(proof_system_input),
        };

        if self.extremes.first.is_none() {
            self.extremes.first = Some(circuit.clone());
        }
        self.extremes.last = Some(circuit.clone());

        let circuit: ZkSyncBaseLayerCircuit<
            GoldilocksField,
            VmWitnessOracle<GoldilocksField>,
            Poseidon2Goldilocks,
        > = circuit.into();

        let recursive_request = RecursionRequest {
            circuit_type: GoldilocksField::from_u64_unchecked(circuit.numeric_circuit_type() as u64),
            public_input: proof_system_input,
        };
        let _ = self
            .queue_simulator
            .push(recursive_request, &*self.round_function);

        circuit
    }

    fn into_results(
        self,
    ) -> (
        FirstAndLastCircuit<S>,
        RecursionQueueSimulator<GoldilocksField>,
        Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    ) {
        (
            self.extremes,
            self.queue_simulator,
            self.compact_form_witnesses,
        )
    }
}
