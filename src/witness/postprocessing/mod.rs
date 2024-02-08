use super::*;

use crate::boojum::algebraic_props::round_function;
use crate::boojum::config::ProvingCSConfig;
use crate::ethereum_types::U256;
use crate::toolset::GeometryConfig;
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
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::zkevm_circuits::secp256r1_verify::Secp256r1VerifyCircuitInstanceWitness;
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
use circuit_definitions::zkevm_circuits::transient_storage_validity_by_grand_product::input::TransientStorageDeduplicatorInstanceWitness;
use circuit_definitions::{Field, RoundFunction};
use crossbeam::atomic::AtomicCell;
use derivative::Derivative;
use std::collections::HashMap;
use std::default;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::Arc;
use circuit_definitions::zkevm_circuits::secp256r1_verify::input::*;
use circuit_definitions::zkevm_circuits::transient_storage_validity_by_grand_product::input::*;

pub const L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH: bool = false;

use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::traits::allocatable::CSAllocatableExt;
use crate::boojum::gadgets::traits::round_function::*;

pub struct BlockFirstAndLastBasicCircuits {
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
    pub transient_storage_sorter_circuits: FirstAndLastCircuit<
        TransientStorageSortAndDedupInstanceSynthesisFunction<Field, RoundFunction>,
    >,
    pub secp256r1_verify_circuits:
        FirstAndLastCircuit<Secp256r1VerifyFunctionInstanceSynthesisFunction<Field, RoundFunction>>,
}

pub struct FirstAndLastCircuit<S>
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
pub(crate) trait ClosedFormInputField<F: SmallField> {
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

impl<F: SmallField> ClosedFormInputField<F> for TransientStorageDeduplicatorInstanceWitness<F> {
    type T = TransientStorageDeduplicatorFSMInputOutput<F>;
    type IN = TransientStorageDeduplicatorInputData<F>;
    type OUT = ();

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

impl<F: SmallField> ClosedFormInputField<F> for Secp256r1VerifyCircuitInstanceWitness<F> {
    type T = Secp256r1VerifyCircuitFSMInputOutput<F>;
    type IN = PrecompileFunctionInputData<F>;
    type OUT = PrecompileFunctionOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

pub(crate) struct CircuitMaker<'a, T, S>
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

impl<'a, T, S> CircuitMaker<'a, T, S>
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
{
    pub(crate) fn new(
        geometry: u32,
        round_function: Arc<Poseidon2Goldilocks>,
        cs_for_witness_generation: &'a mut ConstraintSystemImpl<
            GoldilocksField,
            Poseidon2Goldilocks,
        >,
        cycles_used: &'a mut usize,
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

    pub(crate) fn process(
        &mut self,
        mut circuit_input: T,
        circuit_type: BaseLayerCircuitType,
    ) -> ZkSyncUniformCircuitInstance<GoldilocksField, S> {
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

        let recursive_request = RecursionRequest {
            circuit_type: GoldilocksField::from_u64_unchecked(circuit_type as u64),
            public_input: proof_system_input,
        };
        let _ = self
            .queue_simulator
            .push(recursive_request, &*self.round_function);

        circuit
    }

    pub(crate) fn into_results(
        self,
    ) -> (
        FirstAndLastCircuit<S>,
        RecursionQueueSimulator<GoldilocksField>,
        Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    ) {
        // if we have NO compact form inputs, we need to create a dummy value for scheduler
        // as scheduler can only skip one type at the time, so we need some meaningless compact form witness
        let compact_form_witnesses = if self.compact_form_witnesses.is_empty() {
            use crate::zkevm_circuits::fsm_input_output::CLOSED_FORM_COMMITTMENT_LENGTH;
            use crate::boojum::field::Field;

            vec![ClosedFormInputCompactFormWitness::<GoldilocksField> {
                start_flag: true,
                completion_flag: true,
                observable_input_committment: [GoldilocksField::ZERO; CLOSED_FORM_COMMITTMENT_LENGTH],
                observable_output_committment: [GoldilocksField::ZERO; CLOSED_FORM_COMMITTMENT_LENGTH],
                hidden_fsm_input_committment: [GoldilocksField::ZERO; CLOSED_FORM_COMMITTMENT_LENGTH],
                hidden_fsm_output_committment: [GoldilocksField::ZERO; CLOSED_FORM_COMMITTMENT_LENGTH],
            }]
        } else {
            self.compact_form_witnesses
        };

        (
            self.extremes,
            self.queue_simulator,
            compact_form_witnesses,
        )
    }
}
