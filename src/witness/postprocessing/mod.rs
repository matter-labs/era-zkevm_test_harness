use super::*;

use crate::witness::utils::*;
use crate::zkevm_circuits::eip_4844::input::EIP4844OutputData;
use boojum::gadgets::queue::full_state_queue::FullStateCircuitQueueRawWitness;
use boojum::gadgets::traits::encodable::WitnessVarLengthEncodable;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::boojum::field::U64Representable;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use circuit_definitions::boojum::gadgets::traits::witnessable::WitnessHookable;
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
use circuit_definitions::zkevm_circuits::ecrecover::EcrecoverCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::eip_4844::input::EIP4844CircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::fsm_input_output::{
    ClosedFormInputCompactFormWitness, ClosedFormInputWitness,
};
use circuit_definitions::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionFSMInputOutput;
use circuit_definitions::zkevm_circuits::linear_hasher::input::{
    LinearHasherCircuitInstanceWitness, LinearHasherInputData, LinearHasherOutputData,
};
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorFSMInputOutput;
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorInputData;
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorInstanceWitness;
use circuit_definitions::zkevm_circuits::log_sorter::input::EventsDeduplicatorOutputData;
use circuit_definitions::zkevm_circuits::ram_permutation::input::RamPermutationCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::ram_permutation::input::RamPermutationFSMInputOutput;
use circuit_definitions::zkevm_circuits::ram_permutation::input::RamPermutationInputData;
use circuit_definitions::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;
use circuit_definitions::zkevm_circuits::secp256r1_verify::input::*;
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
use circuit_definitions::zkevm_circuits::transient_storage_validity_by_grand_product::input::*;
use circuit_definitions::Field;
use crossbeam::atomic::AtomicCell;
use derivative::Derivative;
use observable_witness::ObservableWitness;
use oracle::WitnessGenerationArtifact;
use zkevm_circuits::base_structures::memory_query::{MemoryQuery, MEMORY_QUERY_PACKED_WIDTH};
use zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use zkevm_circuits::ram_permutation::input::RamPermutationCycleInputOutputWitness;

use std::sync::Arc;

use crate::zkevm_circuits::base_structures::vm_state::VmLocalState;
use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::{
    VmCircuitWitness, VmInputData, VmOutputData,
};

pub const L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH: bool = false;

use crate::boojum::field::SmallField;

pub mod observable_witness;

use crate::witness::postprocessing::observable_witness::*;

pub(crate) struct BlockFirstAndLastBasicCircuitsObservableWitnesses {
    pub main_vm_circuits: FirstAndLastCircuitWitness<VmObservableWitness<Field>>,
    pub code_decommittments_sorter_circuits:
        FirstAndLastCircuitWitness<CodeDecommittmentsDeduplicatorObservableWitness<Field>>,
    pub code_decommitter_circuits:
        FirstAndLastCircuitWitness<CodeDecommitterObservableWitness<Field>>,
    pub log_demux_circuits: FirstAndLastCircuitWitness<LogDemuxerObservableWitness<Field>>,
    pub keccak_precompile_circuits:
        FirstAndLastCircuitWitness<Keccak256RoundFunctionObservableWitness<Field>>,
    pub sha256_precompile_circuits:
        FirstAndLastCircuitWitness<Sha256RoundFunctionObservableWitness<Field>>,
    pub ecrecover_precompile_circuits:
        FirstAndLastCircuitWitness<EcrecoverObservableWitness<Field>>,
    pub secp256r1_verify_circuits:
        FirstAndLastCircuitWitness<Secp256r1VerifyObservableWitness<Field>>,
    pub ram_permutation_circuits:
        FirstAndLastCircuitWitness<RamPermutationObservableWitness<Field>>,
    pub storage_sorter_circuits:
        FirstAndLastCircuitWitness<StorageDeduplicatorObservableWitness<Field>>,
    pub storage_application_circuits:
        FirstAndLastCircuitWitness<StorageApplicationObservableWitness<Field>>,
    pub transient_storage_sorter_circuits:
        FirstAndLastCircuitWitness<TransientStorageDeduplicatorObservableWitness<Field>>,
    pub events_sorter_circuits:
        FirstAndLastCircuitWitness<EventsDeduplicatorObservableWitness<Field>>,
    pub l1_messages_sorter_circuits:
        FirstAndLastCircuitWitness<EventsDeduplicatorObservableWitness<Field>>,
    pub l1_messages_hasher_circuits:
        FirstAndLastCircuitWitness<LinearHasherObservableWitness<Field>>,
}

pub struct FirstAndLastCircuitWitness<T> {
    pub first: Option<T>,
    pub last: Option<T>,
}

impl<T> Default for FirstAndLastCircuitWitness<T> {
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
        + WitnessVarLengthEncodable<F>
        + WitnessHookable<F>;

    type IN: Clone
        + std::fmt::Debug
        + CSAllocatable<F>
        + CircuitVarLengthEncodable<F>
        + WitnessVarLengthEncodable<F>
        + WitnessHookable<F>;

    type OUT: Clone
        + std::fmt::Debug
        + CSAllocatable<F>
        + CircuitVarLengthEncodable<F>
        + WitnessVarLengthEncodable<F>
        + WitnessHookable<F>;

    fn closed_form_input(&mut self) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT>
    where
        <Self::T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
        <Self::IN as CSAllocatable<F>>::Witness:
            serde::Serialize + serde::de::DeserializeOwned + Eq,
        <Self::OUT as CSAllocatable<F>>::Witness:
            serde::Serialize + serde::de::DeserializeOwned + Eq;
}

impl<F: SmallField> ClosedFormInputField<F> for VmCircuitWitness<F, VmWitnessOracle<F>> {
    type T = VmLocalState<F>;
    type IN = VmInputData<F>;
    type OUT = VmOutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
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

impl<F: SmallField> ClosedFormInputField<F> for EIP4844CircuitInstanceWitness<F> {
    type T = ();
    type IN = ();
    type OUT = EIP4844OutputData<F>;

    fn closed_form_input(
        &mut self,
    ) -> &mut ClosedFormInputWitness<F, Self::T, Self::IN, Self::OUT> {
        &mut self.closed_form_input
    }
}

pub(crate) struct CircuitMaker<T: ClosedFormInputField<GoldilocksField>> {
    geometry: u32,
    round_function: Poseidon2Goldilocks,
    observable_input: Option<<T::IN as CSAllocatable<GoldilocksField>>::Witness>,
    recurion_queue_simulator: RecursionQueueSimulator<GoldilocksField>,
    compact_form_witnesses: Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    extremes: FirstAndLastCircuitWitness<ObservableWitness<GoldilocksField, T>>,
}

impl<T> CircuitMaker<T>
where
    T: ClosedFormInputField<GoldilocksField>,
    <T::T as CSAllocatable<GoldilocksField>>::Witness:
        serde::Serialize + serde::de::DeserializeOwned + Eq,
    <T::IN as CSAllocatable<GoldilocksField>>::Witness:
        serde::Serialize + serde::de::DeserializeOwned + Eq,
    <T::OUT as CSAllocatable<GoldilocksField>>::Witness:
        serde::Serialize + serde::de::DeserializeOwned + Eq,
{
    pub(crate) fn new(geometry: u32, round_function: Poseidon2Goldilocks) -> Self {
        Self {
            geometry,
            round_function,
            observable_input: None,
            recurion_queue_simulator: RecursionQueueSimulator::empty(),
            compact_form_witnesses: vec![],
            extremes: FirstAndLastCircuitWitness::default(),
        }
    }

    pub(crate) fn process<S: ZkSyncUniformSynthesisFunction<GoldilocksField>>(
        &mut self,
        mut circuit_input: T,
        circuit_type: BaseLayerCircuitType,
    ) -> ZkSyncUniformCircuitInstance<GoldilocksField, S>
    where
        S: ZkSyncUniformSynthesisFunction<
            GoldilocksField,
            Config = usize,
            Witness = T,
            RoundFunction = Poseidon2Goldilocks,
        >,
    {
        if self.observable_input.is_none() {
            self.observable_input =
                Some(circuit_input.closed_form_input().observable_input.clone());
        } else {
            circuit_input.closed_form_input().observable_input =
                self.observable_input.as_ref().unwrap().clone();
        }

        let (proof_system_input, compact_form_witness) =
            simulate_public_input_value_from_encodable_witness(
                circuit_input.closed_form_input().clone(),
                &self.round_function,
            );

        self.compact_form_witnesses.push(compact_form_witness);

        let circuit = ZkSyncUniformCircuitInstance {
            witness: AtomicCell::new(Some(circuit_input)),
            config: Arc::new(self.geometry as usize),
            round_function: Arc::new(self.round_function),
            expected_public_input: Some(proof_system_input),
        };
        let mut wit: T = circuit.clone_witness().unwrap();
        if self.extremes.first.is_none() {
            self.extremes.first = Some(ObservableWitness {
                observable_input: wit.closed_form_input().observable_input.clone(),
                observable_output: wit.closed_form_input().observable_output.clone(),
            });
        }
        self.extremes.last = Some(ObservableWitness {
            observable_input: wit.closed_form_input().observable_input.clone(),
            observable_output: wit.closed_form_input().observable_output.clone(),
        });

        let recursive_request = RecursionRequest {
            circuit_type: GoldilocksField::from_u64_unchecked(circuit_type as u64),
            public_input: proof_system_input,
        };
        self.recurion_queue_simulator
            .push(recursive_request, &self.round_function);

        circuit
    }

    pub(crate) fn into_results(
        self,
    ) -> (
        FirstAndLastCircuitWitness<ObservableWitness<GoldilocksField, T>>,
        RecursionQueueSimulator<GoldilocksField>,
        Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
    ) {
        // if we have NO compact form inputs, we need to create a dummy value for scheduler
        // as scheduler can only skip one type at the time, so we need some meaningless compact form witness
        let compact_form_witnesses = if self.compact_form_witnesses.is_empty() {
            use crate::boojum::field::Field;
            use crate::zkevm_circuits::fsm_input_output::CLOSED_FORM_COMMITTMENT_LENGTH;

            vec![ClosedFormInputCompactFormWitness::<GoldilocksField> {
                start_flag: true,
                completion_flag: true,
                observable_input_committment: [GoldilocksField::ZERO;
                    CLOSED_FORM_COMMITTMENT_LENGTH],
                observable_output_committment: [GoldilocksField::ZERO;
                    CLOSED_FORM_COMMITTMENT_LENGTH],
                hidden_fsm_input_committment: [GoldilocksField::ZERO;
                    CLOSED_FORM_COMMITTMENT_LENGTH],
                hidden_fsm_output_committment: [GoldilocksField::ZERO;
                    CLOSED_FORM_COMMITTMENT_LENGTH],
            }]
        } else {
            self.compact_form_witnesses
        };

        (
            self.extremes,
            self.recurion_queue_simulator,
            compact_form_witnesses,
        )
    }
}

pub(crate) fn make_circuits<
    T: ClosedFormInputField<GoldilocksField>,
    S: ZkSyncUniformSynthesisFunction<GoldilocksField>,
    WCB: Fn(ZkSyncUniformCircuitInstance<GoldilocksField, S>) -> ZkSyncBaseLayerCircuit,
    CB: FnMut(WitnessGenerationArtifact),
>(
    geometry: u32,
    circuit_type: BaseLayerCircuitType,
    circuits_data: Vec<T>,
    round_function: Poseidon2Goldilocks,
    wrap_circuit: WCB,
    artifacts_callback: &mut CB,
) -> (
    FirstAndLastCircuitWitness<ObservableWitness<GoldilocksField, T>>,
    Vec<ClosedFormInputCompactFormWitness<GoldilocksField>>,
)
where
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
    let mut maker = CircuitMaker::new(geometry, round_function.clone());

    for circuit_input in circuits_data.into_iter() {
        artifacts_callback(WitnessGenerationArtifact::BaseLayerCircuit(wrap_circuit(
            maker.process(circuit_input, circuit_type),
        )));
    }

    let (
        first_and_last_observable_witnesses,
        recursion_queue_simulator,
        circuits_compact_forms_witnesses,
    ) = maker.into_results();
    artifacts_callback(WitnessGenerationArtifact::RecursionQueue((
        circuit_type as u64,
        recursion_queue_simulator,
        circuits_compact_forms_witnesses.clone(),
    )));

    (
        first_and_last_observable_witnesses,
        circuits_compact_forms_witnesses,
    )
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct RamPermutationQueuesWitness<F: SmallField> {
    pub unsorted_queue_witness: FullStateCircuitQueueRawWitness<
        F,
        MemoryQuery<F>,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        MEMORY_QUERY_PACKED_WIDTH,
    >,
    pub sorted_queue_witness: FullStateCircuitQueueRawWitness<
        F,
        MemoryQuery<F>,
        FULL_SPONGE_QUEUE_STATE_WIDTH,
        MEMORY_QUERY_PACKED_WIDTH,
    >,
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct RamPermutationCircuitInstancePartialWitness<F: SmallField> {
    pub closed_form_input: RamPermutationCycleInputOutputWitness<F>,
}
