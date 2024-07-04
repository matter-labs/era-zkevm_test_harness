use crate::witness::postprocessing::CSAllocatable;
use crate::witness::postprocessing::SmallField;
use crate::witness::postprocessing::*;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
pub(crate) struct ObservableWitness<F: SmallField, T: ClosedFormInputField<F>> {
    pub observable_input: <T::IN as CSAllocatable<F>>::Witness,
    pub observable_output: <T::OUT as CSAllocatable<F>>::Witness,
}

pub(crate) type VmObservableWitness<F> =
    ObservableWitness<F, VmCircuitWitness<F, VmWitnessOracle<F>>>;
pub(crate) type LinearHasherObservableWitness<F> =
    ObservableWitness<F, LinearHasherCircuitInstanceWitness<F>>;
pub(crate) type CodeDecommittmentsDeduplicatorObservableWitness<F> =
    ObservableWitness<F, CodeDecommittmentsDeduplicatorInstanceWitness<F>>;
pub(crate) type CodeDecommitterObservableWitness<F> =
    ObservableWitness<F, CodeDecommitterCircuitInstanceWitness<F>>;
pub(crate) type LogDemuxerObservableWitness<F> =
    ObservableWitness<F, LogDemuxerCircuitInstanceWitness<F>>;
pub(crate) type Keccak256RoundFunctionObservableWitness<F> =
    ObservableWitness<F, Keccak256RoundFunctionCircuitInstanceWitness<F>>;

pub(crate) type Sha256RoundFunctionObservableWitness<F> =
    ObservableWitness<F, Sha256RoundFunctionCircuitInstanceWitness<F>>;
pub(crate) type EcrecoverObservableWitness<F> =
    ObservableWitness<F, EcrecoverCircuitInstanceWitness<F>>;
pub(crate) type Secp256r1VerifyObservableWitness<F> =
    ObservableWitness<F, Secp256r1VerifyCircuitInstanceWitness<F>>;
pub(crate) type RamPermutationObservableWitness<F> =
    ObservableWitness<F, RamPermutationCircuitInstanceWitness<F>>;

pub(crate) type StorageDeduplicatorObservableWitness<F> =
    ObservableWitness<F, StorageDeduplicatorInstanceWitness<F>>;
pub(crate) type StorageApplicationObservableWitness<F> =
    ObservableWitness<F, StorageApplicationCircuitInstanceWitness<F>>;

pub(crate) type TransientStorageDeduplicatorObservableWitness<F> =
    ObservableWitness<F, TransientStorageDeduplicatorInstanceWitness<F>>;
pub(crate) type EventsDeduplicatorObservableWitness<F> =
    ObservableWitness<F, EventsDeduplicatorInstanceWitness<F>>;
