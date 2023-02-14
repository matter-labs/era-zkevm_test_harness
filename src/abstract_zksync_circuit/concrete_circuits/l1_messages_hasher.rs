use derivative::*;
use sync_vm::scheduler::queues::StorageLogRecord;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct L1MessagesRehasherInstanceSynthesisFunction;

use sync_vm::glue::merkleize_l1_messages::input::MESSAGE_SERIALIZATION_BYTES;
use sync_vm::glue::pubdata_hasher::hash_pubdata_entry_point;
use sync_vm::glue::pubdata_hasher::input::PubdataHasherInstanceWitness;
use sync_vm::glue::pubdata_hasher::variable_length::hash_pubdata_entry_point_variable_length;
use sync_vm::scheduler::queues::storage_log::STORAGE_LOG_RECORD_ENCODING_LEN;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for L1MessagesRehasherInstanceSynthesisFunction {
    type Witness = PubdataHasherInstanceWitness<
        E,
        STORAGE_LOG_RECORD_ENCODING_LEN,
        MESSAGE_SERIALIZATION_BYTES,
        StorageLogRecord<E>,
    >;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "L1 messages pubdata hasher".to_string()
    }

    fn get_synthesis_function_dyn<'a, CS: ConstraintSystem<E> + 'a>() -> Box<
        dyn FnOnce(
                &mut CS,
                Option<Self::Witness>,
                &Self::RoundFunction,
                Self::Config,
            ) -> Result<AllocatedNum<E>, SynthesisError>
            + 'a,
    > {
        Box::new(
            hash_pubdata_entry_point_variable_length::<
                _,
                _,
                _,
                STORAGE_LOG_RECORD_ENCODING_LEN,
                MESSAGE_SERIALIZATION_BYTES,
                StorageLogRecord<E>,
            >,
        )
    }
}
