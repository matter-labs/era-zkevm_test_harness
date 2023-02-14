use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct MessagesMerklizerInstanceSynthesisFunction;

use sync_vm::glue::merkleize_l1_messages::input::MessagesMerklizerInstanceWitness;
use sync_vm::glue::merkleize_l1_messages::input::MESSAGE_SERIALIZATION_BYTES;
use sync_vm::glue::merkleize_l1_messages::merkleize::merklize_messages_entry_point;
use sync_vm::glue::merkleize_l1_messages::merkleize::merklize_messages_variable_length_entry_point;
use sync_vm::glue::merkleize_l1_messages::tree_hasher::CircuitKeccakTreeHasher;
use sync_vm::scheduler::data_access_functions::StorageLogRecord;
use sync_vm::scheduler::queues::storage_log::STORAGE_LOG_RECORD_ENCODING_LEN;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for MessagesMerklizerInstanceSynthesisFunction {
    type Witness = MessagesMerklizerInstanceWitness<
        E,
        STORAGE_LOG_RECORD_ENCODING_LEN,
        MESSAGE_SERIALIZATION_BYTES,
        StorageLogRecord<E>,
    >;
    type Config = (usize, bool);
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "L1 messages merklizer".to_string()
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
        // Box::new(merklize_messages_entry_point::<_, _, _, CircuitKeccakTreeHasher<_>, 2, 3, 2>)
        Box::new(
            merklize_messages_variable_length_entry_point::<_, _, _, CircuitKeccakTreeHasher<_>, 2>,
        )
    }
}
