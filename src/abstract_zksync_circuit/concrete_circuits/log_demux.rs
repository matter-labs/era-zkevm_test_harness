use derivative::*;

use super::*;

use sync_vm::glue::traits::GenericHasher;
use sync_vm::rescue_poseidon::RescueParams;

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Copy, Debug, Default(bound = ""))]
pub struct LogDemuxInstanceSynthesisFunction;

use sync_vm::glue::demux_log_queue::demultiplex_storage_logs_enty_point;
use sync_vm::glue::demux_log_queue::input::LogDemuxerCircuitInstanceWitness;

impl<E: Engine> ZkSyncUniformSynthesisFunction<E> for LogDemuxInstanceSynthesisFunction {
    type Witness = LogDemuxerCircuitInstanceWitness<E>;
    type Config = usize;
    type RoundFunction = GenericHasher<E, RescueParams<E, 2, 3>, 2, 3>;

    fn description() -> String {
        "Log demuxer".to_string()
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
        Box::new(demultiplex_storage_logs_enty_point)
    }
}
