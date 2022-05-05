use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::scheduler::queues::StorageLogQueue;
use zk_evm::aux_structures::LogQuery;

use crate::encodings::log_query::LogQueueState;

use crate::bellman::Engine;
use crate::encodings::log_query::LogQueueSimulator;

pub fn log_queries_into_states<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(queries: impl Iterator<Item = LogQuery>, round_function: &R) -> Vec<LogQueueState<E>> {
    let mut result = vec![];
    let mut simulator = LogQueueSimulator::<E>::empty();
    for q in queries {
        let (_, intermediate_info) = simulator.push_and_output_intermediate_data(q, round_function);
        result.push(intermediate_info);
    }

    result
}