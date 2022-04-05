// implement witness oracle to actually compute 
// at the intermediate things that we need during VM execution,
// and then during specialized circuits execution

use sync_vm::{franklin_crypto::bellman::pairing::Engine, circuit_structures::traits::CircuitArithmeticRoundFunction};
use zk_evm::aux_structures::{MemoryQuery, LogQuery};
use crate::{witness::tracer::WitnessTracer, encodings::QueueSimulator};

pub struct VmWitnessOracle<E: Engine> {
    pub memory_read_witness: Vec<(u32, MemoryQuery)>,
    pub all_memory_queries_accumulated: Vec<MemoryQuery>,
    pub rollback_queue_head_segments: Vec<(u32, (usize, E::Fr))>,


    pub sorted_rollup_storage_queries: Vec<LogQuery>,
    pub sorted_porter_storage_queries: Vec<LogQuery>,
    pub sorted_event_queries: Vec<LogQuery>,
    pub sorted_to_l1_queries: Vec<LogQuery>,
    pub sorted_keccak_precompile_queries: Vec<LogQuery>,
    pub sorted_sha256_precompile_queries: Vec<LogQuery>,
    pub sorted_ecrecover_queries: Vec<LogQuery>,
}



impl<E: Engine> VmWitnessOracle<E> {
    pub fn from_witness_tracer<R: CircuitArithmeticRoundFunction<E, 2, 3>>(
        tracer: WitnessTracer,
        round_function: &R,
    ) -> Self {
        // TODO: simulate simultaneously the sponges and queue states
        let mut memory_read_witness = vec![];
        let WitnessTracer { 
            memory_queries, 
            precompile_calls, 
            storage_read_queries, 
            decommittment_queries, 
            callstack_actions, 
            keccak_round_function_witnesses, 
            sha256_round_function_witnesses, 
            ecrecover_witnesses, 
            monotonic_frame_counter, 
            log_frames_stack, 
            callstack_helper 
        } = tracer;

        let mut memory_queue_simulator = QueueSimulator::empty();

        for (_cycle, query) in memory_queries.iter() {
            if !query.rw_flag {
                memory_read_witness.push(query);
            }

            memory_queue_simulator.push(*query, round_function);
        }




        todo!()
    }
}