use decommit_code::decommitter_memory_queries;
use ecrecover::ecrecover_memory_queries;
use keccak256_round_function::keccak256_memory_queries;
use secp256r1_verify::secp256r1_memory_queries;
use sha256_round_function::sha256_memory_queries;

use super::*;
use crate::ethereum_types::U256;

use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::LogQuery as LogQuery_;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;

use circuit_definitions::encodings::memory_query::MemoryQueueState;

pub(crate) mod decommit_code;
pub(crate) mod ecrecover;
pub(crate) mod keccak256_round_function;
pub(crate) mod ram_permutation;
pub(crate) mod secp256r1_verify;
pub(crate) mod sha256_round_function;
pub(crate) mod sort_decommit_requests;

#[derive(Clone)]
pub(crate) struct ImplicitMemoryQueries {
    pub decommitter_memory_queries: Vec<MemoryQuery>,
    pub ecrecover_memory_queries: Vec<MemoryQuery>,
    pub keccak256_memory_queries: Vec<MemoryQuery>,
    pub secp256r1_memory_queries: Vec<MemoryQuery>,
    pub sha256_memory_queries: Vec<MemoryQuery>,
}

impl ImplicitMemoryQueries {
    pub fn amount_of_queries(&self) -> usize {
        self.decommitter_memory_queries.len()
            + self.ecrecover_memory_queries.len()
            + self.keccak256_memory_queries.len()
            + self.secp256r1_memory_queries.len()
            + self.sha256_memory_queries.len()
    }

    fn get_vector(&self, index: usize) -> Option<&Vec<MemoryQuery>> {
        match index {
            0 => Some(&self.decommitter_memory_queries),
            1 => Some(&self.keccak256_memory_queries),
            2 => Some(&self.sha256_memory_queries),
            3 => Some(&self.ecrecover_memory_queries),
            4 => Some(&self.secp256r1_memory_queries),
            _ => None,
        }
    }

    pub fn iter(&self) -> ImplicitMemoryQueriesIter {
        ImplicitMemoryQueriesIter {
            inner: &self,
            circuit_index: 0,
            iter: self.decommitter_memory_queries.iter(),
        }
    }
}

pub struct ImplicitMemoryQueriesIter<'a> {
    inner: &'a ImplicitMemoryQueries,
    circuit_index: usize,
    iter: Iter<'a, MemoryQuery>,
}

use core::slice::Iter;

impl<'a> Iterator for ImplicitMemoryQueriesIter<'a> {
    type Item = &'a MemoryQuery;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next = self.iter.next();

        while next.is_none() {
            self.circuit_index += 1;
            let inner_vec = &self.inner.get_vector(self.circuit_index);
            if inner_vec.is_none() {
                return None;
            }

            self.iter = inner_vec.unwrap().iter();
            next = self.iter.next();
        }

        next
    }
}

use crate::witness::oracle::PrecompilesInputData;
pub fn get_implicit_memory_queries(
    deduplicated_decommit_requests_with_data: &Vec<(DecommittmentQuery, Vec<U256>)>,
    precompiles_inputs: &PrecompilesInputData,
) -> ImplicitMemoryQueries {
    ImplicitMemoryQueries {
        decommitter_memory_queries: decommitter_memory_queries(
            deduplicated_decommit_requests_with_data,
        ),
        ecrecover_memory_queries: ecrecover_memory_queries(&precompiles_inputs.ecrecover_witnesses),
        keccak256_memory_queries: keccak256_memory_queries(
            &precompiles_inputs.keccak_round_function_witnesses,
        ),
        secp256r1_memory_queries: secp256r1_memory_queries(
            &precompiles_inputs.secp256r1_verify_witnesses,
        ),
        sha256_memory_queries: sha256_memory_queries(
            &precompiles_inputs.sha256_round_function_witnesses,
        ),
    }
}

pub(crate) struct SimulatorSnapshot<F: SmallField, const SW: usize> {
    pub head: [F; SW],
    pub tail: [F; SW],
    pub num_items: u32,
}
use crate::boojum::gadgets::queue::QueueStateWitness;
use crate::boojum::gadgets::queue::QueueTailStateWitness;

impl<F: SmallField, const SW: usize> SimulatorSnapshot<F, SW> {
    pub fn take_sponge_like_queue_state(&self) -> QueueStateWitness<F, SW> {
        let result = QueueStateWitness {
            head: self.head,
            tail: QueueTailStateWitness {
                tail: self.tail,
                length: self.num_items,
            },
        };

        result
    }
}

#[derive(Default)]
pub(crate) struct ImplicitMemoryStates<F: SmallField> {
    pub decommitter_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    pub decommitter_memory_states: Vec<MemoryQueueState<F>>,
    pub ecrecover_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    pub ecrecover_memory_states: Vec<MemoryQueueState<F>>,
    pub keccak256_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    pub keccak256_memory_states: Vec<MemoryQueueState<F>>,
    pub secp256r1_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    pub secp256r1_memory_states: Vec<MemoryQueueState<F>>,
    pub sha256_simulator_snapshots: Vec<SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    pub sha256_memory_states: Vec<MemoryQueueState<F>>,
}

impl<F: SmallField> ImplicitMemoryStates<F> {
    pub fn amount_of_states(&self) -> usize {
        self.decommitter_memory_states.len()
            + self.ecrecover_memory_states.len()
            + self.keccak256_memory_states.len()
            + self.secp256r1_memory_states.len()
            + self.sha256_memory_states.len()
    }
}
use crate::witness::aux_data_structs::MemoryQueuePerCircuitSimulator;

fn get_simulator_snapshot<F: SmallField>(
    memory_queue_simulator: &mut MemoryQueuePerCircuitSimulator<F>,
) -> SimulatorSnapshot<F, FULL_SPONGE_QUEUE_STATE_WIDTH> {
    SimulatorSnapshot {
        head: memory_queue_simulator.head,
        tail: memory_queue_simulator.tail,
        num_items: memory_queue_simulator.num_items,
    }
}

use crate::witness::aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator;

pub(crate) fn simulate_implicit_memory_queues<
    F: SmallField,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(
    memory_queue_simulator: &mut MemoryQueuePerCircuitSimulator<F>,
    memory_queue_states_accumulator: &mut LastPerCircuitAccumulator<MemoryQueueState<F>>,
    implicit_memory_queries: &ImplicitMemoryQueries,
    round_function: R,
) -> ImplicitMemoryStates<F> {
    let mut implicit_memory_states = ImplicitMemoryStates::default();

    let mut simulate_subqueue =
        |memory_queries: &Vec<MemoryQuery>, memory_states: &mut Vec<MemoryQueueState<F>>| {
            let mut snapshots = vec![];
            snapshots.push(get_simulator_snapshot(memory_queue_simulator)); // before
            for query in memory_queries.iter() {
                let (_old_tail, intermediate_info) = memory_queue_simulator
                    .push_and_output_intermediate_data(*query, &round_function);

                memory_states.push(intermediate_info);
                memory_queue_states_accumulator.push(intermediate_info);
            }
            snapshots.push(get_simulator_snapshot(memory_queue_simulator)); // after

            snapshots
        };

    implicit_memory_states.decommitter_simulator_snapshots = simulate_subqueue(
        &implicit_memory_queries.decommitter_memory_queries,
        &mut implicit_memory_states.decommitter_memory_states,
    );

    implicit_memory_states.keccak256_simulator_snapshots = simulate_subqueue(
        &implicit_memory_queries.keccak256_memory_queries,
        &mut implicit_memory_states.keccak256_memory_states,
    );

    implicit_memory_states.sha256_simulator_snapshots = simulate_subqueue(
        &implicit_memory_queries.sha256_memory_queries,
        &mut implicit_memory_states.sha256_memory_states,
    );

    implicit_memory_states.ecrecover_simulator_snapshots = simulate_subqueue(
        &implicit_memory_queries.ecrecover_memory_queries,
        &mut implicit_memory_states.ecrecover_memory_states,
    );

    implicit_memory_states.secp256r1_simulator_snapshots = simulate_subqueue(
        &implicit_memory_queries.secp256r1_memory_queries,
        &mut implicit_memory_states.secp256r1_memory_states,
    );

    implicit_memory_states
}
