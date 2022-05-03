use crate::witness::callstack_handler::CallstackWithAuxData;
use sync_vm::vm::state::NUM_SPONGES_PER_CYCLE;
use zk_evm::abstractions::PrecompileCyclesWitness;
use zk_evm::aux_structures::LogQuery;
use zk_evm::aux_structures::*;
use zk_evm::ethereum_types::U256;
use zk_evm::testing::event_sink::ApplicationData;
use zk_evm::vm_state::CallStackEntry;

use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;
use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;

use zk_evm::vm_state::MAX_CALLSTACK_DEPTH;

// cycle indicators below are not timestamps!

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryMarker {
    Forward(usize),
    Rollback(usize),
}

#[derive(Clone, Debug)]
pub struct WitnessTracer {
    pub memory_queries: Vec<(u32, MemoryQuery)>, // flattened memory queries, with cycle indicators
    pub precompile_calls: Vec<()>,
    pub storage_read_queries: Vec<(u32, LogQuery)>, // storage read queries with cycle indicators
    pub decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, ECRecoverRoundWitness)>,
    pub monotonic_query_counter: usize,
    pub log_frames_stack: Vec<ApplicationData<((usize, usize), (QueryMarker, u32, LogQuery))>>, // keep the unique frame index
    pub callstack_with_aux_data: CallstackWithAuxData,
    pub sponge_busy_range: Range<usize>,
    // we need to properly preserve the information about logs. Not just flattening them into something,
    // but also keep the markers on when new frame has started and has finished, and the final frame execution
    // result, so we can properly substitute hash chain results in there for non-determinism
}

#[derive(Clone, Debug)]
pub struct NumberedApplicationData<T> {
    pub index: usize,
    pub forward: Vec<T>,
    pub rollbacks: Vec<T>,
}

impl<T> NumberedApplicationData<T> {
    pub fn new() -> Self {
        Self {
            index: 0,
            forward: vec![],
            rollbacks: vec![],
        }
    }
}

use std::ops::Range;

#[derive(Clone, Debug)]
pub struct LogQueueFramesProcessor {
    pub frame_indexes: Vec<usize>,
    pub frames: NumberedApplicationData<(QueryMarker, LogQuery)>,
    pub ranges: NumberedApplicationData<Range<usize>>,
}

impl LogQueueFramesProcessor {
    pub fn empty() -> Self {
        Self {
            frame_indexes: vec![],
            frames: NumberedApplicationData::new(),
            ranges: NumberedApplicationData::new(),
        }
    }
}

impl WitnessTracer {
    pub fn new() -> Self {
        Self {
            memory_queries: vec![],
            precompile_calls: vec![],
            storage_read_queries: vec![],
            decommittment_queries: vec![],
            keccak_round_function_witnesses: vec![],
            sha256_round_function_witnesses: vec![],
            ecrecover_witnesses: vec![],
            monotonic_query_counter: 0,
            log_frames_stack: vec![ApplicationData::empty()],
            callstack_with_aux_data: CallstackWithAuxData::empty(),
            sponge_busy_range: 0..0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuxCallstackProto {
    // monotonic counter to enumerate frames
    pub monotonic_frame_counter: usize,
    // current frame and it's parent
    pub current: ((usize, usize), CallStackEntry), // we save PARENT index and stack entry itself
    // stack of frames, along with their parents
    pub stack: Vec<((usize, usize), CallStackEntry)>,
    // history of "actions" - VM cycle, and action direction
    pub history: Vec<(u32, (bool, usize, CallStackEntry))>,
}

impl AuxCallstackProto {
    pub fn new_with_max_ergs() -> Self {
        let mut initial_callstack = CallStackEntry::empty_context();
        initial_callstack.ergs_remaining = u32::MAX;

        Self {
            monotonic_frame_counter: 2,
            current: ((0, 1), initial_callstack),
            stack: vec![],
            history: vec![],
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    #[track_caller]
    pub fn push_entry(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_entry: CallStackEntry,
        new_entry: CallStackEntry,
    ) {
        let new_counter = self.monotonic_frame_counter;
        let current_counter = self.current.0 .1;
        self.monotonic_frame_counter += 1;
        let mut old = std::mem::replace(
            &mut self.current,
            ((current_counter, new_counter), new_entry),
        );
        assert_eq!(old.1.code_page, previous_entry.code_page);
        old.1 = previous_entry;
        self.stack.push(old);

        self.history.push((
            monotonic_cycle_counter,
            (true, current_counter, previous_entry),
        ));
        debug_assert!(self.depth() <= MAX_CALLSTACK_DEPTH);
    }

    #[track_caller]
    pub fn pop_entry(&mut self, monotonic_cycle_counter: u32) -> ((usize, usize), CallStackEntry) {
        let previous = self.stack.pop().unwrap();
        let old = std::mem::replace(&mut self.current, previous);

        self.history
            .push((monotonic_cycle_counter, (false, old.0 .1, old.1)));

        old
    }
}

use zk_evm::abstractions::SpongeExecutionMarker;
use zk_evm::vm_state::VmLocalState;
use zk_evm::witness_trace::VmWitnessTracer;

impl VmWitnessTracer for WitnessTracer {
    fn start_new_execution_cycle(&mut self, current_state: &VmLocalState) {
        // println!("New cycle starts");
        // dbg!(&self.sponge_busy_range);
    }
    fn end_execution_cycle(&mut self, current_state: &VmLocalState) {
        // println!("Cycle ends");
        // dbg!(&self.sponge_busy_range);
        if !self.sponge_busy_range.is_empty() {
            if self.sponge_busy_range.contains(&NUM_SPONGES_PER_CYCLE) {
                // drain
                let new_range = NUM_SPONGES_PER_CYCLE..self.sponge_busy_range.end;
                self.sponge_busy_range = new_range
            } else {
                self.sponge_busy_range = 0..0;
            }
        }
    }
    fn add_sponge_marker(
        &mut self,
        monotonic_cycle_counter: u32,
        marker: SpongeExecutionMarker,
        sponges_range: Range<usize>,
        is_pended: bool,
    ) {
        // dbg!(&sponges_range);
        if self.sponge_busy_range.is_empty() {
            if sponges_range.start != 0 {
                let new_range = 0..sponges_range.end;
                self.sponge_busy_range = new_range;
            } else {
                self.sponge_busy_range = sponges_range;
            }
        } else {
            for el in sponges_range.clone() {
                assert!(!self.sponge_busy_range.contains(&el));
            }
            // merge
            self.sponge_busy_range.end = sponges_range.end;
        }
    }

    fn add_memory_query(&mut self, monotonic_cycle_counter: u32, memory_query: MemoryQuery) {
        self.memory_queries
            .push((monotonic_cycle_counter, memory_query));
    }

    fn add_log_query(&mut self, monotonic_cycle_counter: u32, mut log_query: LogQuery) {
        // log reads
        if !log_query.rw_flag && log_query.aux_byte == STORAGE_AUX_BYTE {
            self.storage_read_queries
                .push((monotonic_cycle_counter, log_query));
        }

        self.callstack_with_aux_data
            .add_log_query(monotonic_cycle_counter, log_query);

        let query_counter = self.monotonic_query_counter;
        self.monotonic_query_counter += 1;
        // log in general
        assert!(!log_query.rollback);
        let parent_frame_counter = self
            .callstack_with_aux_data
            .current_entry
            .parent_frame_index;
        let current_frame_counter = self.callstack_with_aux_data.current_entry.frame_index;
        let frames_index = (parent_frame_counter, current_frame_counter);
        let frame_data = self.log_frames_stack.last_mut().unwrap();
        if log_query.rw_flag {
            //  also append rollback
            log_query.rollback = false;
            frame_data.forward.push((
                frames_index,
                (
                    QueryMarker::Forward(query_counter),
                    monotonic_cycle_counter,
                    log_query,
                ),
            ));
            log_query.rollback = true;
            frame_data.rollbacks.push((
                frames_index,
                (
                    QueryMarker::Rollback(query_counter),
                    monotonic_cycle_counter,
                    log_query,
                ),
            ));
        } else {
            // read, do not append to rollback
            log_query.rollback = false;
            frame_data.forward.push((
                frames_index,
                (
                    QueryMarker::Forward(query_counter),
                    monotonic_cycle_counter,
                    log_query,
                ),
            ));
        }
    }

    fn add_decommittment(
        &mut self,
        monotonic_cycle_counter: u32,
        decommittment_query: DecommittmentQuery,
        mem_witness: Vec<U256>,
    ) {
        // this will literally form the queue of decommittment queries, one to one
        self.decommittment_queries.push((
            monotonic_cycle_counter,
            decommittment_query,
            mem_witness,
        ));
    }

    fn add_precompile_call_result(
        &mut self,
        monotonic_cycle_counter: u32,
        call_params: LogQuery,
        _mem_witness_in: Vec<MemoryQuery>,
        _memory_witness_out: Vec<MemoryQuery>,
        round_witness: PrecompileCyclesWitness,
    ) {
        // we bootkeep it to later on use in memory argument by opening and flattening, and in precompile circuits
        match round_witness {
            PrecompileCyclesWitness::Keccak256(wit) => {
                self.keccak_round_function_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit,
                ));
            }
            PrecompileCyclesWitness::Sha256(wit) => {
                self.sha256_round_function_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit,
                ));
            }
            PrecompileCyclesWitness::ECRecover(mut wit) => {
                assert_eq!(wit.len(), 1);
                self.ecrecover_witnesses.push((
                    monotonic_cycle_counter,
                    call_params,
                    wit.drain(0..1).next().unwrap(),
                ));
            }
        }
    }

    fn add_revertable_precompile_call(
        &mut self,
        _monotonic_cycle_counter: u32,
        _call_params: LogQuery,
    ) {
        unreachable!()
    }

    fn start_new_execution_context(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_context: &CallStackEntry,
        new_context: &CallStackEntry,
    ) {
        self.callstack_with_aux_data.push_entry(
            monotonic_cycle_counter,
            *previous_context,
            *new_context,
        );

        // log part
        let new = ApplicationData::empty();
        self.log_frames_stack.push(new);
    }

    fn finish_execution_context(&mut self, monotonic_cycle_counter: u32, panicked: bool) {
        // log part

        self.callstack_with_aux_data
            .pop_entry(monotonic_cycle_counter, panicked);

        // if we panic then we append forward and rollbacks to the forward of parent,
        // otherwise we place rollbacks of child before rollbacks of the parent
        let current_frame = self
            .log_frames_stack
            .pop()
            .expect("frame must be started before finishing");
        let ApplicationData { forward, rollbacks } = current_frame;
        let parent_data = self.log_frames_stack.last_mut().unwrap();
        if panicked {
            parent_data.forward.extend(forward);
            // add to forward part, but in reverse order
            parent_data.forward.extend(rollbacks.into_iter().rev());
        } else {
            parent_data.forward.extend(forward);
            // prepend to the parent's rollback queue
            parent_data.rollbacks.extend(rollbacks);
        }
    }
}
