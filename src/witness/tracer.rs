use zk_evm::testing::event_sink::ApplicationData;
use zk_evm::vm_state::CallStackEntry;
use zk_evm::ethereum_types::U256;
use zk_evm::aux_structures::LogQuery;
use zk_evm::aux_structures::*;
use zk_evm::abstractions::PrecompileCyclesWitness;

use zk_evm::precompiles::keccak256::Keccak256RoundWitness;
use zk_evm::precompiles::sha256::Sha256RoundWitness;
use zk_evm::precompiles::ecrecover::ECRecoverRoundWitness;

use zk_evm::vm_state::MAX_CALLSTACK_DEPTH;

// cycle indicators below are not timestamps!

#[derive(Clone, Debug)]
pub struct WitnessTracer {
    pub memory_queries: Vec<(u32, MemoryQuery)>, // flattened memory queries, with cycle indicators
    pub precompile_calls: Vec<()>,
    pub storage_read_queries: Vec<(u32, LogQuery)>, // storage read queries with cycle indicators
    pub decommittment_queries: Vec<(u32, DecommittmentQuery, Vec<U256>)>,
    pub callstack_actions: Vec<(u32, (bool, u32, CallStackEntry))>,
    pub keccak_round_function_witnesses: Vec<(u32, LogQuery, Vec<Keccak256RoundWitness>)>,
    pub sha256_round_function_witnesses: Vec<(u32, LogQuery, Vec<Sha256RoundWitness>)>,
    pub ecrecover_witnesses: Vec<(u32, LogQuery, Vec<ECRecoverRoundWitness>)>,
    pub log_frames_stack: Vec<ApplicationData<((usize, usize), (u32, LogQuery))>>, // keep the unique frame index
    pub callstack_helper: AuxCallstackProto,
    // we need to properly preserve the information about logs. Not just flattening them into something,
    // but also keep the markers on when new frame has started and has finished, and the final frame execution
    // result, so we can properly substitute hash chain results in there for non-determinism
}

impl WitnessTracer {
    pub fn new() -> Self {
        Self {
            memory_queries: vec![],
            precompile_calls: vec![],
            storage_read_queries: vec![],
            decommittment_queries: vec![],
            callstack_actions: vec![],
            keccak_round_function_witnesses: vec![],
            sha256_round_function_witnesses: vec![],
            ecrecover_witnesses: vec![],
            log_frames_stack: vec![ApplicationData::empty()],
            callstack_helper: AuxCallstackProto::new_with_max_ergs()
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuxCallstackProto {
    pub monotonic_frame_counter: usize,
    pub current: (usize, CallStackEntry), // we save PARENT index and stack entry itself
    pub stack: Vec<(usize, CallStackEntry)>,
}

impl AuxCallstackProto {
    pub fn new_with_max_ergs() -> Self {
        let mut initial_callstack = CallStackEntry::empty_context();
        initial_callstack.ergs_remaining = u32::MAX;

        Self {
            monotonic_frame_counter: 1,
            current: (0, initial_callstack),
            stack: vec![]
        }
    }

    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    #[track_caller]
    pub fn push_entry(&mut self, entry: CallStackEntry) {
        let new_counter = self.monotonic_frame_counter;
        self.monotonic_frame_counter += 1;
        let old = std::mem::replace(&mut self.current, (new_counter, entry));
        self.stack.push(old);
        debug_assert!(self.depth() <= MAX_CALLSTACK_DEPTH);
    }

    #[track_caller]
    pub fn pop_entry(&mut self) -> (usize, CallStackEntry) {
        let previous = self.stack.pop().unwrap();
        let old = std::mem::replace(&mut self.current, previous);

        old
    }
}

use zk_evm::witness_trace::VmWitnessTracer;

impl VmWitnessTracer for WitnessTracer {
    fn add_memory_query(&mut self, monotonic_cycle_counter: u32, memory_query: MemoryQuery) {
        self.memory_queries.push((monotonic_cycle_counter, memory_query));
    }

    fn add_log_query(&mut self, monotonic_cycle_counter: u32, mut log_query: LogQuery) {
        // log reads
        if !log_query.rw_flag && log_query.aux_byte == STORAGE_AUX_BYTE {
            self.storage_read_queries.push((monotonic_cycle_counter, log_query));
        }

        // log in general
        assert!(!log_query.rollback);
        let current_frame_counter = self.callstack_helper.monotonic_frame_counter;
        let parent_frame_counter = self.callstack_helper.current.0;
        let frames_index = (parent_frame_counter, current_frame_counter);
        let frame_data = self.log_frames_stack.last_mut().unwrap();
        if log_query.rw_flag {
            //  also append rollback
            frame_data.forward.push((frames_index, (monotonic_cycle_counter, log_query)));
            log_query.rollback = true;
            frame_data.rollbacks.push((frames_index, (monotonic_cycle_counter, log_query)));
        } else {
            // read, do not append to rollback
            frame_data.forward.push((frames_index, (monotonic_cycle_counter, log_query)));
        }
    }

    fn add_decommittment(&mut self, monotonic_cycle_counter: u32, decommittment_query: DecommittmentQuery, mem_witness: Vec<U256>) {
        // this will literally form the queue of decommittment queries, one to one
        self.decommittment_queries.push((monotonic_cycle_counter, decommittment_query, mem_witness));
    }

    fn add_precompile_call_result(&mut self, monotonic_cycle_counter: u32, call_params: LogQuery, _mem_witness_in: Vec<MemoryQuery>, _memory_witness_out: Vec<MemoryQuery>, round_witness: PrecompileCyclesWitness) {
        // we bootkeep it to later on use in memory argument by opening and flattening, and in precompile circuits
        match round_witness {
            PrecompileCyclesWitness::Keccak256(wit) => {
                self.keccak_round_function_witnesses.push((monotonic_cycle_counter, call_params, wit));
            },
            PrecompileCyclesWitness::Sha256(wit) => {
                self.sha256_round_function_witnesses.push((monotonic_cycle_counter, call_params, wit));
            },
            PrecompileCyclesWitness::ECRecover(wit) => {
                self.ecrecover_witnesses.push((monotonic_cycle_counter, call_params, wit));
            }
        }
    }

    fn add_revertable_precompile_call(&mut self, _monotonic_cycle_counter: u32, _call_params: LogQuery) {
        unreachable!()
    }

    fn start_new_execution_context(&mut self, monotonic_cycle_counter: u32, new_context: &CallStackEntry) {
        // log part
        let new = ApplicationData::empty();
        self.log_frames_stack.push(new);

        // callstack part
        self.callstack_helper.push_entry(*new_context);
        let new_depth = self.callstack_helper.depth() as u32;
        self.callstack_actions.push((monotonic_cycle_counter, (true, new_depth, *new_context)));
    }

    fn finish_execution_context(&mut self, monotonic_cycle_counter: u32, panicked: bool) {
        // log part

        // if we panic then we append forward and rollbacks to the forward of parent,
        // otherwise we place rollbacks of child before rollbacks of the parent
        let current_frame = self.log_frames_stack.pop().expect("frame must be started before finishing");
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

        // callstack part
        let (_, popped) = self.callstack_helper.pop_entry();
        let new_depth = self.callstack_helper.depth() as u32;
        self.callstack_actions.push((monotonic_cycle_counter, (false, new_depth, popped)));
    }
}
