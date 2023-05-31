use std::collections::HashMap;

use crate::witness::tracer::QueryMarker;
use zk_evm::{aux_structures::LogQuery, vm_state::CallStackEntry};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RenumeratedQueryIndex {
    ForwardIndexAndRollbackIndex(usize),
    ForwardNoRollbackIndex(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogAction {
    ForwardAndRolledBack {
        forward_counter: usize,
        renumerated_rollback_counter_as_forward: usize,
    },
    ForwardAndNotRolledBack {
        forward_coutner: usize,
        rollback_counter: usize,
    },
    ForwardNoRollback(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtendedLogQuery {
    Query {
        marker: QueryMarker,
        cycle: u32,
        query: LogQuery,
    },
    FrameForwardHeadMarker(usize),
    FrameForwardTailMarker(usize),
    FrameRollbackHeadMarker(usize),
    FrameRollbackTailMarker(usize),
}

#[derive(Clone, Debug)]
pub struct CallstackEntryWithAuxData {
    pub entry: CallStackEntry,
    pub current_history_record: CallstackActionHistoryEntry,
    pub frame_index: usize,
    pub parent_frame_index: usize,
    pub forward_queue: Vec<ExtendedLogQuery>,
    pub rollback_queue: Vec<ExtendedLogQuery>,
}

impl CallstackEntryWithAuxData {
    pub fn empty() -> Self {
        Self {
            entry: CallStackEntry::empty_context(),
            current_history_record: CallstackActionHistoryEntry::uninitialized(),
            frame_index: 0,
            parent_frame_index: 0,
            forward_queue: vec![ExtendedLogQuery::FrameForwardHeadMarker(0)],
            rollback_queue: vec![ExtendedLogQuery::FrameRollbackTailMarker(0)],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutOfScopeReason {
    Fresh,
    Exited { panic: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CallstackAction {
    PushToStack,
    OutOfScope(OutOfScopeReason),
    PopFromStack { panic: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallstackActionHistoryEntry {
    pub action: CallstackAction,
    pub affected_entry: CallStackEntry,
    pub frame_index: usize,
    pub beginning_cycle: u32,
    pub end_cycle: Option<u32>,
    pub actions: Vec<(u32, LogAction)>,
}

impl CallstackActionHistoryEntry {
    pub fn uninitialized() -> Self {
        Self {
            action: CallstackAction::PushToStack,
            affected_entry: CallStackEntry::empty_context(),
            frame_index: 0,
            beginning_cycle: 0,
            end_cycle: None,
            // last_action_of_parent: None,
            actions: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MergeIntention {
    IntoForwardTail,
    IntoRollbackHead,
}

// special cases: if we merge (potentially empty) segment of the current frame
// to the empty segment of the parent frame, then we need somewhat immutable reference
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueueSegmentIndirectablePointer {
    ForwardHeadAtFrameStart(usize),
    RollbackTailAtFrameStart(usize),
}

#[derive(Clone, Debug)]
pub struct CallstackWithAuxData {
    pub monotonic_frame_counter: usize,
    pub rollbackable_monotonic_counter: usize,
    pub non_rollbackable_monotonic_counter: usize,
    pub forward_flattened_counter: usize,
    pub rollback_flattened_counter: usize,
    pub total_rolled_back: usize,
    pub unique_query_id_counter: u64,
    pub current_entry: CallstackEntryWithAuxData,
    pub depth: usize,
    pub stack: Vec<CallstackEntryWithAuxData>,
    pub full_history: Vec<CallstackActionHistoryEntry>,
    pub log_queue_access_snapshots: Vec<(u32, RenumeratedQueryIndex)>,
    pub log_access_history: Vec<(u32, QueryMarker)>,
    pub child_into_parent: HashMap<usize, usize>,
    pub flat_new_frames_history: Vec<(u32, CallStackEntry)>,
}

impl CallstackWithAuxData {
    pub fn empty() -> Self {
        let initial_history_record = CallstackActionHistoryEntry {
            action: CallstackAction::OutOfScope(OutOfScopeReason::Fresh),
            affected_entry: CallStackEntry::empty_context(),
            frame_index: 0,
            beginning_cycle: 0,
            end_cycle: None,
            actions: vec![],
        };

        let new = Self {
            monotonic_frame_counter: 1,
            rollbackable_monotonic_counter: 0,
            non_rollbackable_monotonic_counter: 0,
            forward_flattened_counter: 0,
            rollback_flattened_counter: 0,
            total_rolled_back: 0,
            unique_query_id_counter: 0,
            current_entry: CallstackEntryWithAuxData::empty(),
            depth: 0,
            stack: vec![],
            full_history: vec![initial_history_record],
            log_queue_access_snapshots: vec![],
            log_access_history: vec![],
            child_into_parent: HashMap::new(),
            flat_new_frames_history: vec![],
        };

        new
    }

    pub fn from_initial_callstack(
        monotonic_cycle_counter: u32,
        simple_entry: CallStackEntry,
    ) -> Self {
        let mut new = Self::empty();
        let current = new.current_entry.entry.clone();
        new.push_entry(monotonic_cycle_counter, current, simple_entry);

        new
    }

    pub fn push_entry(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_simple_entry: CallStackEntry,
        new_simple_entry: CallStackEntry,
    ) {
        self.flat_new_frames_history.push((monotonic_cycle_counter, new_simple_entry));

        let new_counter = self.monotonic_frame_counter;
        self.monotonic_frame_counter += 1;
        self.depth += 1;

        // when we push a new entry we put the previous "current" into the stack,
        // and intoduce a new one, for which we do not add history action as it may be unnecessary

        // we only care about the history of the stack top, so we push previous entry
        let current_frame_index = self.current_entry.frame_index;

        let full_entry = CallstackEntryWithAuxData {
            entry: new_simple_entry,
            current_history_record: CallstackActionHistoryEntry {
                action: CallstackAction::OutOfScope(OutOfScopeReason::Fresh),
                affected_entry: new_simple_entry,
                frame_index: new_counter,
                beginning_cycle: monotonic_cycle_counter,
                end_cycle: None,
                actions: vec![],
            },
            parent_frame_index: current_frame_index,
            frame_index: new_counter,
            forward_queue: vec![ExtendedLogQuery::FrameForwardHeadMarker(new_counter)],
            rollback_queue: vec![ExtendedLogQuery::FrameRollbackTailMarker(new_counter)],
        };

        let history_of_new = full_entry.current_history_record.clone();

        let mut current = std::mem::replace(&mut self.current_entry, full_entry);
        // update as we do not mutate between intermediate points
        current.entry = previous_simple_entry;
        current.current_history_record.affected_entry = previous_simple_entry;
        current.current_history_record.end_cycle = Some(monotonic_cycle_counter);

        let mut history_of_current = current.current_history_record.clone();
        history_of_current.action = CallstackAction::PushToStack;

        self.stack.push(current);
        self.full_history.push(history_of_current);
        self.full_history.push(history_of_new);
    }

    pub fn pop_entry(&mut self, monotonic_cycle_counter: u32, panicked: bool) -> CallStackEntry {
        let mut previous = self.stack.pop().unwrap();
        self.depth -= 1;

        previous.current_history_record.beginning_cycle = monotonic_cycle_counter;
        previous.current_history_record.beginning_cycle = monotonic_cycle_counter;
        previous.current_history_record.actions = vec![]; // cleanup
        previous.current_history_record.end_cycle = None;

        let mut previous_history_record = previous.current_history_record.clone();
        previous_history_record.action = CallstackAction::PopFromStack { panic: panicked };

        // when we pop then current goes out of scope
        let current = std::mem::replace(&mut self.current_entry, previous);

        let CallstackEntryWithAuxData {
            entry: _,
            current_history_record: history_of_current,
            parent_frame_index,
            frame_index,
            forward_queue,
            rollback_queue,
        } = current;

        let mut history_of_current = history_of_current;
        let mut rollback_queue = rollback_queue;

        // work with the rollback parts
        if panicked {
            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry
                .forward_queue
                .push(ExtendedLogQuery::FrameForwardTailMarker(frame_index));

            rollback_queue.push(ExtendedLogQuery::FrameRollbackHeadMarker(frame_index));

            let adjusted_rollbacks = rollback_queue.into_iter().rev().map(|mut el| {
                match &mut el {
                    ExtendedLogQuery::Query { mut marker, .. } => match &mut marker {
                        QueryMarker::Rollback {
                            cycle_of_applied_rollback,
                            ..
                        } => {
                            *cycle_of_applied_rollback = Some(monotonic_cycle_counter);
                        }
                        _ => {}
                    },
                    _ => {}
                }

                el
            });

            self.current_entry.forward_queue.extend(adjusted_rollbacks);

            // count adjustment
            let mut num_rollbacks = 0;

            for (_, el) in history_of_current.actions.iter() {
                match el {
                    LogAction::ForwardAndNotRolledBack { .. } => {
                        num_rollbacks += 1;
                    }
                    _ => {}
                }
            }

            for (_cycle, el) in history_of_current.actions.iter_mut() {
                let adjusted_el = match &*el {
                    LogAction::ForwardAndNotRolledBack {
                        forward_coutner,
                        rollback_counter,
                    } => {
                        // we enumerate rollback counter from the very end of the flattened queue
                        // and instead it should become an element from the forward queue
                        LogAction::ForwardAndRolledBack {
                            forward_counter: *forward_coutner,
                            renumerated_rollback_counter_as_forward: self.forward_flattened_counter
                                + *rollback_counter,
                        }
                    }
                    a @ LogAction::ForwardAndRolledBack { .. } => {
                        // it has become the element of the forward queue already
                        *a
                    }
                    a @ LogAction::ForwardNoRollback(..) => {
                        // never affected
                        *a
                    }
                };

                *el = adjusted_el;
            }

            // renumerate for future
            self.forward_flattened_counter += num_rollbacks;
            self.rollback_flattened_counter -= num_rollbacks;
            self.total_rolled_back += num_rollbacks;
        } else {
            // frame did end up ok, so we merge into parent's rollback

            // just glue
            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry
                .forward_queue
                .push(ExtendedLogQuery::FrameForwardTailMarker(frame_index));
            self.current_entry.rollback_queue.extend(rollback_queue);
            self.current_entry
                .rollback_queue
                .push(ExtendedLogQuery::FrameRollbackHeadMarker(frame_index));
        }

        // update the current history
        history_of_current.action =
            CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: panicked });
        history_of_current.end_cycle = Some(monotonic_cycle_counter);

        self.full_history.push(history_of_current);
        self.full_history.push(previous_history_record);

        current.entry
    }

    pub fn add_log_query(&mut self, monotonic_cycle_counter: u32, log_query: LogQuery) {
        let current_frame_index = self.current_entry.frame_index;
        let unique_query_id = self.unique_query_id_counter;
        self.unique_query_id_counter += 1;

        if log_query.rw_flag {
            // can be rolled back
            let query_index = self.rollbackable_monotonic_counter;
            self.rollbackable_monotonic_counter += 1;

            let marker = QueryMarker::Forward {
                unique_query_id,
                in_frame: current_frame_index,
                index: query_index,
                cycle: monotonic_cycle_counter,
            };
            let full_query = ExtendedLogQuery::Query {
                marker,
                cycle: monotonic_cycle_counter,
                query: log_query,
            };

            self.current_entry.forward_queue.push(full_query);

            let mut rollback_query = log_query;
            rollback_query.rollback = true;

            self.log_access_history
                .push((monotonic_cycle_counter, marker));

            let unique_query_id = self.unique_query_id_counter;
            self.unique_query_id_counter += 1;

            let marker = QueryMarker::Rollback {
                unique_query_id,
                in_frame: current_frame_index,
                index: query_index,
                cycle_of_declaration: monotonic_cycle_counter,
                cycle_of_applied_rollback: None,
            };
            let full_query = ExtendedLogQuery::Query {
                marker,
                cycle: monotonic_cycle_counter,
                query: rollback_query,
            };

            self.current_entry.rollback_queue.push(full_query);

            self.log_access_history
                .push((monotonic_cycle_counter, marker));

            let forward_flattened_counter = self.forward_flattened_counter;
            let rollback_flattened_counter = self.rollback_flattened_counter;

            self.forward_flattened_counter += 1;
            self.rollback_flattened_counter += 1;

            self.current_entry.current_history_record.actions.push((
                monotonic_cycle_counter,
                LogAction::ForwardAndNotRolledBack {
                    forward_coutner: forward_flattened_counter,
                    rollback_counter: rollback_flattened_counter,
                },
            ));

            // snapshot it
            self.log_queue_access_snapshots.push((
                monotonic_cycle_counter,
                RenumeratedQueryIndex::ForwardIndexAndRollbackIndex(query_index),
            ));
        } else {
            assert!(log_query.rollback == false);

            let query_index = self.non_rollbackable_monotonic_counter;
            self.non_rollbackable_monotonic_counter += 1;

            let forward_flattened_counter = self.forward_flattened_counter;
            self.forward_flattened_counter += 1;

            self.current_entry.current_history_record.actions.push((
                monotonic_cycle_counter,
                LogAction::ForwardNoRollback(forward_flattened_counter),
            ));

            // snapshot it
            self.log_queue_access_snapshots.push((
                monotonic_cycle_counter,
                RenumeratedQueryIndex::ForwardNoRollbackIndex(query_index),
            ));

            // just add
            let marker = QueryMarker::ForwardNoRollback {
                unique_query_id,
                in_frame: current_frame_index,
                index: query_index,
                cycle: monotonic_cycle_counter,
            };
            let full_query = ExtendedLogQuery::Query {
                marker,
                cycle: monotonic_cycle_counter,
                query: log_query,
            };

            self.current_entry.forward_queue.push(full_query);

            self.log_access_history
                .push((monotonic_cycle_counter, marker));
        }
    }
}
