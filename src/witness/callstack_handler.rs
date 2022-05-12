use crate::witness::tracer::QueryMarker;
use std::ops::Range;
use zk_evm::{aux_structures::LogQuery, vm_state::CallStackEntry};

use super::*;

#[derive(Clone, Debug)]
pub struct CallstackEntryWithAuxData {
    pub entry: CallStackEntry,
    pub current_history_record: CallstackActionHistoryEntry,
    pub frame_index: usize,
    pub parent_frame_index: usize,
    pub forward_queue: Vec<(QueryMarker, u32, LogQuery)>,
    pub rollback_queue: Vec<(QueryMarker, u32, LogQuery)>,
    pub forward_queue_ranges: Vec<Range<usize>>,
    pub rollback_queue_ranges: Vec<Range<usize>>, // we enumerate from 0 as the tail for the queue
}

impl CallstackEntryWithAuxData {
    pub fn empty() -> Self {
        Self {
            entry: CallStackEntry::empty_context(),
            current_history_record: CallstackActionHistoryEntry::uninitialized(),
            frame_index: 0,
            parent_frame_index: 0,
            forward_queue: vec![],
            rollback_queue: vec![],
            forward_queue_ranges: vec![],
            rollback_queue_ranges: vec![],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutOfScopeReason {
    Fresh,
    Exited{ panic: bool },
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
    pub cycle_index: u32,
    pub monotonic_forward_query_counter_on_first_entry: usize,
    pub monotonic_forward_query_counter_on_exit: Option<usize>,
    pub monotonic_rollback_query_counter_on_first_entry: usize,
    pub monotonic_rollback_query_counter_on_exit: Option<usize>,
    pub forward_queue_ranges_at_entry: Range<usize>,
    pub forward_queue_ranges_changes: Range<usize>,
    pub rollback_queue_ranges_change: Range<usize>,
    pub rollback_queue_ranges_at_entry: Range<usize>,
}

impl CallstackActionHistoryEntry {
    pub fn uninitialized() -> Self {
        Self {
            action: CallstackAction::PushToStack,
            affected_entry: CallStackEntry::empty_context(),
            cycle_index: 0,
            monotonic_forward_query_counter_on_first_entry: 0,
            monotonic_forward_query_counter_on_exit: None,
            monotonic_rollback_query_counter_on_first_entry: 0,
            monotonic_rollback_query_counter_on_exit: None,
            forward_queue_ranges_at_entry: 0..0,
            rollback_queue_ranges_at_entry: 0..0,
            forward_queue_ranges_changes: 0..0,
            rollback_queue_ranges_change: 0..0,
        }
    }

    pub fn total_forward_segment_length_on_pop(&self) -> usize {
        self.forward_queue_ranges_changes.end
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LogQueueAccessAuxData {
    pub monotonic_forward_query_counter: usize,
    pub monotonic_rollback_query_counter: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct CallstackWithAuxData {
    pub monotonic_frame_counter: usize,
    pub monotonic_forward_query_counter: usize,
    pub monotonic_rollback_query_counter: usize,
    pub current_entry: CallstackEntryWithAuxData,
    pub depth: usize,
    pub stack: Vec<CallstackEntryWithAuxData>,
    pub full_history: Vec<CallstackActionHistoryEntry>,
    pub log_queue_access_snapshots: Vec<(u32, LogQueueAccessAuxData)>,
}

impl CallstackWithAuxData {
    pub fn empty() -> Self {
        Self {
            monotonic_frame_counter: 1,
            monotonic_forward_query_counter: 0,
            monotonic_rollback_query_counter: 0,
            current_entry: CallstackEntryWithAuxData::empty(),
            depth: 0,
            stack: vec![],
            full_history: vec![],
            log_queue_access_snapshots: vec![],
        }
    }

    pub fn from_initial_callstack(simple_entry: CallStackEntry) -> Self {
        let current_history_record = CallstackActionHistoryEntry {
            action: CallstackAction::OutOfScope(OutOfScopeReason::Fresh),
            affected_entry: simple_entry,
            cycle_index: 0,
            forward_queue_ranges_at_entry: 0..0,
            rollback_queue_ranges_at_entry: 0..0,
            forward_queue_ranges_changes: 0..0,
            rollback_queue_ranges_change: 0..0,
            monotonic_forward_query_counter_on_first_entry: 0,
            monotonic_forward_query_counter_on_exit: None,
            monotonic_rollback_query_counter_on_first_entry: 0,
            monotonic_rollback_query_counter_on_exit: None,
        };

        let full_entry = CallstackEntryWithAuxData {
            entry: simple_entry,
            current_history_record,
            parent_frame_index: 0,
            frame_index: 1,
            forward_queue: vec![],
            rollback_queue: vec![],
            forward_queue_ranges: vec![],
            rollback_queue_ranges: vec![],
        };

        let previous_history_record = CallstackActionHistoryEntry {
            action: CallstackAction::PushToStack,
            affected_entry: CallStackEntry::empty_context(),
            cycle_index: 0,
            forward_queue_ranges_at_entry: 0..0,
            rollback_queue_ranges_at_entry: 0..0,
            forward_queue_ranges_changes: 0..0,
            rollback_queue_ranges_change: 0..0,
            monotonic_forward_query_counter_on_first_entry: 0,
            monotonic_forward_query_counter_on_exit: None,
            monotonic_rollback_query_counter_on_first_entry: 0,
            monotonic_rollback_query_counter_on_exit: None,
        };

        Self {
            monotonic_frame_counter: 2,
            monotonic_forward_query_counter: 0,
            monotonic_rollback_query_counter: 0,
            current_entry: full_entry,
            depth: 1,
            stack: vec![],
            full_history: vec![previous_history_record],
            log_queue_access_snapshots: vec![],
        }
    }

    pub fn push_entry(
        &mut self,
        monotonic_cycle_counter: u32,
        previous_simple_entry: CallStackEntry,
        new_simple_entry: CallStackEntry,
    ) {
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
                cycle_index: monotonic_cycle_counter,
                forward_queue_ranges_at_entry: self.monotonic_forward_query_counter..self.monotonic_forward_query_counter,
                rollback_queue_ranges_at_entry: self.monotonic_rollback_query_counter..self.monotonic_rollback_query_counter,
                forward_queue_ranges_changes: self.monotonic_forward_query_counter..self.monotonic_forward_query_counter,
                rollback_queue_ranges_change: self.monotonic_rollback_query_counter..self.monotonic_rollback_query_counter,
                monotonic_forward_query_counter_on_first_entry: self.monotonic_forward_query_counter,
                monotonic_forward_query_counter_on_exit: None,
                monotonic_rollback_query_counter_on_first_entry: self.monotonic_rollback_query_counter,
                monotonic_rollback_query_counter_on_exit: None,
            },
            parent_frame_index: current_frame_index,
            frame_index: new_counter,
            forward_queue: vec![],
            rollback_queue: vec![],
            forward_queue_ranges: vec![],
            rollback_queue_ranges: vec![],
        };

        let history_of_new = full_entry.current_history_record.clone();

        let mut current = std::mem::replace(&mut self.current_entry, full_entry);
        // update as we do not mutate between intermediate points
        current.entry = previous_simple_entry;
        current.current_history_record.affected_entry = previous_simple_entry;
        // and flatten the history that we already to have

        assert_eq!(current.current_history_record.forward_queue_ranges_at_entry.end,
            current.current_history_record.forward_queue_ranges_changes.start
        );

        current.current_history_record.forward_queue_ranges_at_entry.end = current.current_history_record.forward_queue_ranges_changes.end;
        current.current_history_record.forward_queue_ranges_changes.start = current.current_history_record.forward_queue_ranges_changes.end;

        assert_eq!(current.current_history_record.rollback_queue_ranges_at_entry.end,
            current.current_history_record.rollback_queue_ranges_change.start
        );

        current.current_history_record.rollback_queue_ranges_at_entry.end = current.current_history_record.rollback_queue_ranges_change.end;
        current.current_history_record.rollback_queue_ranges_change.start = current.current_history_record.rollback_queue_ranges_change.end;

        let mut history_of_current = current.current_history_record.clone();
        history_of_current.action = CallstackAction::PushToStack;
        history_of_current.cycle_index = monotonic_cycle_counter;

        self.stack.push(current);
        self.full_history.push(history_of_current);
        self.full_history.push(history_of_new);
    }

    pub fn pop_entry(&mut self, monotonic_cycle_counter: u32, panicked: bool) -> CallStackEntry {
        let mut previous = self.stack.pop().unwrap();
        self.depth -= 1;

        let previous_history_record = &mut previous.current_history_record;
        let history_of_current = &self.current_entry.current_history_record;

        // now make a history record for previous by joining that properly

        if panicked {
            // glue the forward
            let mut full_history_of_changes = history_of_current.forward_queue_ranges_at_entry.clone();
            assert_eq!(full_history_of_changes.end, history_of_current.forward_queue_ranges_changes.start);
            full_history_of_changes.end = history_of_current.forward_queue_ranges_changes.end;
            // now glue the rollback
            full_history_of_changes.end += history_of_current.rollback_queue_ranges_change.len();

            previous_history_record.forward_queue_ranges_changes = full_history_of_changes;
        } else {
            let mut full_history_of_changes = history_of_current.forward_queue_ranges_at_entry.clone();
            assert_eq!(full_history_of_changes.end, history_of_current.forward_queue_ranges_changes.start);
            full_history_of_changes.end = history_of_current.forward_queue_ranges_changes.end;

            previous_history_record.forward_queue_ranges_changes = full_history_of_changes;

            let mut full_history_of_changes = history_of_current.rollback_queue_ranges_at_entry.clone();
            assert_eq!(full_history_of_changes.end, history_of_current.rollback_queue_ranges_change.start);
            full_history_of_changes.end = history_of_current.rollback_queue_ranges_change.end;

            previous_history_record.rollback_queue_ranges_change = full_history_of_changes; // ?
        }

        let mut previous_history_record = previous.current_history_record.clone();
        previous_history_record.action = CallstackAction::PopFromStack { panic: panicked };

        // when we pop then current goes out of scope
        let current = std::mem::replace(&mut self.current_entry, previous);
        // keep the history as is
        let mut history_of_current = current.current_history_record.clone();
        history_of_current.monotonic_forward_query_counter_on_exit = Some(self.monotonic_forward_query_counter);
        history_of_current.monotonic_rollback_query_counter_on_exit = Some(self.monotonic_rollback_query_counter);
        history_of_current.action = CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: panicked } );

        history_of_current.cycle_index = monotonic_cycle_counter;
        previous_history_record.cycle_index = monotonic_cycle_counter;

        self.full_history.push(history_of_current);
        self.full_history.push(previous_history_record);

        let CallstackEntryWithAuxData {
            entry: _,
            current_history_record: _,
            parent_frame_index: _,
            frame_index: _,
            forward_queue,
            rollback_queue,
            forward_queue_ranges,
            rollback_queue_ranges,
        } = current;

        // merge the queues
        if panicked {
            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry
                .forward_queue_ranges
                .extend(forward_queue_ranges);

            self.current_entry
                .forward_queue
                .extend(rollback_queue.into_iter().rev()); // keep in mind proper composition

            // remap ranges of the rollback queue
            let it = rollback_queue_ranges.into_iter().rev().map(|el| {
                // we need to offset by the current counter and transform into the current counter + something
                let current = self.monotonic_forward_query_counter;
                let num_entries = el.len();
                self.monotonic_forward_query_counter += num_entries;

                current..(current + num_entries)
            });
            self.current_entry.forward_queue_ranges.extend(it)
        } else {
            // just glue

            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry
                .forward_queue_ranges
                .extend(forward_queue_ranges);

            self.current_entry.rollback_queue.extend(rollback_queue);
            self.current_entry
                .rollback_queue_ranges
                .extend(rollback_queue_ranges);
        }

        current.entry
    }

    pub fn add_log_query(&mut self, monotonic_cycle_counter: u32, log_query: LogQuery) {
        let forward_query_index = self.monotonic_forward_query_counter;
        self.monotonic_forward_query_counter += 1;
        if log_query.rw_flag {
            // can be rolled back

            let marker = QueryMarker::Forward(forward_query_index);
            self.current_entry
                .forward_queue
                .push((marker, monotonic_cycle_counter, log_query));
                
            if let Some(last) = self.current_entry.forward_queue_ranges.last_mut() {
                if last.end == forward_query_index {
                    last.end += 1;
                } else {
                    drop(last);
                    self.current_entry
                        .forward_queue_ranges
                        .push(forward_query_index..(forward_query_index + 1));
                }
            } else {
                // just push
                self.current_entry
                    .forward_queue_ranges
                    .push(forward_query_index..(forward_query_index + 1));
            }

            self
                .current_entry
                .current_history_record
                .forward_queue_ranges_changes.end += 1;

            let mut rollback_query = log_query;
            rollback_query.rollback = true;
            let rollback_query_index = self.monotonic_rollback_query_counter;
            self.monotonic_rollback_query_counter += 1;
            let marker = QueryMarker::Rollback(rollback_query_index);
            self.current_entry.rollback_queue.push((
                marker,
                monotonic_cycle_counter,
                rollback_query,
            ));
            if let Some(last) = self.current_entry.rollback_queue_ranges.last_mut() {
                if last.end == rollback_query_index {
                    last.end += 1;
                } else {
                    drop(last);
                    self.current_entry
                        .rollback_queue_ranges
                        .push(rollback_query_index..(rollback_query_index + 1));
                }
            } else {
                // just push
                self.current_entry
                    .rollback_queue_ranges
                    .push(rollback_query_index..(rollback_query_index + 1));
            }

            self
                .current_entry
                .current_history_record
                .rollback_queue_ranges_change.end += 1;

            // snapshot it
            self.log_queue_access_snapshots.push((monotonic_cycle_counter, LogQueueAccessAuxData {
                monotonic_forward_query_counter: forward_query_index,
                monotonic_rollback_query_counter: Some(rollback_query_index)
            }));
        } else {
            // snapshot it
            self.log_queue_access_snapshots.push((monotonic_cycle_counter, LogQueueAccessAuxData {
                monotonic_forward_query_counter: forward_query_index,
                monotonic_rollback_query_counter: None,
            }));

            // just add
            let marker = QueryMarker::Forward(forward_query_index);
            self.current_entry
                .forward_queue
                .push((marker, monotonic_cycle_counter, log_query));
            if let Some(last) = self.current_entry.forward_queue_ranges.last_mut() {
                if last.end == forward_query_index {
                    last.end += 1;
                } else {
                    drop(last);
                    self.current_entry
                        .forward_queue_ranges
                        .push(forward_query_index..(forward_query_index + 1));
                }
            } else {
                // just push
                self.current_entry
                    .forward_queue_ranges
                    .push(forward_query_index..(forward_query_index + 1));
            }

            self
                .current_entry
                .current_history_record
                .forward_queue_ranges_changes.end += 1;
        }
    }
}
