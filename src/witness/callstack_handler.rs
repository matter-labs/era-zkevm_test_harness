use zk_evm::{vm_state::CallStackEntry, aux_structures::LogQuery};
use crate::witness::tracer::QueryMarker;
use std::ops::Range;

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
pub enum CallstackAction {
    PushToStack,
    OutOfScope{panic: bool},
    PopFromStack{panic: bool},
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallstackActionHistoryEntry {
    pub action: CallstackAction,
    pub affected_entry: CallStackEntry,
    pub cycle_index: u32,
    pub forward_queue_ranges_at_entry: Vec<Range<usize>>,
    pub rollback_queue_ranges_at_entry: Vec<Range<usize>>,
    pub forward_queue_ranges_changes: Vec<Range<usize>>,
    pub rollback_queue_ranges_change: Vec<Range<usize>>,
}

impl CallstackActionHistoryEntry {
    pub fn uninitialized() -> Self {
        Self {
            action: CallstackAction::PushToStack,
            affected_entry: CallStackEntry::empty_context(),
            cycle_index: 0,
            forward_queue_ranges_at_entry: vec![],
            rollback_queue_ranges_at_entry: vec![],
            forward_queue_ranges_changes: vec![],
            rollback_queue_ranges_change: vec![],
        }
    }
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
        }
    }

    pub fn from_initial_callstack(simple_entry: CallStackEntry) -> Self {
        let current_history_record = CallstackActionHistoryEntry {
            action: CallstackAction::PushToStack,
            affected_entry: simple_entry,
            cycle_index: 0,
            forward_queue_ranges_at_entry: vec![],
            rollback_queue_ranges_at_entry: vec![],
            forward_queue_ranges_changes: vec![],
            rollback_queue_ranges_change: vec![],
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
            forward_queue_ranges_at_entry: vec![],
            rollback_queue_ranges_at_entry: vec![],
            forward_queue_ranges_changes: vec![],
            rollback_queue_ranges_change: vec![],
        };

        Self {
            monotonic_frame_counter: 2,
            monotonic_forward_query_counter: 0,
            monotonic_rollback_query_counter: 0,
            current_entry: full_entry,
            depth: 1,
            stack: vec![],
            full_history: vec![previous_history_record]
        }
    }

    pub fn push_entry(&mut self, monotonic_cycle_counter: u32, previous_simple_entry: CallStackEntry, new_simple_entry: CallStackEntry) {
        // dbg!(&previous_simple_entry);
        // dbg!(&new_simple_entry);

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
                action: CallstackAction::OutOfScope { panic: false },
                affected_entry: new_simple_entry,
                cycle_index: monotonic_cycle_counter,
                forward_queue_ranges_at_entry: vec![],
                rollback_queue_ranges_at_entry: vec![],
                forward_queue_ranges_changes: vec![],
                rollback_queue_ranges_change: vec![],
            },
            parent_frame_index: current_frame_index,
            frame_index: new_counter,
            forward_queue: vec![],
            rollback_queue: vec![],
            forward_queue_ranges: vec![],
            rollback_queue_ranges: vec![], 
        };

        let mut current = std::mem::replace(&mut self.current_entry, full_entry);
        // update as we do not mutate between intermediate points
        current.entry = previous_simple_entry;
        current.current_history_record.affected_entry = previous_simple_entry;
        // and flatten the history that we already to have
        current.current_history_record.forward_queue_ranges_at_entry.extend(current.current_history_record.forward_queue_ranges_changes.drain(..));
        current.current_history_record.rollback_queue_ranges_at_entry.extend(current.current_history_record.rollback_queue_ranges_change.drain(..));

        let mut history_of_current = current.current_history_record.clone();
        history_of_current.action = CallstackAction::PushToStack;
        history_of_current.cycle_index = monotonic_cycle_counter;

        // dbg!(&current);
        // dbg!(&history_of_current);
        self.stack.push(current);
        self.full_history.push(history_of_current);
    }

    pub fn pop_entry(&mut self, monotonic_cycle_counter: u32, panicked: bool) -> CallStackEntry {
        let mut previous = self.stack.pop().unwrap();
        // dbg!(&previous);
        self.depth -= 1;

        let previous_history_record = &mut previous.current_history_record;
        let history_of_current = &self.current_entry.current_history_record;

        // now make a history record for previous by joining that properly

        if panicked {
            let mut in_scope_monotonic_forward_query_counter = self.monotonic_forward_query_counter;
            previous_history_record.forward_queue_ranges_changes.extend_from_slice(&history_of_current.forward_queue_ranges_changes);
            let it = history_of_current.rollback_queue_ranges_change.iter().cloned().rev().map(|el| {
                // we need to offset by the current counter and transform into the current counter + something
                let current = in_scope_monotonic_forward_query_counter;
                let num_entries = el.len();
                in_scope_monotonic_forward_query_counter += num_entries;

                current..(current+num_entries)
            });
            previous_history_record.forward_queue_ranges_changes.extend(it);
        } else {
            previous_history_record.forward_queue_ranges_changes.extend_from_slice(&history_of_current.forward_queue_ranges_changes);
            previous_history_record.rollback_queue_ranges_change.extend_from_slice(&history_of_current.forward_queue_ranges_changes);
        }

        let mut previous_history_record = previous.current_history_record.clone();
        previous_history_record.action = CallstackAction::PopFromStack { panic: panicked };

        // when we pop then current goes out of scope
        let current = std::mem::replace(&mut self.current_entry, previous);
        // dbg!(&current);
        // keep the history as is
        let mut history_of_current = current.current_history_record.clone();
        history_of_current.action = CallstackAction::OutOfScope { panic: panicked };

        history_of_current.cycle_index = monotonic_cycle_counter;
        previous_history_record.cycle_index = monotonic_cycle_counter;

        // dbg!(&history_of_current);
        // dbg!(&previous_history_record);

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
            self.current_entry.forward_queue_ranges.extend(forward_queue_ranges);

            self.current_entry.forward_queue.extend(rollback_queue.into_iter().rev()); // keep in mind proper composition

            // remap ranges of the rollback queue
            let it = rollback_queue_ranges.into_iter().rev().map(|el| {
                // we need to offset by the current counter and transform into the current counter + something
                let current = self.monotonic_forward_query_counter;
                let num_entries = el.len();
                self.monotonic_forward_query_counter += num_entries;

                current..(current+num_entries)
            });
            self.current_entry.forward_queue_ranges.extend(it)
        } else {
            // just glue

            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry.forward_queue_ranges.extend(forward_queue_ranges);

            self.current_entry.rollback_queue.extend(rollback_queue); 
            self.current_entry.rollback_queue_ranges.extend(rollback_queue_ranges); 
        }

        current.entry
    }

    pub fn add_log_query(&mut self, monotonic_cycle_counter: u32, mut log_query: LogQuery) {
        let forward_query_index = self.monotonic_forward_query_counter;
        self.monotonic_forward_query_counter += 1;
        if log_query.rw_flag {
            // can be rolled back
            let marker = QueryMarker::Forward(forward_query_index);
            self.current_entry.forward_queue.push((marker, monotonic_cycle_counter, log_query));
            if let Some(last) = self.current_entry.forward_queue_ranges.last_mut() {
                if last.end == forward_query_index {
                    last.end += 1;
                } else {
                    drop(last);
                    self.current_entry.forward_queue_ranges.push(forward_query_index..(forward_query_index+1));
                }
            } else {
                // just push
                self.current_entry.forward_queue_ranges.push(forward_query_index..(forward_query_index+1));
            }

            if let Some(entry) = self.current_entry.current_history_record.forward_queue_ranges_changes.last_mut() {
                debug_assert!(entry.end == forward_query_index);
                entry.end += 1;
            } else {
                self.current_entry.current_history_record.forward_queue_ranges_changes.push(forward_query_index..(forward_query_index+1));
            }

            let mut rollback_query = log_query;
            rollback_query.rollback = true;
            let rollback_query_index = self.monotonic_rollback_query_counter;
            self.monotonic_rollback_query_counter += 1;
            let marker = QueryMarker::Rollback(rollback_query_index);
            self.current_entry.rollback_queue.push((marker, monotonic_cycle_counter, rollback_query));
            if let Some(last) = self.current_entry.rollback_queue_ranges.last_mut() {
                if last.end == rollback_query_index {
                    last.end += 1;
                } else {
                    drop(last);
                    self.current_entry.rollback_queue_ranges.push(rollback_query_index..(rollback_query_index+1));
                }
            } else {
                // just push
                self.current_entry.rollback_queue_ranges.push(rollback_query_index..(rollback_query_index+1));
            }

            if let Some(entry) = self.current_entry.current_history_record.rollback_queue_ranges_change.last_mut() {
                debug_assert!(entry.end == rollback_query_index);
                entry.end += 1;
            } else {
                self.current_entry.current_history_record.rollback_queue_ranges_change.push(rollback_query_index..(rollback_query_index+1));
            }
        } else {
            // just add
            let marker = QueryMarker::Forward(forward_query_index);
            self.current_entry.forward_queue.push((marker, monotonic_cycle_counter, log_query));
            if let Some(last) = self.current_entry.forward_queue_ranges.last_mut() {
                if last.end == forward_query_index {
                    last.end += 1;
                } else {
                    drop(last);
                    self.current_entry.forward_queue_ranges.push(forward_query_index..(forward_query_index+1));
                }
            } else {
                // just push
                self.current_entry.forward_queue_ranges.push(forward_query_index..(forward_query_index+1));
            }

            if let Some(entry) = self.current_entry.current_history_record.forward_queue_ranges_changes.last_mut() {
                debug_assert!(entry.end == forward_query_index);
                entry.end += 1;
            } else {
                self.current_entry.current_history_record.forward_queue_ranges_changes.push(forward_query_index..(forward_query_index+1));
            }
        }
    }
}