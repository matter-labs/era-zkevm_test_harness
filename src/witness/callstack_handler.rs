use std::{collections::HashMap};

use crate::witness::tracer::QueryMarker;
use zk_evm::{aux_structures::LogQuery, vm_state::CallStackEntry};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RenumeratedQueryIndex {
    ForwardIndexAndRollbackIndex(usize),
    ForwardNoRollbackIndex(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LogAction {
    ForwardAndRolledBack {forward_counter: usize, renumerated_rollback_counter_as_forward: usize},
    ForwardAndNotRolledBack {forward_coutner: usize, rollback_counter: usize},
    ForwardNoRollback(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtendedLogQuery {
    Query{marker: QueryMarker, cycle: u32, query: LogQuery},
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
    IntoRollbackHead
}

// special cases: if we merge (potentially empty) segment of the current frame
// to the empty segment of the parent frame, then we need somewhat immutable reference
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueueSegmentIndirectablePointer {
    ForwardHeadAtFrameStart(usize),
    RollbackTailAtFrameStart(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueueSegmentPointer {
    GlobalStart,
    GlobalEnd,
    IssuedQuery{rw_flag: bool, rollback: bool, idx: u64, is_head: bool},
    Indirection(QueueSegmentIndirectablePointer),
    // OtherFrameIndirection(QueueSegmentIndirectablePointer),
    OtherFramesQuery{rw_flag: bool, rollback: bool, idx: u64, is_head: bool},
    Dangling
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameSegmentData {
    pub forward_head_pointer: QueueSegmentPointer,
    pub forward_tail_pointer: QueueSegmentPointer,
    pub forward_segment_length: usize,
    pub rollback_head_pointer: QueueSegmentPointer,
    pub rollback_tail_pointer: QueueSegmentPointer,
    pub rollback_segment_length: usize,
    pub did_end_up_in_panic: bool,
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
    pub frame_segments_data: HashMap<usize, FrameSegmentData>,
    pub child_into_parent: HashMap<usize, usize>,
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

        let mut new = Self {
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
            frame_segments_data: HashMap::new(),
            child_into_parent: HashMap::new(),
        };

        new.frame_segments_data.insert(
            0, 
            FrameSegmentData {
                forward_head_pointer: QueueSegmentPointer::GlobalStart,
                forward_tail_pointer: QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::ForwardHeadAtFrameStart(0)),
                forward_segment_length: 0,
                rollback_head_pointer: QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::RollbackTailAtFrameStart(0)),
                rollback_tail_pointer: QueueSegmentPointer::GlobalEnd,
                rollback_segment_length: 0,
                did_end_up_in_panic: false,
            }
        );

        new
    }

    pub fn from_initial_callstack(monotonic_cycle_counter: u32, simple_entry: CallStackEntry) -> Self {
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
        let new_counter = self.monotonic_frame_counter;
        self.monotonic_frame_counter += 1;
        self.depth += 1;

        // when we push a new entry we put the previous "current" into the stack,
        // and intoduce a new one, for which we do not add history action as it may be unnecessary

        // we only care about the history of the stack top, so we push previous entry

        let current_frame_index = self.current_entry.frame_index;
        let current_frame_segment_data = self.frame_segments_data[&current_frame_index];

        // NOTE: those are SEGMENTS, so head/tail of "forward" are NOT from global start to something. Those are only history of this frame

        // we continue from the current tail in any case, and we ensure that we if point to the tail then indeed to the tail
        let this_frame_forward_head_pointer = match current_frame_segment_data.forward_tail_pointer {
            QueueSegmentPointer::GlobalStart => unreachable!(),
            QueueSegmentPointer::GlobalEnd => unreachable!(),
            QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head} => {
                assert!(!is_head);
                QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
            },
            // QueueSegmentPointer::Indirection(ind) => QueueSegmentPointer::OtherFrameIndirection(ind),
            a @ QueueSegmentPointer::Indirection(..) => a,
            a @ QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head} => {
                assert!(!is_head);
                QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
            },
            QueueSegmentPointer::Dangling => unreachable!()
        };

        // forward tail and rollback head are yet indirections
        self.frame_segments_data.insert(
            new_counter, 
            FrameSegmentData {
                forward_head_pointer: this_frame_forward_head_pointer,
                forward_tail_pointer: QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::ForwardHeadAtFrameStart(new_counter)),
                forward_segment_length: 0,
                rollback_head_pointer: QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::RollbackTailAtFrameStart(new_counter)),
                rollback_tail_pointer: QueueSegmentPointer::Dangling,
                rollback_segment_length: 0,
                did_end_up_in_panic: false,
            }
        );

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
        let mut parent_segment_data = self.frame_segments_data.get(&parent_frame_index).copied().unwrap();
        let mut current_frame_record = self.frame_segments_data.get(&frame_index).copied().unwrap();

        // NOTE: those are SEGMENTS, so head/tail of "forward" are NOT from global start to something. Those are only history of this frame 

        // we only need to distinguish situations when the target of merging is empty (100% indirected) or not
        // it can be only indirection or issued query, or whatever comes from our resolver

        // we basically carry the current frame's forward tail into the history of the parent (since parent is supersegment)
        let new_parent_forward_tail = match current_frame_record.forward_tail_pointer {
            QueueSegmentPointer::GlobalStart => unreachable!(),
            QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head} => {
                assert!(!is_head);
                QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
            },
            QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::ForwardHeadAtFrameStart(f)) => {
                // it's an empty frame, even no reads!
                assert_eq!(f, frame_index);
                // resolve the indirection
                let resolved = match current_frame_record.forward_head_pointer {
                    QueueSegmentPointer::Indirection(ind) => {
                        // we chain
                        QueueSegmentPointer::Indirection(ind)
                    },
                    QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head} => {
                        assert!(!is_head);
                        QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
                    },
                    a @ _ => unreachable!("encountered {:?}", a)
                };

                resolved
            },
            a @ QueueSegmentPointer::Indirection(..) => a,
            QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head} => {
                assert!(!is_head);
                QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
            },
            a @ _ => QueueSegmentPointer::Dangling
        };

        if let QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::ForwardHeadAtFrameStart(f)) = current_frame_record.forward_tail_pointer {
            // quick indirection resolution if it's empty frame
            assert_eq!(f, frame_index);
            current_frame_record.forward_tail_pointer = current_frame_record.forward_head_pointer
        }

        // update the parent
        parent_segment_data.forward_tail_pointer = new_parent_forward_tail;
        parent_segment_data.forward_segment_length += current_frame_record.forward_segment_length;

        // work with the rollback parts
        if panicked {
            current_frame_record.did_end_up_in_panic = true;

            // first we resolve a head of the rollback of the current frame
            let new_rollback_head = match current_frame_record.rollback_head_pointer {
                QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head} => {
                    // if we are pointing to the query of this frame then we point to the head
                    assert!(is_head);
                    QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head}
                },
                QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::RollbackTailAtFrameStart(f)) => {
                    // it means that we are appending an empty frame, or a frame where only reads have happened
                    // since forward queue is done (glued to the parent trivially), we can use it's information
                    assert_eq!(f, frame_index);
                    // we just use affinity to the parent's forward, it no longer matters what was an indirection
                    match parent_segment_data.forward_tail_pointer {
                        QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head} => {
                            // if we are pointing to the query of this frame then we point to the head
                            assert!(!is_head);
                            QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
                        },
                        QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head} => {
                            // if we are pointing to the query of this frame then we point to the head
                            assert!(!is_head);
                            QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head}
                        },

                        _ => QueueSegmentPointer::Dangling
                    }
                },
                _ => unreachable!(),
            };

            // we resolved rollback head of the current frame, and since we panicked we can now adjust the tail
            current_frame_record.rollback_head_pointer = new_rollback_head;

            // if the tail is dangling then we had an empty frame
            if current_frame_record.rollback_tail_pointer == QueueSegmentPointer::Dangling {
                // it was a trivial frame that was rolled back, and we should just make it of length 0, where head == tail == parent's tail
                current_frame_record.rollback_tail_pointer = current_frame_record.rollback_head_pointer;
            } else {
                // otherwise we have an explicit one
                assert!(matches!(current_frame_record.rollback_tail_pointer, QueueSegmentPointer::IssuedQuery{..}));
            }

            // very important! Since we did merge, we should also update parent's pointers
            parent_segment_data.forward_tail_pointer = current_frame_record.rollback_tail_pointer;
            parent_segment_data.forward_segment_length += current_frame_record.rollback_segment_length;

            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry.forward_queue.push(ExtendedLogQuery::FrameForwardTailMarker(frame_index));

            rollback_queue.push(ExtendedLogQuery::FrameRollbackHeadMarker(frame_index));

            let adjusted_rollbacks = rollback_queue.into_iter().rev().map(|mut el| {
                match &mut el {
                    ExtendedLogQuery::Query { mut marker, .. } => {
                        match &mut marker {
                            QueryMarker::Rollback { cycle_of_applied_rollback, .. } => {
                                *cycle_of_applied_rollback = Some(monotonic_cycle_counter);
                            },
                            _ => {}
                        }
                    },
                    _ => {}
                }

                el
            });

            self.current_entry
                .forward_queue
                .extend(adjusted_rollbacks);

            // count adjustment
            let mut num_rollbacks = 0;

            for (_, el) in history_of_current.actions.iter() {
                match el {
                    LogAction::ForwardAndNotRolledBack { .. } => {
                        num_rollbacks += 1;
                    },
                    _ => {}
                }
            }

            for (_cycle, el) in history_of_current.actions.iter_mut() {
                let adjusted_el = match &*el {
                    LogAction::ForwardAndNotRolledBack { forward_coutner, rollback_counter } => {
                        // we enumerate rollback counter from the very end of the flattened queue
                        // and instead it should become an element from the forward queue
                        LogAction::ForwardAndRolledBack { 
                            forward_counter: *forward_coutner, 
                            renumerated_rollback_counter_as_forward: self.forward_flattened_counter + *rollback_counter
                        }
                    },
                    a @ LogAction::ForwardAndRolledBack { .. } => {
                        // it has become the element of the forward queue already
                        *a
                    },
                    a @ LogAction::ForwardNoRollback (..) => {
                        // never affected
                        *a
                    },
                };

                *el = adjusted_el;
            }

            // renumerate for future
            self.forward_flattened_counter += num_rollbacks;
            self.rollback_flattened_counter -= num_rollbacks;
            self.total_rolled_back += num_rollbacks;
        } else {
            // frame did end up ok, so we merge into parent's rollback

            if current_frame_record.rollback_tail_pointer == QueueSegmentPointer::Dangling {
                // it means we either did read only, or frame is empty in general
                let new_rollback_tail = match parent_segment_data.rollback_head_pointer {
                    QueueSegmentPointer::GlobalEnd => QueueSegmentPointer::GlobalEnd,
                    QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head} => {
                        // there were rollbacks in parent, and we can use it
                        assert!(is_head);
                        QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head: true}
                    },
                    QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head} => {
                        // transitive pointing
                        assert!(is_head);
                        QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head: true}
                    },
                    QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::RollbackTailAtFrameStart(f)) => {
                        assert_eq!(f, parent_frame_index);
                        // parent's head point to tail (so parent is either yet empty or readonly),
                        // so we try to resolve it
                        match parent_segment_data.rollback_tail_pointer {
                            QueueSegmentPointer::GlobalEnd => QueueSegmentPointer::GlobalEnd,
                            QueueSegmentPointer::Dangling => {
                                // parent's tail is yet dangling, but we point to it anyway
                                QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::RollbackTailAtFrameStart(parent_frame_index))
                            },
                            QueueSegmentPointer::IssuedQuery{rw_flag, rollback, idx, is_head} => {
                                assert!(!is_head);
                                QueueSegmentPointer::OtherFramesQuery{rw_flag, rollback, idx, is_head: true}
                            },
                            a @ _ => unreachable!("encountered {:?}", a),
                        }  
                    },
                    a @ _ => unreachable!("encountered {:?}", a),
                };

                current_frame_record.rollback_tail_pointer = new_rollback_tail;
            } else {
                assert!(matches!(current_frame_record.rollback_tail_pointer, QueueSegmentPointer::IssuedQuery{..}));
            }

            // increase parent's rollback length
            parent_segment_data.rollback_segment_length += current_frame_record.rollback_segment_length;

            if let QueueSegmentPointer::Indirection(QueueSegmentIndirectablePointer::RollbackTailAtFrameStart(f)) = current_frame_record.rollback_head_pointer {
                // trivial frame, resolve indirection
                assert_eq!(f, frame_index);
                current_frame_record.rollback_head_pointer = current_frame_record.rollback_tail_pointer;
            } else {
                assert!(matches!(current_frame_record.rollback_head_pointer, QueueSegmentPointer::IssuedQuery{..}));
            }

            // just glue
            self.current_entry.forward_queue.extend(forward_queue);
            self.current_entry.forward_queue.push(ExtendedLogQuery::FrameForwardTailMarker(frame_index));
            self.current_entry.rollback_queue.extend(rollback_queue);
            self.current_entry.rollback_queue.push(ExtendedLogQuery::FrameRollbackHeadMarker(frame_index));
        }

        let _ = self.frame_segments_data.insert(parent_frame_index, parent_segment_data);
        let _ = self.frame_segments_data.insert(frame_index, current_frame_record);

        // update the current history
        history_of_current.action = CallstackAction::OutOfScope(OutOfScopeReason::Exited { panic: panicked } );
        history_of_current.end_cycle = Some(monotonic_cycle_counter);

        self.full_history.push(history_of_current);
        self.full_history.push(previous_history_record);

        current.entry
    }

    pub fn add_log_query(&mut self, monotonic_cycle_counter: u32, log_query: LogQuery) {
        let current_frame_index = self.current_entry.frame_index;
        let unique_query_id = self.unique_query_id_counter;
        self.unique_query_id_counter += 1;

        let mut current_frame_record = self.frame_segments_data.get_mut(&current_frame_index).unwrap();

        if log_query.rw_flag {
            // can be rolled back
            let query_index = self.rollbackable_monotonic_counter;
            self.rollbackable_monotonic_counter += 1;

            let marker = QueryMarker::Forward {unique_query_id, in_frame: current_frame_index, index: query_index, cycle: monotonic_cycle_counter};

            current_frame_record.forward_tail_pointer = QueueSegmentPointer::IssuedQuery{rw_flag: true, rollback: false, idx: marker.query_id(), is_head: false};
            if matches!(current_frame_record.forward_head_pointer, QueueSegmentPointer::Indirection(..)) {
                // remove indirection immediatelly for simplicity
                current_frame_record.forward_head_pointer = QueueSegmentPointer::IssuedQuery{rw_flag: true, rollback: false, idx: marker.query_id(), is_head: true};
            }
            current_frame_record.forward_segment_length += 1;

            let full_query = ExtendedLogQuery::Query { marker, cycle: monotonic_cycle_counter, query: log_query };

            self.current_entry
                .forward_queue
                .push(full_query);

            let mut rollback_query = log_query;
            rollback_query.rollback = true;

            self.log_access_history.push((monotonic_cycle_counter, marker));

            let unique_query_id = self.unique_query_id_counter;
            self.unique_query_id_counter += 1;

            let marker = QueryMarker::Rollback {unique_query_id, in_frame: current_frame_index, index: query_index, cycle_of_declaration: monotonic_cycle_counter, cycle_of_applied_rollback: None};

            current_frame_record.rollback_head_pointer = QueueSegmentPointer::IssuedQuery{rw_flag: true, rollback: true, idx: marker.query_id(), is_head: true};
            if current_frame_record.rollback_tail_pointer == QueueSegmentPointer::Dangling {
                // we can make it non-dangling and point to explicit query
                current_frame_record.rollback_tail_pointer = QueueSegmentPointer::IssuedQuery{rw_flag: true, rollback: true, idx: marker.query_id(), is_head: false};
            }
            current_frame_record.rollback_segment_length += 1;

            let full_query = ExtendedLogQuery::Query { marker, cycle: monotonic_cycle_counter, query: rollback_query };

            self.current_entry.rollback_queue.push(full_query);

            self.log_access_history.push((monotonic_cycle_counter, marker));

            let forward_flattened_counter = self.forward_flattened_counter;
            let rollback_flattened_counter = self.rollback_flattened_counter;

            self.forward_flattened_counter += 1;
            self.rollback_flattened_counter += 1;

            self.current_entry.current_history_record.actions.push(
                (
                    monotonic_cycle_counter, 
                    LogAction::ForwardAndNotRolledBack { forward_coutner: forward_flattened_counter, rollback_counter: rollback_flattened_counter }
                )
            );

            // snapshot it
            self.log_queue_access_snapshots.push(
                (
                    monotonic_cycle_counter, 
                    RenumeratedQueryIndex::ForwardIndexAndRollbackIndex(
                        query_index
                    )
                )
            );
        } else {
            assert!(log_query.rollback == false);

            let query_index = self.non_rollbackable_monotonic_counter;
            self.non_rollbackable_monotonic_counter += 1;

            let forward_flattened_counter = self.forward_flattened_counter;
            self.forward_flattened_counter += 1;

            self.current_entry.current_history_record.actions.push(
                (
                    monotonic_cycle_counter, 
                    LogAction::ForwardNoRollback(forward_flattened_counter)
                )
            );

            // snapshot it
            self.log_queue_access_snapshots.push(
                (
                    monotonic_cycle_counter, 
                    RenumeratedQueryIndex::ForwardNoRollbackIndex(query_index)
                )
            );

            // just add
            let marker = QueryMarker::ForwardNoRollback{unique_query_id, in_frame: current_frame_index, index: query_index, cycle: monotonic_cycle_counter};

            current_frame_record.forward_tail_pointer = QueueSegmentPointer::IssuedQuery{rw_flag: false, rollback: false, idx: marker.query_id(), is_head: false};
            if matches!(current_frame_record.forward_head_pointer, QueueSegmentPointer::Indirection(..)) {
                // remove indirection immediatelly for simplicity
                current_frame_record.forward_head_pointer = QueueSegmentPointer::IssuedQuery{rw_flag: false, rollback: false, idx: marker.query_id(), is_head: true};
            }
            current_frame_record.forward_segment_length += 1;

            let full_query = ExtendedLogQuery::Query { marker, cycle: monotonic_cycle_counter, query: log_query };

            self.current_entry
                .forward_queue
                .push(full_query);

            self.log_access_history.push((monotonic_cycle_counter, marker));
        }
    }
}
