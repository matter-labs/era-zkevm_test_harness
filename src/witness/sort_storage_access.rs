use crate::encodings::log_query::*;
use zk_evm::aux_structures::LogQuery;
use std::cmp::Ordering;
use rayon::prelude::*;

use crate::ethereum_types::U256;

#[derive(Default, Debug)]
pub struct StorageSlotHistoryKeeper {
    pub initial_value: Option<U256>,
    pub current_value: Option<U256>,
    pub changes_stack: Vec<LogQueryWithExtendedEnumeration>,
    pub did_read_at_depth_zero: bool,
}

pub fn sort_storage_access_queries(unsorted_storage_queries: &[LogQuery]) -> (Vec<LogQueryWithExtendedEnumeration>, Vec<LogQuery>) {
    let mut sorted_storage_queries_with_extra_timestamp: Vec<_> = unsorted_storage_queries.iter()
        .enumerate().map(|(i, el)| {
            LogQueryWithExtendedEnumeration {
                raw_query: *el,
                extended_timestamp: i as u32
            }
    }).collect();

    sorted_storage_queries_with_extra_timestamp.par_sort_by(|a, b| {
        match a.raw_query.shard_id.cmp(&a.raw_query.shard_id) {
            Ordering::Equal => {
                match a.raw_query.address.cmp(&b.raw_query.address) {
                    Ordering::Equal => {
                        match a.raw_query.key.cmp(&b.raw_query.key) {
                            Ordering::Equal => {
                                a.extended_timestamp.cmp(&b.extended_timestamp)
                            },
                            r @ _ => r
                        }
                    },
                    r @ _ => r
                }
            }
            r @ _ => r
        }
    });

    let mut deduplicated_storage_queries = vec![];

    // now just implement the logic to sort and deduplicate
    let mut it = sorted_storage_queries_with_extra_timestamp.iter().peekable();

    loop {
        if it.peek().is_none() {
            break;
        }

        let candidate = it.peek().unwrap().clone();

        let subit = it.clone().take_while(|el| {
            el.raw_query.shard_id == candidate.raw_query.shard_id &&
            el.raw_query.address == candidate.raw_query.address &&
            el.raw_query.key == candidate.raw_query.key
        });

        let mut current_element_history = StorageSlotHistoryKeeper::default();
        let mut last_write_is_rollback = false;

        for (_idx, el) in subit.enumerate() {
            let _ = it.next().unwrap();

            if current_element_history.current_value.is_none() {
                assert!(current_element_history.initial_value.is_none(), "invalid for query {:?}", el);
                // first read potentially
                if el.raw_query.rw_flag == false {
                    current_element_history.did_read_at_depth_zero = true;
                }
            } else {
                // explicit read at zero
                if el.raw_query.rw_flag == false && current_element_history.changes_stack.is_empty() {
                    current_element_history.did_read_at_depth_zero = true;
                }
            }

            if current_element_history.current_value.is_none() {
                assert!(current_element_history.initial_value.is_none(), "invalid for query {:?}", el);
                if el.raw_query.rw_flag == false {
                    current_element_history.initial_value = Some(el.raw_query.read_value);
                    current_element_history.current_value = Some(el.raw_query.read_value);
                } else {
                    assert!(el.raw_query.rollback == false);
                    current_element_history.initial_value = Some(el.raw_query.read_value);
                    current_element_history.current_value = Some(el.raw_query.read_value); // note: We apply updates few lines later
                }
            }

            if el.raw_query.rw_flag == false {
                assert_eq!(&el.raw_query.read_value, current_element_history.current_value.as_ref().unwrap(), "invalid for query {:?}", el);
                // and do not place reads into the stack
            } else if el.raw_query.rw_flag == true {
                // write-like things manipulate the stack
                if el.raw_query.rollback == false {
                    last_write_is_rollback = false;
                    // write
                    assert_eq!(&el.raw_query.read_value, current_element_history.current_value.as_ref().unwrap(), "invalid for query {:?}", el);
                    current_element_history.current_value = Some(el.raw_query.written_value);
                    current_element_history.changes_stack.push(*el);
                } else {
                    last_write_is_rollback = true;
                    // pop from stack
                    let popped_change = current_element_history.changes_stack.pop().unwrap();
                    // we do not explicitly swap values, and use rollback flag instead, so compare this way
                    assert_eq!(el.raw_query.read_value, popped_change.raw_query.read_value, "invalid for query {:?}", el);
                    assert_eq!(el.raw_query.written_value, popped_change.raw_query.written_value, "invalid for query {:?}", el);
                    assert_eq!(&el.raw_query.written_value, current_element_history.current_value.as_ref().unwrap(), "invalid for query {:?}", el);
                    // check that we properly apply rollbacks
                    assert_eq!(el.raw_query.shard_id, popped_change.raw_query.shard_id, "invalid for query {:?}", el);
                    assert_eq!(el.raw_query.address, popped_change.raw_query.address, "invalid for query {:?}", el);
                    assert_eq!(el.raw_query.key, popped_change.raw_query.key, "invalid for query {:?}", el);
                    // apply rollback
                    current_element_history.current_value = Some(el.raw_query.read_value); // our convension
                }
            }
        }

        use zk_evm::aux_structures::Timestamp;

        if current_element_history.did_read_at_depth_zero == false && current_element_history.changes_stack.is_empty() {
            // whatever happened there didn't produce any final changes
            assert_eq!(current_element_history.initial_value.unwrap(), current_element_history.current_value.unwrap());
            assert!(last_write_is_rollback == true);
            // here we know that last write was a rollback, and there we no reads after it (otherwise "did_read_at_depth_zero" == true),
            // so whatever was an initial value in storage slot it's not ever observed, and we do not need to issue even read here
            continue;
        } else {
            if current_element_history.initial_value.unwrap() == current_element_history.current_value.unwrap() {
                // no change, but we may need protective read
                if current_element_history.did_read_at_depth_zero {
                    // protective read
                    let sorted_log_query = LogQuery {
                        timestamp: Timestamp(0),
                        tx_number_in_block: 0,
                        aux_byte: 0,
                        shard_id: candidate.raw_query.shard_id,
                        address: candidate.raw_query.address,
                        key: candidate.raw_query.key,
                        read_value: current_element_history.initial_value.unwrap(),
                        written_value: current_element_history.current_value.unwrap(),
                        rw_flag: false,
                        rollback: false,
                        is_service: false,
                    };
            
                    deduplicated_storage_queries.push(sorted_log_query);
                } else {
                    // we didn't read at depth zero, so it's something like 
                    // - write cell from a into b
                    // ....
                    // - write cell from b into a

                    // There is a catch here:
                    // - if it's two "normal" writes, then operator can claim that initial value 
                    // was "a", but it could have been some other, and in this case we want to 
                    // "read" that it was indeed "a"
                    // - but if the latest "write" was just a rollback, 
                    // then we know that it's basically NOP. We already had a branch above that
                    // protects us in case of write - rollback - read, so we only need to degrade write into
                    // read here if the latest write wasn't a rollback

                    assert!(last_write_is_rollback == false);

                    if last_write_is_rollback == false {
                        // degrade to protective read
                        let sorted_log_query = LogQuery {
                            timestamp: Timestamp(0),
                            tx_number_in_block: 0,
                            aux_byte: 0,
                            shard_id: candidate.raw_query.shard_id,
                            address: candidate.raw_query.address,
                            key: candidate.raw_query.key,
                            read_value: current_element_history.initial_value.unwrap(),
                            written_value: current_element_history.current_value.unwrap(),
                            rw_flag: false,
                            rollback: false,
                            is_service: false,
                        };
            
                        deduplicated_storage_queries.push(sorted_log_query);
                    } else {
                        // we just do nothing!
                    }
                }
            } else {
                // it's final net write
                let sorted_log_query = LogQuery {
                    timestamp: Timestamp(0),
                    tx_number_in_block: 0,
                    aux_byte: 0,
                    shard_id: candidate.raw_query.shard_id,
                    address: candidate.raw_query.address,
                    key: candidate.raw_query.key,
                    read_value: current_element_history.initial_value.unwrap(),
                    written_value: current_element_history.current_value.unwrap(),
                    rw_flag: true,
                    rollback: false,
                    is_service: false,
                };
        
                deduplicated_storage_queries.push(sorted_log_query);
            }
        }
    }

    (sorted_storage_queries_with_extra_timestamp, deduplicated_storage_queries)
}