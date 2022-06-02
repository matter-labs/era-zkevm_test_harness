use crate::encodings::log_query::*;
use zk_evm::aux_structures::LogQuery;
use std::cmp::Ordering;
use rayon::prelude::*;

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

        let mut stack: Vec<LogQueryWithExtendedEnumeration> = vec![];

        let candidate = it.peek().unwrap().clone();

        let subit = it.clone().take_while(|el| {
            el.raw_query.shard_id == candidate.raw_query.shard_id &&
            el.raw_query.address == candidate.raw_query.address &&
            el.raw_query.key == candidate.raw_query.key
        });

        // let tmp: Vec<_> = it.clone().take_while(|el| {
        //     el.raw_query.shard_id == candidate.raw_query.shard_id &&
        //     el.raw_query.address == candidate.raw_query.address &&
        //     el.raw_query.key == candidate.raw_query.key
        // }).collect();

        // dbg!(&tmp);

        let mut did_read_at_no_rollback = false;

        for (idx, el) in subit.enumerate() {
            let _ = it.next().unwrap();

            if idx == 0 {
                if el.raw_query.rw_flag == false {
                    did_read_at_no_rollback = true;
                }
            } else {
                if stack.len() == 0 && el.raw_query.rw_flag == false {
                    did_read_at_no_rollback = true;
                }
            }

            if el.raw_query.rollback {
                loop {
                    // if we see rollback then we start unwinding the stack until we see a write
                    // that we should effectively cancel
                    if let Some(previous) = stack.pop() {
                        if previous.raw_query.rw_flag {
                            assert_eq!(el.raw_query.written_value, previous.raw_query.written_value);
                            break;
                        } else {
                            // we have reads, do nothing until we find write
                        }
                    } else {
                        // nothing in there, we rolled back literally everything
                        // and no reads ever were issued
                        break;
                    }

                }
            } else {
                stack.push(*el);
            }
        }

        if stack.len() == 0 {
            continue;
        }

        let initial_value = stack.first().unwrap().raw_query.read_value;
        let mut final_value = initial_value;
        let mut was_written = false;
        for el in stack.into_iter().rev() {
            if el.raw_query.rw_flag {
                // rollback just indicates, and doesn't swap values out of circuit
                if el.raw_query.rollback {
                    final_value = el.raw_query.read_value;
                } else {
                    final_value = el.raw_query.written_value;
                }

                was_written = true;
                break;
            }
        }

        let write_different = initial_value != final_value && was_written;
        let protective_read_only = !write_different && did_read_at_no_rollback;

        let sorted_rw_flag = if write_different {
            true
        } else if protective_read_only {
            false
        } else {
            unreachable!()
        };

        use zk_evm::aux_structures::Timestamp;

        let sorted_log_query = LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: 0,
            aux_byte: 0,
            shard_id: candidate.raw_query.shard_id,
            address: candidate.raw_query.address,
            key: candidate.raw_query.key,
            read_value: initial_value,
            written_value: final_value,
            rw_flag: sorted_rw_flag,
            rollback: false,
            is_service: false,
        };

        deduplicated_storage_queries.push(sorted_log_query);
    }

    (sorted_storage_queries_with_extra_timestamp, deduplicated_storage_queries)
}