// This file is auto-generated, do not edit it manually

use std::collections::VecDeque;

use boojum::worker::Worker;

use crate::toolset::GeometryConfig;

pub const fn get_geometry_config() -> GeometryConfig {
    GeometryConfig {
        cycles_per_vm_snapshot: 5713,
        cycles_per_log_demuxer: 39058,
        cycles_per_storage_sorter: 25436,
        cycles_per_events_or_l1_messages_sorter: 31287,
        cycles_per_ram_permutation: 76561,
        cycles_code_decommitter_sorter: 63122,
        cycles_per_code_decommitter: 2114,
        cycles_per_storage_application: 33,
        cycles_per_keccak256_circuit: 642,
        cycles_per_sha256_circuit: 2063,
        cycles_per_ecrecover_circuit: 2,
        limit_for_l1_messages_pudata_hasher: 0,
        limit_for_l1_messages_merklizer: 0,
        limit_for_initial_writes_pubdata_hasher: 0,
        limit_for_repeated_writes_pubdata_hasher: 0,
    }
}

fn all_runners() -> Vec<Box<dyn Fn() -> usize + Send>> {
    use crate::capacity_estimator::*;
    vec![
        Box::new(main_vm_capacity),
        Box::new(code_decommittments_sorter_capacity),
        Box::new(code_decommitter_capacity),
        Box::new(log_demuxer_capacity),
        Box::new(keccak256_rf_capacity),
        Box::new(sha256_rf_capacity),
        Box::new(ecrecover_capacity),
        Box::new(ram_permutation_capacity),
        Box::new(event_sorter_capacity),
        Box::new(storage_sorter_capacity),
        Box::new(storage_application_capacity),
    ]
}

pub fn compute_config() -> GeometryConfig {
    use crate::capacity_estimator::*;
    use rayon::prelude::*;

    let runners: Vec<_> = all_runners().into_iter().map(|el| (el, 0u32)).collect();
    let mut sizes = runners;
    sizes.reverse();
    sizes.par_iter_mut().panic_fuse().for_each(|(func, size)| {
        *size = (func)() as u32;
    });
    println!("Parallel estimation is done!");

    let mut sizes: Vec<_> = sizes.into_iter().map(|el| el.1).collect();

    let cycles_per_vm_snapshot = sizes.pop().unwrap();
    let cycles_code_decommitter_sorter = sizes.pop().unwrap();
    let cycles_per_code_decommitter = sizes.pop().unwrap();
    let cycles_per_log_demuxer = sizes.pop().unwrap();
    let cycles_per_keccak256_circuit = sizes.pop().unwrap();
    let cycles_per_sha256_circuit = sizes.pop().unwrap();
    let cycles_per_ecrecover_circuit = sizes.pop().unwrap();
    let cycles_per_ram_permutation = sizes.pop().unwrap();
    let cycles_per_events_or_l1_messages_sorter = sizes.pop().unwrap();
    let cycles_per_storage_sorter = sizes.pop().unwrap();
    let cycles_per_storage_application = sizes.pop().unwrap();

    assert!(sizes.is_empty());

    // let cycles_per_vm_snapshot = main_vm_capacity() as u32;
    // let cycles_code_decommitter_sorter = code_decommittments_sorter_capacity() as u32;
    // let cycles_per_code_decommitter = code_decommitter_capacity() as u32;
    // let cycles_per_log_demuxer = log_demuxer_capacity() as u32;
    // let cycles_per_keccak256_circuit = keccak256_rf_capacity() as u32;
    // let cycles_per_sha256_circuit = sha256_rf_capacity() as u32;
    // let cycles_per_ecrecover_circuit = ecrecover_capacity() as u32;
    // let cycles_per_ram_permutation = ram_permutation_capacity() as u32;
    // let cycles_per_events_or_l1_messages_sorter = event_sorter_capacity() as u32;
    // let cycles_per_storage_sorter = storage_sorter_capacity() as u32;
    // let cycles_per_storage_application = storage_application_capacity() as u32;

    let config = GeometryConfig {
        cycles_per_vm_snapshot,
        cycles_code_decommitter_sorter,
        cycles_per_log_demuxer,
        cycles_per_storage_sorter,
        cycles_per_events_or_l1_messages_sorter,
        cycles_per_ram_permutation,
        cycles_per_code_decommitter,
        cycles_per_storage_application,
        cycles_per_keccak256_circuit,
        cycles_per_sha256_circuit,
        cycles_per_ecrecover_circuit,
        limit_for_initial_writes_pubdata_hasher: 0,
        limit_for_repeated_writes_pubdata_hasher: 0,
        limit_for_l1_messages_merklizer: 0,
        limit_for_l1_messages_pudata_hasher: 0,
    };

    dbg!(&config);

    let mut file = std::fs::File::create("config.json").expect("must open file to save config");
    serde_json::ser::to_writer_pretty(&mut file, &config).expect("must serialize");
    drop(file);

    config
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn run_capacity_estimation() {
        compute_config();
    }
}