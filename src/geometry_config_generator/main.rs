use std::fs::File;
use std::io::Write;

use codegen::Scope;
use rayon::prelude::*;

use zkevm_test_harness::capacity_estimator::{
    code_decommitter_capacity, code_decommittments_sorter_capacity, ecrecover_capacity,
    event_sorter_capacity, keccak256_rf_capacity, l1_messages_hasher_capacity,
    log_demuxer_capacity, main_vm_capacity, ram_permutation_capacity, sha256_rf_capacity,
    storage_application_capacity, storage_sorter_capacity,
};
use zkevm_test_harness::toolset::GeometryConfig;

fn save_geometry_config_file(geometry_config: String, filepath: &str) {
    let file_content =
        "// This file is auto-generated, do not edit it manually\n\n".to_owned() + &geometry_config;
    let mut f = File::create(filepath).expect("Unable to create file");
    f.write_all(file_content.as_bytes())
        .expect("Unable to write data");
}

fn all_runners() -> Vec<Box<dyn Fn() -> usize + Send>> {
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
        Box::new(l1_messages_hasher_capacity),
    ]
}

pub fn compute_config() -> GeometryConfig {
    let runners: Vec<_> = all_runners().into_iter().map(|el| (el, 0u32)).collect();
    let mut sizes = runners;
    sizes.reverse();
    sizes.par_iter_mut().panic_fuse().for_each(|(func, size)| {
        *size = (func)() as u32;
    });

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
    let limit_for_l1_messages_pudata_hasher = sizes.pop().unwrap();

    assert!(sizes.is_empty());

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
        limit_for_l1_messages_pudata_hasher,
    };
    config
}

fn main() {
    let computed_config = compute_config();
    let mut scope = Scope::new();
    scope.import("crate::toolset", "GeometryConfig");
    let function = scope.new_fn("get_geometry_config");
    function.vis("pub const");
    function.ret("GeometryConfig");
    function.line("GeometryConfig {");
    function.line(format!(
        "    cycles_per_vm_snapshot: {},",
        computed_config.cycles_per_vm_snapshot
    ));
    function.line(format!(
        "    cycles_code_decommitter_sorter: {},",
        computed_config.cycles_code_decommitter_sorter
    ));
    function.line(format!(
        "    cycles_per_log_demuxer: {},",
        computed_config.cycles_per_log_demuxer
    ));
    function.line(format!(
        "    cycles_per_storage_sorter: {},",
        computed_config.cycles_per_storage_sorter
    ));
    function.line(format!(
        "    cycles_per_events_or_l1_messages_sorter: {},",
        computed_config.cycles_per_events_or_l1_messages_sorter
    ));
    function.line(format!(
        "    cycles_per_ram_permutation: {},",
        computed_config.cycles_per_ram_permutation
    ));
    function.line(format!(
        "    cycles_per_code_decommitter: {},",
        computed_config.cycles_per_code_decommitter
    ));
    function.line(format!(
        "    cycles_per_storage_application: {},",
        computed_config.cycles_per_storage_application
    ));
    function.line(format!(
        "    cycles_per_keccak256_circuit: {},",
        computed_config.cycles_per_keccak256_circuit
    ));
    function.line(format!(
        "    cycles_per_sha256_circuit: {},",
        computed_config.cycles_per_sha256_circuit
    ));
    function.line(format!(
        "    cycles_per_ecrecover_circuit: {},",
        computed_config.cycles_per_ecrecover_circuit
    ));
    function.line(format!(
        "    limit_for_l1_messages_pudata_hasher: {},",
        computed_config.limit_for_l1_messages_pudata_hasher
    ));
    function.line("}");
    println!("Generated config:\n {}", scope.to_string());
    save_geometry_config_file(scope.to_string(), "src/geometry_config/mod.rs");
}
