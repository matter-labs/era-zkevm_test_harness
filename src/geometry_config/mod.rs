// This file is auto-generated, do not edit it manually

use crate::toolset::GeometryConfig;

pub fn get_geometry_config() -> GeometryConfig {
    GeometryConfig {
    cycles_per_vm_snapshot: 23610,
    limit_for_code_decommitter_sorter: 193953,
    limit_for_log_demuxer: 102143,
    limit_for_storage_sorter: 79890,
    limit_for_events_or_l1_messages_sorter: 89002,
    limit_for_l1_messages_merklizer: 512,
    cycles_per_ram_permutation: 262134,
    cycles_per_code_decommitter: 12310,
    cycles_per_storage_application: 118,
    limit_for_initial_writes_pubdata_hasher: 4766,
    limit_for_repeated_writes_pubdata_hasher: 7566,
    cycles_per_keccak256_circuit: 2141,
    cycles_per_sha256_circuit: 11816,
    cycles_per_ecrecover_circuit: 72,
    }
}
