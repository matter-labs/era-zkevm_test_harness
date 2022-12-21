// This file is auto-generated, do not edit it manually

use crate::toolset::GeometryConfig;

pub const fn get_geometry_config() -> GeometryConfig {
    GeometryConfig {
    cycles_per_vm_snapshot: 23594,
    limit_for_code_decommitter_sorter: 192838,
    limit_for_log_demuxer: 101833,
    cycles_per_storage_sorter: 79700,
    limit_for_events_or_l1_messages_sorter: 88767,
    limit_for_l1_messages_merklizer: 512,
    cycles_per_ram_permutation: 260102,
    cycles_per_code_decommitter: 12306,
    cycles_per_storage_application: 118,
    limit_for_initial_writes_pubdata_hasher: 4765,
    limit_for_repeated_writes_pubdata_hasher: 7564,
    cycles_per_keccak256_circuit: 2141,
    cycles_per_sha256_circuit: 11812,
    cycles_per_ecrecover_circuit: 72,
    }
}