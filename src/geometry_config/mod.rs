// This file is auto-generated, do not edit it manually

use crate::toolset::GeometryConfig;

pub const fn get_geometry_config() -> GeometryConfig {
    GeometryConfig {
        cycles_per_vm_snapshot: 5713,
        cycles_code_decommitter_sorter: 117500,
        cycles_per_log_demuxer: 58750,
        cycles_per_storage_sorter: 44687,
        cycles_per_events_or_l1_messages_sorter: 31287,
        cycles_per_ram_permutation: 136714,
        cycles_per_code_decommitter: 2845,
        cycles_per_storage_application: 33,
        cycles_per_keccak256_circuit: 672,
        cycles_per_sha256_circuit: 2206,
        cycles_per_ecrecover_circuit: 2,
        limit_for_l1_messages_pudata_hasher: 774,
    }
}
