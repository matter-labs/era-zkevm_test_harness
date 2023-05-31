use std::fs::File;
use std::io::Write;

use codegen::Block;
use codegen::{Function, Import, Scope};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Generate geometry config using circuit limit",
    about = "Tool for generating geometry config using limit of individual circuit"
)]
struct Opt {
    #[structopt(long)]
    vm_snapshot: u64,
    #[structopt(long)]
    code_decommitter_sorter: u64,
    #[structopt(long)]
    code_decommitter: u64,
    #[structopt(long)]
    log_demuxer: u64,
    #[structopt(long)]
    keccak256: u64,
    #[structopt(long)]
    sha256: u64,
    #[structopt(long)]
    ecrecover: u64,
    #[structopt(long)]
    ram_permutation: u64,
    #[structopt(long)]
    storage_sorter: u64,
    #[structopt(long)]
    storage_application: u64,
    #[structopt(long)]
    initial_writes: u64,
    #[structopt(long)]
    repeated_writes: u64,
    #[structopt(long)]
    events_or_l1_messages_sorter: u64,
    #[structopt(long)]
    l1_messages_merklizer: u64,
    #[structopt(long)]
    l1_messages_pudata_hasher: u64,
}

fn save_geometry_config_file(geometry_config: String, filepath: &str) {
    let file_content =
        "// This file is auto-generated, do not edit it manually\n\n".to_owned() + &geometry_config;
    let mut f = File::create(filepath).expect("Unable to create file");
    f.write_all(file_content.as_bytes())
        .expect("Unable to write data");
}

fn main() {
    let opt = Opt::from_args();
    let mut scope = Scope::new();
    scope.import("crate::toolset", "GeometryConfig");
    let function = scope.new_fn("get_geometry_config");
    function.vis("pub const");
    function.ret("GeometryConfig");
    function.line("GeometryConfig {");
    function.line(format!("cycles_per_vm_snapshot: {},", opt.vm_snapshot));
    function.line(format!(
        "cycles_per_code_decommitter_sorter: {},",
        opt.code_decommitter_sorter
    ));
    function.line(format!("cycles_per_log_demuxer: {},", opt.log_demuxer));
    function.line(format!(
        "cycles_per_storage_sorter: {},",
        opt.storage_sorter
    ));
    function.line(format!(
        "cycles_per_events_or_l1_messages_sorter: {},",
        opt.events_or_l1_messages_sorter
    ));
    function.line(format!(
        "limit_for_l1_messages_merklizer: {},",
        opt.l1_messages_merklizer
    ));
    function.line(format!(
        "cycles_per_ram_permutation: {},",
        opt.ram_permutation
    ));
    function.line(format!(
        "cycles_per_code_decommitter: {},",
        opt.code_decommitter
    ));
    function.line(format!(
        "cycles_per_storage_application: {},",
        opt.storage_application
    ));
    function.line(format!(
        "limit_for_initial_writes_pubdata_hasher: {},",
        opt.initial_writes
    ));
    function.line(format!(
        "limit_for_repeated_writes_pubdata_hasher: {},",
        opt.repeated_writes
    ));
    function.line(format!("cycles_per_keccak256_circuit: {},", opt.keccak256));
    function.line(format!("cycles_per_sha256_circuit: {},", opt.sha256));
    function.line(format!("cycles_per_ecrecover_circuit: {},", opt.ecrecover));
    function.line(format!(
        "limit_for_l1_messages_pudata_hasher: {},",
        opt.l1_messages_pudata_hasher
    ));
    function.line("}");
    println!("Generated config:\n {}", scope.to_string());
    save_geometry_config_file(scope.to_string(), "src/geometry_config/mod.rs");
}
