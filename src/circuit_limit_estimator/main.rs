use std::fs::File;
use std::io::Write;

use structopt::StructOpt;
use zkevm_test_harness::circuit_limit_estimator::get_circuit_capacity;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Estimate limit for individual circuit",
    about = "Tool for estimating individual circuit limit"
)]
struct Opt {
    /// Numeric circuit type valid value from [3-17].
    #[structopt(long)]
    numeric_circuit: u8,
}

fn save_circuit_limit(limit: usize, filepath: String) {
    let mut f = File::create(filepath).expect("Unable to create file");
    f.write_all(limit.to_string().as_bytes())
        .expect("Unable to write data");
}

fn main() {
    let opt = Opt::from_args();
    println!(
        "Estimating circuit limit for circuit {}",
        opt.numeric_circuit
    );
    let circuit_limit = get_circuit_capacity(opt.numeric_circuit);
    save_circuit_limit(
        circuit_limit,
        format!("circuit_limit_{}.txt", opt.numeric_circuit),
    );
    println!(
        "Estimated circuit limit is {} for circuit {}",
        circuit_limit, opt.numeric_circuit
    );
}
