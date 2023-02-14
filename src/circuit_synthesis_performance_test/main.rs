use std::collections::HashMap;
use std::iter::Iterator;
use std::time::Instant;

use structopt::StructOpt;

use zkevm_test_harness::circuit_limit_estimator::get_circuit_capacity;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "Performance for individual circuit synthesis",
    about = "Tool for performance circuit limit"
)]
struct Opt {
    /// Numeric circuit type valid value from [3-17].
    #[structopt(long)]
    numeric_circuit: u8,
}

fn get_circuit_to_synthesis_upper_bound_in_seconds(circuit_type: u8) -> u64 {
    let map: HashMap<u8, u64> = [
        (3, 5 * 60),  // 5 min
        (4, 5 * 60),  // 5 min
        (5, 5 * 60),  // 5 min
        (6, 5 * 60),  // 5 min
        (7, 5 * 60),  // 5 min
        (8, 5 * 60),  // 5 min
        (9, 5 * 60),  // 8 min
        (9, 5 * 60),  // 8 min
        (10, 5 * 60), // 5 min
        (11, 5 * 60), // 5 min
        (12, 5 * 60), // 6 min
        (13, 5 * 60), // 5 min
        (14, 5 * 60), // 5 min
        (15, 5 * 60), // 5 min
        (16, 5 * 60), // 5 min
        (17, 5 * 60), // 5 min
    ]
    .iter()
    .cloned()
    .collect();
    map[&circuit_type]
}

fn main() {
    let opt = Opt::from_args();
    println!(
        "Starting performance test for circuit {}",
        opt.numeric_circuit
    );
    let start_time = Instant::now();
    get_circuit_capacity(opt.numeric_circuit);
    println!(
        "Finished for circuit {}, took: {} seconds",
        opt.numeric_circuit,
        start_time.elapsed().as_secs()
    );
    assert_eq!(
        true,
        start_time.elapsed().as_secs()
            <= get_circuit_to_synthesis_upper_bound_in_seconds(opt.numeric_circuit)
    );
}
