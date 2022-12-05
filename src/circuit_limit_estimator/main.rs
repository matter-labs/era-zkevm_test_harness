use std::fs::File;
use std::io::Write;

use structopt::StructOpt;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use sync_vm::rescue_poseidon::RescueParams;
use sync_vm::testing::create_test_artifacts_with_optimized_gate;
use sync_vm::traits::GenericHasher;
use zkevm_test_harness::abstract_zksync_circuit::{ZkSyncUniformCircuitCircuitInstance, ZkSyncUniformSynthesisFunction};
use zkevm_test_harness::abstract_zksync_circuit::concrete_circuits::{CodeDecommitterInstanceSynthesisFunction, CodeDecommittmentsSorterSynthesisFunction, ECRecoverFunctionInstanceSynthesisFunction, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction, Keccak256RoundFunctionInstanceSynthesisFunction, LogDemuxInstanceSynthesisFunction, MessagesMerklizerInstanceSynthesisFunction, RAMPermutationInstanceSynthesisFunction, Sha256RoundFunctionInstanceSynthesisFunction, StorageApplicationInstanceSynthesisFunction, StorageInitialWritesRehasherInstanceSynthesisFunction, StorageRepeatedWritesRehasherInstanceSynthesisFunction, StorageSortAndDedupInstanceSynthesisFunction, VmMainInstanceSynthesisFunction};
use zkevm_test_harness::bellman::bn256::Bn256;
use zkevm_test_harness::bellman::plonk::better_better_cs::cs::{PlonkCsWidth4WithNextStepAndCustomGatesParams, SetupAssembly};
use zkevm_test_harness::bellman::plonk::better_better_cs::cs::Circuit;
use zkevm_test_harness::witness::oracle::VmWitnessOracle;
use zkevm_test_harness::witness::postprocessing::{L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH, USE_BLAKE2S_EXTRA_TABLES};

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

fn ensure_cycle_within_2_26_limit(cycles: usize, gates: usize, additive: usize) -> usize {
    let two_power_26: usize = 1 << 26;
    if (cycles * gates + additive) < two_power_26 {
        println!("cycles*gates+additive : {}", cycles * gates + additive);
        return cycles;
    }
    println!("two_power_26 - additive / gates: {}", (two_power_26 - additive) / gates);
    (two_power_26 - additive) / gates
}

fn compute_inner<
    SF: ZkSyncUniformSynthesisFunction<Bn256, RoundFunction=GenericHasher<Bn256, RescueParams<Bn256, 2, 3>, 2, 3>>,
    F: Fn(usize) -> SF::Config
>(
    config_fn: F,
) -> usize {
    let max = 1 << 26;

    let typical_sizes = vec![16, 32];
    let mut gates = vec![];

    for size in typical_sizes.iter().cloned() {
        let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

        let mut setup_assembly = SetupAssembly::<
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            SelectorOptimizedWidth4MainGateWithDNext
        >::new();

        let config = config_fn(size);

        let circuit = ZkSyncUniformCircuitCircuitInstance::<_, SF>::new(
            None,
            config,
            round_function.clone(),
            None,
        );

        circuit.synthesize(&mut setup_assembly).unwrap();

        let n = setup_assembly.n();
        gates.push(n);
    }

    // linear approximation

    let mut per_round_gates = (gates[1] - gates[0]) / (typical_sizes[1] - typical_sizes[0]);

    if (gates[1] - gates[0]) % (typical_sizes[1] - typical_sizes[0]) != 0 {
        println!("non-linear!");
        per_round_gates += 1;
    }

    println!("Single cycle takes {} gates", per_round_gates);

    let additive = gates[1] - per_round_gates * typical_sizes[1];

    println!("O(1) costs = {}", additive);

    let cycles = (max - additive) / per_round_gates;
    let cycles = ensure_cycle_within_2_26_limit(cycles, per_round_gates + 2, additive);

    println!("Can fit {} cycles for circuit type {}", cycles, SF::description());

    let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    let mut setup_assembly = SetupAssembly::<
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext
    >::new();

    let config = config_fn(cycles);

    let circuit = ZkSyncUniformCircuitCircuitInstance::<_, SF>::new(
        None,
        config,
        round_function.clone(),
        None,
    );

    println!("Synthesising largest size");
    circuit.synthesize(&mut setup_assembly).unwrap();
    println!("Finaizing largest size");
    setup_assembly.finalize();
    cycles
}


fn get_circuit_capacity(circuit_type: u8) -> usize {
    match circuit_type {
        3 => compute_inner::<VmMainInstanceSynthesisFunction<_, VmWitnessOracle<_>>, _>(
            |x: usize| {
                x
            }
        ),
        4 => compute_inner::<CodeDecommittmentsSorterSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        5 => compute_inner::<CodeDecommitterInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        6 => compute_inner::<LogDemuxInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        7 => compute_inner::<Keccak256RoundFunctionInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        8 => compute_inner::<Sha256RoundFunctionInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        9 => compute_inner::<ECRecoverFunctionInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        10 => compute_inner::<RAMPermutationInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        11 => compute_inner::<StorageSortAndDedupInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        12 => compute_inner::<StorageApplicationInstanceSynthesisFunction, _>(
            |x: usize| {
                (x, USE_BLAKE2S_EXTRA_TABLES)
            }
        ),
        13 => compute_inner::<StorageInitialWritesRehasherInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        14 => compute_inner::<StorageRepeatedWritesRehasherInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        15 | 16 => compute_inner::<EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction, _>(
            |x: usize| {
                x
            }
        ),
        17 => compute_inner::<MessagesMerklizerInstanceSynthesisFunction, _>(
            |x: usize| {
                (x, L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH)
            }
        ),
        _ => panic!("Unknown circuit type for which the limit can be computed {}", circuit_type)
    }
}

fn save_circuit_limit(limit: usize, filepath: String) {
    let mut f = File::create(filepath)
        .expect("Unable to create file");
    f.write_all(limit.to_string().as_bytes())
        .expect("Unable to write data");
}

fn main() {
    let opt = Opt::from_args();
    println!("Estimating circuit limit for circuit {}", opt.numeric_circuit);
    let circuit_limit = get_circuit_capacity(opt.numeric_circuit);
    save_circuit_limit(circuit_limit, format!("circuit_limit_{}.txt", opt.numeric_circuit));
    println!("Estimated circuit limit is {} for circuit {}", circuit_limit, opt.numeric_circuit);
}
