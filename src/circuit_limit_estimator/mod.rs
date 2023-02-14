use std::panic;

use crate::abstract_zksync_circuit::{ZkSyncUniformCircuitCircuitInstance, ZkSyncUniformSynthesisFunction};
use crate::abstract_zksync_circuit::concrete_circuits::{CodeDecommitterInstanceSynthesisFunction, CodeDecommittmentsSorterSynthesisFunction, ECRecoverFunctionInstanceSynthesisFunction, EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction, Keccak256RoundFunctionInstanceSynthesisFunction, L1MessagesRehasherInstanceSynthesisFunction, LogDemuxInstanceSynthesisFunction, MessagesMerklizerInstanceSynthesisFunction, RAMPermutationInstanceSynthesisFunction, Sha256RoundFunctionInstanceSynthesisFunction, StorageApplicationInstanceSynthesisFunction, StorageInitialWritesRehasherInstanceSynthesisFunction, StorageRepeatedWritesRehasherInstanceSynthesisFunction, StorageSortAndDedupInstanceSynthesisFunction, VmMainInstanceSynthesisFunction};
use crate::bellman::bn256::Bn256;
use crate::bellman::plonk::better_better_cs::cs::{PlonkCsWidth4WithNextStepAndCustomGatesParams, SetupAssembly};
use crate::bellman::plonk::better_better_cs::cs::Circuit;
use crate::sync_vm::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use crate::sync_vm::rescue_poseidon::RescueParams;
use crate::sync_vm::testing::create_test_artifacts_with_optimized_gate;
use crate::sync_vm::traits::GenericHasher;
use crate::witness::oracle::VmWitnessOracle;
use crate::witness::postprocessing::{L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH, USE_BLAKE2S_EXTRA_TABLES};

fn ensure_cycle_within_2_26_limit(cycles: usize, gates: usize, additive: usize) -> usize {
    let two_power_26: usize = 1 << 26;
    if (cycles * gates + additive) < two_power_26 {
        println!("cycles*gates+additive : {}", cycles * gates + additive);
        return cycles;
    }
    println!(
        "two_power_26 - additive / gates: {}",
        (two_power_26 - additive) / gates
    );
    (two_power_26 - additive) / gates
}

fn compute_inner<
    SF: ZkSyncUniformSynthesisFunction<
        Bn256,
        RoundFunction = GenericHasher<Bn256, RescueParams<Bn256, 2, 3>, 2, 3>,
    >,
    F: Fn(usize) -> SF::Config,
>(
    config_fn: F,
    optional_circuit_limit_generation_mode_fn: Option<fn(usize) -> usize>,
) -> usize {
    let max = 1 << 26;

    let typical_sizes = vec![16, 32];
    let mut gates = vec![];

    for size in typical_sizes.iter().cloned() {
        let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

        let mut setup_assembly = SetupAssembly::<
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            SelectorOptimizedWidth4MainGateWithDNext,
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

    let mut cycles = (max - additive) / per_round_gates;
    cycles = ensure_cycle_within_2_26_limit(cycles, per_round_gates + 2, additive);
    match optional_circuit_limit_generation_mode_fn {
        None => {}
        Some(circuit_limit_generation_mode_fn) => {
            cycles = circuit_limit_generation_mode_fn(cycles);
        }
    }
    println!(
        "Can fit {} cycles for circuit type {}",
        cycles,
        SF::description()
    );

    let (_, round_function, _) = create_test_artifacts_with_optimized_gate();

    let mut setup_assembly = SetupAssembly::<
        _,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
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

pub fn get_circuit_capacity(circuit_type: u8) -> usize {
    match circuit_type {
        3 => compute_inner::<VmMainInstanceSynthesisFunction<_, VmWitnessOracle<_>>, _>(
            |x: usize| x,
            None,
        ),
        4 => compute_inner::<CodeDecommittmentsSorterSynthesisFunction, _>(|x: usize| x, None),
        5 => compute_inner::<CodeDecommitterInstanceSynthesisFunction, _>(|x: usize| x, None),
        6 => compute_inner::<LogDemuxInstanceSynthesisFunction, _>(|x: usize| x, None),
        7 => {
            compute_inner::<Keccak256RoundFunctionInstanceSynthesisFunction, _>(|x: usize| x, None)
        }
        8 => compute_inner::<Sha256RoundFunctionInstanceSynthesisFunction, _>(|x: usize| x, None),
        9 => compute_inner::<ECRecoverFunctionInstanceSynthesisFunction, _>(|x: usize| x, None),
        10 => compute_inner::<RAMPermutationInstanceSynthesisFunction, _>(|x: usize| x, None),
        11 => compute_inner::<StorageSortAndDedupInstanceSynthesisFunction, _>(|x: usize| x, None),
        12 => compute_inner::<StorageApplicationInstanceSynthesisFunction, _>(
            |x: usize| (x, USE_BLAKE2S_EXTRA_TABLES),
            None,
        ),
        13 => compute_inner::<StorageInitialWritesRehasherInstanceSynthesisFunction, _>(
            |x: usize| x,
            None,
        ),
        14 => compute_inner::<StorageRepeatedWritesRehasherInstanceSynthesisFunction, _>(
            |x: usize| x,
            None,
        ),
        15 | 16 => compute_inner::<EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction, _>(
            |x: usize| x,
            None,
        ),
        // L1MessagesRehasherInstanceSynthesisFunction
        17 | 18 => compute_inner::<MessagesMerklizerInstanceSynthesisFunction, _>(
            |x: usize| (x, L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH),
            // Round down cycles to power of 2 as L1 message merklizer circuit expects it to be power of 2
            // https://github.com/matter-labs/sync_vm/blob/b538a6105bbc0586ad437484f7f76b2c3e329c46/src/glue/merkleize_l1_messages/merkleize.rs#L298-L301
            Some(|cycles: usize| 2usize.pow((cycles as f64).log2().floor() as u32)),
        ),
        _ => panic!(
            "Unknown circuit type for which the limit can be computed {}",
            circuit_type
        ),
    }
}
