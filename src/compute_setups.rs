use std::{path::{Path, PathBuf}, collections::{HashMap, HashSet}};

use boojum::worker::Worker;

use super::*;

use crate::tests::complex_tests::utils::*;
use crate::tests::complex_tests::generate_base_layer;
use boojum::cs::implementations::prover::ProofConfig;
use boojum::cs::implementations::pow::NoPow;

pub(crate) fn generate_base_layer_vks_and_proofs() {
    let test_artifact = read_test_artifact("basic_test");
    let geometry = crate::geometry_config::get_geometry_config();
    let (
        base_layer_circuit, 
        base_layer_circuit_inputs,
        _,
    ) = generate_base_layer(
        test_artifact, 
        20000,
        geometry
    );

    let worker = Worker::new();

    todo!();

    // let mut processed = HashSet::new();

    // for el in base_layer_circuit.into_flattened_set().into_iter() {
    //     let name = el.short_description();
    //     if processed.contains(&name) {
    //         continue;
    //     }

    //     println!("Will compute for {} circuit type", &name);

    //     let circuit_type = el.numeric_circuit_type();

    //     let (
    //         setup_base,
    //         setup,
    //         vk,
    //         setup_tree,
    //         vars_hint,
    //         wits_hint,
    //         finalization_hint
    //     ) = create_base_layer_setup_data(el.clone(), &worker, BASE_LAYER_FRI_LDE_FACTOR, BASE_LAYER_CAP_SIZE);

    //     let proof_config = ProofConfig {
    //         fri_lde_factor: BASE_LAYER_FRI_LDE_FACTOR,
    //         merkle_tree_cap_size: BASE_LAYER_CAP_SIZE,
    //         fri_folding_schedule: None,
    //         security_level: SECURITY_BITS_TARGET,
    //         pow_bits: 0
    //     };

    //     println!("Proving!");
    //     let now = std::time::Instant::now();

    //     let proof = prove_base_layer_circuit::<NoPow>(
    //         el.clone(), 
    //         &worker, 
    //         proof_config, 
    //         &setup_base, 
    //         &setup, 
    //         &setup_tree, 
    //         &vk, 
    //         &vars_hint, 
    //         &wits_hint, 
    //         &finalization_hint
    //     );

    //     println!("Proving is DONE, taken {:?}", now.elapsed());

    //     let is_valid = verify_base_layer_proof::<NoPow>(
    //         &el, 
    //         &proof, 
    //         &vk
    //     );

    //     assert!(is_valid);

    //     let vk_file = path_for_base_layer_circuit_vk(circuit_type, "json");
    //     let mut vk_file = std::fs::File::create(vk_file).unwrap();
    //     serde_json::ser::to_writer(&mut vk_file, &vk).unwrap();

    //     let finalization_file = path_for_base_layer_circuit_finalization(circuit_type, "json");
    //     let mut finalization_file = std::fs::File::create(finalization_file).unwrap();
    //     serde_json::ser::to_writer(&mut finalization_file, &finalization_hint).unwrap();

    //     let proof_file = path_for_base_layer_circuit_proof(circuit_type, "json");
    //     let mut proof_file = std::fs::File::create(proof_file).unwrap();
    //     serde_json::ser::to_writer(&mut proof_file, &proof).unwrap();

    //     processed.insert(name);
    // }
}

#[test]
fn test_run_create_base_layer_vks_and_proofs() {
    generate_base_layer_vks_and_proofs();
}