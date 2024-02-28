use crate::boojum::config::ProvingCSConfig;
use crate::boojum::worker::Worker;
use crate::prover_utils::create_base_layer_setup_data;
use crate::tests::complex_tests::generate_base_layer;
use crate::tests::complex_tests::utils::read_basic_test_artifact;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::{BASE_LAYER_CAP_SIZE, BASE_LAYER_FRI_LDE_FACTOR};
use std::time::Instant;

#[test]
fn test_base_layer_circuit_synthesis() {
    let test_artifact = read_basic_test_artifact();
    let geometry = crate::geometry_config::get_geometry_config();
    let (base_layer_circuit, _, _, _) = generate_base_layer(test_artifact, 20000, geometry);
    let circuit = base_layer_circuit
        .into_flattened_set()
        .into_iter()
        .next()
        .expect("failed to get circuit");
    let worker = Worker::new_with_num_threads(8);
    let (_, _, _, _, _, _, finalization_hint) = create_base_layer_setup_data(
        circuit.clone(),
        &worker,
        BASE_LAYER_FRI_LDE_FACTOR,
        BASE_LAYER_CAP_SIZE,
    );
    let started_at = Instant::now();
    circuit.synthesis::<GoldilocksField>(&finalization_hint);
    println!("synthesis took {:?}", started_at.elapsed());
}
