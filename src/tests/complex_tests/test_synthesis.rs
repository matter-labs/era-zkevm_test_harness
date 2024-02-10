use crate::boojum::config::ProvingCSConfig;
use crate::boojum::worker::Worker;
use crate::prover_utils::create_base_layer_setup_data;
use crate::tests::complex_tests::generate_base_layer;
use crate::tests::complex_tests::utils::read_basic_test_artifact;
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::zkevm_circuits::eip_4844::input::ENCODABLE_BYTES_PER_BLOB;
use circuit_definitions::{BASE_LAYER_CAP_SIZE, BASE_LAYER_FRI_LDE_FACTOR};
use std::time::Instant;

#[test]
fn test_base_layer_circuit_synthesis() {
    let test_artifact = read_basic_test_artifact();
    let geometry = crate::geometry_config::get_geometry_config();
    let blobs = std::array::from_fn(|i| {
        if i == 0 {
            Some(vec![0xff; ENCODABLE_BYTES_PER_BLOB])
        } else {
            None
        }
    });
    let (base_layer_circuit, _, _) = generate_base_layer(test_artifact, 20000, geometry, blobs);
    let circuit = base_layer_circuit
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
