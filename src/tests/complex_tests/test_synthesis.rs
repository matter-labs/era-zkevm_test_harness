use crate::boojum::config::ProvingCSConfig;
use crate::boojum::worker::Worker;
use crate::prover_utils::create_base_layer_setup_data;
use crate::tests::complex_tests::generate_base_layer;
use crate::tests::complex_tests::utils::read_basic_test_artifact;
use crate::tests::{synthesize_base_layer_aux, ResolverRecordStorage, synthesize_base_layer_aux_2};
use circuit_definitions::boojum::field::goldilocks::GoldilocksField;
use circuit_definitions::circuit_definitions::base_layer::ZkSyncBaseLayerCircuit;
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

#[test]
fn playback_base_layer_witness() {
    let test_artifact = read_basic_test_artifact();
    let geometry = crate::geometry_config::get_geometry_config();
    let (
        base_layer_circuits,
        base_layer_circuits_inputs,
        per_circuit_closed_form_inputs,
        scheduler_partial_input,
    ) = generate_base_layer(test_artifact, 20000, geometry);

    for (idx, (el, input_value)) in base_layer_circuits
        .clone()
        .into_flattened_set()
        .into_iter()
        .zip(
            base_layer_circuits_inputs
                .clone()
                .into_flattened_set()
                .into_iter(),
        )
        .enumerate()
    {
        let descr = el.short_description();
        println!("Doing {}: {}", idx, descr);

        // match &el {
        //     ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
        //         dbg!(&*inner.config);
        //         // let witness = inner.clone_witness().unwrap();
        //         // dbg!(&witness.closed_form_input);
        //         // dbg!(witness.closed_form_input.start_flag);
        //         // dbg!(witness.closed_form_input.completion_flag);
        //     }
        //     _ => {
        //         continue;
        //     }
        // }

        let mut storage = ResolverRecordStorage::new();
        
        let elc = el.clone();

        let now = Instant::now();
        synthesize_base_layer_aux(elc, &storage);
        println!("active: {:?}", now.elapsed());

        storage.swap();

        assert!(storage.record.is_some());

        let now = Instant::now();
        synthesize_base_layer_aux_2(el, &storage);
        println!("playback: {:?}", now.elapsed());


        // return;
        // panic!("--- done ---");
    }
}
