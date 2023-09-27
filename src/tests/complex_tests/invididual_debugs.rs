use super::*;

#[cfg(test)]
mod test {
    use super::*;
    use circuit_definitions::encodings::recursion_request::RecursionQueueSimulator;
    use std::io::Read;

    #[test]
    fn read_and_run() {
        let circuit_file_name = "prover_jobs_fri_38193_240_1_BasicCircuits_0_raw.bin";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();

        type BaseLayerCircuit = ZkSyncBaseLayerCircuit<
            GoldilocksField,
            VmWitnessOracle<GoldilocksField>,
            ZkSyncDefaultRoundFunction,
        >;

        let mut circuit: BaseLayerCircuit = bincode::deserialize(&buffer).unwrap();
        // circuit.debug_witness();

        match &mut circuit {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {
                let witness = inner.clone_witness().unwrap();
                dbg!(
                    witness
                        .closed_form_input
                        .hidden_fsm_input
                        .context_composite_u128
                );
                dbg!(
                    witness
                        .closed_form_input
                        .hidden_fsm_output
                        .context_composite_u128
                );
            }
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
                let witness = inner.clone_witness().unwrap();
                let _current_config = (*inner.config).clone();
                dbg!(_current_config);
                inner.config = std::sync::Arc::new(117500);
                dbg!(&*inner.config);

                assert_eq!(witness.closed_form_input.start_flag, true);
                assert_eq!(witness.closed_form_input.completion_flag, true);

                let initial_items = witness.initial_queue_witness.elements;
                let sorted_items = witness.sorted_queue_witness.elements;
                dbg!(initial_items.len());
                dbg!(sorted_items.len());

                let mut tmp: Vec<_> = initial_items.clone().into();
                tmp.sort_by(|a, b| match a.0.code_hash.cmp(&b.0.code_hash) {
                    std::cmp::Ordering::Equal => a.0.timestamp.cmp(&b.0.timestamp),
                    a @ _ => a,
                });

                let other: Vec<_> = sorted_items.clone().into();

                for (idx, (a, b)) in tmp.into_iter().zip(other.into_iter()).enumerate() {
                    assert_eq!(a.0, b.0, "failed at index {}", idx);
                }

                // assert_eq!(tmp, other);

                // self-check that we had a proper oracle
                let mut tmp: Option<(U256, u32, u32)> = None;
                for (query, _) in sorted_items.iter() {
                    if let Some((hash, page, timestamp)) = tmp.as_mut() {
                        if *hash == query.code_hash {
                            assert_eq!(*page, query.page);
                            assert!(query.timestamp > *timestamp);
                        } else {
                            assert!(query.code_hash >= *hash);
                            *hash = query.code_hash;
                            *page = query.page;
                            *timestamp = query.timestamp;
                        }
                    } else {
                        tmp = Some((query.code_hash, query.page, query.timestamp));
                    }
                }
            }
            _ => {}
        }

        base_test_circuit(circuit);
    }

    #[test]
    fn test_and_run_recursive() {
        // let file_name = "closed_form_inputs_35828_1_raw.bin";
        // let mut content = std::fs::File::open(file_name).unwrap();
        // let mut buffer = vec![];
        // content.read_to_end(&mut buffer).unwrap();

        // let t: RecursionQueueSimulator<GoldilocksField> = bincode::deserialize(&buffer).unwrap();
        // dbg!(&t);

        let circuit_file_name = "prover_jobs_fri_38142_0_3_NodeAggregation_1_raw.bin";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();

        let mut circuit: ZkSyncRecursiveLayerCircuit = bincode::deserialize(&buffer).unwrap();
        // circuit.debug_witness();

        match &mut circuit {
            ZkSyncRecursiveLayerCircuit::SchedulerCircuit(inner) => {
                dbg!(&inner.witness.leaf_layer_parameters);
                for el in inner.witness.proof_witnesses.iter() {
                    let vk = inner.witness.node_layer_vk_witness.clone();
                    // let vk = ZkSyncRecursionLayerVerificationKey::from_inner(ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8, vk);
                    // let proof = ZkSyncRecursionLayerProof::from_inner(ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8, el.clone());
                    let valid = verify_recursion_layer_proof_for_type::<NoPow>(
                        ZkSyncRecursionLayerStorageType::NodeLayerCircuit,
                        el,
                        &vk,
                    );
                    assert!(valid);
                }
            }
            ZkSyncRecursiveLayerCircuit::NodeLayerCircuit(inner) => {
                let vk = inner.witness.vk_witness.clone();
                for el in inner.witness.proof_witnesses.iter() {
                    // let vk = ZkSyncRecursionLayerVerificationKey::from_inner(ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8, vk);
                    // let proof = ZkSyncRecursionLayerProof::from_inner(ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8, el.clone());
                    let valid = verify_recursion_layer_proof_for_type::<NoPow>(
                        ZkSyncRecursionLayerStorageType::NodeLayerCircuit,
                        el,
                        &vk,
                    );
                    assert!(valid);
                }
            }
            _ => {}
        }

        test_recursive_circuit(circuit);
    }
}
