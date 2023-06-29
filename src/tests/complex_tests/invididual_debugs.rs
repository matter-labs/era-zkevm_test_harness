use super::*;

#[cfg(test)]
mod test {
    use std::io::Read;
    use super::*;

    #[test]
    fn read_and_run() {
        let circuit_file_name = "prover_jobs_fri_33218_769_2_BasicCircuits_0_raw.bin";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();

        type BaseLayerCircuit = ZkSyncBaseLayerCircuit<GoldilocksField, VmWitnessOracle<GoldilocksField>, ZkSyncDefaultRoundFunction>;

        let circuit: BaseLayerCircuit = bincode::deserialize(&buffer).unwrap();
        // circuit.debug_witness();

        match &circuit {
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
                let witness = inner.clone_witness().unwrap();
                dbg!(&*inner.config);

                assert_eq!(witness.closed_form_input.start_flag, true);
                assert_eq!(witness.closed_form_input.completion_flag, true);

                let initial_items = witness.initial_queue_witness.elements;
                let sorted_items = witness.sorted_queue_witness.elements;
                dbg!(initial_items.len());
                dbg!(sorted_items.len());
                
                let mut tmp: Vec<_> = initial_items.clone().into();
                tmp.sort_by(|a, b| {
                    match a.0.code_hash.cmp(&b.0.code_hash) {
                        std::cmp::Ordering::Equal => a.0.timestamp.cmp(&b.0.timestamp),
                        a @ _ => a,
                    }
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
            },
            _ => {}
        }

        base_test_circuit(circuit);
    }
}