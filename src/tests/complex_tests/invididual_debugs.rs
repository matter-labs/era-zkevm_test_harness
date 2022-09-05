use super::*;

#[cfg(test)]
mod test {
    use sync_vm::{testing::create_test_artifacts_with_optimized_gate, franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit};
    use std::io::Read;
    use super::*;

    #[test]
    fn read_and_run() {
        // let circuit_file_name = "prover_input_26";
        // let circuit_file_name = "prover_input_11";
        let circuit_file_name = "prover_input_1";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let circuit: ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>> = bincode::deserialize(&buffer).unwrap();

        match &circuit {
            ZkSyncCircuit::KeccakRoundFunction(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner.closed_form_input.start_flag);
                dbg!(&inner.closed_form_input.completion_flag);
                dbg!(&inner.closed_form_input.hidden_fsm_input.precompile_state.call_params);
                dbg!(&inner.closed_form_input.hidden_fsm_input.precompile_state.u64_words_buffer);
                dbg!(&inner.closed_form_input.hidden_fsm_input.precompile_state.u64_words_buffer_markers);
            },
            ZkSyncCircuit::Sha256RoundFunction(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner.closed_form_input.start_flag);
                dbg!(&inner.closed_form_input.completion_flag);
                dbg!(&inner.closed_form_input.hidden_fsm_input.internal_fsm.precompile_call_params);
                dbg!(&inner);
            },
            ZkSyncCircuit::StorageApplication(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner.closed_form_input.start_flag);
                dbg!(&inner.merkle_paths.len());
                dbg!(&inner.leaf_indexes_for_reads.len());
                dbg!(&inner);
            },
            _ => unreachable!()
        }

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();

        circuit.synthesize(&mut cs).unwrap();

        let is_satisified = cs.is_satisfied();
        assert!(is_satisified);
    }
}