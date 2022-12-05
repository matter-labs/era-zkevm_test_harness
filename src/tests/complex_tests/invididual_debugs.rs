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
        // let circuit_file_name = "prover_input_120656";
        let circuit_file_name = "prover_jobs_602490_8_Main VM_BasicCircuits.bin";
        // let circuit_file_name = "prover_jobs.json";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let circuit: ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>> = bincode::deserialize(&buffer).unwrap();

        use sync_vm::franklin_crypto::bellman::Field;
        let mut expected_input = sync_vm::testing::Fr::zero();

        match &circuit {
            ZkSyncCircuit::KeccakRoundFunction(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner.closed_form_input.observable_input);
            },
            ZkSyncCircuit::Sha256RoundFunction(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner);
            },
            ZkSyncCircuit::StorageApplication(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner);
            },
            ZkSyncCircuit::MainVM(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner);
                let (public_input_committment, _) = simulate_public_input_value_from_witness(inner.closed_form_input);

                expected_input = public_input_committment;
            },
            ZkSyncCircuit::RAMPermutation(inner) => {
                // let inner = inner.clone();
                // let inner = inner.witness.take().unwrap();

                // let (public_input_committment, _) = simulate_public_input_value_from_witness(inner.closed_form_input);

                // expected_input = public_input_committment;
            },
            _ => unreachable!()
        }

        dbg!(circuit.short_description());

        dbg!(expected_input);

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();

        circuit.synthesize(&mut cs).unwrap();

        // let is_satisified = cs.is_satisfied();
        // assert!(is_satisified);
    }

    #[test]
    fn artificial_padding() {
        use crate::franklin_crypto::plonk::circuit::allocated_num::Num;
        use sync_vm::testing::Fr;
        use sync_vm::franklin_crypto::bellman::Field;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let a = Num::alloc(&mut cs, Some(Fr::one())).unwrap();
        let b = Num::alloc(&mut cs, Some(Fr::one())).unwrap();
        let _c = a.mul(&mut cs, &b).unwrap();
        cs.finalize_to_size_log_2(26);
    }
}