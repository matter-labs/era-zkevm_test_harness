use super::*;

#[cfg(test)]
mod test {
    use crate::abstract_zksync_circuit::concrete_circuits::{ZkSyncProof, ZkSyncVerificationKey};
    use std::io::Read;
    use sync_vm::{
        franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit,
        testing::create_test_artifacts_with_optimized_gate,
    };

    use super::*;

    #[test]
    fn read_and_run() {
        // let proof_file_name = "proof";
        // let mut content = std::fs::File::open(proof_file_name).unwrap();
        // let mut buffer = vec![];
        // content.read_to_end(&mut buffer).unwrap();
        // let proof: ZkSyncProof<Bn256> = bincode::deserialize(&buffer).unwrap();
        // match proof {
        //     ZkSyncProof::Scheduler(inner) => {
        //         dbg!(&inner.inputs);
        //     },
        //     _ => {}
        // }

        // let verification_key_file_name = "verification_0_key_1.json";
        // let mut content = std::fs::File::open(verification_key_file_name).unwrap();
        // let mut buffer = vec![];
        // content.read_to_end(&mut buffer).unwrap();
        // use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
        // let vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>> = serde_json::from_slice(&buffer).unwrap();
        // dbg!(vk);
        // let vk: ZkSyncVerificationKey<Bn256> = serde_json::from_slice(&buffer).unwrap();
        // match vk {
        //     ZkSyncVerificationKey::Scheduler(inner) => {
        //         dbg!(&inner);
        //     },
        //     _ => {}
        // }

        // let circuit_file_name = "prover_input_26";
        // let circuit_file_name = "prover_input_11";
        // let circuit_file_name = "prover_input_120656";
        //
        let circuit_file_name = "circuit_503.bin";
        // let circuit_file_name = "prover_jobs.json";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let circuit: ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>> =
            bincode::deserialize(&buffer).unwrap();

        // let mut file_for_json = std::fs::File::create(&format!("{}.json", circuit_file_name)).unwrap();
        // serde_json::to_writer(&mut file_for_json, &circuit).unwrap();

        use sync_vm::franklin_crypto::bellman::Field;
        let mut expected_input = sync_vm::testing::Fr::zero();

        match &circuit {
            ZkSyncCircuit::KeccakRoundFunction(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner.closed_form_input.start_flag);
                dbg!(&inner.closed_form_input.completion_flag);
                dbg!(&inner.closed_form_input.observable_input);
                dbg!(&inner.closed_form_input.hidden_fsm_input);
            }
            ZkSyncCircuit::Sha256RoundFunction(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner);
            }
            ZkSyncCircuit::StorageApplication(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner);
            }
            ZkSyncCircuit::MainVM(inner) => {
                let inner = inner.clone();
                let inner = inner.witness.take().unwrap();
                dbg!(&inner);
                let (public_input_committment, _) =
                    simulate_public_input_value_from_witness(inner.closed_form_input);

                expected_input = public_input_committment;
            }
            ZkSyncCircuit::RAMPermutation(inner) => {
                // let inner = inner.clone();
                // let inner = inner.witness.take().unwrap();

                // let (public_input_committment, _) = simulate_public_input_value_from_witness(inner.closed_form_input);

                // expected_input = public_input_committment;
            }
            _ => {
                // unreachable!()
            }
        }

        dbg!(circuit.short_description());

        dbg!(expected_input);

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();

        circuit.synthesize(&mut cs).unwrap();

        let is_satisified = cs.is_satisfied();
        assert!(is_satisified);
    }

    #[test]
    fn artificial_padding() {
        use crate::franklin_crypto::plonk::circuit::allocated_num::Num;
        use sync_vm::franklin_crypto::bellman::Field;
        use sync_vm::testing::Fr;

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        let a = Num::alloc(&mut cs, Some(Fr::one())).unwrap();
        let b = Num::alloc(&mut cs, Some(Fr::one())).unwrap();
        let _c = a.mul(&mut cs, &b).unwrap();
        cs.finalize_to_size_log_2(26);
    }
}
