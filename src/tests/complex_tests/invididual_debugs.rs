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
        // let proof_file_name = "132.bin";
        // let mut content = std::fs::File::open(proof_file_name).unwrap();
        // let mut buffer = vec![];
        // content.read_to_end(&mut buffer).unwrap();
        // let proof: ZkSyncProof<Bn256> = bincode::deserialize(&buffer).unwrap();
        // match &proof {
        //     ZkSyncProof::Scheduler(inner) => {
        //         dbg!(&inner.inputs);
        //     },
        //     ZkSyncProof::MainVM(inner) => {
        //         dbg!(&inner.inputs);
        //         dbg!(&inner.n);
        //     }
        //     _ => {}
        // }

        // let verification_key_file_name = "verification_3_key.json";
        // let mut content = std::fs::File::open(verification_key_file_name).unwrap();
        // let mut buffer = vec![];
        // content.read_to_end(&mut buffer).unwrap();
        // use crate::bellman::plonk::better_better_cs::setup::VerificationKey;
        // let vk: VerificationKey<Bn256, ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>>> = serde_json::from_slice(&buffer).unwrap();
        // let vk = ZkSyncVerificationKey::MainVM(vk);
        // // let vk: ZkSyncVerificationKey<Bn256> = serde_json::from_slice(&buffer).unwrap();
        // match &vk {
        //     ZkSyncVerificationKey::Scheduler(inner) => {
        //         dbg!(&inner);
        //     },
        //     _ => {}
        // }

        // let is_valid = vk.verify_proof(&proof);
        // assert!(is_valid);

        let circuit_file_name = "prover_jobs_58348_452_L1 messages sorter_BasicCircuits.bin";
        // let circuit_file_name = "prover_jobs_1204_132_Main VM_BasicCircuits.bin";

        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let circuit: ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>> =
            bincode::deserialize(&buffer).unwrap();

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
                assert_eq!(inner.storage_queue_witness.wit.len(), inner.merkle_paths.len());
                assert_eq!(inner.storage_queue_witness.wit.len(), inner.leaf_indexes_for_reads.len());
                dbg!(&inner.closed_form_input.start_flag);
                println!("0x{:032x}", inner.closed_form_input.observable_input.initial_root[0]);
                println!("0x{:032x}", inner.closed_form_input.observable_input.initial_root[1]);
                println!("0x{:032x}", inner.closed_form_input.hidden_fsm_input.root_hash[0]);
                println!("0x{:032x}", inner.closed_form_input.hidden_fsm_input.root_hash[1]);
                // dbg!(&inner);
            }
            ZkSyncCircuit::MainVM(inner) => {
                let inner = inner.clone();
                dbg!(&inner.config);
                panic!();
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
        dbg!(&cs.input_assingments);
        println!("Checking if satisfied");
        let is_satisified = cs.is_satisfied();
        assert!(is_satisified);

        // // let worker = crate::sync_vm::franklin_crypto::bellman::worker::Worker::new();
        // // let setup = cs.create_setup(&worker).expect("must create setup");

        // let sponge_params = bn254_rescue_params();
        // let rns_params = get_prefered_rns_params();
        // let transcript_params = (&sponge_params, &rns_params);

        // // this only works for basic circuits

        // use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
        // // let vk =
        // // circuit_testing::create_vk::<Bn256, _, PlonkCsWidth4WithNextStepAndCustomGatesParams>(
        // //     circuit.clone(),
        // // )
        // // .unwrap();

        // use crate::sync_vm::recursion::RescueTranscriptForRecursion;
        // let (_proof, _vk) = circuit_testing::prove_only_circuit_for_params::<
        //     Bn256,
        //     _,
        //     PlonkCsWidth4WithNextStepAndCustomGatesParams,
        //     RescueTranscriptForRecursion<'_>,
        // >(circuit.clone(), Some(transcript_params), vk.clone(), None)
        // .unwrap();
    }

    #[test]
    fn one_off_proof() {
        let circuit_file_name = "prover_jobs_58348_452_L1 messages sorter_BasicCircuits.bin";
        let mut content = std::fs::File::open(circuit_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let circuit: ZkSyncCircuit<Bn256, VmWitnessOracle<Bn256>> =
            bincode::deserialize(&buffer).unwrap();

        let sponge_params = bn254_rescue_params();
        let rns_params = get_prefered_rns_params();
        let transcript_params = (&sponge_params, &rns_params);        

        use crate::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
        use sync_vm::recursion::RescueTranscriptForRecursion;

        let (proof, _vk) = circuit_testing::prove_and_verify_circuit_for_params::<
            Bn256,
            _,
            PlonkCsWidth4WithNextStepAndCustomGatesParams,
            RescueTranscriptForRecursion<'_>,
        >(
            circuit,
            Some(transcript_params)
        )
        .unwrap();

        // SERIALIZE PROOF!
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
