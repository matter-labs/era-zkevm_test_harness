//!
//! The methods in this file allows you to debug failing circuits from production.
//! Just pass the necessary contents of .bin file into the debug_basic or debug_recursive.
use crate::ethereum_types::U256;
use crate::{
    proof_wrapper_utils::{wrap_proof, WrapperConfig},
    prover_utils::verify_recursion_layer_proof_for_type,
    tests::{base_test_circuit, test_recursive_circuit},
};
use circuit_definitions::boojum::cs::implementations::pow::NoPow;
use circuit_definitions::circuit_definitions::{
    base_layer::{ZkSyncBaseLayerCircuit, ZkSyncBaseLayerProof},
    recursion_layer::{
        ZkSyncRecursionLayerProof, ZkSyncRecursionLayerStorageType,
        ZkSyncRecursionLayerVerificationKey, ZkSyncRecursiveLayerCircuit,
    },
};
use std::io::Read;

#[derive(serde::Serialize, serde::Deserialize)]
pub enum CircuitWrapper {
    Base(ZkSyncBaseLayerCircuit),
    Recursive(ZkSyncRecursiveLayerCircuit),
}

pub fn debug_circuit(buffer: &[u8]) {
    let circuit: CircuitWrapper = bincode::deserialize(&buffer).unwrap();
    match circuit {
        CircuitWrapper::Base(basic_circuit) => debug_basic_circuit(basic_circuit),
        CircuitWrapper::Recursive(recursive_circuit) => debug_recursive_circuit(recursive_circuit),
    }
}

fn debug_basic_circuit(circuit: ZkSyncBaseLayerCircuit) {
    let mut circuit = circuit.clone();
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
        ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
            let witness = inner.clone_witness().unwrap();
            let requests: Vec<_> = witness
                .requests_queue_witness
                .elements
                .iter()
                .map(|el| el.0.clone())
                .collect();
            dbg!(requests);
        }
        _ => {}
    }

    base_test_circuit(circuit);
}

fn debug_recursive_circuit(circuit: ZkSyncRecursiveLayerCircuit) {
    match &circuit {
        ZkSyncRecursiveLayerCircuit::SchedulerCircuit(_) => {
            // dbg!(&inner.witness.leaf_layer_parameters);
            // for el in inner.witness.proof_witnesses.iter() {
            //     let vk = inner.witness.node_layer_vk_witness.clone();
            //     // let vk = ZkSyncRecursionLayerVerificationKey::from_inner(ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8, vk);
            //     // let proof = ZkSyncRecursionLayerProof::from_inner(ZkSyncRecursionLayerStorageType::NodeLayerCircuit as u8, el.clone());
            //     let valid = verify_recursion_layer_proof_for_type::<NoPow>(
            //         ZkSyncRecursionLayerStorageType::NodeLayerCircuit,
            //         el,
            //         &vk,
            //     );
            //     assert!(valid);
            // }
            panic!("Scheduler circuit not supported yet");
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
        ZkSyncRecursiveLayerCircuit::RecursionTipCircuit(inner) => {
            let vk = inner.witness.vk_witness.clone();
            println!(
                "Got {:?} proofs to verify",
                inner.witness.proof_witnesses.len()
            );
            for (i, el) in inner.witness.proof_witnesses.iter().enumerate() {
                println!("Proof {:?} Starting verification", i);
                let valid = verify_recursion_layer_proof_for_type::<NoPow>(
                    ZkSyncRecursionLayerStorageType::NodeLayerCircuit,
                    el,
                    &vk,
                );
                assert!(valid);
                println!("Proof {:?} OK", i);
            }
        }

        _ => {
            panic!("Other recursion circuit types not supported yet");
        }
    }

    test_recursive_circuit(circuit);
}
