#[cfg(test)]
mod test {
    use crate::proof_wrapper_utils::wrap_proof;

    use super::super::*;
    use std::io::Read;

    #[ignore = "For manual running only"]
    #[test]
    fn read_and_run() {
        let circuit_file_name = "prover_jobs_23_05.bin";
        let buffer = std::fs::read(circuit_file_name).unwrap();
        debug::debug_circuit(&buffer);
    }

    #[ignore = "For manual running only"]
    #[test]
    fn test_and_run_recursive() {
        let circuit_file_name = "prover_jobs_fri_38142_0_3_NodeAggregation_1_raw.bin";
        let buffer = std::fs::read(circuit_file_name).unwrap();
        debug::debug_circuit(&buffer);
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    pub enum FriProofWrapper {
        Base(ZkSyncBaseLayerProof),
        Recursive(ZkSyncRecursionLayerProof),
    }

    #[ignore = "For manual running only"]
    #[test]
    fn test_wrapper_layer() {
        let proof_file_name = "proofs_fri_proof_33908687.bin";

        let mut content = std::fs::File::open(proof_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let proof: FriProofWrapper = bincode::deserialize(&buffer).unwrap();

        let vk_file_name = "scheduler_vk.json";

        let mut content = std::fs::File::open(vk_file_name).unwrap();
        let mut buffer = vec![];
        content.read_to_end(&mut buffer).unwrap();
        let vk: ZkSyncRecursionLayerVerificationKey = serde_json::from_slice(&buffer).unwrap();

        let FriProofWrapper::Recursive(proof) = proof else {
            panic!();
        };

        let config = WrapperConfig::new(1);
        let _ = wrap_proof(proof, vk, config);
    }
}
