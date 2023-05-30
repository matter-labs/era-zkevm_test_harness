use super::*;
use std::{fs::File, error::Error};

use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::*;

pub type SourceResult<T> = Result<T, Box<dyn Error>>;

use derivative::*;

// Object save trait to just get things for SYSTEM
pub trait SetupDataSource {
    fn get_base_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerVerificationKey>;
    fn get_base_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerProof>;
    fn get_base_layer_finalization_hint(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerFinalizationHint>;
    fn get_recursion_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncRecursionLayerVerificationKey>;
    fn get_recursion_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_recursion_layer_finalization_hint(&self, circuit_type: u8) -> SourceResult<ZkSyncRecursionLayerFinalizationHint>;

    fn set_base_layer_vk(&mut self, vk: ZkSyncBaseLayerVerificationKey) -> SourceResult<()>;
    fn set_base_layer_padding_proof(&mut self, proof: ZkSyncBaseLayerProof) -> SourceResult<()>;
    fn set_base_layer_finalization_hint(&self, hint: ZkSyncBaseLayerFinalizationHint) -> SourceResult<()>;
    fn set_recursion_layer_vk(&mut self, vk: ZkSyncRecursionLayerVerificationKey) -> SourceResult<()>;
    fn set_recursion_layer_padding_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()>;
    fn set_recursion_layer_finalization_hint(&self, hint: ZkSyncRecursionLayerFinalizationHint) -> SourceResult<()>;
}

// Object save trait to just get things for BLOCK
pub trait BlockDataSource {
    fn get_base_layer_proof(&self, circuit_type: u8, index: usize) -> SourceResult<ZkSyncBaseLayerProof>;
    fn get_leaf_layer_proof(&self, circuit_type: u8, index: usize) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_node_layer_proof(&self, circuit_type: u8, step: usize, index: usize) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_scheduler_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof>;

    fn set_base_layer_proof(&mut self, index: usize, proof: ZkSyncBaseLayerProof) -> SourceResult<()>;
    fn set_leaf_layer_proof(&mut self, index: usize, proof: ZkSyncRecursionLayerProof) -> SourceResult<()>;
    fn set_node_layer_proof(&mut self, step: usize, index: usize, proof: ZkSyncRecursionLayerProof) -> SourceResult<()>;
    fn set_scheduler_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()>;
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug)]
pub struct LocalFileDataSource;

impl SetupDataSource for LocalFileDataSource {
    fn get_base_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerVerificationKey> {
        let file = File::open(format!("./setup/base_layer/vk_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_base_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerProof> {
        let file = File::open(format!("./setup/base_layer/padding_proof_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_base_layer_finalization_hint(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerFinalizationHint> {
        let file = File::open(format!("./setup/base_layer/finalization_hint_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        let file = File::open(format!("./setup/recursion_layer/vk_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!("./setup/recursion_layer/padding_proof_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_finalization_hint(&self, circuit_type: u8) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        let file = File::open(format!("./setup/recursion_layer/finalization_hint_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }

    fn set_base_layer_vk(&mut self, vk: ZkSyncBaseLayerVerificationKey) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        let file = File::create(format!("./setup/base_layer/vk_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &vk).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_base_layer_padding_proof(&mut self, proof: ZkSyncBaseLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!("./setup/base_layer/padding_proof_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_base_layer_finalization_hint(&self, hint: ZkSyncBaseLayerFinalizationHint) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        let file = File::create(format!("./setup/base_layer/finalization_hint_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &hint).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_recursion_layer_vk(&mut self, vk: ZkSyncRecursionLayerVerificationKey) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        let file = File::create(format!("./setup/recursion_layer/vk_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &vk).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_recursion_layer_padding_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!("./setup/recursion_layer/padding_proof_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_recursion_layer_finalization_hint(&self, hint: ZkSyncRecursionLayerFinalizationHint) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        let file = File::create(format!("./setup/recursion_layer/finalization_hint_{}.json", circuit_type)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &hint).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
}

impl BlockDataSource for LocalFileDataSource {
    fn get_base_layer_proof(&self, circuit_type: u8, index: usize) -> SourceResult<ZkSyncBaseLayerProof> {
        let file = File::open(format!("./test_proofs/base_layer/basic_circuit_proof_{}_{}.json", circuit_type, index)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_leaf_layer_proof(&self, circuit_type: u8, index: usize) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!("./test_proofs/recursion_layer/leaf_layer_proof_{}_{}.json", circuit_type, index)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_node_layer_proof(&self, circuit_type: u8, step: usize, index: usize) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!("./test_proofs/recursion_layer/node_layer_proof_{}_{}_{}.json", circuit_type, step, index)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_scheduler_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open("./test_proofs/recursion_layer/scheduler_proof.json").map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }

    fn set_base_layer_proof(&mut self, index: usize, proof: ZkSyncBaseLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!("./test_proofs/base_layer/basic_circuit_proof_{}_{}.json", circuit_type, index)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_leaf_layer_proof(&mut self, index: usize, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!("./test_proofs/recursion_layer/leaf_layer_proof_{}_{}.json", circuit_type, index)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_node_layer_proof(&mut self, step: usize, index: usize, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!("./test_proofs/recursion_layer/node_layer_proof_{}_{}_{}.json", circuit_type, step, index)).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_scheduler_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        let file = File::create("./test_proofs/recursion_layer/scheduler_proof.json").map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
}