use super::{BlockDataSource, SetupDataSource, SourceResult};
use circuit_definitions::boojum::cs::implementations::setup::FinalizationHintsForProver;
use circuit_definitions::circuit_definitions::aux_layer::{
    EIP4844VerificationKey, ZkSyncCompressionForWrapperFinalizationHint,
    ZkSyncCompressionForWrapperProof, ZkSyncCompressionForWrapperVerificationKey,
    ZkSyncCompressionLayerFinalizationHint, ZkSyncCompressionLayerProof,
    ZkSyncCompressionLayerVerificationKey, ZkSyncSnarkWrapperProof, ZkSyncSnarkWrapperSetup,
    ZkSyncSnarkWrapperVK,
};
use circuit_definitions::circuit_definitions::base_layer::{
    ZkSyncBaseLayerFinalizationHint, ZkSyncBaseLayerProof, ZkSyncBaseLayerVerificationKey,
};
use circuit_definitions::circuit_definitions::recursion_layer::{
    ZkSyncRecursionLayerFinalizationHint, ZkSyncRecursionLayerProof,
    ZkSyncRecursionLayerVerificationKey,
};
use serde::{Deserialize, Serialize};

use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::Setup as SnarkSetup;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;

use derivative::*;
use std::sync::Arc;
use std::{error::Error, fs::File};

#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct LocalFileDataSource {
    pub setup_data_location: String,
    pub block_data_location: String,
}

impl Default for LocalFileDataSource {
    fn default() -> Self {
        Self {
            setup_data_location: "./setup".to_string(),
            block_data_location: "./test_proofs".to_string(),
        }
    }
}

impl LocalFileDataSource {
    fn get_proof<T: for<'de> Deserialize<'de>>(&self, file_name: String) -> SourceResult<T> {
        let file = File::open(format!("{}/{}.json", self.block_data_location, file_name))
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }

    fn set_proof<T: Serialize>(&self, file_name: String, proof: T) -> SourceResult<()> {
        let file = File::create(format!("{}/{}.json", self.block_data_location, file_name))
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;
        Ok(())
    }

    fn get_setup_data<T: for<'de> Deserialize<'de>>(&self, file_name: String) -> SourceResult<T> {
        let file = File::open(format!("{}/{}.json", self.setup_data_location, file_name))
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }

    fn set_setup_data<T: Serialize>(&self, file_name: String, data: T) -> SourceResult<()> {
        LocalFileDataSource::write_pretty(
            format!("{}/{}.json", self.setup_data_location, file_name),
            data,
        )
    }

    /// creates folders if missing
    pub fn create_folders_for_storing_data(&self) {
        let subfolders = ["/base_layer", "/recursion_layer", "/aux_layer"];

        for subfolder in subfolders.iter() {
            let dir_location = format!("{}{}", self.setup_data_location, subfolder);
            if std::fs::read_dir(&dir_location).is_err() {
                std::fs::create_dir_all(dir_location).unwrap();
            }

            let dir_location = format!("{}{}", self.block_data_location, subfolder);
            if std::fs::read_dir(&dir_location).is_err() {
                std::fs::create_dir_all(dir_location).unwrap();
            }
        }
    }
    pub fn write_pretty<T: Serialize>(filepath: String, proof: T) -> SourceResult<()> {
        std::fs::write(&filepath, serde_json::to_string_pretty(&proof).unwrap())
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        Ok(())
    }
}

impl SetupDataSource for LocalFileDataSource {
    fn get_base_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerVerificationKey> {
        self.get_setup_data(format!("base_layer/vk_{}", circuit_type))
    }
    fn get_base_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncBaseLayerFinalizationHint> {
        self.get_setup_data(format!("base_layer/finalization_hint_{}", circuit_type))
    }
    fn get_recursion_layer_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        self.get_setup_data(format!("recursion_layer/vk_{}", circuit_type))
    }
    fn get_recursion_layer_node_vk(&self) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        self.get_setup_data("recursion_layer/vk_node".to_string())
    }
    fn get_recursion_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        self.get_setup_data(format!(
            "recursion_layer/finalization_hint_{}",
            circuit_type
        ))
    }
    fn get_recursion_layer_node_finalization_hint(
        &self,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        self.get_setup_data("recursion_layer/finalization_hint_node".to_string())
    }

    fn get_compression_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerVerificationKey> {
        self.get_setup_data(format!("aux_layer/compression_vk_{}", circuit_type))
    }
    fn get_compression_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerFinalizationHint> {
        self.get_setup_data(format!("aux_layer/compression_hint_{}", circuit_type))
    }
    fn get_compression_for_wrapper_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperVerificationKey> {
        self.get_setup_data(format!(
            "aux_layer/compression_for_wrapper_vk_{}",
            circuit_type
        ))
    }
    fn get_compression_for_wrapper_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperFinalizationHint> {
        self.get_setup_data(format!(
            "aux_layer/compression_for_wrapper_hint_{}",
            circuit_type
        ))
    }
    fn get_wrapper_setup(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperSetup> {
        println!("Read wrapper setup from file. Can take a while.");
        let start = std::time::Instant::now();

        let mut file = File::open(format!(
            "{}/aux_layer/wrapper_setup_{}.setup",
            self.setup_data_location, circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        let result =
            Arc::new(SnarkSetup::read(&mut file).map_err(|el| Box::new(el) as Box<dyn Error>)?);

        let result = ZkSyncSnarkWrapperSetup::from_inner(circuit_type, result);

        println!("Wrapper setup read from file. Took {:?}", start.elapsed());

        Ok(result)
    }
    fn get_wrapper_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperVK> {
        let mut file = File::open(format!(
            "{}/aux_layer/wrapper_vk_{}.key",
            self.setup_data_location, circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        let result = ZkSyncSnarkWrapperVK::from_inner(
            circuit_type,
            SnarkVK::read(&mut file).map_err(|el| Box::new(el) as Box<dyn Error>)?,
        );

        Ok(result)
    }

    fn set_base_layer_vk(&mut self, vk: ZkSyncBaseLayerVerificationKey) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        self.set_setup_data(format!("base_layer/vk_{}", circuit_type), vk)
    }

    fn set_base_layer_finalization_hint(
        &mut self,
        hint: ZkSyncBaseLayerFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        self.set_setup_data(
            format!("base_layer/finalization_hint_{}", circuit_type),
            hint,
        )
    }
    fn set_recursion_layer_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        self.set_setup_data(format!("recursion_layer/vk_{}", circuit_type), vk)
    }
    fn set_recursion_layer_node_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        self.set_setup_data("recursion_layer/vk_node".to_string(), vk)
    }

    fn set_recursion_layer_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        self.set_setup_data(
            format!("recursion_layer/finalization_hint_{}", circuit_type),
            hint,
        )
    }
    fn set_recursion_layer_node_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        self.set_setup_data("recursion_layer/finalization_hint_node".to_string(), hint)
    }
    fn set_compression_vk(
        &mut self,
        vk: ZkSyncCompressionLayerVerificationKey,
    ) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        self.set_setup_data(format!("aux_layer/compression_vk_{}", circuit_type), vk)
    }
    fn set_compression_hint(
        &mut self,
        hint: ZkSyncCompressionLayerFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        self.set_setup_data(format!("aux_layer/compression_hint_{}", circuit_type), hint)
    }
    fn set_compression_for_wrapper_vk(
        &mut self,
        vk: ZkSyncCompressionForWrapperVerificationKey,
    ) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        self.set_setup_data(
            format!("aux_layer/compression_for_wrapper_vk_{}", circuit_type),
            vk,
        )
    }
    fn set_compression_for_wrapper_hint(
        &mut self,
        hint: ZkSyncCompressionForWrapperFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        self.set_setup_data(
            format!("aux_layer/compression_for_wrapper_hint_{}", circuit_type),
            hint,
        )
    }
    fn set_wrapper_setup(&mut self, setup: ZkSyncSnarkWrapperSetup) -> SourceResult<()> {
        println!("Writing wrapper setup to file. Can take a while.");
        let start = std::time::Instant::now();

        let circuit_type = setup.numeric_circuit_type();
        let mut file = File::create(format!(
            "{}/aux_layer/wrapper_setup_{}.setup",
            self.setup_data_location, circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        setup
            .into_inner()
            .write(&mut file)
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        println!("Wrapper setup written to file. Took {:?}", start.elapsed());

        Ok(())
    }
    fn set_wrapper_vk(&mut self, vk: ZkSyncSnarkWrapperVK) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        let mut file = File::create(format!(
            "{}/aux_layer/wrapper_vk_{}.key",
            self.setup_data_location, circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        vk.into_inner()
            .write(&mut file)
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }

    fn get_recursion_tip_vk(&self) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        self.get_setup_data("recursion_layer/vk_recursion_tip".to_string())
    }
    fn get_recursion_tip_finalization_hint(
        &self,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        self.get_setup_data("recursion_layer/finalization_hint_recursion_tip".to_string())
    }
    fn set_recursion_tip_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        self.set_setup_data("recursion_layer/vk_recursion_tip".to_string(), vk)
    }
    fn set_recursion_tip_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        self.set_setup_data(
            "recursion_layer/finalization_hint_recursion_tip".to_string(),
            hint,
        )
    }
}

impl BlockDataSource for LocalFileDataSource {
    fn get_base_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncBaseLayerProof> {
        self.get_proof(format!(
            "base_layer/basic_circuit_proof_{}_{}",
            circuit_type, index
        ))
    }

    fn get_leaf_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.get_proof(format!(
            "recursion_layer/leaf_layer_proof_{}_{}",
            circuit_type, index
        ))
    }
    fn get_node_layer_proof(
        &self,
        circuit_type: u8,
        step: usize,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.get_proof(format!(
            "recursion_layer/node_layer_proof_{}_{}_{}",
            circuit_type, step, index
        ))
    }

    fn get_scheduler_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.get_proof("recursion_layer/scheduler_proof".to_string())
    }
    fn get_compression_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncCompressionLayerProof> {
        self.get_proof(format!("aux_layer/compression_proof_{}", circuit_type))
    }

    fn get_compression_for_wrapper_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperProof> {
        self.get_proof(format!(
            "aux_layer/compression_for_wrapper_proof_{}",
            circuit_type
        ))
    }
    fn get_wrapper_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperProof> {
        let mut file = File::open(format!(
            "{}/aux_layer/wrapper_proof_{}.proof",
            self.block_data_location, circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        let result = ZkSyncSnarkWrapperProof::from_inner(
            circuit_type,
            SnarkProof::read(&mut file).map_err(|el| Box::new(el) as Box<dyn Error>)?,
        );

        Ok(result)
    }

    fn set_base_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncBaseLayerProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        self.set_proof(
            format!("base_layer/basic_circuit_proof_{}_{}", circuit_type, index),
            proof,
        )
    }

    fn set_leaf_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        self.set_proof(
            format!(
                "recursion_layer/leaf_layer_proof_{}_{}",
                circuit_type, index
            ),
            proof,
        )
    }
    fn set_node_layer_proof(
        &mut self,
        circuit_type: u8,
        step: usize,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        self.set_proof(
            format!(
                "recursion_layer/node_layer_proof_{}_{}_{}",
                circuit_type, step, index
            ),
            proof,
        )
    }
    fn set_scheduler_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        self.set_proof("recursion_layer/scheduler_proof".to_string(), proof)
    }
    fn set_compression_proof(&mut self, proof: ZkSyncCompressionLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        self.set_proof(
            format!("aux_layer/compression_proof_{}", circuit_type),
            proof,
        )
    }
    fn set_compression_for_wrapper_proof(
        &mut self,
        proof: ZkSyncCompressionForWrapperProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        self.set_proof(
            format!("aux_layer/compression_for_wrapper_proof_{}", circuit_type),
            proof,
        )
    }
    fn set_wrapper_proof(&mut self, proof: ZkSyncSnarkWrapperProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let mut file = File::create(format!(
            "{}/aux_layer/wrapper_proof_{}.proof",
            self.block_data_location, circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        proof
            .into_inner()
            .write(&mut file)
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_recursive_tip_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        self.set_proof("recursion_layer/recursive_tip_proof".to_string(), proof)
    }

    fn get_recursive_tip_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.get_proof("recursion_layer/recursive_tip_proof".to_string())
    }
}
