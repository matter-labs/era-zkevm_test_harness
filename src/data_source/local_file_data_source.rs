use super::{BlockDataSource, SetupDataSource, SourceResult};
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
use serde::Serialize;

use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::Setup as SnarkSetup;
use crate::snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;

use derivative::*;
use std::sync::Arc;
use std::{error::Error, fs::File};

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug)]
pub struct LocalFileDataSource;

impl LocalFileDataSource {
    pub const SETUP_DATA_LOCATION: &'static str = "./fresh/setup";
    pub const BLOCK_DATA_LOCATION: &'static str = "./fresh/test_proofs";

    /// creates folders if missing
    pub fn create_folders_for_storing_data() {
        let subfolders = ["/base_layer", "/recursion_layer", "/aux_layer"];

        for subfolder in subfolders.iter() {
            let dir_location = format!("{}{}", Self::SETUP_DATA_LOCATION, subfolder);
            if std::fs::read_dir(&dir_location).is_err() {
                std::fs::create_dir_all(dir_location).unwrap();
            }

            let dir_location = format!("{}{}", Self::BLOCK_DATA_LOCATION, subfolder);
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
        let file = File::open(format!(
            "{}/base_layer/vk_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_base_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerProof> {
        let file = File::open(format!(
            "{}/base_layer/padding_proof_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_base_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncBaseLayerFinalizationHint> {
        let file = File::open(format!(
            "{}/base_layer/finalization_hint_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        let file = File::open(format!(
            "{}/recursion_layer/vk_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_node_vk(&self) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        let file = File::open(format!(
            "{}/recursion_layer/vk_node.json",
            Self::SETUP_DATA_LOCATION
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_padding_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!(
            "{}/recursion_layer/padding_proof_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_leaf_padding_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!(
            "{}/recursion_layer/padding_proof_leaf.json",
            Self::SETUP_DATA_LOCATION
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_node_padding_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!(
            "{}/recursion_layer/padding_proof_node.json",
            Self::SETUP_DATA_LOCATION
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        let file = File::open(format!(
            "{}/recursion_layer/finalization_hint_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_recursion_layer_node_finalization_hint(
        &self,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        let file = File::open(format!(
            "{}/recursion_layer/finalization_hint_node.json",
            Self::SETUP_DATA_LOCATION
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_compression_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerVerificationKey> {
        let file = File::open(format!(
            "{}/aux_layer/compression_vk_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_compression_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerFinalizationHint> {
        let file = File::open(format!(
            "{}/aux_layer/compression_hint_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_compression_for_wrapper_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperVerificationKey> {
        let file = File::open(format!(
            "{}/aux_layer/compression_for_wrapper_vk_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_compression_for_wrapper_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperFinalizationHint> {
        let file = File::open(format!(
            "{}/aux_layer/compression_for_wrapper_hint_{}.json",
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_wrapper_setup(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperSetup> {
        println!("Read wrapper setup from file. Can take a while.");
        let start = std::time::Instant::now();

        let mut file = File::open(format!(
            "{}/aux_layer/wrapper_setup_{}.setup",
            Self::SETUP_DATA_LOCATION,
            circuit_type
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
            Self::SETUP_DATA_LOCATION,
            circuit_type
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

        LocalFileDataSource::write_pretty(
            format!(
                "{}/base_layer/vk_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            vk,
        )
    }
    fn set_base_layer_padding_proof(&mut self, proof: ZkSyncBaseLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/base_layer/padding_proof_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            proof,
        )
    }
    fn set_base_layer_finalization_hint(
        &mut self,
        hint: ZkSyncBaseLayerFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/base_layer/finalization_hint_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            hint,
        )
    }
    fn set_recursion_layer_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/recursion_layer/vk_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            vk,
        )
    }
    fn set_recursion_layer_node_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        LocalFileDataSource::write_pretty(
            format!("{}/recursion_layer/vk_node.json", Self::SETUP_DATA_LOCATION),
            &vk,
        )
    }
    fn set_recursion_layer_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();

        LocalFileDataSource::write_pretty(
            format!(
                "{}/recursion_layer/padding_proof_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            proof,
        )
    }
    fn set_recursion_layer_leaf_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        LocalFileDataSource::write_pretty(
            format!(
                "{}/recursion_layer/padding_proof_leaf.json",
                Self::SETUP_DATA_LOCATION
            ),
            proof,
        )
    }
    fn set_recursion_layer_node_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        LocalFileDataSource::write_pretty(
            format!(
                "{}/recursion_layer/padding_proof_node.json",
                Self::SETUP_DATA_LOCATION
            ),
            proof,
        )
    }
    fn set_recursion_layer_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/recursion_layer/finalization_hint_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            hint,
        )
    }
    fn set_recursion_layer_node_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        LocalFileDataSource::write_pretty(
            format!(
                "{}/recursion_layer/finalization_hint_node.json",
                Self::SETUP_DATA_LOCATION
            ),
            hint,
        )
    }
    fn set_compression_vk(
        &mut self,
        vk: ZkSyncCompressionLayerVerificationKey,
    ) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/setup/aux_layer/compression_vk_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            vk,
        )
    }
    fn set_compression_hint(
        &mut self,
        hint: ZkSyncCompressionLayerFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/aux_layer/compression_hint_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            hint,
        )
    }
    fn set_compression_for_wrapper_vk(
        &mut self,
        vk: ZkSyncCompressionForWrapperVerificationKey,
    ) -> SourceResult<()> {
        let circuit_type = vk.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/aux_layer/compression_for_wrapper_vk_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            vk,
        )
    }
    fn set_compression_for_wrapper_hint(
        &mut self,
        hint: ZkSyncCompressionForWrapperFinalizationHint,
    ) -> SourceResult<()> {
        let circuit_type = hint.numeric_circuit_type();
        LocalFileDataSource::write_pretty(
            format!(
                "{}/aux_layer/compression_for_wrapper_hint_{}.json",
                Self::SETUP_DATA_LOCATION,
                circuit_type
            ),
            hint,
        )
    }
    fn set_wrapper_setup(&mut self, setup: ZkSyncSnarkWrapperSetup) -> SourceResult<()> {
        println!("Writing wrapper setup to file. Can take a while.");
        let start = std::time::Instant::now();

        let circuit_type = setup.numeric_circuit_type();
        let mut file = File::create(format!(
            "{}/aux_layer/wrapper_setup_{}.setup",
            Self::SETUP_DATA_LOCATION,
            circuit_type
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
            Self::SETUP_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        vk.into_inner()
            .write(&mut file)
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }

    fn get_eip4844_vk(&self) -> SourceResult<EIP4844VerificationKey> {
        let file = File::open(format!(
            "{}/aux_layer/eip4844_vk.json",
            Self::SETUP_DATA_LOCATION,
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }

    fn set_eip4844_vk(&mut self, vk: EIP4844VerificationKey) -> SourceResult<()> {
        LocalFileDataSource::write_pretty(
            format!("{}/aux_layer/eip4844_vk.json", Self::SETUP_DATA_LOCATION,),
            vk,
        )
    }
}

impl BlockDataSource for LocalFileDataSource {
    fn get_base_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncBaseLayerProof> {
        let file = File::open(format!(
            "{}/base_layer/basic_circuit_proof_{}_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type,
            index
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_leaf_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!(
            "{}/recursion_layer/leaf_layer_proof_{}_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type,
            index
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_node_layer_proof(
        &self,
        circuit_type: u8,
        step: usize,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!(
            "{}/recursion_layer/node_layer_proof_{}_{}_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type,
            step,
            index
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_scheduler_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        let file = File::open(format!(
            "{}/recursion_layer/scheduler_proof.json",
            Self::BLOCK_DATA_LOCATION
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_compression_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncCompressionLayerProof> {
        let file = File::open(format!(
            "{}/aux_layer/compression_proof_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_compression_for_wrapper_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperProof> {
        let file = File::open(format!(
            "{}/aux_layer/compression_for_wrapper_proof_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        let result = serde_json::from_reader(file).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(result)
    }
    fn get_wrapper_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperProof> {
        let mut file = File::open(format!(
            "{}/aux_layer/wrapper_proof_{}.proof",
            Self::BLOCK_DATA_LOCATION,
            circuit_type
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
        let file = File::create(format!(
            "{}/base_layer/basic_circuit_proof_{}_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type,
            index
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_leaf_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!(
            "{}/recursion_layer/leaf_layer_proof_{}_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type,
            index
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_node_layer_proof(
        &mut self,
        circuit_type: u8,
        step: usize,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        let file = File::create(format!(
            "{}/recursion_layer/node_layer_proof_{}_{}_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type,
            step,
            index
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_scheduler_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        let file = File::create(format!(
            "{}/recursion_layer/scheduler_proof.json",
            Self::BLOCK_DATA_LOCATION
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_compression_proof(&mut self, proof: ZkSyncCompressionLayerProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!(
            "{}/aux_layer/compression_proof_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_compression_for_wrapper_proof(
        &mut self,
        proof: ZkSyncCompressionForWrapperProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let file = File::create(format!(
            "{}/aux_layer/compression_for_wrapper_proof_{}.json",
            Self::BLOCK_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;
        serde_json::to_writer(file, &proof).map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
    fn set_wrapper_proof(&mut self, proof: ZkSyncSnarkWrapperProof) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        let mut file = File::create(format!(
            "{}/aux_layer/wrapper_proof_{}.proof",
            Self::BLOCK_DATA_LOCATION,
            circuit_type
        ))
        .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        proof
            .into_inner()
            .write(&mut file)
            .map_err(|el| Box::new(el) as Box<dyn Error>)?;

        Ok(())
    }
}
