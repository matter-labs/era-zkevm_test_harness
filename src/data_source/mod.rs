use super::*;
use std::{error::Error, fs::File};

use circuit_definitions::circuit_definitions::aux_layer::*;
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::circuit_definitions::recursion_layer::*;

use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::proof::Proof as SnarkProof;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey as SnarkVK;

pub type SourceResult<T> = Result<T, Box<dyn Error>>;

use derivative::*;

pub mod in_memory_data_source;
pub mod local_file_data_source;

// Object save trait to just get things for SYSTEM
pub trait SetupDataSource {
    fn get_base_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerVerificationKey>;
    fn get_base_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerProof>;
    fn get_base_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncBaseLayerFinalizationHint>;
    fn get_recursion_layer_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerVerificationKey>;
    fn get_recursion_layer_node_vk(&self) -> SourceResult<ZkSyncRecursionLayerVerificationKey>;
    fn get_recursion_layer_padding_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_recursion_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint>;
    fn get_recursion_layer_leaf_padding_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_recursion_layer_node_padding_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_recursion_layer_node_finalization_hint(
        &self,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint>;
    fn get_compression_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerVerificationKey>;
    fn get_compression_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerFinalizationHint>;
    fn get_compression_for_wrapper_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperVerificationKey>;
    fn get_compression_for_wrapper_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperFinalizationHint>;
    fn get_wrapper_setup(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperSetup>;
    fn get_wrapper_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperVK>;

    fn set_base_layer_vk(&mut self, vk: ZkSyncBaseLayerVerificationKey) -> SourceResult<()>;
    fn set_base_layer_padding_proof(&mut self, proof: ZkSyncBaseLayerProof) -> SourceResult<()>;
    fn set_base_layer_finalization_hint(
        &mut self,
        hint: ZkSyncBaseLayerFinalizationHint,
    ) -> SourceResult<()>;
    fn set_recursion_layer_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()>;
    fn set_recursion_layer_node_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()>;
    fn set_recursion_layer_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()>;
    fn set_recursion_layer_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()>;
    fn set_recursion_layer_leaf_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()>;
    fn set_recursion_layer_node_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()>;
    fn set_recursion_layer_node_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()>;
    fn set_compression_vk(&mut self, vk: ZkSyncCompressionLayerVerificationKey)
        -> SourceResult<()>;
    fn set_compression_hint(
        &mut self,
        hint: ZkSyncCompressionLayerFinalizationHint,
    ) -> SourceResult<()>;
    fn set_compression_for_wrapper_vk(
        &mut self,
        vk: ZkSyncCompressionForWrapperVerificationKey,
    ) -> SourceResult<()>;
    fn set_compression_for_wrapper_hint(
        &mut self,
        hint: ZkSyncCompressionForWrapperFinalizationHint,
    ) -> SourceResult<()>;
    fn set_wrapper_setup(&mut self, setup: ZkSyncSnarkWrapperSetup) -> SourceResult<()>;
    fn set_wrapper_vk(&mut self, vk: ZkSyncSnarkWrapperVK) -> SourceResult<()>;
}

// Object save trait to just get things for BLOCK
pub trait BlockDataSource {
    fn get_base_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncBaseLayerProof>;
    fn get_leaf_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_node_layer_proof(
        &self,
        circuit_type: u8,
        step: usize,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_scheduler_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof>;
    fn get_compression_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncCompressionLayerProof>;
    fn get_compression_for_wrapper_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperProof>;
    fn get_wrapper_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperProof>;

    fn set_base_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncBaseLayerProof,
    ) -> SourceResult<()>;
    fn set_leaf_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()>;
    fn set_node_layer_proof(
        &mut self,
        circuit_type: u8,
        step: usize,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()>;
    fn set_scheduler_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()>;
    fn set_compression_proof(&mut self, proof: ZkSyncCompressionLayerProof) -> SourceResult<()>;
    fn set_compression_for_wrapper_proof(
        &mut self,
        proof: ZkSyncCompressionForWrapperProof,
    ) -> SourceResult<()>;
    fn set_wrapper_proof(&mut self, proof: ZkSyncSnarkWrapperProof) -> SourceResult<()>;
}
