use super::{BlockDataSource, SetupDataSource, SourceResult};
use circuit_definitions::circuit_definitions::aux_layer::{
    ZkSyncCompressionForWrapperFinalizationHint, ZkSyncCompressionForWrapperProof,
    ZkSyncCompressionForWrapperVerificationKey, ZkSyncCompressionLayerFinalizationHint,
    ZkSyncCompressionLayerProof, ZkSyncCompressionLayerVerificationKey, ZkSyncSnarkWrapperProof,
    ZkSyncSnarkWrapperSetup, ZkSyncSnarkWrapperVK,
};
use circuit_definitions::circuit_definitions::base_layer::{
    ZkSyncBaseLayerFinalizationHint, ZkSyncBaseLayerProof, ZkSyncBaseLayerVerificationKey,
};
use circuit_definitions::circuit_definitions::recursion_layer::{
    ZkSyncRecursionLayerFinalizationHint, ZkSyncRecursionLayerProof,
    ZkSyncRecursionLayerVerificationKey,
};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};

pub struct InMemoryDataSource {
    ///data structures required for holding [`SetupDataSource`] result
    base_layer_vk: HashMap<u8, ZkSyncBaseLayerVerificationKey>,
    base_layer_padding_proof: HashMap<u8, ZkSyncBaseLayerProof>,
    base_layer_finalization_hint: HashMap<u8, ZkSyncBaseLayerFinalizationHint>,
    recursion_layer_vk: HashMap<u8, ZkSyncRecursionLayerVerificationKey>,
    recursion_layer_node_vk: Option<ZkSyncRecursionLayerVerificationKey>,
    recursion_layer_padding_proof: HashMap<u8, ZkSyncRecursionLayerProof>,
    recursion_layer_finalization_hint: HashMap<u8, ZkSyncRecursionLayerFinalizationHint>,
    recursion_layer_leaf_padding_proof: Option<ZkSyncRecursionLayerProof>,
    recursion_layer_node_padding_proof: Option<ZkSyncRecursionLayerProof>,
    recursion_layer_node_finalization_hint: Option<ZkSyncRecursionLayerFinalizationHint>,
    compression_vk: HashMap<u8, ZkSyncCompressionLayerVerificationKey>,
    compression_hint: HashMap<u8, ZkSyncCompressionLayerFinalizationHint>,
    compression_for_wrapper_vk: HashMap<u8, ZkSyncCompressionForWrapperVerificationKey>,
    compression_for_wrapper_hint: HashMap<u8, ZkSyncCompressionForWrapperFinalizationHint>,
    wrapper_setup: HashMap<u8, ZkSyncSnarkWrapperSetup>,
    wrapper_vk: HashMap<u8, ZkSyncSnarkWrapperVK>,

    ///data structures required for holding [`BlockDataSource`] result
    base_layer_proofs: HashMap<(u8, usize), ZkSyncBaseLayerProof>,
    leaf_layer_proofs: HashMap<(u8, usize), ZkSyncRecursionLayerProof>,
    node_layer_proofs: HashMap<(u8, usize, usize), ZkSyncRecursionLayerProof>,
    scheduler_proof: Option<ZkSyncRecursionLayerProof>,
    compression_proof: HashMap<u8, ZkSyncCompressionLayerProof>,
    compression_for_wrapper_proof: HashMap<u8, ZkSyncCompressionForWrapperProof>,
    wrapper_proof: HashMap<u8, ZkSyncSnarkWrapperProof>,
}

impl InMemoryDataSource {
    pub fn new() -> Self {
        InMemoryDataSource {
            base_layer_vk: HashMap::new(),
            base_layer_padding_proof: HashMap::new(),
            base_layer_finalization_hint: HashMap::new(),
            recursion_layer_vk: HashMap::new(),
            recursion_layer_node_vk: None,
            recursion_layer_padding_proof: HashMap::new(),
            recursion_layer_finalization_hint: HashMap::new(),
            recursion_layer_leaf_padding_proof: None,
            recursion_layer_node_padding_proof: None,
            recursion_layer_node_finalization_hint: None,
            compression_vk: HashMap::new(),
            compression_hint: HashMap::new(),
            compression_for_wrapper_vk: HashMap::new(),
            compression_for_wrapper_hint: HashMap::new(),
            wrapper_setup: HashMap::new(),
            wrapper_vk: HashMap::new(),
            base_layer_proofs: HashMap::new(),
            leaf_layer_proofs: HashMap::new(),
            node_layer_proofs: HashMap::new(),
            scheduler_proof: None,
            compression_proof: HashMap::new(),
            compression_for_wrapper_proof: HashMap::new(),
            wrapper_proof: HashMap::new(),
        }
    }
}

impl SetupDataSource for InMemoryDataSource {
    fn get_base_layer_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerVerificationKey> {
        self.base_layer_vk
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_base_layer_padding_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncBaseLayerProof> {
        self.base_layer_padding_proof
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_base_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncBaseLayerFinalizationHint> {
        self.base_layer_finalization_hint
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_recursion_layer_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        self.recursion_layer_vk
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_recursion_layer_node_vk(&self) -> SourceResult<ZkSyncRecursionLayerVerificationKey> {
        Ok(self.recursion_layer_node_vk.clone().unwrap())
    }

    fn get_recursion_layer_padding_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.recursion_layer_padding_proof
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_recursion_layer_finalization_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        self.recursion_layer_finalization_hint
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_recursion_layer_leaf_padding_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        Ok(self.recursion_layer_leaf_padding_proof.clone().unwrap())
    }

    fn get_recursion_layer_node_padding_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        Ok(self.recursion_layer_node_padding_proof.clone().unwrap())
    }

    fn get_recursion_layer_node_finalization_hint(
        &self,
    ) -> SourceResult<ZkSyncRecursionLayerFinalizationHint> {
        Ok(self.recursion_layer_node_finalization_hint.clone().unwrap())
    }

    fn get_compression_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerVerificationKey> {
        self.compression_vk
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_compression_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionLayerFinalizationHint> {
        self.compression_hint
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_compression_for_wrapper_vk(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperVerificationKey> {
        self.compression_for_wrapper_vk
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_compression_for_wrapper_hint(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperFinalizationHint> {
        self.compression_for_wrapper_hint
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_wrapper_setup(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperSetup> {
        self.wrapper_setup
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_wrapper_vk(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperVK> {
        self.wrapper_vk
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn set_base_layer_vk(&mut self, vk: ZkSyncBaseLayerVerificationKey) -> SourceResult<()> {
        self.base_layer_vk.insert(vk.numeric_circuit_type(), vk);
        Ok(())
    }

    fn set_base_layer_padding_proof(&mut self, proof: ZkSyncBaseLayerProof) -> SourceResult<()> {
        self.base_layer_padding_proof
            .insert(proof.numeric_circuit_type(), proof);
        Ok(())
    }

    fn set_base_layer_finalization_hint(
        &mut self,
        hint: ZkSyncBaseLayerFinalizationHint,
    ) -> SourceResult<()> {
        self.base_layer_finalization_hint
            .insert(hint.numeric_circuit_type(), hint);
        Ok(())
    }

    fn set_recursion_layer_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        self.recursion_layer_vk
            .insert(vk.numeric_circuit_type(), vk);
        Ok(())
    }

    fn set_recursion_layer_node_vk(
        &mut self,
        vk: ZkSyncRecursionLayerVerificationKey,
    ) -> SourceResult<()> {
        self.recursion_layer_node_vk = Some(vk);
        Ok(())
    }

    fn set_recursion_layer_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        self.recursion_layer_padding_proof
            .insert(proof.numeric_circuit_type(), proof);
        Ok(())
    }

    fn set_recursion_layer_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        self.recursion_layer_finalization_hint
            .insert(hint.numeric_circuit_type(), hint);
        Ok(())
    }

    fn set_recursion_layer_leaf_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        self.recursion_layer_leaf_padding_proof = Some(proof);
        Ok(())
    }

    fn set_recursion_layer_node_padding_proof(
        &mut self,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        self.recursion_layer_node_padding_proof = Some(proof);
        Ok(())
    }

    fn set_recursion_layer_node_finalization_hint(
        &mut self,
        hint: ZkSyncRecursionLayerFinalizationHint,
    ) -> SourceResult<()> {
        self.recursion_layer_node_finalization_hint = Some(hint);
        Ok(())
    }

    fn set_compression_vk(
        &mut self,
        vk: ZkSyncCompressionLayerVerificationKey,
    ) -> SourceResult<()> {
        self.compression_vk.insert(vk.numeric_circuit_type(), vk);
        Ok(())
    }

    fn set_compression_hint(
        &mut self,
        hint: ZkSyncCompressionLayerFinalizationHint,
    ) -> SourceResult<()> {
        self.compression_hint
            .insert(hint.numeric_circuit_type(), hint);
        Ok(())
    }

    fn set_compression_for_wrapper_vk(
        &mut self,
        vk: ZkSyncCompressionForWrapperVerificationKey,
    ) -> SourceResult<()> {
        self.compression_for_wrapper_vk
            .insert(vk.numeric_circuit_type(), vk);
        Ok(())
    }

    fn set_compression_for_wrapper_hint(
        &mut self,
        hint: ZkSyncCompressionForWrapperFinalizationHint,
    ) -> SourceResult<()> {
        self.compression_for_wrapper_hint
            .insert(hint.numeric_circuit_type(), hint);
        Ok(())
    }

    fn set_wrapper_setup(&mut self, setup: ZkSyncSnarkWrapperSetup) -> SourceResult<()> {
        self.wrapper_setup
            .insert(setup.numeric_circuit_type(), setup);
        Ok(())
    }

    fn set_wrapper_vk(&mut self, vk: ZkSyncSnarkWrapperVK) -> SourceResult<()> {
        self.wrapper_vk.insert(vk.numeric_circuit_type(), vk);
        Ok(())
    }
}

impl BlockDataSource for InMemoryDataSource {
    fn get_base_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncBaseLayerProof> {
        self.base_layer_proofs
            .get(&(circuit_type, index))
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!(
                    "no base layer proof for circuit type {} index {}",
                    circuit_type, index
                ),
            )))
    }

    fn get_leaf_layer_proof(
        &self,
        circuit_type: u8,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.leaf_layer_proofs
            .get(&(circuit_type, index))
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!(
                    "no leaf layer proof for circuit type {} index {}",
                    circuit_type, index
                ),
            )))
    }

    fn get_node_layer_proof(
        &self,
        circuit_type: u8,
        step: usize,
        index: usize,
    ) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.node_layer_proofs
            .get(&(circuit_type, step, index))
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!(
                    "no node layer proof for circuit type {} index {} step {}",
                    circuit_type, index, step
                ),
            )))
    }

    fn get_scheduler_proof(&self) -> SourceResult<ZkSyncRecursionLayerProof> {
        self.scheduler_proof.clone().ok_or(Box::new(Error::new(
            ErrorKind::Other,
            format!("no scheduler proof"),
        )))
    }

    fn get_compression_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncCompressionLayerProof> {
        self.compression_proof
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_compression_for_wrapper_proof(
        &self,
        circuit_type: u8,
    ) -> SourceResult<ZkSyncCompressionForWrapperProof> {
        self.compression_for_wrapper_proof
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn get_wrapper_proof(&self, circuit_type: u8) -> SourceResult<ZkSyncSnarkWrapperProof> {
        self.wrapper_proof
            .get(&circuit_type)
            .cloned()
            .ok_or(Box::new(Error::new(
                ErrorKind::Other,
                format!("no data for circuit type {}", circuit_type),
            )))
    }

    fn set_base_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncBaseLayerProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        self.base_layer_proofs.insert((circuit_type, index), proof);
        Ok(())
    }

    fn set_leaf_layer_proof(
        &mut self,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        let circuit_type = proof.numeric_circuit_type();
        self.leaf_layer_proofs.insert((circuit_type, index), proof);
        Ok(())
    }

    fn set_node_layer_proof(
        &mut self,
        circuit_type: u8,
        step: usize,
        index: usize,
        proof: ZkSyncRecursionLayerProof,
    ) -> SourceResult<()> {
        self.node_layer_proofs
            .insert((circuit_type, step, index), proof);
        Ok(())
    }

    fn set_scheduler_proof(&mut self, proof: ZkSyncRecursionLayerProof) -> SourceResult<()> {
        self.scheduler_proof = Some(proof);
        Ok(())
    }

    fn set_compression_proof(&mut self, proof: ZkSyncCompressionLayerProof) -> SourceResult<()> {
        self.compression_proof
            .insert(proof.numeric_circuit_type(), proof);
        Ok(())
    }

    fn set_compression_for_wrapper_proof(
        &mut self,
        proof: ZkSyncCompressionForWrapperProof,
    ) -> SourceResult<()> {
        self.compression_for_wrapper_proof
            .insert(proof.numeric_circuit_type(), proof);
        Ok(())
    }

    fn set_wrapper_proof(&mut self, proof: ZkSyncSnarkWrapperProof) -> SourceResult<()> {
        self.wrapper_proof
            .insert(proof.numeric_circuit_type(), proof);
        Ok(())
    }
}
