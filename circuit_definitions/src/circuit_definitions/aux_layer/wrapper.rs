use super::*;

use crate::circuit_definitions::aux_layer::compression_modes::*;
use snark_wrapper::franklin_crypto::bellman::pairing::Engine;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem as SnarkConstraintSystem;
use snark_wrapper::traits::circuit::ErasedBuilderForWrapperVerifier;
use snark_wrapper::traits::circuit::ProofWrapperFunction;

use crate::ProofConfig;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ZkSyncCompressionWrapper {
    CompressionMode1Circuit,
    CompressionMode2Circuit,
    CompressionMode3Circuit,
    CompressionMode4Circuit,
    CompressionMode5Circuit,
}

impl ZkSyncCompressionWrapper {
    pub fn from_numeric_circuit_type(num_type: u8) -> Self {
        match num_type {
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8 => {
                Self::CompressionMode1Circuit
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8 => {
                Self::CompressionMode2Circuit
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8 => {
                Self::CompressionMode3Circuit
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8 => {
                Self::CompressionMode4Circuit
            }
            a if a == ZkSyncCompressionLayerStorageType::CompressionMode5Circuit as u8 => {
                Self::CompressionMode5Circuit
            }
            a => panic!("Unknown numeric circuit type: {}", a),
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        match &self {
            Self::CompressionMode1Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8
            }
            Self::CompressionMode2Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8
            }
            Self::CompressionMode3Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8
            }
            Self::CompressionMode4Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8
            }
            Self::CompressionMode5Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode5Circuit as u8
            }
        }
    }
}

impl<E: Engine> ProofWrapperFunction<E> for ZkSyncCompressionWrapper {
    fn builder_for_wrapper<CS: SnarkConstraintSystem<E> + 'static>(
        &self,
    ) -> Box<dyn ErasedBuilderForWrapperVerifier<E, CS>> {
        match &self {
            Self::CompressionMode1Circuit => {
                Box::new(CompressionMode1ForWrapperCircuitBuilder::default())
            }
            Self::CompressionMode2Circuit => {
                Box::new(CompressionMode2ForWrapperCircuitBuilder::default())
            }
            Self::CompressionMode3Circuit => {
                Box::new(CompressionMode3ForWrapperCircuitBuilder::default())
            }
            Self::CompressionMode4Circuit => {
                Box::new(CompressionMode4ForWrapperCircuitBuilder::default())
            }
            Self::CompressionMode5Circuit => {
                Box::new(CompressionMode5ForWrapperCircuitBuilder::default())
            }
        }
    }

    fn proof_config_for_compression_step(&self) -> ProofConfig {
        match &self {
            Self::CompressionMode1Circuit => {
                CompressionMode1ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode2Circuit => {
                CompressionMode2ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode3Circuit => {
                CompressionMode3ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode4Circuit => {
                CompressionMode4ForWrapper::proof_config_for_compression_step()
            }
            Self::CompressionMode5Circuit => {
                CompressionMode5ForWrapper::proof_config_for_compression_step()
            }
        }
    }
}
