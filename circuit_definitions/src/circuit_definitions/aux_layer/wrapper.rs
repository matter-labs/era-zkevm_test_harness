use super::*;

use snark_wrapper::franklin_crypto::bellman::pairing::Engine;
use snark_wrapper::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem as SnarkConstraintSystem;
use snark_wrapper::traits::circuit::ErasedBuilderForWrapperVerifier;
use snark_wrapper::traits::circuit::ProofWrapperFunction;

use crate::ProofConfig;

enum CompressionWrapper {
    CompressionMode1Circuit,
    CompressionMode2Circuit,
    CompressionMode3Circuit,
    CompressionMode4Circuit,
    CompressionModeToL1Circuit,
}

impl CompressionWrapper {
    fn numeric_circuit_type(&self) -> u8 {
        match &self {
            CompressionWrapper::CompressionMode1Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode1Circuit as u8
            }
            CompressionWrapper::CompressionMode2Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode2Circuit as u8
            }
            CompressionWrapper::CompressionMode3Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode3Circuit as u8
            }
            CompressionWrapper::CompressionMode4Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionMode4Circuit as u8
            }
            CompressionWrapper::CompressionModeToL1Circuit => {
                ZkSyncCompressionLayerStorageType::CompressionModeToL1Circuit as u8
            }
        }
    }
}

impl<E: Engine> ProofWrapperFunction<E> for CompressionWrapper {
    fn geometry_for_compression_step() -> CSGeometry {
        todo!()
    }

    fn lookup_parameters_for_compression_step() -> LookupParameters {
        todo!()
    }

    fn builder_for_wrapper<CS: SnarkConstraintSystem<E> + 'static>(
    ) -> Box<dyn ErasedBuilderForWrapperVerifier<E, CS>> {
        Box::new(CompressionMode2ForWrapperCircuitBuilder::default())
    }

    fn proof_config_for_compression_step() -> ProofConfig {
        todo!()
    }
}
