use circuit_definitions::circuit_definitions::recursion_layer::ZkSyncRecursionLayerProof;

use crate::{
    data_source::{local_file_data_source::LocalFileDataSource, BlockDataSource},
    helper::artifact_utils::TestArtifact,
};
use std::fs::{self, File};

const BASIC_TEST_JSON_LOCATION: &str = "src/tests/complex_tests/test_artifacts/basic_test.json";

// Reads the example basic artifact.
// To regenerate, please follow README in https://github.com/matter-labs/test-contract/tree/v1.5.0
#[allow(dead_code)]
pub fn read_basic_test_artifact() -> TestArtifact {
    let basic_test_bytes = fs::read(BASIC_TEST_JSON_LOCATION).expect("failed reading file");
    let text = std::str::from_utf8(&basic_test_bytes)
        .expect("basic test json should be utf8 encoded string");
    serde_json::from_str(text).unwrap()
}

// Returns an 'empty' node proof, that can be used in cases where we don't have any basic (and node) circuits of a given type.
pub fn empty_node_proof() -> ZkSyncRecursionLayerProof {
    bincode::deserialize_from(
        File::open("src/tests/complex_tests/test_artifacts/empty_proof.bin").unwrap(),
    )
    .unwrap()
}
