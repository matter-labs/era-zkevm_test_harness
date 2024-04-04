use crate::helper::artifact_utils::TestArtifact;
use std::fs;

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
