use crate::helper::artifact_utils::TestArtifact;
use crate::helper::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use std::{fs, path::PathBuf};

const TEST_ARTIFACTS_DIR: &'static str = "./src/tests/complex_tests/test_artifacts/";

pub fn read_test_artifact(test_name: &str) -> TestArtifact {
    let mut path = PathBuf::from(TEST_ARTIFACTS_DIR);

    path.push(test_name);
    path.set_extension("json");

    if !path.exists() {
        panic!(
            "The test artifacts directory {:?} does not exist",
            path.as_path()
        );
    }

    let text = fs::read_to_string(path.as_path())
        .unwrap_or_else(|_| panic!("Failed to read the test artifact"));
    serde_json::from_str(text.as_str()).unwrap()

    // serde_json::from_str(text.as_str()).unwrap_or_else(|_| panic!("Failed to deserialize the test artifact"))
}
