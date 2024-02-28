use crate::helper::artifact_utils::TestArtifact;
use crate::helper::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use std::{fs, path::PathBuf};

const BASIC_TEST_JSON: &[u8] = include_bytes!("test_artifacts/basic_test.json");

pub fn read_basic_test_artifact() -> TestArtifact {
    let text = std::str::from_utf8(BASIC_TEST_JSON).expect("failed converting file");
    serde_json::from_str(text).unwrap()
}
